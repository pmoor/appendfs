use crate::clock::Clock;
use crate::log::record::{FILE_HEADER_SIZE, FileHeader, FlushCommitPayload, OpCode, RecordHeader};
use crate::storage::{Storage, StorageWriter, WriteMode};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

struct ActiveLogFile {
    writer: Box<dyn StorageWriter>,
    generation: u64,
    current_offset: u64,
    filename: String,
}

enum ActiveLogState {
    Unopened {
        generation: u64,
        created_at: Option<std::time::SystemTime>,
    },
    Open(ActiveLogFile),
}

fn open_generation_file(
    storage: &Arc<dyn Storage>,
    generation: u64,
    created_at: std::time::SystemTime,
) -> io::Result<ActiveLogFile> {
    let filename = format!("{:06}.log", generation);
    let mut writer = storage.open_writer(&filename, WriteMode::CreateNew)?;

    let file_header = FileHeader::new(generation, created_at);
    let header_bytes = file_header.to_bytes();
    writer.append(&header_bytes)?;
    writer.sync()?;

    Ok(ActiveLogFile {
        writer,
        generation,
        current_offset: FILE_HEADER_SIZE as u64,
        filename,
    })
}

use crate::crypto::VolumeKey;

/// Active log writer managing append-only writes to generation log files with automatic rolling.
pub struct LogWriter {
    active_state: Mutex<ActiveLogState>,
    tx_id: AtomicU64,
    storage: Arc<dyn Storage>,
    max_log_size: u64,
    volume_key: Arc<VolumeKey>,
    _lock: Option<Box<dyn crate::storage::StorageLock>>,
}

impl std::fmt::Debug for LogWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogWriter")
            .field("tx_id", &self.tx_id.load(Ordering::Relaxed))
            .field("max_log_size", &self.max_log_size)
            .field("cipher", &self.volume_key.cipher())
            .finish()
    }
}

impl LogWriter {
    /// Creates a new generation log file backed by a custom `Storage` instance.
    pub fn create(
        storage: Arc<dyn Storage>,
        generation: u64,
        clock: &dyn Clock,
        max_log_size: u64,
        start_tx_id: u64,
        volume_key: Arc<VolumeKey>,
    ) -> io::Result<Self> {
        let lock = storage.acquire_exclusive_lock()?;
        let active_file = open_generation_file(&storage, generation, clock.now())?;
        Ok(Self {
            active_state: Mutex::new(ActiveLogState::Open(active_file)),
            tx_id: AtomicU64::new(start_tx_id),
            storage,
            max_log_size,
            volume_key,
            _lock: Some(lock),
        })
    }

    /// Creates a lazy log writer backed by a custom `Storage` instance. The generation file
    /// is not created until the first append or roll.
    pub fn create_lazy(
        storage: Arc<dyn Storage>,
        generation: u64,
        max_log_size: u64,
        start_tx_id: u64,
        volume_key: Arc<VolumeKey>,
    ) -> io::Result<Self> {
        let lock = storage.acquire_exclusive_lock()?;
        Ok(Self {
            active_state: Mutex::new(ActiveLogState::Unopened {
                generation,
                created_at: None,
            }),
            tx_id: AtomicU64::new(start_tx_id),
            storage,
            max_log_size,
            volume_key,
            _lock: Some(lock),
        })
    }

    /// Returns the active VolumeHeader used to encrypt record payloads.
    pub fn volume_key(&self) -> &Arc<VolumeKey> {
        &self.volume_key
    }

    /// Returns the underlying storage instance.
    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }

    /// Returns `true` if a physical `.log` file has been created on disk.
    pub fn is_open(&self) -> bool {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        matches!(*state, ActiveLogState::Open(_))
    }

    /// Rolls to a new generation log file (or opens the initial lazy log file) if needed.
    pub fn roll_if_needed(&self, estimated_additional_bytes: u64, clock: &dyn Clock) -> io::Result<Option<u64>> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        match &mut *state {
            ActiveLogState::Unopened { generation, created_at } => {
                let gen_num = *generation;
                let c_time = created_at.unwrap_or_else(|| clock.now());
                let active_file = open_generation_file(&self.storage, gen_num, c_time)?;
                *state = ActiveLogState::Open(active_file);
                log::info!("Lazily opened initial log file for generation {}", gen_num);
                Ok(Some(gen_num))
            }
            ActiveLogState::Open(active) => {
                if active.current_offset <= FILE_HEADER_SIZE as u64
                    || active.current_offset + estimated_additional_bytes <= self.max_log_size
                {
                    return Ok(None);
                }

                active.writer.sync()?;

                let next_gen = active.generation + 1;
                let next_active = open_generation_file(&self.storage, next_gen, clock.now())?;

                log::info!("Rolled log file to generation {} ({})", next_gen, next_active.filename);

                *active = next_active;
                Ok(Some(next_gen))
            }
        }
    }

    /// Appends a record (`RecordHeader` + payload bytes) to the active log file.
    pub fn append_record(&self, op_code: OpCode, inode: u64, payload: &[u8]) -> io::Result<(u64, u64, u64)> {
        let tx = self.tx_id.fetch_add(1, Ordering::SeqCst);

        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        let active = match &mut *state {
            ActiveLogState::Open(a) => a,
            ActiveLogState::Unopened { generation, created_at } => {
                let gen_num = *generation;
                let c_time = created_at.unwrap_or_else(std::time::SystemTime::now);
                let active_file = open_generation_file(&self.storage, gen_num, c_time)?;
                *state = ActiveLogState::Open(active_file);
                match &mut *state {
                    ActiveLogState::Open(a) => a,
                    _ => unreachable!(),
                }
            }
        };

        let generation = active.generation;
        let cipher_payload = self
            .volume_key
            .encrypt_record(generation, tx, op_code as u8, inode, payload)
            .map_err(io::Error::other)?;

        let header = RecordHeader {
            op_code,
            tx_id: tx,
            inode,
            payload_len: cipher_payload.len() as u32,
            checksum: crate::log::record::checksum_payload(&cipher_payload),
        };
        let header_bytes = header.to_bytes();
        let total_bytes = header_bytes.len() + cipher_payload.len();

        let record_log_offset = active.current_offset;
        let write_result = (|| -> io::Result<()> {
            active.writer.append(&header_bytes)?;
            if !cipher_payload.is_empty() {
                active.writer.append(&cipher_payload)?;
            }
            Ok(())
        })();

        if let Err(e) = write_result {
            let _ = active.writer.truncate(record_log_offset);
            active.current_offset = record_log_offset;
            return Err(e);
        }

        active.current_offset += total_bytes as u64;

        Ok((tx, generation, record_log_offset))
    }

    /// Rolls back the active log file to `offset` if it is currently in `generation`
    /// and its offset is past `offset`. Truncates the underlying file on disk and seeks back.
    pub fn rollback_to(&self, generation: u64, offset: u64) -> io::Result<()> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let ActiveLogState::Open(active) = &mut *state
            && active.generation == generation
            && active.current_offset > offset
        {
            let _ = active.writer.truncate(offset);
            active.current_offset = offset;
        }
        Ok(())
    }

    /// Emits the `OpCode::FlushCommit` trailer confirming `record_count` records
    pub fn emit_flush_commit(&self, record_count: u32, clock: &dyn Clock) -> io::Result<u64> {
        let now = clock.now();
        let commit_payload = FlushCommitPayload {
            timestamp: now,
            record_count,
        };

        let payload_bytes =
            bincode::serialize(&commit_payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let (tx, _, _) = self.append_record(OpCode::FlushCommit, 0, &payload_bytes)?;
        Ok(tx)
    }

    /// Flushes unwritten internal buffers to persistent media.
    pub fn flush(&self) -> io::Result<()> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let ActiveLogState::Open(active) = &mut *state {
            active.writer.sync()
        } else {
            Ok(())
        }
    }

    /// Performs a physical sync.
    pub fn sync(&self) -> io::Result<()> {
        self.flush()
    }

    /// Returns the active generation sequence number.
    pub fn generation(&self) -> u64 {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { generation, .. } => *generation,
            ActiveLogState::Open(active) => active.generation,
        }
    }

    /// Returns the current byte offset of the active log file.
    pub fn current_offset(&self) -> u64 {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { .. } => 0,
            ActiveLogState::Open(active) => active.current_offset,
        }
    }

    /// Returns the active log file name (e.g. `000001.log`).
    pub fn filename(&self) -> String {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { generation, .. } => format!("{:06}.log", generation),
            ActiveLogState::Open(active) => active.filename.clone(),
        }
    }

    /// Returns the filesystem path to the active log file if OsStorage is used.
    pub fn path(&self) -> PathBuf {
        PathBuf::from(self.filename())
    }

    /// Returns the last transaction ID assigned by this writer.
    pub fn last_tx_id(&self) -> u64 {
        self.tx_id.load(Ordering::SeqCst).saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::DEFAULT_MAX_LOG_SIZE;
    use crate::clock::SystemClock;
    use crate::log::reader::LogReader;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_log_writer_create_and_append() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(
            storage.clone(),
            1,
            &clock,
            DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        assert_eq!(writer.generation(), 1);
        let (tx, gen_num, offset) = writer.append_record(OpCode::Data, 100, b"test_data").unwrap();
        assert_eq!(tx, 1);
        assert_eq!(gen_num, 1);
        assert_eq!(offset, FILE_HEADER_SIZE as u64);
    }

    #[test]
    fn test_append_record_never_rolls_mid_batch() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 30, 1, VolumeKey::plaintext_arc()).unwrap();

        for _ in 0..5 {
            let (_, gen_num, _) = writer.append_record(OpCode::Data, 1, b"0123456789").unwrap();
            assert_eq!(gen_num, 1);
        }
        assert_eq!(writer.generation(), 1);
    }

    #[test]
    fn test_roll_if_needed_rolls_between_batches() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 60, 1, VolumeKey::plaintext_arc()).unwrap();

        writer.append_record(OpCode::Data, 1, b"0123456789").unwrap();
        assert_eq!(writer.generation(), 1);

        writer.roll_if_needed(1000, &clock).unwrap();
        assert_eq!(writer.generation(), 2);

        let (_, gen_num, _) = writer.append_record(OpCode::Data, 2, b"0123456789").unwrap();
        assert_eq!(gen_num, 2);
    }

    #[test]
    fn test_emit_flush_commit_round_trip() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(
            storage.clone(),
            1,
            &clock,
            DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        writer.append_record(OpCode::InodeDelta, 1, b"payload").unwrap();
        writer.append_record(OpCode::Data, 1, b"more").unwrap();
        writer.emit_flush_commit(2, &clock).unwrap();

        let records: Vec<_> = LogReader::open(storage.as_ref(), &writer.filename(), VolumeKey::plaintext_arc())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].header.op_code, OpCode::FlushCommit);
        let payload: FlushCommitPayload = bincode::deserialize(&records[2].payload).unwrap();
        assert_eq!(payload.record_count, 2);
    }

    #[test]
    fn test_lazy_log_writer_creates_no_file_until_first_write() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer =
            LogWriter::create_lazy(storage.clone(), 1, DEFAULT_MAX_LOG_SIZE, 1, VolumeKey::plaintext_arc()).unwrap();

        assert!(!writer.is_open());
        assert_eq!(writer.generation(), 1);
        assert!(!storage.exists("000001.log"));

        let opened_gen = writer.roll_if_needed(100, &clock).unwrap();
        assert_eq!(opened_gen, Some(1));
        assert!(writer.is_open());
        assert!(storage.exists("000001.log"));

        let no_roll = writer.roll_if_needed(100, &clock).unwrap();
        assert_eq!(no_roll, None);
    }
}
