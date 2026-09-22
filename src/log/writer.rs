use crate::clock::Clock;
use crate::log::record::{FILE_HEADER_SIZE, FileHeader, FlushCommitPayload, OpCode, RecordHeader};
use crate::storage::{BufferedStorageWriter, Storage, StorageWriter, WriteMode};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

struct ActiveLogFile {
    writer: Box<dyn StorageWriter>,
    generation: u64,
    revision: u32,
    current_offset: u64,
    filename: String,
    created_at: std::time::SystemTime,
    record_count: u32,
    total_data_bytes: u64,
    md5_hasher: md5::Context,
    batch_checkpoint_hasher: Option<md5::Context>,
    batch_checkpoint_record_count: u32,
    batch_checkpoint_data_bytes: u64,
}

impl ActiveLogFile {
    fn append_record(
        &mut self,
        volume_key: &VolumeKey,
        compression: crate::compress::Compression,
        op_code: OpCode,
        inode: u64,
        payload: &[u8],
    ) -> io::Result<(u64, u64, u32)> {
        let generation = self.generation;
        let revision = self.revision;
        let record_log_offset = self.current_offset;
        let (actual_op, cipher_payload, auth_tag) = crate::log::codec::encode(
            volume_key,
            compression,
            crate::log::codec::RecordId {
                generation,
                revision,
                record_offset: record_log_offset,
                op_code: op_code as u8,
                inode,
            },
            payload,
        )?;

        let header = RecordHeader {
            op_code: actual_op,
            inode,
            payload_len: cipher_payload.len() as u32,
            auth_tag,
        };
        let header_bytes = header.to_bytes();
        let total_bytes = header_bytes.len() + cipher_payload.len();

        let write_result = (|| -> io::Result<()> {
            self.writer.append(&header_bytes)?;
            if !cipher_payload.is_empty() {
                self.writer.append(&cipher_payload)?;
            }
            Ok(())
        })();

        if let Err(e) = write_result {
            let _ = self.writer.truncate(record_log_offset);
            self.current_offset = record_log_offset;
            return Err(e);
        }

        self.md5_hasher.consume(header_bytes);
        if !cipher_payload.is_empty() {
            self.md5_hasher.consume(&cipher_payload);
        }
        self.current_offset += total_bytes as u64;

        Ok((generation, record_log_offset, total_bytes as u32))
    }

    fn seal(
        mut self,
        volume_key: &VolumeKey,
        timestamp: std::time::SystemTime,
    ) -> io::Result<super::manifest::LogFileInfo> {
        if self.current_offset > FILE_HEADER_SIZE as u64 {
            let seal_payload = crate::log::record::SealPayload {
                timestamp,
                record_count: self.record_count,
            };
            let payload_bytes =
                crate::wire::serialize(&seal_payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            self.append_record(
                volume_key,
                crate::compress::Compression::None,
                OpCode::Seal,
                0,
                &payload_bytes,
            )?;
        }
        self.writer.sync()?;
        drop(self.writer);
        let sealed_md5 = self.md5_hasher.compute().0;
        Ok(super::manifest::LogFileInfo {
            generation: self.generation,
            revision: 0,
            filename: self.filename,
            created_at: self.created_at,
            record_count: self.record_count,
            total_bytes: self.current_offset,
            total_data_bytes: self.total_data_bytes,
            md5: sealed_md5,
            sealed: true,
        })
    }
}

#[allow(clippy::large_enum_variant)]
enum ActiveLogState {
    Unopened {
        generation: u64,
        created_at: Option<std::time::SystemTime>,
    },
    Open(ActiveLogFile),
}

/// Syncs and seals `active`, then replaces it with a freshly opened next generation.
///
/// Shared by the three ways a generation ends - size, age, and an explicit force-roll - so
/// they cannot drift on how a log file is closed out.
fn seal_and_open_next(
    active: ActiveLogFile,
    storage: &Arc<dyn Storage>,
    volume_key: &VolumeKey,
    clock: &dyn Clock,
    reason: &str,
) -> io::Result<(ActiveLogFile, super::manifest::LogFileInfo)> {
    let next_gen = active.generation + 1;
    let now = clock.now();
    let sealed_info = active.seal(volume_key, now)?;
    let next_active = open_generation_file(storage, next_gen, now)?;
    log::info!(
        "{} log file to generation {} ({})",
        reason,
        next_gen,
        next_active.filename
    );
    Ok((next_active, sealed_info))
}

fn open_generation_file(
    storage: &Arc<dyn Storage>,
    generation: u64,
    created_at: std::time::SystemTime,
) -> io::Result<ActiveLogFile> {
    let filename = super::log_filename(generation);
    let raw_writer = storage.open_writer(&filename, WriteMode::CreateNew)?;
    let mut writer = BufferedStorageWriter::new(raw_writer)?;
    let mut md5_hasher = md5::Context::new();

    let file_header = FileHeader::new(generation, created_at);
    let header_bytes = file_header.to_bytes();
    writer.append(&header_bytes)?;
    writer.sync()?;
    md5_hasher.consume(header_bytes);

    Ok(ActiveLogFile {
        writer: Box::new(writer),
        generation,
        revision: file_header.revision,
        current_offset: FILE_HEADER_SIZE as u64,
        filename,
        created_at,
        record_count: 0,
        total_data_bytes: 0,
        md5_hasher,
        batch_checkpoint_hasher: None,
        batch_checkpoint_record_count: 0,
        batch_checkpoint_data_bytes: 0,
    })
}

use crate::crypto::VolumeKey;

/// Active log writer managing append-only writes to generation log files with automatic rolling.
pub struct LogWriter {
    active_state: Mutex<ActiveLogState>,
    batch_id: AtomicU64,
    batch_checkpoint_batch_id: AtomicU64,
    storage: Arc<dyn Storage>,
    max_log_size: u64,
    max_log_age: Option<std::time::Duration>,
    volume_key: Arc<VolumeKey>,
    /// Compression applied to payloads before encryption. Set from the volume header via
    /// [`LogWriter::with_compression`] rather than passed to every constructor, which would
    /// reintroduce the telescoping shape this module deliberately avoids.
    compression: crate::compress::Compression,
    _lock: Option<Box<dyn crate::storage::StorageLock>>,
}

impl std::fmt::Debug for LogWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogWriter")
            .field("batch_id", &self.batch_id.load(Ordering::Relaxed))
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
        start_batch_id: u64,
        volume_key: Arc<VolumeKey>,
    ) -> io::Result<Self> {
        let lock = storage.acquire_exclusive_lock()?;
        let active_file = open_generation_file(&storage, generation, clock.now())?;
        Ok(Self {
            active_state: Mutex::new(ActiveLogState::Open(active_file)),
            batch_id: AtomicU64::new(start_batch_id),
            batch_checkpoint_batch_id: AtomicU64::new(start_batch_id),
            storage,
            max_log_size,
            max_log_age: None,
            volume_key,
            compression: crate::compress::Compression::None,
            _lock: Some(lock),
        })
    }

    /// Creates a lazy log writer backed by a custom `Storage` instance. The generation file
    /// is not created until the first append or roll.
    pub fn create_lazy(
        storage: Arc<dyn Storage>,
        generation: u64,
        max_log_size: u64,
        start_batch_id: u64,
        volume_key: Arc<VolumeKey>,
    ) -> io::Result<Self> {
        let lock = storage.acquire_exclusive_lock()?;
        Ok(Self {
            active_state: Mutex::new(ActiveLogState::Unopened {
                generation,
                created_at: None,
            }),
            batch_id: AtomicU64::new(start_batch_id),
            batch_checkpoint_batch_id: AtomicU64::new(start_batch_id),
            storage,
            max_log_size,
            max_log_age: None,
            volume_key,
            compression: crate::compress::Compression::None,
            _lock: Some(lock),
        })
    }

    /// Creates a lazy log writer with an injected clock whose initial creation timestamp
    /// is used when the active log file is eventually opened.
    pub fn create_lazy_with_clock(
        storage: Arc<dyn Storage>,
        generation: u64,
        clock: &dyn Clock,
        max_log_size: u64,
        start_batch_id: u64,
        volume_key: Arc<VolumeKey>,
    ) -> io::Result<Self> {
        let lock = storage.acquire_exclusive_lock()?;
        Ok(Self {
            active_state: Mutex::new(ActiveLogState::Unopened {
                generation,
                created_at: Some(clock.now()),
            }),
            batch_id: AtomicU64::new(start_batch_id),
            batch_checkpoint_batch_id: AtomicU64::new(start_batch_id),
            storage,
            max_log_size,
            max_log_age: None,
            volume_key,
            compression: crate::compress::Compression::None,
            _lock: Some(lock),
        })
    }

    /// Sets the maximum duration an active generation log can remain open before rolling.
    pub fn with_max_log_age(mut self, max_age: Option<std::time::Duration>) -> Self {
        self.max_log_age = max_age;
        self
    }

    /// Sets the compression applied to record payloads before they are encrypted.
    pub fn with_compression(mut self, compression: crate::compress::Compression) -> Self {
        self.compression = compression;
        self
    }

    /// Returns the volume key used to encrypt record payloads.
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
    /// Returns the sealed `LogFileInfo` if a rollover occurred.
    pub fn roll_if_needed(&self, clock: &dyn Clock) -> io::Result<Option<super::manifest::LogFileInfo>> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        match &*state {
            ActiveLogState::Unopened { .. } => {}
            ActiveLogState::Open(active) => {
                let size_exceeded =
                    active.current_offset > FILE_HEADER_SIZE as u64 && active.current_offset >= self.max_log_size;

                let age_exceeded = if let Some(max_age) = self.max_log_age {
                    active.current_offset > FILE_HEADER_SIZE as u64
                        && clock.now().duration_since(active.created_at).unwrap_or_default() >= max_age
                } else {
                    false
                };

                if !size_exceeded && !age_exceeded {
                    return Ok(None);
                }
            }
        }

        let old_state = std::mem::replace(
            &mut *state,
            ActiveLogState::Unopened {
                generation: 0,
                created_at: None,
            },
        );

        match old_state {
            ActiveLogState::Unopened { generation, created_at } => {
                let gen_num = generation;
                let c_time = created_at.unwrap_or_else(|| clock.now());
                match open_generation_file(&self.storage, gen_num, c_time) {
                    Ok(active_file) => {
                        *state = ActiveLogState::Open(active_file);
                        log::info!("Lazily opened log file for generation {}", gen_num);
                        Ok(None)
                    }
                    Err(e) => {
                        *state = ActiveLogState::Unopened {
                            generation: gen_num,
                            created_at,
                        };
                        Err(e)
                    }
                }
            }
            ActiveLogState::Open(active) => {
                let next_gen = active.generation + 1;
                match seal_and_open_next(active, &self.storage, &self.volume_key, clock, "Rolled") {
                    Ok((next_active, sealed_info)) => {
                        *state = ActiveLogState::Open(next_active);
                        Ok(Some(sealed_info))
                    }
                    Err(e) => {
                        *state = ActiveLogState::Unopened {
                            generation: next_gen,
                            created_at: None,
                        };
                        Err(e)
                    }
                }
            }
        }
    }

    /// Rolls the active generation if it has been open longer than `max_log_age`, ignoring
    /// its size, putting the writer into lazy mode so the new generation file is not opened
    /// until the next write.
    ///
    /// The flusher runs this at the end of every cycle, including the idle ones, so an
    /// untouched filesystem still seals its generation on schedule. Leaving the successor
    /// unopened (lazy) ensures an idle filesystem does not generate empty log files over time.
    pub fn roll_if_aged(&self, clock: &dyn Clock) -> io::Result<Option<super::manifest::LogFileInfo>> {
        let Some(max_age) = self.max_log_age else {
            return Ok(None);
        };
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        match &*state {
            // Nothing written yet, so there is nothing to seal.
            ActiveLogState::Unopened { .. } => return Ok(None),
            ActiveLogState::Open(active) => {
                if active.current_offset <= FILE_HEADER_SIZE as u64
                    || clock.now().duration_since(active.created_at).unwrap_or_default() < max_age
                {
                    return Ok(None);
                }
            }
        }

        let old_state = std::mem::replace(
            &mut *state,
            ActiveLogState::Unopened {
                generation: 0,
                created_at: None,
            },
        );
        let ActiveLogState::Open(active) = old_state else {
            unreachable!();
        };

        let next_gen = active.generation + 1;
        let sealed_info = active.seal(&self.volume_key, clock.now())?;
        log::info!(
            "Age-rolled log file: sealed generation {}, next generation {} is lazy (unopened)",
            sealed_info.generation,
            next_gen
        );
        *state = ActiveLogState::Unopened {
            generation: next_gen,
            created_at: None,
        };
        Ok(Some(sealed_info))
    }

    /// Forcefully rolls the active generation file to `generation + 1` if it has committed data,
    /// returning the sealed `LogFileInfo`.
    pub fn force_roll(&self, clock: &dyn Clock) -> io::Result<Option<super::manifest::LogFileInfo>> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        match &*state {
            ActiveLogState::Unopened { .. } => return Ok(None),
            ActiveLogState::Open(active) => {
                if active.current_offset <= FILE_HEADER_SIZE as u64 {
                    return Ok(None);
                }
            }
        }

        let old_state = std::mem::replace(
            &mut *state,
            ActiveLogState::Unopened {
                generation: 0,
                created_at: None,
            },
        );
        let ActiveLogState::Open(active) = old_state else {
            unreachable!();
        };

        let next_gen = active.generation + 1;
        match seal_and_open_next(active, &self.storage, &self.volume_key, clock, "Force-rolled") {
            Ok((next_active, sealed_info)) => {
                *state = ActiveLogState::Open(next_active);
                Ok(Some(sealed_info))
            }
            Err(e) => {
                *state = ActiveLogState::Unopened {
                    generation: next_gen,
                    created_at: None,
                };
                Err(e)
            }
        }
    }

    /// If the active log file is currently open and has committed data, syncs and seals it,
    /// transitioning writer state to `Unopened { generation: next_gen, created_at: None }`.
    /// Returns the sealed `LogFileInfo` if sealed.
    pub fn seal_active(&self, clock: &dyn Clock) -> io::Result<Option<super::manifest::LogFileInfo>> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        match &*state {
            ActiveLogState::Unopened { .. } => return Ok(None),
            ActiveLogState::Open(active) => {
                if active.current_offset <= FILE_HEADER_SIZE as u64 {
                    return Ok(None);
                }
            }
        }

        let old_state = std::mem::replace(
            &mut *state,
            ActiveLogState::Unopened {
                generation: 0,
                created_at: None,
            },
        );
        let ActiveLogState::Open(active) = old_state else {
            unreachable!();
        };

        let next_gen = active.generation + 1;
        let sealed_info = active.seal(&self.volume_key, clock.now())?;
        log::info!(
            "Sealed active log generation {}, next generation {} is lazy (unopened)",
            sealed_info.generation,
            next_gen
        );
        *state = ActiveLogState::Unopened {
            generation: next_gen,
            created_at: None,
        };
        Ok(Some(sealed_info))
    }

    /// Checkpoints the running MD5 hasher, counters, and batch_id at the beginning of a flush batch for rollback safety.
    pub fn checkpoint_batch_start(&self) {
        self.batch_checkpoint_batch_id
            .store(self.batch_id.load(Ordering::SeqCst), Ordering::SeqCst);
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let ActiveLogState::Open(active) = &mut *state {
            active.batch_checkpoint_hasher = Some(active.md5_hasher.clone());
            active.batch_checkpoint_record_count = active.record_count;
            active.batch_checkpoint_data_bytes = active.total_data_bytes;
        }
    }

    /// Appends a record (`RecordHeader` + payload bytes) to the active log file.
    ///
    /// Returns `(generation, record_log_offset, record_size)`.
    pub fn append_record(&self, op_code: OpCode, inode: u64, payload: &[u8]) -> io::Result<(u64, u64, u32)> {
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

        active.append_record(&self.volume_key, self.compression, op_code, inode, payload)
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
            if let Some(ref checkpoint) = active.batch_checkpoint_hasher {
                active.md5_hasher = checkpoint.clone();
            }
            active.record_count = active.batch_checkpoint_record_count;
            active.total_data_bytes = active.batch_checkpoint_data_bytes;
        }
        self.batch_id
            .store(self.batch_checkpoint_batch_id.load(Ordering::SeqCst), Ordering::SeqCst);
        Ok(())
    }

    /// Emits the `OpCode::FlushCommit` trailer confirming `record_count` records,
    /// and updates active log record and data byte counters.
    /// Assigns and returns the next monotonic `batch_id`.
    ///
    /// Note: To physically sync records through to durable media, call [`LogWriter::flush`].
    pub fn emit_flush_commit(&self, record_count: u32, data_bytes: u64, clock: &dyn Clock) -> io::Result<u64> {
        let batch_id = self.batch_id.fetch_add(1, Ordering::SeqCst);
        let now = clock.now();
        let commit_payload = FlushCommitPayload {
            batch_id,
            timestamp: now,
            record_count,
        };

        let payload_bytes =
            crate::wire::serialize(&commit_payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if let Err(e) = self.append_record(OpCode::FlushCommit, 0, &payload_bytes) {
            self.batch_id.store(batch_id, Ordering::SeqCst);
            return Err(e);
        }

        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let ActiveLogState::Open(active) = &mut *state {
            active.record_count += record_count + 1;
            active.total_data_bytes += data_bytes;
        }

        Ok(batch_id)
    }

    /// Flushes unwritten internal buffers through to persistent media.
    ///
    /// This is a physical sync, not a buffer hand-off: the flusher calls it on every batch,
    /// which is what makes a completed batch durable.
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

    /// Returns the creation timestamp of the active log file if known.
    pub fn created_at(&self) -> Option<std::time::SystemTime> {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { created_at, .. } => *created_at,
            ActiveLogState::Open(active) => Some(active.created_at),
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

    /// Returns the current log filename.
    pub fn filename(&self) -> String {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { generation, .. } => super::log_filename(*generation),
            ActiveLogState::Open(active) => active.filename.clone(),
        }
    }

    /// Returns the filesystem path to the active log file if OsStorage is used.
    pub fn path(&self) -> PathBuf {
        PathBuf::from(self.filename())
    }

    /// Returns the last batch ID assigned by this writer.
    pub fn last_batch_id(&self) -> u64 {
        self.batch_id.load(Ordering::SeqCst).saturating_sub(1)
    }

    /// Returns the streaming MD5 digest of all bytes written to the active log file so far.
    pub fn current_md5(&self) -> Option<[u8; 16]> {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { .. } => None,
            ActiveLogState::Open(active) => Some(active.md5_hasher.clone().compute().0),
        }
    }

    /// Returns the number of records committed in the active log file.
    pub fn record_count(&self) -> u32 {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { .. } => 0,
            ActiveLogState::Open(active) => active.record_count,
        }
    }

    /// Returns the total uncompressed data bytes written to the active log file.
    pub fn total_data_bytes(&self) -> u64 {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { .. } => 0,
            ActiveLogState::Open(active) => active.total_data_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::DEFAULT_MAX_LOG_SIZE;
    use crate::clock::{AdvancingClock, SystemClock};
    use crate::log::reader::LogReader;
    use crate::storage::MemoryStorage;
    use std::time::SystemTime;

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
        let (gen_num, offset, rec_size) = writer.append_record(OpCode::Data, 100, b"test_data").unwrap();
        assert_eq!(gen_num, 1);
        assert_eq!(offset, FILE_HEADER_SIZE as u64);
        assert_eq!(rec_size, (crate::log::record::RECORD_HEADER_SIZE + 9) as u32);
    }

    #[test]
    fn test_log_writer_creation_fails_on_read_only_storage() {
        let mem: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let ro_storage: Arc<dyn Storage> = Arc::new(crate::storage::ReadOnlyStorage::new(mem));

        let res = LogWriter::create_lazy(ro_storage, 1, DEFAULT_MAX_LOG_SIZE, 1, VolumeKey::plaintext_arc());
        assert!(res.is_err(), "LogWriter creation must fail on ReadOnlyStorage");
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_append_record_never_rolls_mid_batch() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 30, 1, VolumeKey::plaintext_arc()).unwrap();

        for _ in 0..5 {
            let (gen_num, _, _) = writer.append_record(OpCode::Data, 1, b"0123456789").unwrap();
            assert_eq!(gen_num, 1);
        }
        assert_eq!(writer.generation(), 1);
    }

    #[test]
    fn test_roll_if_needed_rolls_between_batches() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 40, 1, VolumeKey::plaintext_arc()).unwrap();

        writer.append_record(OpCode::Data, 1, b"0123456789").unwrap();
        assert_eq!(writer.generation(), 1);

        writer.roll_if_needed(&clock).unwrap();
        assert_eq!(writer.generation(), 2);

        let (gen_num, _, _) = writer.append_record(OpCode::Data, 2, b"0123456789").unwrap();
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
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        writer.append_record(OpCode::InodeDelta, 1, b"payload").unwrap();
        writer.append_record(OpCode::Data, 1, b"more").unwrap();
        let committed_batch_id = writer.emit_flush_commit(2, 4, &clock).unwrap();
        writer.flush().unwrap();
        assert_eq!(committed_batch_id, 1);

        let records: Vec<_> = LogReader::open(storage.as_ref(), &writer.filename(), VolumeKey::plaintext_arc())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].header.op_code, OpCode::FlushCommit);
        let payload: FlushCommitPayload = crate::wire::deserialize(&records[2].payload).unwrap();
        assert_eq!(payload.batch_id, 1);
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

        let opened_gen = writer.roll_if_needed(&clock).unwrap();
        assert_eq!(opened_gen, None);
        assert!(writer.is_open());
        assert!(storage.exists("000001.log"));

        let no_roll = writer.roll_if_needed(&clock).unwrap();
        assert_eq!(no_roll, None);
    }

    #[test]
    fn test_on_the_fly_md5_computation_matches_disk_bytes() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 100, 1, VolumeKey::plaintext_arc()).unwrap();

        writer.append_record(OpCode::Data, 1, b"first record payload").unwrap();
        writer
            .append_record(OpCode::InodeDelta, 1, b"second record payload")
            .unwrap();
        writer.emit_flush_commit(2, 20, &clock).unwrap();
        writer.flush().unwrap();

        // Roll to generation 2 -> returns sealed LogFileInfo
        let roll_res = writer.roll_if_needed(&clock).unwrap();
        let sealed_info = roll_res.unwrap();
        assert_eq!(sealed_info.generation, 1);
        assert_eq!(sealed_info.record_count, 3);
        assert_eq!(sealed_info.total_data_bytes, 20);
        assert_eq!(writer.generation(), 2);
        let sealed_md5 = sealed_info.md5;

        // Check against MD5 computed by reading back 000001.log from disk
        let disk_bytes = storage.get_file_bytes("000001.log").unwrap();
        let expected_md5 = *md5::compute(&disk_bytes);
        assert_eq!(
            sealed_md5, expected_md5,
            "On-the-fly computed MD5 must match raw disk bytes bit-for-bit!"
        );

        // Verify the terminal record in 000001.log is OpCode::Seal
        let records: Vec<_> = LogReader::open(storage.as_ref(), "000001.log", VolumeKey::plaintext_arc())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(records.len(), 4);
        assert_eq!(records[3].header.op_code, OpCode::Seal);
        let seal: crate::log::record::SealPayload = crate::wire::deserialize(&records[3].payload).unwrap();
        assert_eq!(seal.record_count, 3);
    }

    #[test]
    fn test_roll_if_aged_puts_writer_in_lazy_mode_and_does_not_open_file() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = AdvancingClock::new(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000));
        let writer = LogWriter::create(
            storage.clone(),
            1,
            &clock,
            DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap()
        .with_max_log_age(Some(std::time::Duration::from_secs(3600)));

        assert!(writer.is_open());
        assert_eq!(writer.generation(), 1);
        assert!(storage.exists("000001.log"));

        // No user records yet: current_offset <= FILE_HEADER_SIZE, so roll_if_aged does not roll
        clock.advance(std::time::Duration::from_secs(3601));
        let rolled = writer.roll_if_aged(&clock).unwrap();
        assert!(rolled.is_none());
        assert_eq!(writer.generation(), 1);

        // Write a user record so the log has committed data
        writer.append_record(OpCode::Data, 10, b"some data").unwrap();

        // Aged out now: rolls, seals generation 1, and leaves generation 2 in lazy mode
        let rolled = writer.roll_if_aged(&clock).unwrap();
        assert!(rolled.is_some());
        let sealed_info = rolled.unwrap();
        assert_eq!(sealed_info.generation, 1);
        assert_eq!(writer.generation(), 2);
        let sealed_md5 = sealed_info.md5;

        // Verify sealed generation MD5 matches storage bytes
        let disk_bytes = storage.get_file_bytes("000001.log").unwrap();
        assert_eq!(sealed_md5, *md5::compute(&disk_bytes));

        // Writer is now in lazy mode for generation 2
        assert_eq!(writer.generation(), 2);
        assert!(!writer.is_open());
        assert!(!storage.exists("000002.log"));

        // Additional age-checks while lazy must do nothing and not create files
        clock.advance(std::time::Duration::from_secs(3600 * 24 * 7));
        assert!(writer.roll_if_aged(&clock).unwrap().is_none());
        assert!(!writer.is_open());
        assert!(!storage.exists("000002.log"));
        assert!(!storage.exists("000003.log"));

        // First write into generation 2 lazily opens 000002.log
        let (gen_num, offset, _) = writer.append_record(OpCode::Data, 10, b"generation 2 data").unwrap();
        assert_eq!(gen_num, 2);
        assert_eq!(offset, FILE_HEADER_SIZE as u64);
        assert!(writer.is_open());
        assert!(storage.exists("000002.log"));
    }

    #[test]
    fn test_seal_active_seals_and_switches_to_lazy() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 1000, 1, VolumeKey::plaintext_arc()).unwrap();

        // When nothing written, seal_active returns None
        assert!(writer.seal_active(&clock).unwrap().is_none());

        writer.append_record(OpCode::Data, 1, b"active data").unwrap();
        let sealed = writer.seal_active(&clock).unwrap().unwrap();
        assert_eq!(sealed.generation, 1);
        assert_ne!(sealed.md5, [0u8; 16]);
        assert_eq!(writer.generation(), 2);
        assert!(!writer.is_open());
    }

    #[test]
    fn test_batch_checkpoint_and_rollback_restores_batch_id() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 1000, 1, VolumeKey::plaintext_arc()).unwrap();
        let initial_offset = writer.current_offset();

        // Checkpoint before batch starts at batch_id = 1
        writer.checkpoint_batch_start();

        // Write some records and emit flush commit
        writer.append_record(OpCode::Data, 1, b"batch data").unwrap();
        let committed_id = writer.emit_flush_commit(1, 10, &clock).unwrap();
        writer.flush().unwrap();
        assert_eq!(committed_id, 1);
        assert_eq!(writer.last_batch_id(), 1);

        // Simulate flush failure: rollback to initial_offset
        writer.rollback_to(1, initial_offset).unwrap();
        assert_eq!(writer.last_batch_id(), 0);

        // Retrying the batch should re-use batch_id 1
        writer.checkpoint_batch_start();
        writer.append_record(OpCode::Data, 1, b"batch data retry").unwrap();
        let retried_id = writer.emit_flush_commit(1, 16, &clock).unwrap();
        writer.flush().unwrap();
        assert_eq!(retried_id, 1);
        assert_eq!(writer.last_batch_id(), 1);
    }
}
