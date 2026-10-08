use crate::clock::Clock;
use crate::crypto::{LogFileKey, VolumeKey};
use crate::log::record::{FILE_HEADER_SIZE, FileHeader, FlushCommitPayload, OpCode, RECORD_HEADER_SIZE, RecordHeader};
use crate::storage::{BufferedStorageWriter, Storage, StorageWriter, WriteMode};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

/// Initial capacity for the reusable per-record staging buffer (4.25 MiB).
/// Accommodates max 4 MiB payload + zstd compression expansion bound + header.
const INITIAL_RECORD_BUFFER_CAPACITY: usize = 4 * 1024 * 1024 + 256 * 1024;

struct ActiveLogFile {
    writer: Box<dyn StorageWriter>,
    generation: u32,
    /// The key this file's records are encrypted under, derived from the salt in its header.
    file_key: LogFileKey,
    /// Sequence number the next record in this file will be encrypted under.
    ///
    /// Advanced whenever a record is encoded and never moved back, not even by
    /// [`LogWriter::rollback_to`]: a retried write must not re-encrypt a different payload under
    /// a nonce the failed attempt already used, since those bytes may already be on disk.
    next_sequence: u64,
    current_offset: u64,
    filename: String,
    created_at: std::time::SystemTime,
    record_count: u32,
    total_data_bytes: u64,
    md5_hasher: md5::Context,
    record_buf: Vec<u8>,
}

impl ActiveLogFile {
    fn append_serialized<T: serde::Serialize>(
        &mut self,
        op_code: OpCode,
        inode: u64,
        value: &T,
    ) -> io::Result<(u32, u64, u32)> {
        let generation = self.generation;
        let record_log_offset = self.current_offset;
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("generation {} has used every record sequence number", generation),
            )
        })?;
        let header_size = RECORD_HEADER_SIZE;

        if self.record_buf.len() < header_size {
            self.record_buf.resize(header_size, 0);
        } else {
            self.record_buf.truncate(header_size);
        }

        crate::wire::serialize_into(&mut self.record_buf, value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let payload_len = (self.record_buf.len() - header_size) as u32;

        let auth_tag = self
            .file_key
            .encrypt_record_in_place(sequence, op_code as u8, inode, &mut self.record_buf[header_size..])
            .map_err(io::Error::from)?;

        let header = RecordHeader {
            op_code,
            inode,
            payload_len,
            sequence,
            auth_tag,
        };
        self.record_buf[..header_size].copy_from_slice(&header.to_bytes());

        let total_bytes = self.record_buf.len();
        let write_result = self.writer.append(&self.record_buf);
        if let Err(e) = write_result {
            let _ = self.writer.truncate(record_log_offset);
            self.current_offset = record_log_offset;
            return Err(e);
        }

        self.md5_hasher.consume(&self.record_buf);
        self.current_offset += total_bytes as u64;

        Ok((generation, record_log_offset, total_bytes as u32))
    }

    fn append_data_slices(
        &mut self,
        compression: crate::compress::Compression,
        inode: u64,
        slices: &[&[u8]],
        total_uncompressed_len: usize,
    ) -> io::Result<(u32, u64, u32)> {
        let generation = self.generation;
        let record_log_offset = self.current_offset;
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("generation {} has used every record sequence number", generation),
            )
        })?;
        let header_size = RECORD_HEADER_SIZE;

        let mut actual_op = OpCode::Data;
        let mut payload_len = total_uncompressed_len;
        let mut compressed_successfully = false;

        if compression == crate::compress::Compression::Zstd && total_uncompressed_len > 0 {
            if self.record_buf.len() < header_size {
                self.record_buf.resize(header_size, 0);
            } else {
                self.record_buf.truncate(header_size);
            }

            let compress_result = (|| -> io::Result<usize> {
                let mut encoder = zstd::stream::Encoder::new(&mut self.record_buf, crate::compress::ZSTD_LEVEL)?;
                encoder.set_pledged_src_size(Some(total_uncompressed_len as u64))?;
                for slice in slices {
                    std::io::Write::write_all(&mut encoder, slice)?;
                }
                encoder.finish()?;
                Ok(self.record_buf.len() - header_size)
            })();

            if let Ok(comp_len) = compress_result
                && crate::compress::is_compression_beneficial(total_uncompressed_len, comp_len)
            {
                actual_op = OpCode::DataZstd;
                payload_len = comp_len;
                compressed_successfully = true;
            }
        }

        if !compressed_successfully {
            actual_op = OpCode::Data;
            payload_len = total_uncompressed_len;
            let total_needed = header_size + total_uncompressed_len;
            if self.record_buf.len() < total_needed {
                self.record_buf.resize(total_needed, 0);
            }
            let mut offset = header_size;
            for slice in slices {
                self.record_buf[offset..offset + slice.len()].copy_from_slice(slice);
                offset += slice.len();
            }
        }

        let auth_tag = self
            .file_key
            .encrypt_record_in_place(
                sequence,
                actual_op as u8,
                inode,
                &mut self.record_buf[header_size..header_size + payload_len],
            )
            .map_err(io::Error::from)?;

        let header = RecordHeader {
            op_code: actual_op,
            inode,
            payload_len: payload_len as u32,
            sequence,
            auth_tag,
        };
        self.record_buf[..header_size].copy_from_slice(&header.to_bytes());

        let total_bytes = header_size + payload_len;
        let write_result = self.writer.append(&self.record_buf[..total_bytes]);
        if let Err(e) = write_result {
            let _ = self.writer.truncate(record_log_offset);
            self.current_offset = record_log_offset;
            return Err(e);
        }

        self.md5_hasher.consume(&self.record_buf[..total_bytes]);
        self.current_offset += total_bytes as u64;

        Ok((generation, record_log_offset, total_bytes as u32))
    }

    #[cfg(any(test, feature = "testing"))]
    fn append_raw_payload(&mut self, op_code: OpCode, inode: u64, payload: &[u8]) -> io::Result<(u32, u64, u32)> {
        let generation = self.generation;
        let record_log_offset = self.current_offset;
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("generation {} has used every record sequence number", generation),
            )
        })?;
        let header_size = RECORD_HEADER_SIZE;
        let total_needed = header_size + payload.len();

        if self.record_buf.len() < total_needed {
            self.record_buf.resize(total_needed, 0);
        }

        self.record_buf[header_size..total_needed].copy_from_slice(payload);

        let auth_tag = self
            .file_key
            .encrypt_record_in_place(
                sequence,
                op_code as u8,
                inode,
                &mut self.record_buf[header_size..total_needed],
            )
            .map_err(io::Error::from)?;

        let header = RecordHeader {
            op_code,
            inode,
            payload_len: payload.len() as u32,
            sequence,
            auth_tag,
        };
        self.record_buf[..header_size].copy_from_slice(&header.to_bytes());

        let write_result = self.writer.append(&self.record_buf[..total_needed]);
        if let Err(e) = write_result {
            let _ = self.writer.truncate(record_log_offset);
            self.current_offset = record_log_offset;
            return Err(e);
        }

        self.md5_hasher.consume(&self.record_buf[..total_needed]);
        self.current_offset += total_needed as u64;

        Ok((generation, record_log_offset, total_needed as u32))
    }

    fn seal(mut self, timestamp: std::time::SystemTime) -> io::Result<super::manifest::LogFileInfo> {
        if self.current_offset > FILE_HEADER_SIZE as u64 {
            let seal_payload = crate::log::record::SealPayload {
                timestamp,
                record_count: self.record_count,
            };
            self.append_serialized(OpCode::Seal, 0, &seal_payload)?;
        }
        self.writer.sync()?;
        drop(self.writer);
        let sealed_md5 = self.md5_hasher.compute().0;
        Ok(super::manifest::LogFileInfo {
            version: crate::log::record::CURRENT_VERSION,
            generation: self.generation,
            revision: 0,
            filename: self.filename,
            created_at: self.created_at,
            record_count: self.record_count,
            total_bytes: self.current_offset,
            total_data_bytes: self.total_data_bytes,
            md5: sealed_md5,
            sealed_at: Some(timestamp),
        })
    }
}

#[allow(clippy::large_enum_variant)]
enum ActiveLogState {
    Unopened {
        generation: u32,
        created_at: Option<std::time::SystemTime>,
    },
    Open(ActiveLogFile),
}

impl ActiveLogState {
    fn get_or_open(&mut self, storage: &Arc<dyn Storage>, keying: &FileKeying) -> io::Result<&mut ActiveLogFile> {
        match self {
            ActiveLogState::Open(a) => Ok(a),
            ActiveLogState::Unopened { generation, created_at } => {
                let gen_num = *generation;
                let c_time = created_at.unwrap_or_else(std::time::SystemTime::now);
                let active_file = open_generation_file(storage, keying, gen_num, c_time)?;
                *self = ActiveLogState::Open(active_file);
                match self {
                    ActiveLogState::Open(a) => Ok(a),
                    _ => unreachable!(),
                }
            }
        }
    }
}

/// Syncs and seals `active`, then replaces it with a freshly opened next generation.
///
/// Shared by the three ways a generation ends - size, age, and an explicit force-roll - so
/// they cannot drift on how a log file is closed out.
fn seal_and_open_next(
    mut active: ActiveLogFile,
    storage: &Arc<dyn Storage>,
    keying: &FileKeying,
    clock: &dyn Clock,
    reason: &str,
) -> io::Result<(ActiveLogFile, super::manifest::LogFileInfo)> {
    let next_gen = next_generation(active.generation)?;
    let now = clock.now();
    let record_buf = std::mem::take(&mut active.record_buf);
    let sealed_info = active.seal(now)?;
    let mut next_active = open_generation_file(storage, keying, next_gen, now)?;
    next_active.record_buf = record_buf;
    log::info!(
        "{} log file to generation {} ({})",
        reason,
        next_gen,
        next_active.filename
    );
    Ok((next_active, sealed_info))
}

/// Seals the open generation in `state` if it has committed data, leaving its successor
/// lazy (unopened) so no file exists for it until something is written.
///
/// On failure the writer is left lazy on the successor, as [`seal_and_open_next`] does.
fn seal_into_lazy(
    state: &mut ActiveLogState,
    clock: &dyn Clock,
    meta: &RwLock<ActiveLogMeta>,
) -> io::Result<Option<super::manifest::LogFileInfo>> {
    let ActiveLogState::Open(active) = &*state else {
        return Ok(None);
    };
    if active.current_offset <= FILE_HEADER_SIZE as u64 {
        return Ok(None);
    }
    let next_gen = next_generation(active.generation)?;
    let ActiveLogState::Open(active) = std::mem::replace(
        state,
        ActiveLogState::Unopened {
            generation: next_gen,
            created_at: None,
        },
    ) else {
        unreachable!();
    };
    {
        let mut m = match meta.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        m.generation = next_gen;
        m.filename = super::log_filename(next_gen);
        m.created_at = None;
        m.current_offset = 0;
        m.record_count = 0;
        m.total_data_bytes = 0;
        m.is_open = false;
    }
    let sealed_info = active.seal(clock.now())?;
    log::info!(
        "Sealed log generation {}, next generation {} is lazy (unopened)",
        sealed_info.generation,
        next_gen
    );
    Ok(Some(sealed_info))
}

/// The generation following `generation`, or an error at the end of the sequence.
///
/// A generation is a `u32` everywhere it appears, which is what lets the record nonce carry
/// one without a range check. The flip side is that `+ 1` can overflow: in release mode it
/// would wrap silently to generation 0 and reuse every nonce the volume has ever derived, so
/// the roll fails instead. Reaching this needs 4.29 billion generations.
fn next_generation(generation: u32) -> io::Result<u32> {
    generation.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "generation {} is the last one this format can address; the volume cannot roll further",
                generation
            ),
        )
    })
}

fn open_generation_file(
    storage: &Arc<dyn Storage>,
    keying: &FileKeying,
    generation: u32,
    created_at: std::time::SystemTime,
) -> io::Result<ActiveLogFile> {
    let key_salt = (keying.key_salts)(generation);
    let filename = super::log_filename(generation);
    let raw_writer = storage.open_writer(&filename, WriteMode::CreateNew)?;
    let mut writer = BufferedStorageWriter::new(raw_writer)?;
    let mut md5_hasher = md5::Context::new();

    let file_header = FileHeader::new(generation, created_at, key_salt);
    let header_bytes = file_header.to_bytes();
    writer.append(&header_bytes)?;
    writer.sync()?;
    md5_hasher.consume(header_bytes);

    Ok(ActiveLogFile {
        writer: Box::new(writer),
        generation,
        file_key: keying.volume_key.log_file_key(&key_salt),
        next_sequence: 0,
        current_offset: FILE_HEADER_SIZE as u64,
        filename,
        created_at,
        record_count: 0,
        total_data_bytes: 0,
        md5_hasher,
        record_buf: Vec::with_capacity(INITIAL_RECORD_BUFFER_CAPACITY),
    })
}

/// Produces the key salt for each log file a [`LogWriter`] creates, given its generation.
///
/// Random by default. Replaceable only so fixture generation and tests can produce the same
/// bytes on every run - see [`LogWriter::with_key_salts`]. A source that ever returned the
/// same salt twice would put two files under one key.
type KeySaltSource = Box<dyn Fn(u32) -> [u8; 16] + Send + Sync>;

/// Everything needed to key a newly created log file.
struct FileKeying {
    volume_key: Arc<VolumeKey>,
    key_salts: KeySaltSource,
}

impl FileKeying {
    fn random(volume_key: Arc<VolumeKey>) -> Self {
        Self {
            volume_key,
            key_salts: Box::new(|_| crate::crypto::generate_random_16()),
        }
    }
}

/// Point-in-time snapshot of [`LogWriter`] state for atomic rollback on write failures.
#[derive(Clone)]
pub struct LogCheckpoint {
    pub generation: u32,
    pub offset: u64,
    pub batch_id: u64,
    hasher: Option<md5::Context>,
    record_count: u32,
    total_data_bytes: u64,
}

impl std::fmt::Debug for LogCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogCheckpoint")
            .field("generation", &self.generation)
            .field("offset", &self.offset)
            .field("batch_id", &self.batch_id)
            .field("record_count", &self.record_count)
            .field("total_data_bytes", &self.total_data_bytes)
            .finish()
    }
}

/// Point-in-time in-memory metadata for the active log file.
///
/// Kept separate from [`ActiveLogState`] so inspection queries ([`LogWriter::generation`],
/// [`LogWriter::is_open`], [`LogWriter::current_offset`], etc.) never contend with
/// slow physical I/O writes or fsyncs on [`ActiveLogState`].
#[derive(Debug, Clone)]
struct ActiveLogMeta {
    generation: u32,
    filename: String,
    created_at: Option<std::time::SystemTime>,
    current_offset: u64,
    record_count: u32,
    total_data_bytes: u64,
    is_open: bool,
}

/// Active log writer managing append-only writes to generation log files with automatic rolling.
pub struct LogWriter {
    active_state: Mutex<ActiveLogState>,
    meta: RwLock<ActiveLogMeta>,
    batch_id: AtomicU64,
    storage: Arc<dyn Storage>,
    max_log_size: u64,
    max_log_age: Option<std::time::Duration>,
    keying: FileKeying,
    /// Compression applied to payloads before encryption. Set from the volume header via
    /// [`LogWriter::with_compression`] rather than passed to every constructor, which would
    /// reintroduce the telescoping shape this module deliberately avoids.
    compression: crate::compress::Compression,
    lock: Option<Box<dyn crate::storage::StorageLock>>,
}

impl std::fmt::Debug for LogWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogWriter")
            .field("batch_id", &self.batch_id.load(Ordering::Relaxed))
            .field("max_log_size", &self.max_log_size)
            .field("cipher", &self.keying.volume_key.cipher())
            .finish()
    }
}

impl LogWriter {
    fn update_meta_from_open(&self, active: &ActiveLogFile) {
        let mut meta = match self.meta.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        meta.generation = active.generation;
        meta.filename = active.filename.clone();
        meta.created_at = Some(active.created_at);
        meta.current_offset = active.current_offset;
        meta.record_count = active.record_count;
        meta.total_data_bytes = active.total_data_bytes;
        meta.is_open = true;
    }

    fn update_meta_from_unopened(&self, generation: u32, created_at: Option<std::time::SystemTime>) {
        let mut meta = match self.meta.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        meta.generation = generation;
        meta.filename = super::log_filename(generation);
        meta.created_at = created_at;
        meta.current_offset = 0;
        meta.record_count = 0;
        meta.total_data_bytes = 0;
        meta.is_open = false;
    }

    /// Creates a new generation log file backed by a custom `Storage` instance.
    pub fn create(
        storage: Arc<dyn Storage>,
        generation: u32,
        clock: &dyn Clock,
        max_log_size: u64,
        start_batch_id: u64,
        volume_key: Arc<VolumeKey>,
    ) -> io::Result<Self> {
        let lock = storage.acquire_exclusive_lock()?;
        let keying = FileKeying::random(volume_key);
        let active_file = open_generation_file(&storage, &keying, generation, clock.now())?;
        let meta = ActiveLogMeta {
            generation,
            filename: active_file.filename.clone(),
            created_at: Some(active_file.created_at),
            current_offset: active_file.current_offset,
            record_count: 0,
            total_data_bytes: 0,
            is_open: true,
        };
        Ok(Self {
            active_state: Mutex::new(ActiveLogState::Open(active_file)),
            meta: RwLock::new(meta),
            batch_id: AtomicU64::new(start_batch_id),
            storage,
            max_log_size,
            max_log_age: None,
            keying,
            compression: crate::compress::Compression::None,
            lock: Some(lock),
        })
    }

    /// Creates a lazy log writer backed by a custom `Storage` instance. The generation file
    /// is not created until the first append or roll.
    pub fn create_lazy(
        storage: Arc<dyn Storage>,
        generation: u32,
        max_log_size: u64,
        start_batch_id: u64,
        volume_key: Arc<VolumeKey>,
    ) -> io::Result<Self> {
        let lock = storage.acquire_exclusive_lock()?;
        let meta = ActiveLogMeta {
            generation,
            filename: super::log_filename(generation),
            created_at: None,
            current_offset: 0,
            record_count: 0,
            total_data_bytes: 0,
            is_open: false,
        };
        Ok(Self {
            active_state: Mutex::new(ActiveLogState::Unopened {
                generation,
                created_at: None,
            }),
            meta: RwLock::new(meta),
            batch_id: AtomicU64::new(start_batch_id),
            storage,
            max_log_size,
            max_log_age: None,
            keying: FileKeying::random(volume_key),
            compression: crate::compress::Compression::None,
            lock: Some(lock),
        })
    }

    /// Creates a lazy log writer with an injected clock whose initial creation timestamp
    /// is used when the active log file is eventually opened.
    pub fn create_lazy_with_clock(
        storage: Arc<dyn Storage>,
        generation: u32,
        clock: &dyn Clock,
        max_log_size: u64,
        start_batch_id: u64,
        volume_key: Arc<VolumeKey>,
    ) -> io::Result<Self> {
        let lock = storage.acquire_exclusive_lock()?;
        let meta = ActiveLogMeta {
            generation,
            filename: super::log_filename(generation),
            created_at: Some(clock.now()),
            current_offset: 0,
            record_count: 0,
            total_data_bytes: 0,
            is_open: false,
        };
        Ok(Self {
            active_state: Mutex::new(ActiveLogState::Unopened {
                generation,
                created_at: Some(clock.now()),
            }),
            meta: RwLock::new(meta),
            batch_id: AtomicU64::new(start_batch_id),
            storage,
            max_log_size,
            max_log_age: None,
            keying: FileKeying::random(volume_key),
            compression: crate::compress::Compression::None,
            lock: Some(lock),
        })
    }

    /// Sets the maximum duration an active generation log can remain open before rolling.
    pub fn with_max_log_age(mut self, max_age: Option<std::time::Duration>) -> Self {
        self.max_log_age = max_age;
        self
    }

    /// Replaces the random source of per-file key salts with `key_salts`.
    ///
    /// For fixture generation and tests that need identical bytes on every run - see [`LogWriter::with_key_salts`].
    /// Takes effect for files opened from now on, so pair it with a lazy constructor to cover the first.
    ///
    /// Crate-private rather than `cfg`-gated to tests: the `generate_compat_fixture` binary is
    /// built without the `testing` feature and reaches this through [`crate::compat`]. Nothing
    /// outside the crate can replace the salt source.
    pub(crate) fn with_key_salts(mut self, key_salts: impl Fn(u32) -> [u8; 16] + Send + Sync + 'static) -> Self {
        self.keying.key_salts = Box::new(key_salts);
        self
    }

    /// Sets the compression applied to record payloads before they are encrypted.
    pub fn with_compression(mut self, compression: crate::compress::Compression) -> Self {
        self.compression = compression;
        self
    }

    /// Returns the volume key used to encrypt record payloads.
    pub fn volume_key(&self) -> &Arc<VolumeKey> {
        &self.keying.volume_key
    }

    /// Returns the underlying storage instance.
    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }

    /// Records the calling process as the holder of the volume lock - see
    /// [`crate::storage::StorageLock::record_holder`].
    pub fn record_lock_holder(&self) -> io::Result<()> {
        self.lock.as_ref().map_or(Ok(()), |lock| lock.record_holder())
    }

    /// Returns `true` if a physical `.log` file has been created on disk.
    pub fn is_open(&self) -> bool {
        let meta = match self.meta.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        meta.is_open
    }

    /// Seals the active generation if it has reached `max_log_size` or `max_log_age`, leaving
    /// its successor lazy (unopened) until [`LogWriter::open_if_unopened`] has something to
    /// write to it. Returns the sealed `LogFileInfo` if a rollover occurred.
    pub fn roll_if_needed(&self, clock: &dyn Clock) -> io::Result<Option<super::manifest::LogFileInfo>> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let ActiveLogState::Open(active) = &*state else {
            return Ok(None);
        };
        let size_exceeded = active.current_offset >= self.max_log_size;
        let age_exceeded = self
            .max_log_age
            .is_some_and(|max_age| clock.now().duration_since(active.created_at).unwrap_or_default() >= max_age);
        if !size_exceeded && !age_exceeded {
            return Ok(None);
        }
        seal_into_lazy(&mut state, clock, &self.meta)
    }

    /// Ensures that the active log file is open. If it is currently lazy/unopened,
    /// opens it using the provided clock.
    pub fn open_if_unopened(&self, clock: &dyn Clock) -> io::Result<()> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        if let ActiveLogState::Unopened { generation, created_at } = *state {
            let c_time = created_at.unwrap_or_else(|| clock.now());
            let active_file = open_generation_file(&self.storage, &self.keying, generation, c_time)?;
            self.update_meta_from_open(&active_file);
            *state = ActiveLogState::Open(active_file);
            log::info!("Lazily opened log file for generation {}", generation);
        }
        Ok(())
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

        let next_gen = next_generation(active.generation)?;
        match seal_and_open_next(active, &self.storage, &self.keying, clock, "Force-rolled") {
            Ok((next_active, sealed_info)) => {
                self.update_meta_from_open(&next_active);
                *state = ActiveLogState::Open(next_active);
                Ok(Some(sealed_info))
            }
            Err(e) => {
                self.update_meta_from_unopened(next_gen, None);
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
        seal_into_lazy(&mut state, clock, &self.meta)
    }

    /// Captures a point-in-time snapshot of the log writer state (generation, offset,
    /// batch_id, record counters, and MD5 hasher) that can be restored via [`LogWriter::rollback_to`].
    pub fn checkpoint(&self) -> LogCheckpoint {
        let batch_id = self.batch_id.load(Ordering::SeqCst);
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { generation, .. } => LogCheckpoint {
                generation: *generation,
                offset: 0,
                batch_id,
                hasher: None,
                record_count: 0,
                total_data_bytes: 0,
            },
            ActiveLogState::Open(active) => LogCheckpoint {
                generation: active.generation,
                offset: active.current_offset,
                batch_id,
                hasher: Some(active.md5_hasher.clone()),
                record_count: active.record_count,
                total_data_bytes: active.total_data_bytes,
            },
        }
    }

    /// Appends a serializable struct as a record payload directly into the internal reusable buffer
    /// without intermediate heap allocations.
    ///
    /// Returns `(generation, record_log_offset, record_size)`.
    pub fn append_serialized<T: serde::Serialize>(
        &self,
        op_code: OpCode,
        inode: u64,
        value: &T,
    ) -> io::Result<(u32, u64, u32)> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let was_unopened = matches!(*state, ActiveLogState::Unopened { .. });
        let active = state.get_or_open(&self.storage, &self.keying)?;
        if was_unopened {
            self.update_meta_from_open(active);
        }
        let res = active.append_serialized(op_code, inode, value)?;
        self.update_meta_from_open(active);
        Ok(res)
    }

    /// Appends a raw file data record from one or more contiguous slices, compressing
    /// optimistically directly into the internal reusable buffer if compression is enabled.
    ///
    /// Returns `(generation, record_log_offset, record_size)`.
    pub fn append_data_slices(
        &self,
        inode: u64,
        slices: &[&[u8]],
        total_uncompressed_len: usize,
    ) -> io::Result<(u32, u64, u32)> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let was_unopened = matches!(*state, ActiveLogState::Unopened { .. });
        let active = state.get_or_open(&self.storage, &self.keying)?;
        if was_unopened {
            self.update_meta_from_open(active);
        }
        let res = active.append_data_slices(self.compression, inode, slices, total_uncompressed_len)?;
        self.update_meta_from_open(active);
        Ok(res)
    }

    /// Appends a data record from a single payload slice to the active log file,
    /// compressing optimistically directly into the internal reusable buffer if enabled.
    ///
    /// Returns `(generation, record_log_offset, record_size)`.
    pub fn append_data(&self, inode: u64, data: &[u8]) -> io::Result<(u32, u64, u32)> {
        self.append_data_slices(inode, &[data], data.len())
    }

    /// Appends a raw record with explicit opcode and byte payload without compression.
    ///
    /// Intended for test suites constructing arbitrary or edge-case records directly.
    #[cfg(any(test, feature = "testing"))]
    pub fn append_raw_for_test(&self, op_code: OpCode, inode: u64, payload: &[u8]) -> io::Result<(u32, u64, u32)> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let was_unopened = matches!(*state, ActiveLogState::Unopened { .. });
        let active = state.get_or_open(&self.storage, &self.keying)?;
        if was_unopened {
            self.update_meta_from_open(active);
        }
        let res = active.append_raw_payload(op_code, inode, payload)?;
        self.update_meta_from_open(active);
        Ok(res)
    }

    /// Rolls back the active log file to the given `checkpoint`.
    ///
    /// Truncates the underlying file on disk back to `checkpoint.offset`, restoring
    /// the running MD5 hasher, counters, and next `batch_id`.
    ///
    /// The record sequence is deliberately not restored, so records written after a rollback
    /// take fresh nonces rather than reusing those of the records that were discarded.
    pub fn rollback_to(&self, checkpoint: &LogCheckpoint) -> io::Result<()> {
        self.batch_id.store(checkpoint.batch_id, Ordering::SeqCst);
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let ActiveLogState::Open(active) = &mut *state
            && active.generation == checkpoint.generation
            && active.current_offset > checkpoint.offset
        {
            let res = active.writer.truncate(checkpoint.offset);
            active.current_offset = checkpoint.offset;
            if let Some(ref h) = checkpoint.hasher {
                active.md5_hasher = h.clone();
            }
            active.record_count = checkpoint.record_count;
            active.total_data_bytes = checkpoint.total_data_bytes;
            self.update_meta_from_open(active);
            res?;
        }
        Ok(())
    }

    /// Emits the `OpCode::FlushCommit` trailer confirming `record_count` records,
    /// and updates active log record and data byte counters.
    /// Assigns and returns the next monotonic `batch_id`.
    ///
    /// `timestamp` is supplied by the caller rather than read from a clock here, so a batch
    /// written again after a [`LogWriter::rollback_to`] records the same commit time - see
    /// `FlushBatch::commit_timestamp`.
    ///
    /// Note: To physically sync records through to durable media, call [`LogWriter::flush`].
    pub fn emit_flush_commit(
        &self,
        record_count: u32,
        data_bytes: u64,
        timestamp: std::time::SystemTime,
    ) -> io::Result<u64> {
        let batch_id = self.batch_id.fetch_add(1, Ordering::SeqCst);
        let commit_payload = FlushCommitPayload {
            batch_id,
            timestamp,
            record_count,
        };

        if let Err(e) = self.append_serialized(OpCode::FlushCommit, 0, &commit_payload) {
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
            self.update_meta_from_open(active);
        }

        Ok(batch_id)
    }

    /// Synchronously flushes in-memory buffers through to durable media.
    pub fn flush(&self) -> io::Result<()> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let ActiveLogState::Open(active) = &mut *state {
            active.writer.sync()?;
        }
        Ok(())
    }

    /// Returns the current active generation number.
    pub fn generation(&self) -> u32 {
        let meta = match self.meta.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        meta.generation
    }

    /// Returns the active log file name.
    pub fn filename(&self) -> String {
        let meta = match self.meta.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        meta.filename.clone()
    }

    /// Returns the current byte offset in the active generation log file.
    ///
    /// For unopened writers, returns `0` (before the initial `FileHeader`).
    pub fn current_offset(&self) -> u64 {
        let meta = match self.meta.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        meta.current_offset
    }

    /// Returns the ID of the last committed flush batch, or 0 if none has been committed yet.
    pub fn last_batch_id(&self) -> u64 {
        self.batch_id.load(Ordering::SeqCst).saturating_sub(1)
    }

    /// Returns the number of user and flush records written to the active log file.
    pub fn record_count(&self) -> u32 {
        let meta = match self.meta.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        meta.record_count
    }

    /// Returns the total uncompressed data bytes written to the active log file.
    pub fn total_data_bytes(&self) -> u64 {
        let meta = match self.meta.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        meta.total_data_bytes
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
    fn test_generation_space_ends_rather_than_wrapping() {
        // Wrapping here would restart the generation sequence at 0 and reuse every nonce the
        // volume has derived, so the end of the space has to be an error, not a wrap.
        assert_eq!(next_generation(0).unwrap(), 1);
        assert_eq!(next_generation(u32::MAX - 1).unwrap(), u32::MAX);

        let err = next_generation(u32::MAX).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("cannot roll further"), "{}", err);
    }

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
        let (gen_num, offset, rec_size) = writer.append_data(100, b"test_data").unwrap();
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
    fn test_append_data_never_rolls_mid_batch() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 30, 1, VolumeKey::plaintext_arc()).unwrap();

        for _ in 0..5 {
            let (gen_num, _, _) = writer.append_data(1, b"0123456789").unwrap();
            assert_eq!(gen_num, 1);
        }
        assert_eq!(writer.generation(), 1);
    }

    #[test]
    fn test_roll_if_needed_rolls_between_batches() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 40, 1, VolumeKey::plaintext_arc()).unwrap();

        writer.append_data(1, b"0123456789").unwrap();
        assert_eq!(writer.generation(), 1);

        writer.roll_if_needed(&clock).unwrap();
        assert_eq!(writer.generation(), 2);

        let (gen_num, _, _) = writer.append_data(2, b"0123456789").unwrap();
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

        writer.append_raw_for_test(OpCode::InodeDelta, 1, b"payload").unwrap();
        writer.append_data(1, b"more").unwrap();
        let committed_batch_id = writer.emit_flush_commit(2, 4, clock.now()).unwrap();
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

        // Nothing to seal, and rolling is not what opens a lazy generation.
        assert_eq!(writer.roll_if_needed(&clock).unwrap(), None);
        assert!(!writer.is_open());
        assert!(!storage.exists("000001.log"));

        writer.open_if_unopened(&clock).unwrap();
        assert!(writer.is_open());
        assert!(storage.exists("000001.log"));

        let no_roll = writer.roll_if_needed(&clock).unwrap();
        assert_eq!(no_roll, None);
    }

    #[test]
    fn test_on_the_fly_md5_computation_matches_disk_bytes() {
        let storage = Arc::new(MemoryStorage::new());
        let mock_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let clock = crate::clock::MockClock(mock_time);
        let writer = LogWriter::create(storage.clone(), 1, &clock, 100, 1, VolumeKey::plaintext_arc()).unwrap();

        writer.append_data(1, b"first record payload").unwrap();
        writer
            .append_raw_for_test(OpCode::InodeDelta, 1, b"second record payload")
            .unwrap();
        writer.emit_flush_commit(2, 20, clock.now()).unwrap();
        writer.flush().unwrap();

        // Roll to generation 2 -> returns sealed LogFileInfo
        let roll_res = writer.roll_if_needed(&clock).unwrap();
        let sealed_info = roll_res.unwrap();
        assert_eq!(sealed_info.version, crate::log::record::CURRENT_VERSION);
        assert!(sealed_info.is_sealed());
        assert_eq!(sealed_info.sealed_at, Some(mock_time));
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
    fn test_roll_if_needed_on_age_puts_writer_in_lazy_mode_and_does_not_open_file() {
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

        // No user records yet: current_offset <= FILE_HEADER_SIZE, so roll_if_needed does not roll
        clock.advance(std::time::Duration::from_secs(3601));
        let rolled = writer.roll_if_needed(&clock).unwrap();
        assert!(rolled.is_none());
        assert_eq!(writer.generation(), 1);

        // Write a user record so the log has committed data
        writer.append_data(10, b"some data").unwrap();

        // Aged out now: rolls, seals generation 1, and leaves generation 2 in lazy mode
        let rolled = writer.roll_if_needed(&clock).unwrap();
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
        assert!(writer.roll_if_needed(&clock).unwrap().is_none());
        assert!(!writer.is_open());
        assert!(!storage.exists("000002.log"));

        assert!(!storage.exists("000003.log"));

        // First write into generation 2 lazily opens 000002.log
        let (gen_num, offset, _) = writer.append_data(10, b"generation 2 data").unwrap();
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

        writer.append_data(1, b"active data").unwrap();
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

        // Checkpoint before batch starts at batch_id = 1
        let checkpoint1 = writer.checkpoint();

        // Write some records and emit flush commit
        writer.append_data(1, b"batch data").unwrap();
        let committed_id = writer.emit_flush_commit(1, 10, clock.now()).unwrap();
        writer.flush().unwrap();
        assert_eq!(committed_id, 1);
        assert_eq!(writer.last_batch_id(), 1);

        // Simulate flush failure: rollback to checkpoint1
        writer.rollback_to(&checkpoint1).unwrap();
        assert_eq!(writer.last_batch_id(), 0);

        // Retrying the batch should re-use batch_id 1
        let checkpoint2 = writer.checkpoint();
        assert_eq!(checkpoint2.offset, checkpoint1.offset);
        assert_eq!(checkpoint2.batch_id, 1);
        writer.append_data(1, b"batch data retry").unwrap();
        let retried_id = writer.emit_flush_commit(1, 16, clock.now()).unwrap();
        writer.flush().unwrap();
        assert_eq!(retried_id, 1);
        assert_eq!(writer.last_batch_id(), 1);
    }

    #[test]
    fn test_multiple_independent_checkpoints() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 10000, 1, VolumeKey::plaintext_arc()).unwrap();

        // Checkpoint A (before batch 1)
        let cp_a = writer.checkpoint();

        writer.append_data(1, b"batch 1 data").unwrap();
        let b1 = writer.emit_flush_commit(1, 12, clock.now()).unwrap();
        assert_eq!(b1, 1);

        // Checkpoint B (after batch 1, before batch 2)
        let cp_b = writer.checkpoint();
        assert_eq!(cp_b.batch_id, 2);
        assert!(cp_b.offset > cp_a.offset);

        writer.append_data(2, b"batch 2 data").unwrap();
        let b2 = writer.emit_flush_commit(1, 12, clock.now()).unwrap();
        assert_eq!(b2, 2);

        // Checkpoint C (after batch 2, before batch 3)
        let cp_c = writer.checkpoint();
        assert_eq!(cp_c.batch_id, 3);
        assert!(cp_c.offset > cp_b.offset);

        writer.append_data(3, b"batch 3 partial").unwrap();

        // Roll back to CP B: should restore to end of batch 1
        writer.rollback_to(&cp_b).unwrap();
        assert_eq!(writer.current_offset(), cp_b.offset);
        assert_eq!(writer.last_batch_id(), 1);

        // Further roll back to CP A: should restore to before batch 1
        writer.rollback_to(&cp_a).unwrap();
        assert_eq!(writer.current_offset(), cp_a.offset);
        assert_eq!(writer.last_batch_id(), 0);
    }

    #[test]
    fn test_append_serialized_direct() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 10000, 1, VolumeKey::plaintext_arc()).unwrap();

        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestMetadata {
            name: String,
            count: u64,
            tags: Vec<String>,
        }

        let meta = TestMetadata {
            name: "test_dir".to_string(),
            count: 42,
            tags: vec!["a".to_string(), "b".to_string()],
        };

        let (gen_num, _offset, size) = writer.append_serialized(OpCode::InodeDelta, 10, &meta).unwrap();
        writer.flush().unwrap();
        assert_eq!(gen_num, 1);
        assert!(size > 37);

        let reader =
            super::super::reader::LogReader::open(storage.as_ref(), "000001.log", VolumeKey::plaintext_arc()).unwrap();
        let records: Vec<_> = reader.collect::<io::Result<Vec<_>>>().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].header.op_code, OpCode::InodeDelta);
        assert_eq!(records[0].header.inode, 10);
        let decoded: TestMetadata = crate::wire::deserialize(&records[0].payload).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn test_append_data_slices_optimistic_compression() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(storage.clone(), 1, &clock, 100000, 1, VolumeKey::plaintext_arc())
            .unwrap()
            .with_compression(crate::compress::Compression::Zstd);

        // Highly compressible repetitive data
        let chunk1 = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let chunk2 = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let full = [chunk1.as_slice(), chunk2.as_slice()].concat();

        let (gen_num, _, _) = writer.append_data_slices(20, &[chunk1, chunk2], full.len()).unwrap();
        writer.flush().unwrap();
        assert_eq!(gen_num, 1);

        let reader =
            super::super::reader::LogReader::open(storage.as_ref(), "000001.log", VolumeKey::plaintext_arc()).unwrap();
        let records: Vec<_> = reader.collect::<io::Result<Vec<_>>>().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].header.op_code, OpCode::DataZstd);
        assert_eq!(records[0].payload, full);

        // Incompressible data should fall back to OpCode::Data
        let mut incompressible = vec![0u8; 1000];
        let mut x: u64 = 0x9E3779B97F4A7C15;
        for b in incompressible.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }

        let slice1 = &incompressible[..500];
        let slice2 = &incompressible[500..];
        let (gen2, _, _) = writer
            .append_data_slices(21, &[slice1, slice2], incompressible.len())
            .unwrap();
        writer.flush().unwrap();
        assert_eq!(gen2, 1);

        let reader2 =
            super::super::reader::LogReader::open(storage.as_ref(), "000001.log", VolumeKey::plaintext_arc()).unwrap();
        let records2: Vec<_> = reader2.collect::<io::Result<Vec<_>>>().unwrap();
        assert_eq!(records2.len(), 2);
        assert_eq!(records2[1].header.op_code, OpCode::Data);
        assert_eq!(records2[1].payload, incompressible);
    }

    #[test]
    fn test_metadata_queries_not_blocked_by_sync_or_write() {
        use std::sync::atomic::{AtomicBool, Ordering};

        #[derive(Default, Clone)]
        struct IoBlocker {
            block_sync: Arc<AtomicBool>,
            in_sync: Arc<AtomicBool>,
            release_sync: Arc<AtomicBool>,
            block_append: Arc<AtomicBool>,
            in_append: Arc<AtomicBool>,
            release_append: Arc<AtomicBool>,
        }

        struct BlockingWriter {
            inner: Box<dyn StorageWriter>,
            blocker: IoBlocker,
        }

        impl StorageWriter for BlockingWriter {
            fn append(&mut self, data: &[u8]) -> io::Result<()> {
                if self.blocker.block_append.load(Ordering::SeqCst) {
                    self.blocker.in_append.store(true, Ordering::SeqCst);
                    while !self.blocker.release_append.load(Ordering::SeqCst) {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
                self.inner.append(data)
            }
            fn truncate(&mut self, len: u64) -> io::Result<()> {
                self.inner.truncate(len)
            }
            fn sync(&mut self) -> io::Result<()> {
                if self.blocker.block_sync.load(Ordering::SeqCst) {
                    self.blocker.in_sync.store(true, Ordering::SeqCst);
                    while !self.blocker.release_sync.load(Ordering::SeqCst) {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
                self.inner.sync()
            }
            fn len(&self) -> io::Result<u64> {
                self.inner.len()
            }
        }

        struct BlockingStorage {
            base: MemoryStorage,
            blocker: IoBlocker,
        }

        impl Storage for BlockingStorage {
            fn open_reader(&self, name: &str) -> io::Result<Arc<dyn crate::storage::StorageReader>> {
                self.base.open_reader(name)
            }
            fn open_writer(&self, name: &str, mode: WriteMode) -> io::Result<Box<dyn StorageWriter>> {
                let inner = self.base.open_writer(name, mode)?;
                Ok(Box::new(BlockingWriter {
                    inner,
                    blocker: self.blocker.clone(),
                }))
            }
            fn rename(&self, from: &str, to: &str) -> io::Result<()> {
                self.base.rename(from, to)
            }
            fn remove_file(&self, name: &str) -> io::Result<()> {
                self.base.remove_file(name)
            }
            fn list_files(&self) -> io::Result<Vec<String>> {
                self.base.list_files()
            }
            fn exists(&self, name: &str) -> bool {
                self.base.exists(name)
            }
            fn acquire_exclusive_lock(&self) -> io::Result<Box<dyn crate::storage::StorageLock>> {
                self.base.acquire_exclusive_lock()
            }
        }

        let blocker = IoBlocker::default();
        let storage = Arc::new(BlockingStorage {
            base: MemoryStorage::new(),
            blocker: blocker.clone(),
        });
        let clock = SystemClock;
        let writer = Arc::new(LogWriter::create(storage, 1, &clock, 100000, 1, VolumeKey::plaintext_arc()).unwrap());

        writer.append_data(10, b"initial payload").unwrap();
        writer
            .emit_flush_commit(1, b"initial payload".len() as u64, clock.now())
            .unwrap();
        let initial_offset = writer.current_offset();
        assert!(initial_offset > 0);
        assert_eq!(writer.generation(), 1);
        assert!(writer.is_open());
        assert_eq!(writer.record_count(), 2);
        assert_eq!(writer.total_data_bytes(), b"initial payload".len() as u64);

        // 1. Verify that while `writer.flush()` is blocked in physical `sync()`,
        // metadata queries return immediately.
        blocker.block_sync.store(true, Ordering::SeqCst);
        let writer_clone = Arc::clone(&writer);
        let sync_handle = std::thread::spawn(move || {
            writer_clone.flush().unwrap();
        });

        // Wait until background thread is blocked in `sync()`
        while !blocker.in_sync.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // Queries must succeed immediately without blocking on `active_state`
        let t0 = std::time::Instant::now();
        assert!(writer.is_open());
        assert_eq!(writer.generation(), 1);
        assert_eq!(writer.filename(), "000001.log");
        assert_eq!(writer.current_offset(), initial_offset);
        assert_eq!(writer.record_count(), 2);
        assert_eq!(writer.total_data_bytes(), b"initial payload".len() as u64);
        assert!(t0.elapsed() < std::time::Duration::from_millis(100));

        // Release the sync
        blocker.release_sync.store(true, Ordering::SeqCst);
        sync_handle.join().unwrap();

        // 2. Verify that while `writer.append_data()` is blocked in physical `append()`
        // (e.g. kernel dirty page writeback throttling), metadata queries return immediately.
        blocker.block_append.store(true, Ordering::SeqCst);
        let writer_clone2 = Arc::clone(&writer);
        let large_payload = vec![0x55u8; 128 * 1024];
        let append_handle = std::thread::spawn(move || {
            writer_clone2.append_data(11, &large_payload).unwrap();
        });

        // Wait until background thread is blocked in `append()`
        while !blocker.in_append.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // Queries must succeed immediately
        let t1 = std::time::Instant::now();
        assert!(writer.is_open());
        assert_eq!(writer.generation(), 1);
        assert_eq!(writer.filename(), "000001.log");
        assert!(t1.elapsed() < std::time::Duration::from_millis(100));

        // Release the append
        blocker.release_append.store(true, Ordering::SeqCst);
        append_handle.join().unwrap();

        assert_eq!(writer.record_count(), 2);
    }
}
