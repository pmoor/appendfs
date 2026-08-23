use crate::log::record::{
    DecodedPayload, FILE_HEADER_SIZE, FileHeader, FlushCommitPayload, LogEntryDelta, OpCode, RECORD_HEADER_SIZE,
    RecordHeader,
};
use crate::storage::{Storage, StorageReader};
use std::io;
use std::sync::Arc;
use std::time::SystemTime;

/// Represents a single deserialized log record read from a `.log` file.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub header: RecordHeader,
    pub payload: Vec<u8>,
    pub record_log_offset: u64,
}

impl LogRecord {
    /// Decodes the raw binary payload into a strongly-typed `DecodedPayload`.
    pub fn decode(&self) -> Result<DecodedPayload<'_>, bincode::Error> {
        match self.header.op_code {
            OpCode::Data => Ok(DecodedPayload::Data(&self.payload)),
            OpCode::InodeDelta => bincode::deserialize::<LogEntryDelta>(&self.payload).map(DecodedPayload::InodeDelta),
            OpCode::FlushCommit => {
                bincode::deserialize::<FlushCommitPayload>(&self.payload).map(DecodedPayload::FlushCommit)
            }
        }
    }

    /// Extracts the timestamp associated with this record.
    pub fn op_time(&self) -> Option<SystemTime> {
        self.decode().ok().and_then(|d| d.op_time())
    }
}

use crate::crypto::VolumeKey;

/// Iterator for sequentially reading records from a `.log` generation file.
pub struct LogReader {
    reader: Arc<dyn StorageReader>,
    header: FileHeader,
    current_offset: u64,
    volume_key: Arc<VolumeKey>,
}

impl LogReader {
    /// Opens a `.log` file from a `Storage` instance, verifies its `FileHeader`, and initializes the iterator.
    pub fn open(storage: &dyn Storage, filename: &str, volume_key: Arc<VolumeKey>) -> io::Result<Self> {
        let reader = storage.open_reader(filename)?;

        let mut header_buf = [0u8; FILE_HEADER_SIZE];
        reader.read_exact_at(0, &mut header_buf)?;

        let header = FileHeader::from_bytes(&header_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Self {
            reader,
            header,
            current_offset: FILE_HEADER_SIZE as u64,
            volume_key,
        })
    }

    /// Returns the parsed `FileHeader` of this log file.
    pub fn file_header(&self) -> &FileHeader {
        &self.header
    }
}

impl Iterator for LogReader {
    type Item = io::Result<LogRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        let record_offset = self.current_offset;
        let file_len = match self.reader.len() {
            Ok(l) => l,
            Err(e) => return Some(Err(e)),
        };

        if record_offset >= file_len {
            return None;
        }

        let mut header_buf = [0u8; RECORD_HEADER_SIZE];
        match self.reader.read_exact_at(record_offset, &mut header_buf) {
            Ok(()) => {}
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    return None;
                }
                return Some(Err(e));
            }
        }

        let header = match RecordHeader::from_bytes(&header_buf) {
            Ok(h) => h,
            Err(e) => return Some(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
        };

        let mut raw_payload = vec![0u8; header.payload_len as usize];
        if let Err(e) = self
            .reader
            .read_exact_at(record_offset + RECORD_HEADER_SIZE as u64, &mut raw_payload)
        {
            return Some(Err(e));
        }

        self.current_offset += RECORD_HEADER_SIZE as u64 + header.payload_len as u64;

        let actual_checksum = crate::log::record::checksum_payload(&raw_payload);
        if actual_checksum != header.checksum {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "checksum mismatch at offset {}: expected {:?}, computed {:?} (possible bitrot)",
                    record_offset, header.checksum, actual_checksum
                ),
            )));
        }

        let decrypted_payload = match self.volume_key.decrypt_record(
            self.header.generation,
            header.tx_id,
            header.op_code as u8,
            header.inode,
            &raw_payload,
        ) {
            Ok(p) => p,
            Err(e) => return Some(Err(e.into())),
        };

        Some(Ok(LogRecord {
            header,
            payload: decrypted_payload,
            record_log_offset: record_offset,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::crypto::VolumeKey;
    use crate::log::record::OpCode;
    use crate::log::writer::LogWriter;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_log_reader_iteration() {
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

        writer.append_record(OpCode::Data, 2, b"payload1").unwrap();
        writer.append_record(OpCode::InodeDelta, 3, b"payload22").unwrap();
        writer.sync().unwrap();

        let reader = LogReader::open(&storage, &writer.filename(), VolumeKey::plaintext_arc()).unwrap();
        assert_eq!(reader.file_header().generation, 1);

        let records: Vec<LogRecord> = reader.map(|r| r.unwrap()).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].header.op_code, OpCode::Data);
        assert_eq!(records[0].payload, b"payload1");
        assert_eq!(records[1].header.op_code, OpCode::InodeDelta);
        assert_eq!(records[1].payload, b"payload22");
    }
}
