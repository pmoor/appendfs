use appendfs::InMemoryFS;
use appendfs::clock::{AdvancingClock, Clock};
use appendfs::log::LogWriter;
use appendfs::storage::{MemoryStorage, Storage};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

// Stripped-down deterministic PRNG for reproducible benchmark permutations.
struct BenchRng {
    state: u64,
}

impl BenchRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x123456789ABCDEF0 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    // Generates a random usize in the range `[min, max]` (inclusive).
    fn gen_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        min + (self.next_u64() as usize % (max - min + 1))
    }
}

// Minimal in-memory filesystem harness (stripped-down from TestFS).
// Operates entirely in memory with no kernel FUSE or disk I/O.
struct BenchFS {
    fs: InMemoryFS,
    _storage: Arc<dyn Storage>,
    clock: Arc<AdvancingClock>,
}

impl BenchFS {
    fn new() -> Self {
        let clock = Arc::new(AdvancingClock::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ));
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());

        let master = appendfs::crypto::MasterKey::new([0x42u8; 32]);
        let (volume_header, volume_key) = appendfs::crypto::VolumeHeader::new_encrypted(
            &master,
            [0u8; 16],
            appendfs::crypto::KeySource::KeyFile,
            appendfs::compress::Compression::Zstd,
        )
        .unwrap();
        let volume_key = Arc::new(volume_key);

        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                volume_key.clone(),
            )
            .unwrap()
            .with_compression(appendfs::compress::Compression::Zstd),
        );

        let mut fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));
        fs.set_storage(storage.clone());
        fs.volume_key = volume_key;
        fs.volume_header = volume_header;

        // Export initial 000000.summary snapshot to initialize volume at clock.now()
        let snapshot = fs.snapshot_all();
        let manifest = fs.manifest.read().unwrap().clone();
        let _ = appendfs::log::export_summary(
            &appendfs::log::SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &fs.volume_header,
                generation: 0,
                last_batch_id: 0,
                next_inode: 2,
                created_at: clock.now(),
            },
            storage.as_ref(),
            &fs.volume_key,
        );

        Self {
            fs,
            _storage: storage,
            clock,
        }
    }

    fn advance_time(&self, secs: u64) {
        self.clock.advance(Duration::from_secs(secs));
    }

    fn create_file(&self, parent: u64, name: &str) -> Result<u64, appendfs::error::FsError> {
        appendfs::operations::read_write::create_core(&self.fs, parent, name, 0o644, 0, 1000, 1000).map(|attr| attr.ino)
    }

    fn write_at(&self, ino: u64, offset: u64, data: &[u8]) -> Result<usize, appendfs::error::FsError> {
        let fh = appendfs::operations::read_write::open_core(&self.fs, ino, libc::O_RDWR as u32)?;
        let res = appendfs::operations::read_write::write_handle_core(&self.fs, ino, fh, data, offset as i64);
        let _ = appendfs::operations::read_write::release_core(&self.fs, ino, fh);
        res
    }

    fn read_at(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, appendfs::error::FsError> {
        let fh = appendfs::operations::read_write::open_core(&self.fs, ino, libc::O_RDONLY as u32)?;
        let res = appendfs::operations::read_write::read_core(&self.fs, ino, fh, offset as i64, len);
        let _ = appendfs::operations::read_write::release_core(&self.fs, ino, fh);
        res.and_then(|resp| resp.into_bytes().ok_or(appendfs::error::FsError::EIO))
    }

    fn flush(&self) {
        let _ = self.fs.quiesce();
    }

    fn sync(&self) {
        let _ = self.fs.quiesce();
    }
}

// Workload: Mixed reads and writes.
// Simulates a balanced workload: sequential appends, scattered updates,
// and random reads, flushing whenever staged data crosses `FLUSH_SIZE_BYTES`.
#[library_benchmark]
fn bench_mixed_workload() -> usize {
    let bench = BenchFS::new();
    let mut rng = BenchRng::new(3003);

    const NUM_FILES: usize = 4;
    const NUM_STEPS: usize = 2200;
    const FLUSH_SIZE_BYTES: usize = 128 * 1024; // 128 KiB flush threshold

    let mut files = Vec::new();
    let mut file_sizes = Vec::new();

    for i in 0..NUM_FILES {
        let name = format!("mixed_file_{}.bin", i);
        let ino = bench.create_file(1, &name).unwrap();
        let initial_data = vec![0x55; 32 * 1024];
        let _ = bench.write_at(ino, 0, &initial_data);
        files.push(ino);
        file_sizes.push(initial_data.len() as u64);
    }
    bench.flush();

    let mut ops_done = 0usize;
    let mut uncommitted_bytes = 0usize;
    let mut flush_count = 0usize;

    for step in 0..NUM_STEPS {
        bench.advance_time(1);
        let file_idx = rng.gen_range(0, NUM_FILES - 1);
        let ino = files[file_idx];
        let cur_len = file_sizes[file_idx];

        // 50% Appends, 30% Updates, 20% Reads
        let op = rng.gen_range(0, 9);
        match op {
            0..=4 => {
                // 50% Append write
                let append_len = rng.gen_range(512, 4096);
                let payload: Vec<u8> = (0..append_len).map(|b| ((step + b) & 0xff) as u8).collect();
                if let Ok(written) = bench.write_at(ino, cur_len, &payload) {
                    file_sizes[file_idx] += written as u64;
                    uncommitted_bytes += written;
                    ops_done += 1;
                }
            }
            5..=7 => {
                // 30% Random update / overwrite
                let update_len = rng.gen_range(256, 2048);
                let max_off = cur_len.saturating_sub(update_len as u64) as usize;
                let offset = rng.gen_range(0, max_off) as u64;
                let payload: Vec<u8> = (0..update_len).map(|b| ((step + b) & 0xff) as u8).collect();
                if let Ok(written) = bench.write_at(ino, offset, &payload) {
                    uncommitted_bytes += written;
                    ops_done += 1;
                }
            }
            _ => {
                // 20% Read
                let read_len = rng.gen_range(512, 8192);
                let max_off = cur_len.saturating_sub(read_len as u64) as usize;
                let offset = rng.gen_range(0, max_off) as u64;
                if let Ok(buf) = bench.read_at(ino, offset, read_len) {
                    black_box(&buf);
                    ops_done += 1;
                }
            }
        }

        // Flush once staged write data exceeds flush threshold
        if uncommitted_bytes >= FLUSH_SIZE_BYTES {
            bench.flush();
            uncommitted_bytes = 0;
            flush_count += 1;
        }
    }

    bench.sync();
    black_box((ops_done, flush_count));
    ops_done
}

library_benchmark_group!(
    name = in_memory_fs_group;
    benchmarks = bench_mixed_workload
);

main!(library_benchmark_groups = in_memory_fs_group);
