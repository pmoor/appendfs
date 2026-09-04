use appendfs::clock::SystemClock;
use appendfs::crypto::{VolumeHeader, VolumeKey};
use appendfs::log::{LogFileCache, LogWriter, init_volume};
use appendfs::operations::read_write::{create_core, read_core, write_core};
use appendfs::remote::bootstrap_from_remote;
use appendfs::remote::worker::{cross_copy_file, upload_storage_file};
use appendfs::remote::{
    BlockCache, CountingRemoteStore, FailingRemoteStore, LatencyRemoteStore, LocalDirRemoteStore, MemoryBlockCache,
    MockRemoteStore, OnDiskBlockCache, RemoteRegistry, RemoteStore, RemoteTargetConfig, check_remote_integrity,
};
use appendfs::storage::OsStorage;
use appendfs::{Clock, Storage};
use std::fs;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tempfile::TempDir;

#[test]
fn test_remote_replication_and_authenticated_md5_ledger() {
    let dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    // 1. Initialize volume
    let summary_file = init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext()).unwrap();
    assert_eq!(summary_file, "000000.summary");

    // 2. Recover InMemoryFS and append records to multiple generations
    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());

    // Write file 1 (gen 1)
    let root = 1;
    let file1_attr = create_core(&fs, root, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
    let file_ino = file1_attr.ino;
    let content1 = b"Generation 1 payload: The quick brown fox jumps over the lazy dog";
    write_core(&fs, file_ino, content1, 0).unwrap();
    fs.sync_log().unwrap();

    // Force roll to generation 2 (seals gen 1)
    let (next_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    assert_eq!(next_gen, 2);
    {
        let mut manifest = fs.manifest.write().unwrap();
        manifest.set_generation_md5(next_gen - 1, sealed_md5);
        manifest.record_roll(next_gen, clock.now(), 24);
    }

    // Write file 2 (gen 2)
    let file2_attr = create_core(&fs, root, "file2.txt", 0o644, 0, 1000, 1000).unwrap();
    let file2_ino = file2_attr.ino;
    let content2 = b"Generation 2 payload: All good things come to an end";
    write_core(&fs, file2_ino, content2, 0).unwrap();
    fs.sync_log().unwrap();

    // Export summary snapshot (computes and populates sealed generation 1 MD5 into manifest!)
    let exported_summary = fs.export_summary(storage.as_ref()).unwrap();
    assert_eq!(exported_summary, "000002.summary");

    // Verify generation 1 MD5 is now recorded in the manifest ledger
    let manifest = fs.manifest.read().unwrap().clone();
    let gen1_info = manifest.get_by_generation(1).unwrap();
    assert!(
        gen1_info.md5.is_some(),
        "Sealed generation 1 must have authenticated MD5 recorded"
    );
    let gen1_md5 = gen1_info.md5.unwrap();

    // 3. Setup two mock remote targets: "aws" (writable) and "b2" (writable)
    let remote_aws = Arc::new(MockRemoteStore::new());
    let remote_b2 = Arc::new(MockRemoteStore::new());

    // Upload sealed 000001.log and 000002.summary to remotes
    upload_storage_file(storage.as_ref(), remote_aws.as_ref(), "000001.log", Some(&gen1_md5)).unwrap();
    upload_storage_file(storage.as_ref(), remote_aws.as_ref(), "000002.summary", None).unwrap();

    // Verify remote_aws object matches
    let aws_head = remote_aws.head_object("000001.log").unwrap().unwrap();
    assert_eq!(aws_head.size, gen1_info.total_bytes);
    assert_eq!(aws_head.etag_md5(), Some(gen1_md5));

    // Cross-copy from aws to b2
    cross_copy_file(
        remote_aws.as_ref(),
        remote_b2.as_ref(),
        "000001.log",
        gen1_info.total_bytes,
        Some(&gen1_md5),
    )
    .unwrap();
    let b2_head = remote_b2.head_object("000001.log").unwrap().unwrap();
    assert_eq!(b2_head.size, gen1_info.total_bytes);
    assert_eq!(b2_head.etag_md5(), Some(gen1_md5));

    // 4. Run integrity check on remote_aws against manifest
    let report = check_remote_integrity(remote_aws.as_ref(), "aws", &manifest);
    assert!(
        report.is_clean(),
        "Remote integrity check must pass with matching MD5 and size"
    );

    // Corrupt remote object on remote_aws: change bytes and length
    remote_aws
        .put_object("000001.log", &mut &[0u8; 10][..], 10, None)
        .unwrap();
    let corrupt_report = check_remote_integrity(remote_aws.as_ref(), "aws", &manifest);
    assert!(
        !corrupt_report.is_clean(),
        "Integrity check must catch size and MD5 mismatch"
    );
}

#[test]
fn test_tiered_eviction_and_sparse_remote_extent_reads() {
    let dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext()).unwrap();

    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());

    // Write a large extent across multiple KB in generation 1
    let file_attr = create_core(&fs, 1, "archival.dat", 0o644, 0, 1000, 1000).unwrap();
    let ino = file_attr.ino;
    let original_bytes: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    write_core(&fs, ino, &original_bytes, 0).unwrap();
    fs.sync_log().unwrap();

    // Roll to generation 2
    let (next_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    {
        let mut manifest = fs.manifest.write().unwrap();
        manifest.set_generation_md5(next_gen - 1, sealed_md5);
        manifest.record_roll(next_gen, clock.now(), 24);
    }
    fs.export_summary(storage.as_ref()).unwrap();

    let manifest = fs.manifest.read().unwrap().clone();
    let gen1_info = manifest.get_by_generation(1).unwrap();
    let gen1_md5 = gen1_info.md5.unwrap();

    // Upload 000001.log to remote store
    let mock = Arc::new(MockRemoteStore::new());
    upload_storage_file(storage.as_ref(), mock.as_ref(), "000001.log", Some(&gen1_md5)).unwrap();

    // Wrap mock in FailingRemoteStore to test network failover
    let failing_remote = Arc::new(FailingRemoteStore::new(mock.clone()));

    // SIMULATE TIERED LOCAL EVICTION: Delete 000001.log from local disk!
    let local_gen1_path = dir.path().join("000001.log");
    assert!(local_gen1_path.exists());
    fs::remove_file(&local_gen1_path).unwrap();
    assert!(!local_gen1_path.exists(), "000001.log was pruned from local disk");

    // Setup TieredCache with OnDiskBlockCache in .cache/
    let cache_dir = dir.path().join(".cache");
    let block_cache = Arc::new(OnDiskBlockCache::new(&cache_dir, 50 * 1024 * 1024).unwrap());
    let remotes = vec![("mock_s3".to_string(), failing_remote.clone() as Arc<dyn RemoteStore>)];

    let log_cache = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        remotes,
        Some(Arc::clone(&fs.manifest)),
    ));
    fs.log_cache = Some(log_cache);

    // Read back archival.dat from the filesystem:
    // Local file is GONE, so TieredStorageReader should fetch 1MB aligned block from remote,
    // cache it in .cache/, and return exact bytes!
    let read_back = read_core(&fs, ino, original_bytes.len(), 0).unwrap();
    assert_eq!(
        read_back, original_bytes,
        "Sparse remote extent read matched original bytes bit-for-bit!"
    );

    // Verify that the on-disk block cache now holds block 0
    assert!(
        block_cache.read_block(1, 0).unwrap().is_some(),
        "Block 0 must now be cached on disk"
    );

    // Second read hits in-memory and on-disk cache directly (even if remote goes down!)
    failing_remote.fail_next_n_requests(10);
    let read_back2 = read_core(&fs, ino, 100, 500).unwrap();
    assert_eq!(read_back2, &original_bytes[500..600]);
}

#[test]
fn test_disaster_recovery_bootstrap_from_remote() {
    let storage = Arc::new(appendfs::storage::MemoryStorage::new());
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext()).unwrap();
    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());

    let file_attr = create_core(&fs, 1, "important.txt", 0o644, 0, 1000, 1000).unwrap();
    let ino = file_attr.ino;
    write_core(&fs, ino, b"disaster recovery data", 0).unwrap();
    fs.sync_log().unwrap();

    let summary_file = fs.export_summary(storage.as_ref()).unwrap();

    // Upload to remote
    let remote = Arc::new(MockRemoteStore::new());
    upload_storage_file(storage.as_ref(), remote.as_ref(), &summary_file, None).unwrap();
    upload_storage_file(storage.as_ref(), remote.as_ref(), "000001.log", None).unwrap();

    // Now, create a completely fresh, empty in-memory destination storage (simulating a fresh machine)
    let fresh_storage = Arc::new(appendfs::storage::MemoryStorage::new());

    let mut remote_cfg = RemoteTargetConfig::new("backup-bucket");
    remote_cfg.region = "us-east-1".to_string();

    // Bootstrap from remote!
    let recovered_summary =
        bootstrap_from_remote(remote.as_ref(), fresh_storage.as_ref(), "origin", remote_cfg).unwrap();

    assert_eq!(recovered_summary, summary_file);
    assert!(fresh_storage.exists(&summary_file));
    assert!(fresh_storage.exists("remotes.toml"));

    // Recover volume in the fresh storage
    let fresh_fs = appendfs::recover_fs(fresh_storage, appendfs::RecoveryTarget::Latest, clock, volume_key).unwrap();
    let base = fresh_fs.base.read().unwrap();
    assert!(base.len() >= 2); // root + important.txt
}

#[test]
fn test_read_only_remote_and_cloud_forking() {
    let dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext()).unwrap();
    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());

    // Write file in generation 1
    let file_attr = create_core(&fs, 1, "base.txt", 0o644, 0, 1000, 1000).unwrap();
    let ino = file_attr.ino;
    write_core(&fs, ino, b"upstream base file contents", 0).unwrap();
    fs.sync_log().unwrap();

    // Roll to generation 2
    let (next_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    {
        let mut manifest = fs.manifest.write().unwrap();
        manifest.set_generation_md5(next_gen - 1, sealed_md5);
        manifest.record_roll(next_gen, clock.now(), 24);
    }
    fs.export_summary(storage.as_ref()).unwrap();

    // Setup an upstream read-only remote
    let upstream_remote = Arc::new(MockRemoteStore::new());
    upload_storage_file(storage.as_ref(), upstream_remote.as_ref(), "000001.log", None).unwrap();
    upload_storage_file(storage.as_ref(), upstream_remote.as_ref(), "000002.summary", None).unwrap();

    // Setup a downstream writable remote
    let _downstream_remote = Arc::new(MockRemoteStore::new());

    let mut registry = RemoteRegistry::new();
    let mut upstream_cfg = RemoteTargetConfig::new("upstream-bucket");
    upstream_cfg.read_only = true;
    registry.add_remote("upstream", upstream_cfg);

    let downstream_cfg = RemoteTargetConfig::new("downstream-bucket");
    registry.add_remote("downstream", downstream_cfg);

    // Verify configured stores
    let stores = registry.build_all_stores();
    assert_eq!(stores.len(), 2);

    let (_, _, up_ro, _) = stores.iter().find(|(name, _, _, _)| name == "upstream").unwrap();
    assert!(*up_ro, "Upstream remote must be marked read-only");

    let (_, _, down_ro, _) = stores.iter().find(|(name, _, _, _)| name == "downstream").unwrap();
    assert!(!*down_ro, "Downstream remote must be writable");
}

#[test]
fn test_active_log_part_sync_and_consolidation_on_seal() {
    let dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext()).unwrap();
    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());

    let remote = Arc::new(MockRemoteStore::new());

    // Setup registry with active_sync_interval = 0 (sync on every tick)
    let mut registry = RemoteRegistry::new();
    registry.policy.active_sync_interval_secs = 0;
    registry.policy.min_synced_remotes = 1;
    let target = RemoteTargetConfig::new("my-bucket");
    registry.add_remote("primary", target);
    registry.set_store_override("primary", remote.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    let fs_arc = Arc::new(fs);
    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();

    // 1. Write first chunk of active data
    let file1_attr = create_core(&fs_arc, 1, "active_file.txt", 0o644, 0, 1000, 1000).unwrap();
    let ino = file1_attr.ino;
    write_core(&fs_arc, ino, b"Part 0 slice: hello appendfs active sync!", 0).unwrap();
    fs_arc.sync_log().unwrap();

    // Run sync cycle -> uploads 000001.part0000.log!
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        dir.path(),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    // Verify part0000 exists on remote!
    let part0 = remote.head_object("000001.part0000.log").unwrap();
    assert!(
        part0.is_some(),
        "Active incremental part0000 must be uploaded to remote"
    );
    assert!(part0.unwrap().size > 0);

    // 2. Write second chunk of active data
    write_core(&fs_arc, ino, b"Part 1 slice: more mutations appended!", 100).unwrap();
    fs_arc.sync_log().unwrap();

    last_part_sync = std::time::SystemTime::UNIX_EPOCH; // reset timer to force next upload
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        dir.path(),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    let part1 = remote.head_object("000001.part0001.log").unwrap();
    assert!(
        part1.is_some(),
        "Active incremental part0001 must be uploaded to remote"
    );

    // 3. Roll generation: seals generation 1 into generation 2!
    let (next_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    {
        let mut manifest = fs_arc.manifest.write().unwrap();
        manifest.set_generation_md5(next_gen - 1, sealed_md5);
        manifest.record_roll(next_gen, clock.now(), 24);
    }
    fs_arc.export_summary(storage.as_ref()).unwrap();

    // Run sync cycle after roll: should upload full 000001.log and delete transient parts!
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        dir.path(),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    // Full 000001.log must exist
    let sealed_log = remote.head_object("000001.log").unwrap();
    assert!(sealed_log.is_some(), "Sealed unified log 000001.log must be on remote");

    // Transient parts MUST be cleaned up!
    let remaining_parts = remote.list_objects("000001.part").unwrap();
    assert!(
        remaining_parts.is_empty(),
        "Transient active parts must be deleted upon generation consolidation!"
    );
}

#[test]
fn test_local_dir_remote_store_streaming_and_md5_sidecars() {
    let dir = TempDir::new().unwrap();
    let store = LocalDirRemoteStore::new(dir.path());

    let data = b"AppendFS streaming replication to local/NFS filesystem targets";
    let real_md5: [u8; 16] = *md5::compute(data);

    // Upload with valid MD5
    store
        .put_object("000001.log", &mut &data[..], data.len() as u64, Some(&real_md5))
        .unwrap();

    // Verify head_object finds object and parses ETag from .md5 sidecar file
    let obj = store.head_object("000001.log").unwrap().unwrap();
    assert_eq!(obj.size, data.len() as u64);
    assert_eq!(obj.etag_md5(), Some(real_md5));

    // Verify physical .md5 sidecar file exists on disk
    assert!(dir.path().join("000001.log.md5").exists());

    // Range read
    let mut range_buf = Vec::new();
    let bytes_copied = store.get_object_range("000001.log", 9, 9, &mut range_buf).unwrap();
    assert_eq!(bytes_copied, 9);
    assert_eq!(range_buf, b"streaming");

    // Full read
    let mut full_buf = Vec::new();
    store.get_object("000001.log", &mut full_buf).unwrap();
    assert_eq!(full_buf, data);

    // Upload with bad MD5 fails with InvalidData BadDigest
    let fake_md5 = [0xFF; 16];
    let err = store
        .put_object("bad.log", &mut &data[..], data.len() as u64, Some(&fake_md5))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("BadDigest"));
    assert!(!dir.path().join("bad.log").exists());

    // If .md5 sidecar is missing, etag is None (unverified) without reading entire file
    fs::remove_file(dir.path().join("000001.log.md5")).unwrap();
    let obj_no_md5 = store.head_object("000001.log").unwrap().unwrap();
    assert_eq!(obj_no_md5.etag, None);

    // Delete object cleans up both data and .md5
    store.delete_object("000001.log").unwrap();
    assert!(store.head_object("000001.log").unwrap().is_none());
}

#[test]
fn test_nfs_local_volume_replication_and_pruning() {
    let dir = TempDir::new().unwrap();
    let nfs_dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext()).unwrap();

    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());

    // Setup RemoteRegistry pointing to a local directory representing an NFS share
    let mut registry = RemoteRegistry::new();
    let nas_cfg = RemoteTargetConfig::new_path(nfs_dir.path());
    registry.add_remote("nas", nas_cfg);
    registry.policy.min_synced_remotes = 1;
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    // 1. Write file in generation 1
    let root = 1u64;
    let file_attr = create_core(&fs, root, "nfs_file.txt", 0o644, 0, 1000, 1000).unwrap();
    let file_ino = file_attr.ino;
    let payload = b"Data that will replicate to NFS NAS share and be read tier-cached!";
    write_core(&fs, file_ino, payload, 0).unwrap();
    fs.sync_log().unwrap();

    // Force roll to generation 2 (seals generation 1)
    let (next_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    {
        let mut manifest = fs.manifest.write().unwrap();
        manifest.set_generation_md5(next_gen - 1, sealed_md5);
        manifest.record_roll(next_gen, clock.now(), 24);
    }
    fs.export_summary(storage.as_ref()).unwrap();

    // 2. Run replication cycle: uploads 000001.log and summary to NFS share
    let fs_arc = Arc::new(fs);
    let mut last_part_sync = std::time::SystemTime::now();
    let mut uploaded_parts = std::collections::HashMap::new();
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        dir.path(),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    // Verify NFS share has 000001.log and sibling 000001.log.md5
    assert!(nfs_dir.path().join("000001.log").exists());
    assert!(nfs_dir.path().join("000001.log.md5").exists());
    let md5_content = fs::read_to_string(nfs_dir.path().join("000001.log.md5")).unwrap();
    assert_eq!(md5_content.trim(), hex::encode(sealed_md5));

    // 3. Verify integrity check passes on the NFS remote
    let nas_store = registry_arc.read().unwrap().get_remote("nas").unwrap().build_store();
    let report = check_remote_integrity(nas_store.as_ref(), "nas", &fs_arc.manifest.read().unwrap());
    assert!(report.is_clean(), "Integrity check against NFS remote must pass");

    // 4. Prune local 000001.log to simulate tiered storage eviction
    fs::remove_file(dir.path().join("000001.log")).unwrap();
    assert!(!dir.path().join("000001.log").exists());

    // 5. Setup tiered reader attached to LogFileCache
    let mut fs = Arc::try_unwrap(fs_arc).ok().unwrap();
    let block_cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));
    let remotes = vec![("nas".to_string(), nas_store.clone() as Arc<dyn RemoteStore>)];
    let log_cache = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        remotes,
        Some(Arc::clone(&fs.manifest)),
    ));
    fs.log_cache = Some(log_cache);

    // Read back nfs_file.txt from the filesystem:
    // Local 000001.log is GONE, so TieredStorageReader should fetch 1MB aligned block from NFS remote,
    // cache it in block cache, and return exact bytes!
    let read_back = read_core(&fs, file_ino, payload.len(), 0).unwrap();
    assert_eq!(
        read_back, payload,
        "Sparse NFS remote extent read matched original payload bit-for-bit!"
    );

    // Verify block cache populated
    assert!(
        block_cache.read_block(1, 0).unwrap().is_some(),
        "Block 0 must now be cached"
    );
}

#[test]
fn test_local_read_populates_block_cache_before_purge() {
    let dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext()).unwrap();

    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());

    // 1. Write file in generation 1
    let root = 1u64;
    let file1_attr = create_core(&fs, root, "hot_file.txt", 0o644, 0, 1000, 1000).unwrap();
    let file1_ino = file1_attr.ino;
    let payload1 = b"Hot file content that will be pre-warmed into block cache from local disk";
    write_core(&fs, file1_ino, payload1, 0).unwrap();
    fs.sync_log().unwrap();

    // 2. Force roll to generation 2 (seals generation 1)
    let (next_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    assert_eq!(next_gen, 2);
    {
        let mut manifest = fs.manifest.write().unwrap();
        manifest.set_generation_md5(next_gen - 1, sealed_md5);
        manifest.record_roll(next_gen, clock.now(), 24);
    }
    fs.export_summary(storage.as_ref()).unwrap();

    // 3. Write file in active generation 2
    let file2_attr = create_core(&fs, root, "active_file.txt", 0o644, 0, 1000, 1000).unwrap();
    let file2_ino = file2_attr.ino;
    let payload2 = b"Active generation content that reads directly without block caching";
    write_core(&fs, file2_ino, payload2, 0).unwrap();
    fs.sync_log().unwrap();

    // 4. Attach LogFileCache with OnDiskBlockCache (NO remotes configured!)
    let cache_dir = dir.path().join(".cache");
    let block_cache = Arc::new(OnDiskBlockCache::new(&cache_dir, 50 * 1024 * 1024).unwrap());
    let log_cache = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        Vec::<appendfs::remote::RemoteReadTarget>::new(), // Zero remotes!
        Some(Arc::clone(&fs.manifest)),
    ));
    fs.log_cache = Some(log_cache.clone());

    // Verify cache is empty before any reads
    assert!(!cache_dir.join("000001_000000.bin").exists());
    assert!(!cache_dir.join("000002_000000.bin").exists());

    // 5. Read sealed generation 1 file while 000001.log is STILL on local disk:
    // Should read from local disk AND pre-warm into .cache/!
    let read_sealed = read_core(&fs, file1_ino, payload1.len(), 0).unwrap();
    assert_eq!(read_sealed, payload1);

    // Block 0 of generation 1 MUST now be cached on disk in .cache/!
    assert!(cache_dir.join("000001_000000.bin").exists());
    assert!(block_cache.read_block(1, 0).unwrap().is_some());

    // 6. Read active generation 2 file:
    // Must NOT write to .cache/ because active generation avoids partial block caching!
    let read_active = read_core(&fs, file2_ino, payload2.len(), 0).unwrap();
    assert_eq!(read_active, payload2);
    assert!(!cache_dir.join("000002_000000.bin").exists());

    // 7. Clear in-memory decrypted cache so the next read MUST hit disk
    log_cache.decrypted_cache.clear();

    // 8. Physically DELETE 000001.log from local disk (simulate 30-day purge)
    fs::remove_file(dir.path().join("000001.log")).unwrap();
    assert!(!dir.path().join("000001.log").exists());

    // 9. Read sealed file again:
    // 000001.log is GONE, NO remotes exist, but read MUST succeed directly from .cache/!
    let read_cached_after_purge = read_core(&fs, file1_ino, payload1.len(), 0).unwrap();
    assert_eq!(
        read_cached_after_purge, payload1,
        "Read succeeded directly from pre-warmed block cache after local log was purged!"
    );
}

#[test]
fn test_remote_read_priority_prefers_lower_priority_remotes() {
    let dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext()).unwrap();

    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());

    // 1. Write file into generation 1
    let root = 1u64;
    let file_attr = create_core(&fs, root, "archived.txt", 0o644, 0, 1000, 1000).unwrap();
    let file_ino = file_attr.ino;
    let payload = b"Remote data that should be fetched from NAS before falling back to S3";
    write_core(&fs, file_ino, payload, 0).unwrap();
    fs.sync_log().unwrap();

    // 2. Roll to generation 2 (seals generation 1)
    let (next_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    assert_eq!(next_gen, 2);
    {
        let mut manifest = fs.manifest.write().unwrap();
        manifest.set_generation_md5(next_gen - 1, sealed_md5);
        manifest.record_roll(next_gen, clock.now(), 24);
    }
    fs.export_summary(storage.as_ref()).unwrap();

    // 3. Read raw 000001.log bytes from local disk
    let raw_log_bytes = std::fs::read(dir.path().join("000001.log")).unwrap();

    // 4. Create two mock stores: NAS (priority 10) and S3 (priority 100)
    let nas_store = Arc::new(MockRemoteStore::new());
    let s3_store = Arc::new(MockRemoteStore::new());

    // Upload 000001.log to BOTH stores
    nas_store
        .put_object("000001.log", &mut &raw_log_bytes[..], raw_log_bytes.len() as u64, None)
        .unwrap();
    s3_store
        .put_object("000001.log", &mut &raw_log_bytes[..], raw_log_bytes.len() as u64, None)
        .unwrap();

    // Configure registry with S3 added first, but NAS having lower numerical priority (10 < 100)
    let mut registry = RemoteRegistry::new();
    let mut s3_cfg = RemoteTargetConfig::new("my-cloud-s3");
    s3_cfg.read_priority = 100;
    registry.add_remote("s3", s3_cfg);
    let counting_s3 = Arc::new(CountingRemoteStore::new(s3_store.clone()));
    registry.set_store_override("s3", counting_s3.clone());

    let mut nas_cfg = RemoteTargetConfig::new_path("/mnt/nas");
    nas_cfg.read_priority = 10;
    registry.add_remote("nas", nas_cfg);
    let counting_nas_back = Arc::new(CountingRemoteStore::new(nas_store.clone()));
    let nas_failing = Arc::new(FailingRemoteStore::new(counting_nas_back.clone()));
    let counting_nas_front = Arc::new(CountingRemoteStore::new(nas_failing.clone()));
    registry.set_store_override("nas", counting_nas_front.clone());

    // Verify build_read_stores order: "nas" (10) MUST come before "s3" (100)
    let remote_stores = registry.build_read_stores();
    assert_eq!(remote_stores[0].name, "nas");
    assert_eq!(remote_stores[1].name, "s3");

    // 5. Delete local 000001.log to force remote tiered reading
    std::fs::remove_file(dir.path().join("000001.log")).unwrap();

    // 6. Setup LogFileCache with block_cache and ordered remote_stores
    let cache_dir = dir.path().join(".cache");
    let block_cache = Arc::new(OnDiskBlockCache::new(&cache_dir, 50 * 1024 * 1024).unwrap());
    let log_cache = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        remote_stores,
        Some(Arc::clone(&fs.manifest)),
    ));
    fs.log_cache = Some(log_cache.clone());

    // 7. Perform read: should query NAS first, succeed, and NOT touch S3!
    let read1 = read_core(&fs, file_ino, payload.len(), 0).unwrap();
    assert_eq!(read1, payload);

    assert_eq!(
        counting_nas_front.range_reads(),
        1,
        "NAS front must receive read request"
    );
    assert_eq!(counting_nas_back.range_reads(), 1, "NAS served read");
    assert_eq!(counting_s3.total_requests(), 0, "S3 must NOT be called");

    // 8. Test failover: clear block cache and decrypted cache, make NAS fail next request
    std::fs::remove_file(cache_dir.join("000001_000000.bin")).unwrap();
    log_cache.decrypted_cache.clear();
    nas_failing.fail_next_n_requests(1);

    // 9. Perform read: NAS fails, so it fails over to S3!
    let read2 = read_core(&fs, file_ino, payload.len(), 0).unwrap();
    assert_eq!(read2, payload);

    assert_eq!(counting_nas_front.range_reads(), 2, "NAS was tried first and failed");
    assert_eq!(counting_nas_back.range_reads(), 1, "NAS backend only served 1 read");
    assert_eq!(counting_s3.range_reads(), 1, "S3 served failover read");
}

#[test]
fn test_latency_remote_store_in_tiered_reading() {
    use std::time::{Duration, Instant};

    let dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext()).unwrap();
    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());

    let file_attr = create_core(&fs, 1, "latency_test.dat", 0o644, 0, 1000, 1000).unwrap();
    let payload = b"Testing latency injection on tiered remote store reads";
    write_core(&fs, file_attr.ino, payload, 0).unwrap();
    fs.sync_log().unwrap();

    let (next_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    assert_eq!(next_gen, 2);
    {
        let mut manifest = fs.manifest.write().unwrap();
        manifest.set_generation_md5(next_gen - 1, sealed_md5);
        manifest.record_roll(next_gen, clock.now(), 24);
    }
    fs.export_summary(storage.as_ref()).unwrap();

    let raw_log_bytes = std::fs::read(dir.path().join("000001.log")).unwrap();

    let mock_store = Arc::new(MockRemoteStore::new());
    mock_store
        .put_object("000001.log", &mut &raw_log_bytes[..], raw_log_bytes.len() as u64, None)
        .unwrap();

    // Wrap in LatencyRemoteStore and inject 20ms delay on get_object_range
    let latency_store = Arc::new(LatencyRemoteStore::new(mock_store.clone()));
    latency_store.set_method_delay("get_object_range", Duration::from_millis(20));

    // Delete local 000001.log to force remote tiered read
    std::fs::remove_file(dir.path().join("000001.log")).unwrap();

    let cache_dir = dir.path().join(".cache");
    let block_cache = Arc::new(OnDiskBlockCache::new(&cache_dir, 50 * 1024 * 1024).unwrap());
    let counting_store = Arc::new(CountingRemoteStore::new(latency_store.clone()));
    let remotes = vec![(
        "delayed_remote".to_string(),
        counting_store.clone() as Arc<dyn RemoteStore>,
    )];
    let log_cache = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        remotes,
        Some(Arc::clone(&fs.manifest)),
    ));
    fs.log_cache = Some(log_cache.clone());

    // 1st read: misses cache, queries latency_store, takes >= 19ms
    let start1 = Instant::now();
    let read1 = read_core(&fs, file_attr.ino, payload.len(), 0).unwrap();
    let elapsed1 = start1.elapsed();
    assert_eq!(read1, payload);
    assert!(
        elapsed1 >= Duration::from_millis(19),
        "1st read should include injected latency, took {:?}",
        elapsed1
    );
    assert_eq!(counting_store.range_reads(), 1);

    // 2nd read: served directly from cache, near instantaneous (< 10ms)
    let start2 = Instant::now();
    let read2 = read_core(&fs, file_attr.ino, payload.len(), 0).unwrap();
    let elapsed2 = start2.elapsed();
    assert_eq!(read2, payload);
    assert!(
        elapsed2 < Duration::from_millis(10),
        "2nd read should hit cache without latency, took {:?}",
        elapsed2
    );
    assert_eq!(counting_store.range_reads(), 1);
}

#[test]
fn test_virtual_remotes_status_file_lifecycle_and_content() {
    use appendfs::fs::VIRTUAL_FH_FLAG;
    use appendfs::operations::dir::list_dir_core;

    let dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext()).unwrap();

    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();

    let writer =
        Arc::new(LogWriter::create_lazy(storage.clone(), 1, 100 * 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());

    // Configure 2 remotes (NAS and S3)
    let nas_store = Arc::new(MockRemoteStore::new());
    let s3_store = Arc::new(MockRemoteStore::new());

    let mut registry = RemoteRegistry::new();
    let mut nas_cfg = RemoteTargetConfig::new_path("/mnt/nas");
    nas_cfg.read_priority = 10;
    registry.add_remote("nas", nas_cfg);
    registry.set_store_override("nas", nas_store.clone());

    let mut s3_cfg = RemoteTargetConfig::new("my-s3-bucket");
    s3_cfg.read_priority = 100;
    s3_cfg.prefix = "logs/".to_string();
    registry.add_remote("s3", s3_cfg);
    registry.set_store_override("s3", s3_store.clone());

    let registry_arc = Arc::new(std::sync::RwLock::new(registry));
    fs.set_remote_registry(Arc::clone(&registry_arc));

    let fs_arc = Arc::new(fs);

    // 1. Root directory listing contains .remotes
    let entries = list_dir_core(&fs_arc, 1).unwrap();
    let remotes_entry = entries.iter().find(|(name, _)| name == ".remotes");
    assert!(
        remotes_entry.is_some(),
        ".remotes must appear in root directory listing"
    );
    let remotes_ino = remotes_entry.unwrap().1;
    assert!(fs_arc.virtual_files.is_virtual_ino(remotes_ino));

    // 2. Lookup child .remotes on parent 1
    assert_eq!(fs_arc.lookup_child(1, ".remotes"), Some(remotes_ino));

    // 3. Write data, roll log, and run replication cycle
    let file = create_core(&fs_arc, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
    write_core(&fs_arc, file.ino, b"data before roll", 0).unwrap();
    fs_arc.sync_log().unwrap();

    let (rolled_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    {
        let mut manifest = fs_arc.manifest.write().unwrap();
        manifest.set_generation_md5(rolled_gen - 1, sealed_md5);
        manifest.record_roll(rolled_gen, clock.now(), 40);
    }
    fs_arc.export_summary(storage.as_ref()).unwrap();

    // Run replication cycle
    let mut last_part = std::time::SystemTime::now();
    let mut uploaded_parts = std::collections::HashMap::new();
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        dir.path(),
        &mut last_part,
        &mut uploaded_parts,
    )
    .unwrap();

    // 4. Open virtual file handle
    let fh = fs_arc.open_file_handle(remotes_ino, 0);
    assert_ne!(fh & VIRTUAL_FH_FLAG, 0, "Virtual handle must have high-bit flag set");

    // 5. Read .remotes content
    let content_bytes = read_core(&fs_arc, remotes_ino, 4096, 0).unwrap();
    let content_str = String::from_utf8(content_bytes).unwrap();

    assert!(content_str.contains("=== Remote Status (Volume Head Generation: 2) ==="));
    assert!(content_str.contains("[Remote: nas]"));
    assert!(content_str.contains("Target:             local/nfs (/mnt/nas)"));
    assert!(content_str.contains("Read Priority:      10"));
    assert!(content_str.contains("Status:             Up to date"));
    assert!(content_str.contains("Synced Generation:  1 / 1"));
    assert!(content_str.contains("Replication Lag:    0 sealed generation(s)"));

    assert!(content_str.contains("[Remote: s3]"));
    assert!(content_str.contains("Target:             s3 (bucket: my-s3-bucket, prefix: logs/)"));
    assert!(content_str.contains("Read Priority:      100"));
    assert!(content_str.contains("Status:             Up to date"));
    assert!(content_str.contains("Synced Generation:  1 / 1"));

    // 6. Release file handle
    fs_arc.release_file_handle(fh, remotes_ino).unwrap();
    assert!(fs_arc.virtual_handles.read().unwrap().get(&fh).is_none());
}

#[test]
fn test_tiered_storage_reader_coalesces_concurrent_remote_reads() {
    use appendfs::remote::TieredStorageReader;
    use appendfs::storage::StorageReader;
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;

    let dir = TempDir::new().unwrap();
    let cache = Arc::new(OnDiskBlockCache::new(dir.path(), 50 * 1024 * 1024).unwrap());

    // 2 MiB payload with deterministic bytes
    let payload = vec![0x77u8; 2 * 1024 * 1024];

    let mock = Arc::new(MockRemoteStore::new());
    mock.put_object("000001.log", &mut &payload[..], payload.len() as u64, None)
        .unwrap();

    // Wrap in LatencyRemoteStore (30ms per request) to create a clear concurrency window
    let latency_store = Arc::new(LatencyRemoteStore::new(mock));
    latency_store.set_fixed_delay(Duration::from_millis(30));

    // Wrap in CountingRemoteStore to verify exactly 1 remote request per block
    let counting_store = Arc::new(CountingRemoteStore::new(latency_store));

    let remotes: Vec<appendfs::remote::RemoteReadTarget> = vec![appendfs::remote::RemoteReadTarget::new(
        "s3",
        counting_store.clone(),
        100,
    )];

    let reader = Arc::new(TieredStorageReader::new(
        1,
        "000001.log",
        payload.len() as u64,
        remotes,
        cache.clone(),
    ));

    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::new();

    for i in 0..num_threads {
        let r = Arc::clone(&reader);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            // Synchronize thread start so they hit the reader concurrently
            b.wait();
            // Read various offsets within block 0
            let offset = (i as u64) * 1024;
            let mut buf = [0u8; 512];
            r.read_exact_at(offset, &mut buf).unwrap();
            assert_eq!(buf, [0x77u8; 512]);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Crucial assertions:
    // 1. Exactly 1 range read was issued to the remote store for block 0 (instead of 8!)
    assert_eq!(
        counting_store.range_reads(),
        1,
        "Expected exactly 1 remote range read for block 0 due to coalescing, got {}",
        counting_store.range_reads()
    );

    // 2. The coalescer recorded 1 leader fetch and 7 coalesced requests
    assert_eq!(reader.coalescer.leader_requests(), 1);
    assert_eq!(reader.coalescer.coalesced_requests(), (num_threads - 1) as u64);
    assert_eq!(reader.coalescer.total_requests(), num_threads as u64);

    // 3. Block 0 is now cached on disk
    assert!(cache.read_block(1, 0).unwrap().is_some());
}

#[test]
fn test_event_driven_immediate_replication_on_log_roll() {
    let dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = Arc::new(VolumeKey::plaintext());

    let _summary_file = init_volume(storage.clone(), volume_key.as_ref(), VolumeHeader::plaintext()).unwrap();

    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());
    let fs_arc = Arc::new(fs);

    let mut registry = RemoteRegistry::new();
    let remote = Arc::new(MockRemoteStore::new());
    registry.add_remote("mock", RemoteTargetConfig::new("mock-bucket"));
    registry.set_store_override("mock", remote.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    // Start background replication worker with a 1-HOUR poll interval.
    // If it were relying solely on periodic polling, it would take 3600s to replicate!
    let mut worker = appendfs::remote::RemoteReplicationWorker::start_with_interval(
        fs_arc.clone(),
        registry_arc.clone(),
        dir.path().to_path_buf(),
        std::time::Duration::from_secs(3600),
    );

    // Write data to active log
    let file1 = create_core(&fs_arc, 1, "test_file.txt", 0o644, 0, 1000, 1000).unwrap();
    write_core(&fs_arc, file1.ino, b"Data to seal into generation 1", 0).unwrap();
    fs_arc.sync_log().unwrap();

    // Force roll generation 1 -> 2. This seals generation 1 and notifies the worker via Condvar!
    let (next_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    {
        let mut manifest = fs_arc.manifest.write().unwrap();
        manifest.set_generation_md5(next_gen - 1, sealed_md5);
        manifest.record_roll(next_gen, clock.now(), 24);
    }
    fs_arc.notify_replication();

    // Poll for up to 2 seconds for the remote to receive 000001.log
    let start = std::time::Instant::now();
    let mut replicated = false;
    while start.elapsed() < std::time::Duration::from_secs(2) {
        if remote.head_object("000001.log").unwrap().is_some() {
            replicated = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    assert!(
        replicated,
        "Log generation 1 must be replicated immediately via event-driven wake-up without waiting for the 3600s poll interval!"
    );

    worker.stop();
}

#[test]
fn test_audit_interval_skips_confirmed_files_until_audit() {
    let dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = Arc::new(VolumeKey::plaintext());

    let _summary_file = init_volume(storage.clone(), volume_key.as_ref(), VolumeHeader::plaintext()).unwrap();

    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());
    let fs_arc = Arc::new(fs);

    let raw_remote = Arc::new(MockRemoteStore::new());
    let counting_store = Arc::new(CountingRemoteStore::new(raw_remote.clone()));

    let mut registry = RemoteRegistry::new();
    registry.policy.audit_interval_secs = 14400; // 4 hours
    registry.add_remote("counting", RemoteTargetConfig::new("counting-bucket"));
    registry.set_store_override("counting", counting_store.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    // Write data to active log
    let file1 = create_core(&fs_arc, 1, "audit_test.txt", 0o644, 0, 1000, 1000).unwrap();
    write_core(&fs_arc, file1.ino, b"Audit test data payload", 0).unwrap();
    fs_arc.sync_log().unwrap();

    // Seal generation 1
    let (next_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    {
        let mut manifest = fs_arc.manifest.write().unwrap();
        manifest.set_generation_md5(next_gen - 1, sealed_md5);
        manifest.record_roll(next_gen, clock.now(), 24);
    }

    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();
    let mut last_audit = std::time::SystemTime::now(); // Recent audit
    let mut confirmed_gens = std::collections::HashMap::new();
    let mut confirmed_sums = std::collections::HashMap::new();

    // 1. First incremental cycle: generation 1 is not confirmed, so it gets probed and uploaded
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        dir.path(),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false,
    )
    .unwrap();

    assert_eq!(
        counting_store.puts(),
        2,
        "000001.log and 000000.summary must be uploaded"
    );
    let head_calls_initial = counting_store.heads();
    assert!(
        head_calls_initial >= 2,
        "head_object must be checked for log and summary"
    );

    // 2. Second incremental cycle (no new files, audit interval has not elapsed):
    // Should skip head_object for confirmed 000001.log!
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        dir.path(),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false,
    )
    .unwrap();

    assert_eq!(
        counting_store.heads(),
        head_calls_initial,
        "Incremental cycle must NOT call head_object on confirmed generations!"
    );

    // 3. Full audit cycle (force_audit = true, simulating 4-hour elapsed audit):
    // Must re-probe head_object on all sealed files!
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        dir.path(),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        true,
    )
    .unwrap();

    assert!(
        counting_store.heads() > head_calls_initial,
        "Full audit cycle must re-probe head_object for remote integrity check"
    );
}

#[test]
fn test_last_summary_generation_restored_on_recovery_and_allows_pruning() {
    let dir = TempDir::new().unwrap();
    let nfs_dir = TempDir::new().unwrap();
    let storage = Arc::new(OsStorage::new(dir.path()));
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext()).unwrap();

    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    let writer = Arc::new(LogWriter::create_lazy(storage.clone(), 1, 1024 * 1024, 1, volume_key.clone()).unwrap());
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(dir.path());

    // Write file in generation 1
    let root = 1u64;
    let file_attr = create_core(&fs, root, "test.txt", 0o644, 0, 1000, 1000).unwrap();
    write_core(&fs, file_attr.ino, b"data to replicate and prune", 0).unwrap();
    fs.sync_log().unwrap();

    fs.export_summary(storage.as_ref()).unwrap();
    assert_eq!(fs.last_summary_generation.load(Ordering::SeqCst), 1);

    // Roll to generation 2
    let (next_gen, sealed_md5) = writer.force_roll(&*clock).unwrap().unwrap();
    {
        let mut manifest = fs.manifest.write().unwrap();
        manifest.set_generation_md5(next_gen - 1, sealed_md5);
        manifest.record_roll(next_gen, clock.now(), 24);
    }

    // Drop filesystem and writer, simulating a restart/remount
    drop(writer);
    drop(fs);

    // Remove 000002.summary (emitted on clean drop) to simulate recovery from 000001.summary
    if storage.exists("000002.summary") {
        storage.remove_file("000002.summary").unwrap();
    }

    // Recover filesystem
    let mut recovered_fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();

    // Verify last_summary_generation was restored from 000001.summary
    assert_eq!(
        recovered_fs.last_summary_generation.load(Ordering::SeqCst),
        1,
        "last_summary_generation must be seeded from recovered summary file"
    );

    let writer2 = Arc::new(LogWriter::create_lazy(storage.clone(), 2, 1024 * 1024, 1, volume_key.clone()).unwrap());
    recovered_fs.log_writer = Some(writer2);
    recovered_fs.set_log_dir(dir.path());

    // Configure remote registry with 0-second retention to test pruning
    let mut registry = RemoteRegistry::new();
    let nas_cfg = RemoteTargetConfig::new_path(nfs_dir.path());
    registry.add_remote("nas", nas_cfg);
    registry.policy.min_synced_remotes = 1;
    registry.policy.local_retention_secs = Some(0);
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    let fs_arc = Arc::new(recovered_fs);
    let mut last_part_sync = std::time::SystemTime::now();
    let mut uploaded_parts = std::collections::HashMap::new();

    // Run cycle: should replicate 000001.log and prune it immediately without waiting for a new summary!
    assert!(dir.path().join("000001.log").exists());
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        dir.path(),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    // Verify 000001.log was pruned from local disk
    assert!(
        !dir.path().join("000001.log").exists(),
        "000001.log must be pruned immediately after restart without waiting for a new summary"
    );
    // Verify it exists in the remote store
    assert!(nfs_dir.path().join("000001.log").exists());
}
