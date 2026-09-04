use crate::log::SummaryReader;
use crate::remote::RemoteStore;
use crate::remote::config::{RemoteRegistry, RemoteTargetConfig};
use crate::storage::{Storage, WriteMode};
use std::io::{self, Write};

/// Bootstraps a local volume directory from an existing remote object store (`appendfs init --from-remote`).
///
/// Downloads the latest `.summary` snapshot (and any unsealed active part files), verifying
/// headers and checksums. Saves the remote configuration into `remotes.toml` so subsequent
/// mounts immediately recognize the remote.
pub fn bootstrap_from_remote(
    remote: &dyn RemoteStore,
    storage: &dyn Storage,
    remote_name: &str,
    remote_cfg: RemoteTargetConfig,
) -> io::Result<String> {
    // 1. Discover all remote objects
    let objects = remote.list_objects("")?;
    if objects.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Remote store contains no objects (empty bucket/prefix)",
        ));
    }

    // 2. Find newest .summary file
    let mut latest_summary: Option<(u64, String)> = None;
    for obj in &objects {
        if obj.key.ends_with(".summary") {
            let stem = obj.key.trim_end_matches(".summary");
            if let Ok(gen_num) = stem.parse::<u64>()
                && latest_summary.as_ref().is_none_or(|(g, _)| gen_num > *g)
            {
                latest_summary = Some((gen_num, obj.key.clone()));
            }
        }
    }

    let (summary_gen, summary_key) = latest_summary.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "No valid .summary checkpoint files found in remote store",
        )
    })?;

    let local_summary_name = format!("{:06}.summary", summary_gen);
    let tmp_summary_name = format!("{:06}.summary.tmp", summary_gen);

    // 3. Download summary snapshot to tmp and verify
    {
        let mut writer = storage.open_writer(&tmp_summary_name, WriteMode::Overwrite)?;
        struct StorageWriterAdapter<'a>(&'a mut Box<dyn crate::storage::StorageWriter>);
        impl<'a> Write for StorageWriterAdapter<'a> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.append(buf)?;
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.0.sync()
            }
        }
        let mut adapter = StorageWriterAdapter(&mut writer);
        remote.get_object(&summary_key, &mut adapter)?;
        writer.sync()?;
    }

    // Verify summary header
    SummaryReader::read_volume_header(storage, &tmp_summary_name)?;
    storage.rename(&tmp_summary_name, &local_summary_name)?;
    log::info!(
        "Downloaded latest checkpoint {} from remote '{}'",
        local_summary_name,
        remote_name
    );

    // 4. Download any active intermediate parts for generation summary_gen + 1 (or summary_gen)
    let next_gen = summary_gen + 1;
    let part_prefix = format!("{:06}.part", next_gen);
    let mut part_objects: Vec<_> = objects
        .into_iter()
        .filter(|o| o.key.starts_with(&part_prefix) && o.key.ends_with(".log"))
        .collect();

    if !part_objects.is_empty() {
        part_objects.sort_by(|a, b| a.key.cmp(&b.key));
        let active_log_name = format!("{:06}.log", next_gen);
        log::info!(
            "Found {} active unsealed part(s) for generation {}; reconstructing {}...",
            part_objects.len(),
            next_gen,
            active_log_name
        );

        let mut log_writer = storage.open_writer(&active_log_name, WriteMode::Overwrite)?;
        let header = crate::log::record::FileHeader::new(next_gen, std::time::SystemTime::now());
        log_writer.append(&header.to_bytes())?;

        for part in part_objects {
            struct LogPartWriterAdapter<'a>(&'a mut Box<dyn crate::storage::StorageWriter>);
            impl<'a> Write for LogPartWriterAdapter<'a> {
                fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                    self.0.append(buf)?;
                    Ok(buf.len())
                }
                fn flush(&mut self) -> io::Result<()> {
                    self.0.sync()
                }
            }
            let mut adapter = LogPartWriterAdapter(&mut log_writer);
            remote.get_object(&part.key, &mut adapter)?;
        }
        log_writer.sync()?;
    }

    // 5. Save remote configuration to remotes.toml in storage
    let mut registry = RemoteRegistry::load_from_storage(storage)?;
    registry.add_remote(remote_name, remote_cfg);
    registry.save_to_storage(storage)?;

    Ok(local_summary_name)
}
