use crate::crypto::VolumeKey;
use crate::log::{RecoveryTarget, SummaryReader};
use crate::remote::RemoteReadTarget;
use crate::storage::{Storage, StorageWriter, WriteMode};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::sync::Arc;

struct StorageWriterAdapter<'a>(&'a mut Box<dyn StorageWriter>);

impl<'a> Write for StorageWriterAdapter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.append(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.sync()
    }
}

/// Streams a file directly from remote stores into `storage` without polluting block cache.
fn fetch_object_from_remotes(
    remote_stores: &[RemoteReadTarget],
    storage: &dyn Storage,
    key: &str,
    target_name: &str,
) -> io::Result<bool> {
    let tmp_name = format!("{}.tmp", target_name);
    for target_remote in remote_stores {
        let mut writer = match storage.open_writer(&tmp_name, WriteMode::Overwrite) {
            Ok(w) => w,
            Err(_) => continue,
        };
        let download_res = {
            let mut adapter = StorageWriterAdapter(&mut writer);
            target_remote.store.get_object(key, &mut adapter)
        };
        if download_res.is_ok() && writer.sync().is_ok() {
            drop(writer);
            if storage.rename(&tmp_name, target_name).is_ok() {
                return Ok(true);
            }
        } else {
            let _ = storage.remove_file(&tmp_name);
        }
    }
    let _ = storage.remove_file(&tmp_name);
    Ok(false)
}

/// Downloads and verifies a summary checkpoint file from remote stores.
fn fetch_and_verify_summary(
    remote_stores: &[RemoteReadTarget],
    storage: &dyn Storage,
    gen_num: u64,
    volume_key: Arc<VolumeKey>,
    target: RecoveryTarget,
) -> io::Result<Option<SummaryReader>> {
    let summary_name = format!("{:06}.summary", gen_num);
    let tmp_name = format!("{:06}.summary.tmp", gen_num);

    for target_remote in remote_stores {
        let mut writer = match storage.open_writer(&tmp_name, WriteMode::Overwrite) {
            Ok(w) => w,
            Err(_) => continue,
        };
        let download_res = {
            let mut adapter = StorageWriterAdapter(&mut writer);
            target_remote.store.get_object(&summary_name, &mut adapter)
        };
        if download_res.is_err() || writer.sync().is_err() {
            let _ = storage.remove_file(&tmp_name);
            continue;
        }
        drop(writer);

        match SummaryReader::open(storage, &tmp_name, volume_key.clone()) {
            Ok(reader) => {
                let eligible = match target {
                    RecoveryTarget::Latest => true,
                    RecoveryTarget::TxId(max_tx) => reader.header.last_tx_id <= max_tx,
                    RecoveryTarget::Timestamp(max_time) => reader.header.created_at <= max_time,
                    RecoveryTarget::Generation(max_gen) => gen_num <= max_gen,
                };
                if eligible {
                    storage.rename(&tmp_name, &summary_name)?;
                    log::info!(
                        "Fetched and verified remote checkpoint {} from remote '{}' (generation: {}, last_tx_id: {})",
                        summary_name,
                        target_remote.name,
                        gen_num,
                        reader.header.last_tx_id
                    );
                    return Ok(Some(reader));
                } else {
                    let _ = storage.remove_file(&tmp_name);
                    return Ok(None);
                }
            }
            Err(e) => {
                log::warn!(
                    "Remote summary {} from '{}' failed verification: {}",
                    summary_name,
                    target_remote.name,
                    e
                );
                let _ = storage.remove_file(&tmp_name);
            }
        }
    }

    let _ = storage.remove_file(&tmp_name);
    Ok(None)
}

/// Discovers and fetches any missing historical summary and log replay files from remote stores
/// necessary to satisfy a recovery target.
///
/// If local storage has pruned older summaries and logs, uses the timeline manifest in the latest
/// local summary file to identify the appropriate generation, downloads and verifies the historical
/// checkpoint file, and fetches any missing `.log` files needed for log replay.
pub fn prepare_remote_recovery_for_target(
    storage: &dyn Storage,
    target: RecoveryTarget,
    volume_key: Arc<VolumeKey>,
    remote_stores: &[RemoteReadTarget],
) -> io::Result<Option<String>> {
    if remote_stores.is_empty() {
        return Ok(None);
    }

    let files = storage.list_files()?;
    let mut local_summaries = Vec::new();
    for file in &files {
        if file.ends_with(".summary") {
            let stem = file.trim_end_matches(".summary");
            if let Ok(gen_num) = stem.parse::<u64>() {
                local_summaries.push((gen_num, file.clone()));
            }
        }
    }
    local_summaries.sort_by_key(|(g, _)| *g);

    let mut best_local_eligible: Option<(u64, crate::log::SummaryHeader)> = None;
    for (gen_num, file) in &local_summaries {
        if let Ok(reader) = SummaryReader::open(storage, file, volume_key.clone()) {
            let eligible = match target {
                RecoveryTarget::Latest => true,
                RecoveryTarget::TxId(max_tx) => reader.header.last_tx_id <= max_tx,
                RecoveryTarget::Timestamp(max_time) => reader.header.created_at <= max_time,
                RecoveryTarget::Generation(max_gen) => *gen_num <= max_gen,
            };
            if eligible && best_local_eligible.as_ref().is_none_or(|(g, _)| *gen_num > *g) {
                best_local_eligible = Some((*gen_num, reader.header));
            }
        }
    }

    // If local storage has no summaries at all, search remotes for the newest checkpoint
    if local_summaries.is_empty() {
        let mut remote_summary_gens = BTreeSet::new();
        for target_remote in remote_stores {
            if let Ok(objs) = target_remote.store.list_objects("") {
                for obj in objs {
                    if obj.key.ends_with(".summary") {
                        let stem = obj.key.trim_end_matches(".summary");
                        if let Ok(gen_num) = stem.parse::<u64>() {
                            remote_summary_gens.insert(gen_num);
                        }
                    }
                }
            }
        }

        if let Some(&latest_remote_gen) = remote_summary_gens.last()
            && let Ok(Some(reader)) = fetch_and_verify_summary(
                remote_stores,
                storage,
                latest_remote_gen,
                volume_key.clone(),
                RecoveryTarget::Latest,
            )
        {
            let summary_name = format!("{:06}.summary", latest_remote_gen);
            local_summaries.push((latest_remote_gen, summary_name));
            let eligible = match target {
                RecoveryTarget::Latest => true,
                RecoveryTarget::TxId(max_tx) => reader.header.last_tx_id <= max_tx,
                RecoveryTarget::Timestamp(max_time) => reader.header.created_at <= max_time,
                RecoveryTarget::Generation(max_gen) => latest_remote_gen <= max_gen,
            };
            if eligible {
                best_local_eligible = Some((latest_remote_gen, reader.header));
            }
        }
    }

    let latest_summary_file = match local_summaries.last() {
        Some((_, f)) => f,
        None => return Ok(None),
    };

    let latest_reader = match SummaryReader::open(storage, latest_summary_file, volume_key.clone()) {
        Ok(r) => r,
        Err(e) => {
            log::warn!(
                "Could not read manifest from latest summary {}: {}",
                latest_summary_file,
                e
            );
            return Ok(None);
        }
    };

    let manifest = latest_reader.manifest;
    let max_manifest_gen = manifest.logs.last().map(|l| l.generation).unwrap_or(0);

    let candidate_upper = match target {
        RecoveryTarget::Latest => max_manifest_gen,
        RecoveryTarget::Generation(max_gen) => max_gen.min(max_manifest_gen),
        RecoveryTarget::Timestamp(max_time) => manifest
            .logs
            .iter()
            .filter(|l| l.created_at <= max_time)
            .map(|l| l.generation)
            .max()
            .unwrap_or(0),
        RecoveryTarget::TxId(_) => max_manifest_gen,
    };

    let mut chosen_summary_gen = best_local_eligible.as_ref().map(|(g, _)| *g);

    for cand_gen in (0..=candidate_upper).rev() {
        if let Some(best_gen) = chosen_summary_gen
            && best_gen >= cand_gen
        {
            break;
        }

        let summary_name = format!("{:06}.summary", cand_gen);
        if storage.exists(&summary_name) {
            continue;
        }

        if let Ok(Some(_)) = fetch_and_verify_summary(remote_stores, storage, cand_gen, volume_key.clone(), target) {
            chosen_summary_gen = Some(cand_gen);
            break;
        }
    }

    // Replay log check: download any missing intermediate .log files between chosen summary and target
    if let Some(base_gen) = chosen_summary_gen {
        let replay_upper = match target {
            RecoveryTarget::Generation(max_gen) => max_gen.min(max_manifest_gen),
            RecoveryTarget::Timestamp(max_time) => manifest
                .logs
                .iter()
                .filter(|l| l.created_at <= max_time)
                .map(|l| l.generation)
                .max()
                .unwrap_or(base_gen),
            RecoveryTarget::TxId(_) | RecoveryTarget::Latest => max_manifest_gen,
        };

        for log_gen in (base_gen + 1)..=replay_upper {
            let log_name = crate::log::log_filename(log_gen);
            if !storage.exists(&log_name) && fetch_object_from_remotes(remote_stores, storage, &log_name, &log_name)? {
                log::info!(
                    "Fetched missing log file {} from remote for historical replay",
                    log_name
                );
            }
        }
    }

    Ok(chosen_summary_gen.map(|g| format!("{:06}.summary", g)))
}
