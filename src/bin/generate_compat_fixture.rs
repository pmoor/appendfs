//! Generates deterministic AppendFS golden compatibility fixtures.
//!
//! # Usage
//! ```bash
//! # Regenerate all canonical golden fixtures:
//! cargo run --bin generate_compat_fixture
//! cargo run --bin generate_compat_fixture --all
//!
//! # Regenerate specific fixtures:
//! cargo run --bin generate_compat_fixture tests/fixtures/v2
//! cargo run --bin generate_compat_fixture tests/fixtures/v2_key_file_compressed
//! ```
//!
//! Only fixtures of the current format version (`CURRENT_VERSION`) can be generated. Those of
//! older versions, such as `v1`, are frozen: they are what proves volumes written in those
//! formats still recover.

use appendfs::compat::{
    COMPAT_FIXTURE_DUMP_FILES, COMPAT_FIXTURE_FILES, COMPAT_FSCK_REPORT_FILENAME, COMPAT_KEY_FILENAME,
    CompatFixtureConfig, create_canonical_compat_volume,
};
use std::path::{Path, PathBuf};

fn generate_one(out_dir: &Path, config: CompatFixtureConfig) {
    println!(
        "Generating AppendFS format compatibility fixtures in: {} (config: {:?})",
        out_dir.display(),
        config
    );
    if let Err(e) = create_canonical_compat_volume(out_dir, config) {
        eprintln!("Error generating compatibility fixture in {}: {}", out_dir.display(), e);
        std::process::exit(1);
    }
    println!("Successfully generated fixtures:");
    for name in COMPAT_FIXTURE_FILES
        .iter()
        .chain(COMPAT_FIXTURE_DUMP_FILES.iter())
        .chain([COMPAT_FSCK_REPORT_FILENAME].iter())
    {
        println!("  - {}", out_dir.join(name).display());
    }
    if config.is_encrypted() {
        println!("  - {}", out_dir.join(COMPAT_KEY_FILENAME).display());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || (args.len() == 2 && args[1] == "--all") {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixtures_dir = manifest_dir.join("tests/fixtures");
        for config in CompatFixtureConfig::ALL {
            let out_dir = fixtures_dir.join(config.default_dir_name());
            generate_one(&out_dir, config);
        }
        return;
    }

    if args.len() != 2 {
        eprintln!("Usage: generate_compat_fixture [--all | <directory>]");
        std::process::exit(1);
    }

    let out_dir = PathBuf::from(&args[1]);
    let Some(config) = CompatFixtureConfig::from_dir_path(&out_dir) else {
        eprintln!(
            "Error: cannot tell which fixture '{}' is; expected a name like 'v2' or 'v2_key_file_compressed'",
            out_dir.display()
        );
        std::process::exit(1);
    };

    generate_one(&out_dir, config);
}
