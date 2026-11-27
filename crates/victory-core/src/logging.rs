//! One tracing setup for every binary.
//!
//! Filter with `SCARLETT_LOG` (falls back to `RUST_LOG`), e.g.
//! `SCARLETT_LOG=victory_loader=trace,info`. Debug and trace output exist
//! only in builds with the `diagnostics` feature; a plain release build
//! logs info and above whatever the filter asks for.
//!
//! When `SCARLETT_LOG_FILE` (or `VICTORY_LOG_FILE`) is set, events matching
//! `SCARLETT_LOG_FILE_FILTER` (or `SCARLETT_LOG` if unset) are also written
//! without ANSI escapes to that file.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::Mutex;

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// The most verbose level this build can log.
const CAP: LevelFilter = if cfg!(feature = "diagnostics") {
    LevelFilter::TRACE
} else {
    LevelFilter::INFO
};

const DEFAULT_FILE_FILTER: &str =
    "warn,victory_gpu::host=info,victory_gpu::host::card_steps=info,victory_gpu::residency=info";

fn env_filter(primary: &str, secondary: Option<&str>, fallback: &str) -> EnvFilter {
    std::env::var(primary)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            secondary
                .and_then(|k| std::env::var(k).ok())
                .filter(|v| !v.trim().is_empty())
        })
        .and_then(|v| EnvFilter::try_new(v).ok())
        .unwrap_or_else(|| EnvFilter::new(fallback))
}

fn open_log_file(path: &Path) -> Option<Mutex<File>> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = std::fs::create_dir_all(parent);
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
        .map(Mutex::new)
}

pub fn init(default_level: &str) {
    let console_filter = env_filter("SCARLETT_LOG", Some("RUST_LOG"), default_level);
    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_writer(std::io::stderr)
        .with_filter(console_filter);

    let file_layer = std::env::var_os("SCARLETT_LOG_FILE")
        .filter(|v| !v.is_empty())
        .and_then(|p| open_log_file(Path::new(&p)))
        .map(|file| {
            let file_filter = env_filter("SCARLETT_LOG_FILE_FILTER", None, DEFAULT_FILE_FILTER);
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_writer(file)
                .with_filter(file_filter)
        });

    let _ = tracing_subscriber::registry()
        .with(CAP)
        .with(console_layer)
        .with(file_layer)
        .try_init();
}
