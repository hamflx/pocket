use clap::Parser;
use tracing::{error, info};

mod config;
mod credentials;
mod index_crdt;
mod fs_types;
mod storage;
mod s3_backend;
mod remote_fs;
mod service;
mod cli;

pub use remote_fs::RemoteFilesystem;
pub use fs_types::MemEntry;

fn main() {
    // 初始化 tracing 日志，输出到日志文件
    let _guard = {
        use std::fs;
        use std::{ffi::OsStr, path::Path};
        use tracing_appender::rolling;
        use tracing_subscriber::{EnvFilter, fmt};

        let log_path = config::log_file_path();
        if let Some(parent) = log_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let dir = log_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = log_path
            .file_name()
            .unwrap_or_else(|| OsStr::new("pocket.log"));

        let file_appender = rolling::never(dir, file_name);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        fmt()
            .with_env_filter(env_filter)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();

        info!("Logging to {}", log_path.display());

        guard
    };

    let cli = cli::Cli::parse();

    if let Some(command) = cli.command {
        if let Err(e) = cli::handle_command(command) {
            error!("Error: {e}");
            let mut source = e.source();
            while let Some(err) = source {
                error!("  Caused by: {err}");
                source = err.source();
            }
            std::process::exit(1);
        }
        return;
    }

    if let Err(e) = service::run_main() {
        error!("Error: {e}");
        let mut source = e.source();
        while let Some(err) = source {
            error!("  Caused by: {err}");
            source = err.source();
        }
        // 退出时返回非零表示错误
        std::process::exit(1);
    }
}
