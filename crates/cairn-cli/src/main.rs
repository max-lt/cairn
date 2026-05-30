//! Cairn CLI entrypoint.
//!
//! Build commands with `clap`, load the TOML config, open an [`Engine`],
//! and dispatch. Library-style helpers in `commands.rs` keep the actual
//! business logic out of `main` so it stays testable.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};

mod commands;

#[derive(Debug, Parser)]
#[command(name = "cairn", version, about = "Content-Addressed File Inventory & Recovery", long_about = None)]
struct Cli {
    /// Path to the TOML config file. Defaults to $CAIRN_CONFIG or `cairn.toml`
    /// in the current directory.
    #[arg(short, long, env = "CAIRN_CONFIG", global = true)]
    config: Option<PathBuf>,

    /// Path to the local redb catalog database. Defaults to
    /// `cairn.catalog.redb` next to the config (or the working dir).
    #[arg(long, env = "CAIRN_CATALOG", global = true)]
    catalog: Option<PathBuf>,

    /// Log filter, in `tracing_subscriber::EnvFilter` syntax. Defaults to
    /// `info`.
    #[arg(long, env = "CAIRN_LOG", global = true, default_value = "info")]
    log: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run a full pass (scan + backup + push).
    Scan,
    /// Print index statistics: contents, duplicates, orphans, sync state.
    Status,
    /// List content with more than one live location.
    Dupes,
    /// Show every location (live + tombstoned) for a path or a hex content hash.
    Locate {
        /// Either a filesystem path or a 64-char hex content hash.
        target: String,
    },
    /// List backed-up content with no live location.
    Orphans,
    /// Recover content from the remote to an output path.
    Restore {
        /// Either a path (resolved through the catalog) or a 64-char hex
        /// content hash.
        target: String,
        /// Where to write the restored bytes.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify the chain continuity of this machine's pushed segments.
    Check,
    /// Show or apply remote-blob retention.
    Gc {
        /// Drop content whose last `Vanished` is at least this many seconds
        /// old. Defaults to the config's `retention.retain_after_secs`.
        #[arg(long)]
        retain_after_secs: Option<u64>,
        /// Without this flag, gc is a dry-run that lists candidates only.
        #[arg(long)]
        confirm: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(err) = init_tracing(&cli.log) {
        eprintln!("failed to init logging: {err:?}");
        return ExitCode::FAILURE;
    }

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("cairn: {err:?}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(filter: &str) -> anyhow::Result<()> {
    use tracing_subscriber::{EnvFilter, fmt};
    let env_filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .try_init()
        .ok(); // tolerate "already initialised" in test contexts
    Ok(())
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let config_path = cli
        .config
        .clone()
        .or_else(|| Some(PathBuf::from("cairn.toml")))
        .unwrap();
    let catalog_path = cli
        .catalog
        .clone()
        .unwrap_or_else(|| default_catalog_path(&config_path));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    match cli.cmd {
        Cmd::Scan => rt.block_on(commands::run_scan(&config_path, &catalog_path)),
        Cmd::Status => rt.block_on(commands::run_status(&config_path, &catalog_path)),
        Cmd::Dupes => rt.block_on(commands::run_dupes(&config_path, &catalog_path)),
        Cmd::Locate { target } => {
            rt.block_on(commands::run_locate(&config_path, &catalog_path, &target))
        }
        Cmd::Orphans => rt.block_on(commands::run_orphans(&config_path, &catalog_path)),
        Cmd::Restore { target, out } => rt.block_on(commands::run_restore(
            &config_path,
            &catalog_path,
            &target,
            &out,
        )),
        Cmd::Check => rt.block_on(commands::run_check(&config_path, &catalog_path)),
        Cmd::Gc {
            retain_after_secs,
            confirm,
        } => rt.block_on(commands::run_gc(
            &config_path,
            &catalog_path,
            retain_after_secs,
            confirm,
        )),
    }
}

fn default_catalog_path(config_path: &std::path::Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("cairn.catalog.redb")
}
