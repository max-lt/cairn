//! End-to-end smoke test of the `cairn` CLI binary.
//!
//! Drives the actual binary (built by cargo at test time, found via
//! `CARGO_BIN_EXE_cairn`) through scan → status → restore against a
//! LocalFilesystem remote backend, with a fixed machine key and a
//! deterministic config TOML.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

fn cairn_bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_cairn"))
}

fn run(args: &[&str], config: &Path, catalog: &Path) -> (std::process::ExitStatus, String, String) {
    let mut cmd = Command::new(cairn_bin());
    cmd.arg("--config")
        .arg(config)
        .arg("--catalog")
        .arg(catalog)
        .arg("--log")
        .arg("warn")
        .args(args)
        .stdin(Stdio::null());
    let out = cmd.output().expect("failed to spawn cairn binary");
    (
        out.status,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn write_config(
    tmp: &Path,
    scan_root: &Path,
    remote_dir: &Path,
    machine_key_path: &Path,
) -> std::path::PathBuf {
    let config = format!(
        r#"
scan_roots = [{scan:?}]
excludes = []

[remote]
backend = "local_filesystem"
path = {remote:?}

[chunking]
avg_size = 65536

[machine]
key_path = {key:?}
"#,
        scan = scan_root.display().to_string(),
        remote = remote_dir.display().to_string(),
        key = machine_key_path.display().to_string(),
    );
    let path = tmp.join("cairn.toml");
    fs::write(&path, config).unwrap();
    path
}

#[test]
fn help_prints_usage() {
    let out = Command::new(cairn_bin()).arg("--help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("cairn"));
    assert!(stdout.contains("scan"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("restore"));
}

#[test]
fn scan_then_status_reports_indexed_content() {
    let tmp = tempfile::tempdir().unwrap();
    let scan_root = tmp.path().join("data");
    fs::create_dir(&scan_root).unwrap();
    fs::write(scan_root.join("a.txt"), b"alpha").unwrap();
    fs::write(scan_root.join("b.txt"), b"beta").unwrap();
    fs::write(scan_root.join("twin.txt"), b"alpha").unwrap();

    let remote_dir = tmp.path().join("remote");
    fs::create_dir(&remote_dir).unwrap();
    let key_path = tmp.path().join("machine.key");
    let catalog_path = tmp.path().join("cairn.catalog.redb");
    let config = write_config(tmp.path(), &scan_root, &remote_dir, &key_path);

    let (status, stdout, stderr) = run(&["scan"], &config, &catalog_path);
    assert!(status.success(), "scan failed: stderr={stderr}");
    assert!(stdout.contains("Scan complete"), "stdout was: {stdout}");
    assert!(stdout.contains("files seen:           3"));
    assert!(stdout.contains("contents backed up:   2")); // alpha + beta

    let (status, stdout, stderr) = run(&["status"], &config, &catalog_path);
    assert!(status.success(), "status failed: stderr={stderr}");
    assert!(stdout.contains("contents indexed:     2"));
    assert!(stdout.contains("duplicates:           1"));
    assert!(stdout.contains("orphans (backed up):  0"));
}

#[test]
fn restore_recovers_a_deleted_file_via_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let scan_root = tmp.path().join("data");
    fs::create_dir(&scan_root).unwrap();
    let body = b"this file must be recoverable via the CLI";
    let original = scan_root.join("important.txt");
    fs::write(&original, body).unwrap();

    let remote_dir = tmp.path().join("remote");
    fs::create_dir(&remote_dir).unwrap();
    let key_path = tmp.path().join("machine.key");
    let catalog_path = tmp.path().join("cairn.catalog.redb");
    let config = write_config(tmp.path(), &scan_root, &remote_dir, &key_path);

    // scan + back up
    let (status, _, stderr) = run(&["scan"], &config, &catalog_path);
    assert!(status.success(), "scan failed: {stderr}");

    // delete the local copy
    fs::remove_file(&original).unwrap();
    assert!(!original.exists());

    // restore via the CLI by path
    let out_path = tmp.path().join("recovered.txt");
    let (status, stdout, stderr) = run(
        &[
            "restore",
            original.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
        ],
        &config,
        &catalog_path,
    );
    assert!(
        status.success(),
        "restore failed: stderr={stderr}, stdout={stdout}"
    );
    assert!(stdout.contains("restored"));
    assert_eq!(fs::read(&out_path).unwrap(), body);
}

#[test]
fn dupes_and_orphans_commands_run() {
    let tmp = tempfile::tempdir().unwrap();
    let scan_root = tmp.path().join("data");
    fs::create_dir(&scan_root).unwrap();
    fs::write(scan_root.join("a.txt"), b"shared").unwrap();
    fs::write(scan_root.join("b.txt"), b"shared").unwrap();

    let remote_dir = tmp.path().join("remote");
    fs::create_dir(&remote_dir).unwrap();
    let key_path = tmp.path().join("machine.key");
    let catalog_path = tmp.path().join("cairn.catalog.redb");
    let config = write_config(tmp.path(), &scan_root, &remote_dir, &key_path);

    run(&["scan"], &config, &catalog_path);

    let (status, stdout, _) = run(&["dupes"], &config, &catalog_path);
    assert!(status.success());
    // The shared content has two locations.
    assert!(stdout.contains(" bytes)"));

    let (status, stdout, _) = run(&["orphans"], &config, &catalog_path);
    assert!(status.success());
    assert!(stdout.contains("no orphans"));
}

#[test]
fn check_reports_clean_after_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let scan_root = tmp.path().join("data");
    fs::create_dir(&scan_root).unwrap();
    fs::write(scan_root.join("a.txt"), b"alpha").unwrap();

    let remote_dir = tmp.path().join("remote");
    fs::create_dir(&remote_dir).unwrap();
    let key_path = tmp.path().join("machine.key");
    let catalog_path = tmp.path().join("cairn.catalog.redb");
    let config = write_config(tmp.path(), &scan_root, &remote_dir, &key_path);

    run(&["scan"], &config, &catalog_path);
    let (status, stdout, _) = run(&["check"], &config, &catalog_path);
    assert!(status.success());
    assert!(stdout.contains("no corruption found"));
}
