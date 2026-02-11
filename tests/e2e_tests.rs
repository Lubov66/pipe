//! End-to-end tests for the pipe CLI.
//!
//! These tests invoke the compiled `pipe` binary against a real server.
//! They are gated behind the `e2e` feature flag and run sequentially
//! (single test keypair/session lifecycle).
//!
//! Run with:
//!   cargo test --features e2e --test e2e_tests -- --test-threads=1
//!
//! Set PIPE_E2E_API to override the server URL:
//!   PIPE_E2E_API=http://localhost:3333 cargo test --features e2e --test e2e_tests -- --test-threads=1

#![cfg(feature = "e2e")]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;

struct TestEnv {
    dir: PathBuf,
    bin: PathBuf,
}

static ENV: OnceLock<TestEnv> = OnceLock::new();

fn env() -> &'static TestEnv {
    ENV.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("pipe-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("Failed to create temp dir");

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let release = manifest_dir.join("target/release/pipe");
        let debug = manifest_dir.join("target/debug/pipe");
        let bin = if release.exists() {
            release
        } else if debug.exists() {
            debug
        } else {
            panic!("No pipe binary found. Run `cargo build` first.");
        };

        TestEnv { dir, bin }
    })
}

fn api_url() -> String {
    std::env::var("PIPE_E2E_API")
        .unwrap_or_else(|_| "https://us-west-01-firestarter.pipenetwork.com".to_string())
}

fn config_path() -> PathBuf {
    env().dir.join("config.json")
}

fn keypair_path() -> PathBuf {
    env().dir.join("wallet.json")
}

/// Run the pipe CLI with the given arguments, using isolated config and API.
fn run_pipe(args: &[&str]) -> Output {
    Command::new(&env().bin)
        .args(["--api", &api_url(), "--config", config_path().to_str().unwrap()])
        .args(args)
        .output()
        .expect("Failed to execute pipe binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{} failed (exit={:?}):\nstdout: {}\nstderr: {}",
        context,
        output.status.code(),
        stdout(output),
        stderr(output)
    );
}

fn assert_failure(output: &Output, context: &str) {
    assert!(
        !output.status.success(),
        "{} should have failed but succeeded:\nstdout: {}",
        context,
        stdout(output)
    );
}

// ── Tests run in order (--test-threads=1) ─────────────────────

#[test]
fn t01_pre_auth_commands_fail() {
    let _ = env();
    // Clean slate — no config file
    let _ = std::fs::remove_file(config_path());

    let out = run_pipe(&["profile"]);
    assert_failure(&out, "profile without auth");

    let out = run_pipe(&["sessions"]);
    assert_failure(&out, "sessions without auth");

    let out = run_pipe(&["credits-status"]);
    assert_failure(&out, "credits-status without auth");
}

#[test]
fn t02_wallet_keygen() {
    let _ = env();
    let kp = keypair_path();
    let _ = std::fs::remove_file(&kp);

    let out = run_pipe(&["wallet-keygen", "--output", kp.to_str().unwrap()]);
    assert_success(&out, "wallet-keygen");
    assert!(kp.exists(), "Keypair file should exist");

    let s = stdout(&out);
    assert!(
        s.contains("Public key:") || s.contains("pubkey"),
        "Should print public key: {}",
        s
    );
}

#[test]
fn t03_wallet_keygen_refuses_overwrite() {
    let _ = env();
    let kp = keypair_path();
    assert!(kp.exists(), "Keypair should already exist from t02");

    let out = run_pipe(&["wallet-keygen", "--output", kp.to_str().unwrap()]);
    assert_failure(&out, "wallet-keygen without --force");
}

#[test]
fn t04_wallet_keygen_force() {
    let _ = env();
    let kp = keypair_path();

    let out = run_pipe(&["wallet-keygen", "--output", kp.to_str().unwrap(), "--force"]);
    assert_success(&out, "wallet-keygen --force");
}

#[test]
fn t05_wallet_auth() {
    let _ = env();
    let kp = keypair_path();

    let out = run_pipe(&["wallet-auth", "--keypair", kp.to_str().unwrap()]);
    assert_success(&out, "wallet-auth");
    assert!(config_path().exists(), "Config file should be created after auth");

    let s = stdout(&out);
    assert!(
        s.contains("Authenticated") || s.contains("success") || s.contains("User ID"),
        "Should confirm authentication: {}",
        s
    );
}

#[test]
fn t06_profile() {
    let _ = env();

    let out = run_pipe(&["profile"]);
    assert_success(&out, "profile");

    let s = stdout(&out);
    assert!(s.contains("User ID") || s.contains("user_id"), "Should show user ID: {}", s);
    assert!(
        s.contains("Wallet") || s.contains("wallet"),
        "Should show wallet: {}",
        s
    );
}

#[test]
fn t07_profile_whoami_alias() {
    let _ = env();

    let out = run_pipe(&["whoami"]);
    assert_success(&out, "whoami alias");

    let s = stdout(&out);
    assert!(s.contains("User ID") || s.contains("user_id"), "whoami should show user ID: {}", s);
}

#[test]
fn t08_credits_status() {
    let _ = env();

    let out = run_pipe(&["credits-status"]);
    assert_success(&out, "credits-status");
}

#[test]
fn t09_usage() {
    let _ = env();

    let out = run_pipe(&["usage"]);
    assert_success(&out, "usage");

    let s = stdout(&out).to_lowercase();
    assert!(s.contains("usage") || s.contains("period"), "Should show usage info: {}", s);
}

#[test]
fn t10_usage_with_period() {
    let _ = env();

    let out = run_pipe(&["usage", "--period", "7d"]);
    assert_success(&out, "usage --period 7d");
}

#[test]
fn t11_sessions_list() {
    let _ = env();

    let out = run_pipe(&["sessions"]);
    assert_success(&out, "sessions");

    let s = stdout(&out);
    assert!(
        s.contains("Session") || s.contains("session") || s.contains("current"),
        "Should list sessions: {}",
        s
    );
}

#[test]
fn t12_s3_key_create() {
    let _ = env();

    let out = run_pipe(&["s3-key-create"]);
    assert_success(&out, "s3-key-create");

    let s = stdout(&out);
    assert!(
        s.contains("Access Key ID") || s.contains("AWS_ACCESS_KEY_ID"),
        "Should return access key: {}",
        s
    );

    // Save the key ID for later tests
    let key_id = s
        .lines()
        .find(|l| l.contains("Access Key ID") || l.contains("AWS_ACCESS_KEY_ID"))
        .and_then(|l| {
            // Try "export AWS_ACCESS_KEY_ID=XXXX" format
            l.split('=').nth(1).map(|s| s.trim().to_string())
                .or_else(|| l.split_whitespace().last().map(|s| s.to_string()))
        })
        .unwrap_or_default();

    // Write key ID to temp file for subsequent tests
    std::fs::write(env().dir.join("last_key_id"), &key_id).ok();
}

#[test]
fn t13_s3_key_list() {
    let _ = env();

    let out = run_pipe(&["s3-key-list"]);
    assert_success(&out, "s3-key-list");
}

#[test]
fn t14_s3_key_delete() {
    let _ = env();

    let key_id_path = env().dir.join("last_key_id");
    let key_id = std::fs::read_to_string(&key_id_path).unwrap_or_default();
    let key_id = key_id.trim();

    if key_id.is_empty() {
        eprintln!("  SKIP  s3-key-delete — no key ID from s3-key-create");
        return;
    }

    let out = run_pipe(&["s3-key-delete", key_id, "--yes"]);
    assert_success(&out, "s3-key-delete");
}

#[test]
fn t15_s3_info() {
    let _ = env();

    let out = run_pipe(&["s3-info"]);
    assert_success(&out, "s3-info");

    let s = stdout(&out);
    assert!(
        s.contains("Endpoint") || s.contains("endpoint"),
        "Should show S3 endpoint: {}",
        s
    );
}

#[test]
fn t16_config_show() {
    let _ = env();

    let out = run_pipe(&["config", "show"]);
    assert_success(&out, "config show");

    let s = stdout(&out);
    assert!(s.contains("Config file") || s.contains("config"), "Should show config info: {}", s);
}

#[test]
fn t17_logout() {
    let _ = env();

    let out = run_pipe(&["logout"]);
    assert_success(&out, "logout");

    let s = stdout(&out);
    assert!(
        s.contains("Logged out") || s.contains("logged out") || s.contains("cleared"),
        "Should confirm logout: {}",
        s
    );
}

#[test]
fn t18_post_logout_commands_fail() {
    let _ = env();

    let out = run_pipe(&["profile"]);
    assert_failure(&out, "profile after logout");

    let out = run_pipe(&["sessions"]);
    assert_failure(&out, "sessions after logout");
}

#[test]
fn t99_cleanup() {
    if let Some(e) = ENV.get() {
        let _ = std::fs::remove_dir_all(&e.dir);
    }
}
