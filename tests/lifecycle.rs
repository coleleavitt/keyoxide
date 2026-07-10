#![cfg(unix)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

use tempfile::TempDir;

struct TestEnv {
    _temp: TempDir,
    home: PathBuf,
    runtime: PathBuf,
    bin_dir: PathBuf,
    gpg_socket: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp dir");
        let home = temp.path().join("home");
        let runtime = temp.path().join("runtime");
        let bin_dir = temp.path().join("bin");
        let gpg_dir = temp.path().join("gnupg-runtime");

        fs::create_dir_all(home.join(".config/keyoxide")).expect("config dir");
        fs::create_dir_all(home.join(".ssh")).expect("ssh dir");
        fs::create_dir_all(home.join(".gnupg/private-keys-v1.d")).expect("gpg key dir");
        fs::create_dir_all(&runtime).expect("runtime dir");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        fs::create_dir_all(&gpg_dir).expect("gpg runtime dir");

        let passphrase = home.join(".config/keyoxide/passphrase");
        fs::write(&passphrase, "test-passphrase\n").expect("passphrase");
        fs::set_permissions(&passphrase, fs::Permissions::from_mode(0o600))
            .expect("passphrase mode");

        let gpgconf = bin_dir.join("gpgconf");
        fs::write(
            &gpgconf,
            "#!/bin/sh\nprintf '%s\\n' \"$KEYOXIDE_TEST_GPG_SOCKET\"\n",
        )
        .expect("gpgconf stub");
        fs::set_permissions(&gpgconf, fs::Permissions::from_mode(0o755)).expect("gpgconf mode");

        Self {
            _temp: temp,
            home,
            runtime,
            bin_dir,
            gpg_socket: gpg_dir.join("S.gpg-agent"),
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_keyoxide"));
        command
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env("KEYOXIDE_TEST_GPG_SOCKET", &self.gpg_socket)
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin_dir.display()))
            .env("RUST_LOG", "keyoxide=error")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn ssh_socket(&self) -> PathBuf {
        self.runtime.join("keyoxide/ssh.sock")
    }
}

struct RunResult {
    output: Output,
    timed_out: bool,
}

fn run_with_timeout(mut command: Command, timeout: Duration) -> RunResult {
    let mut child = command.spawn().expect("spawn keyoxide");
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;

    loop {
        if child.try_wait().expect("poll keyoxide").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            child.kill().expect("kill timed-out keyoxide");
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    RunResult {
        output: child.wait_with_output().expect("collect keyoxide output"),
        timed_out,
    }
}

fn assert_failed_quickly(result: &RunResult) {
    assert!(!result.timed_out, "keyoxide hung instead of failing");
    assert!(
        !result.output.status.success(),
        "keyoxide unexpectedly succeeded"
    );
}

#[test]
fn help_exits_without_starting_the_agent() {
    let env = TestEnv::new();
    let result = run_with_timeout(env.command(&["--help"]), Duration::from_millis(500));

    assert!(!result.timed_out, "--help started the long-running daemon");
    assert!(result.output.status.success());
    assert!(String::from_utf8_lossy(&result.output.stdout).contains("Usage:"));
    assert!(!env.ssh_socket().exists());
    assert!(!env.gpg_socket.exists());
}

#[test]
fn check_does_not_start_an_agent() {
    let env = TestEnv::new();
    let result = run_with_timeout(env.command(&["--check"]), Duration::from_millis(500));

    assert_failed_quickly(&result);
    assert!(!env.ssh_socket().exists());
    assert!(!env.gpg_socket.exists());
}

#[test]
fn startup_refuses_to_unlink_a_live_foreign_gpg_socket() {
    let env = TestEnv::new();
    let _foreign_listener = UnixListener::bind(&env.gpg_socket).expect("foreign listener");
    let before = socket_identity(&env.gpg_socket);

    let result = run_with_timeout(env.command(&[]), Duration::from_millis(500));

    assert_failed_quickly(&result);
    assert_eq!(socket_identity(&env.gpg_socket), before);
    assert!(!env.ssh_socket().exists());
}

#[test]
fn failed_second_bind_rolls_back_the_first_socket() {
    let mut env = TestEnv::new();
    env.gpg_socket = env._temp.path().join("missing-parent/S.gpg-agent");

    let result = run_with_timeout(env.command(&[]), Duration::from_millis(500));

    assert_failed_quickly(&result);
    assert!(
        !env.ssh_socket().exists(),
        "failed startup left a stale SSH socket"
    );
}

#[test]
fn sigterm_removes_only_the_agents_owned_sockets() {
    let env = TestEnv::new();
    let mut child = env.command(&[]).spawn().expect("spawn keyoxide");

    wait_for(Duration::from_secs(1), || {
        env.ssh_socket().exists() && env.gpg_socket.exists()
    });
    let check = run_with_timeout(env.command(&["--check"]), Duration::from_millis(500));
    assert!(!check.timed_out);
    assert!(check.output.status.success());

    let signal_result = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    assert_eq!(signal_result, 0);
    wait_for(Duration::from_secs(1), || {
        child.try_wait().expect("poll keyoxide").is_some()
    });
    let output = child.wait_with_output().expect("collect keyoxide output");

    assert!(output.status.success());
    assert!(!env.ssh_socket().exists());
    assert!(!env.gpg_socket.exists());
}

fn wait_for(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("condition was not met before timeout");
}

fn socket_identity(path: &Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(path).expect("socket metadata");
    (metadata.dev(), metadata.ino())
}
