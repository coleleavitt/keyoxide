use std::sync::Arc;
use std::time::{Duration, Instant};

use keyoxide::agent::AgentState;
use keyoxide::cli::{Command, HELP, parse_args};
use keyoxide::config::{Config, SocketPaths};
use keyoxide::error::{Error, Result};
use keyoxide::gpg::keys::load_gpg_keys;
use keyoxide::health::{check_agent, gpg_is_keyoxide};
use keyoxide::socket::{AgentSockets, SocketState, probe_socket};
use keyoxide::ssh::keys::load_ssh_keys;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let command = match parse_args(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("keyoxide: {error}\n\n{HELP}");
            std::process::exit(2);
        }
    };

    match command {
        Command::Help => {
            print!("{HELP}");
            return;
        }
        Command::Version => {
            println!("keyoxide {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Command::Check | Command::Run { .. } => {}
    }

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("keyoxide=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Err(error) = execute(command).await {
        eprintln!("keyoxide: {error}");
        std::process::exit(1);
    }
}

async fn execute(command: Command) -> Result<()> {
    let paths = Config::socket_paths()?;
    match command {
        Command::Check => {
            check_agent(&paths)?;
            println!("keyoxide is healthy");
            Ok(())
        }
        Command::Run { replace } => run_agent(paths, replace).await,
        Command::Help | Command::Version => unreachable!("handled before runtime setup"),
    }
}

async fn run_agent(paths: SocketPaths, replace: bool) -> Result<()> {
    if check_agent(&paths).is_ok() {
        return Err(Error::SocketInUse(paths.gpg_socket_path.clone()));
    }

    let config = Config::load_with_socket_paths(paths.clone())?;
    let state = Arc::new(AgentState::new());

    let ssh_keys = load_ssh_keys(&config.ssh_key_dir, config.passphrase());
    info!("loaded {} SSH keys", ssh_keys.len());
    state.set_ssh_keys(ssh_keys);

    let gpg_keys = load_gpg_keys(&config.gpg_key_dir, config.passphrase());
    info!("loaded {} GPG keys", gpg_keys.len());
    state.set_gpg_keys(gpg_keys);

    if matches!(probe_socket(&paths.ssh_socket_path)?, SocketState::Live) {
        return Err(Error::SocketInUse(paths.ssh_socket_path.clone()));
    }

    if replace {
        stop_native_gpg_agent(&paths)?;
    }

    let sockets = AgentSockets::bind(&paths.ssh_socket_path, &paths.gpg_socket_path)?;
    info!("SSH agent socket: {:?}", paths.ssh_socket_path);
    info!("GPG agent socket: {:?}", paths.gpg_socket_path);
    print_env_vars(&paths);

    let ssh_state = Arc::clone(&state);
    let gpg_state = Arc::clone(&state);
    let result = tokio::select! {
        result = keyoxide::ssh::run_ssh_agent(sockets.ssh.listener(), ssh_state) => result,
        result = keyoxide::gpg::run_gpg_agent(sockets.gpg.listener(), gpg_state) => result,
        signal = shutdown_signal() => {
            signal?;
            info!("shutting down");
            Ok(())
        }
    };

    drop(sockets);
    result
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

fn stop_native_gpg_agent(paths: &SocketPaths) -> Result<()> {
    match probe_socket(&paths.gpg_socket_path)? {
        SocketState::Missing | SocketState::Stale => return Ok(()),
        SocketState::Live => {}
    }

    if gpg_is_keyoxide(&paths.gpg_socket_path)? {
        return Err(Error::SocketInUse(paths.gpg_socket_path.clone()));
    }

    info!("stopping native gpg-agent before taking over its socket");
    let status = std::process::Command::new("gpgconf")
        .args(["--kill", "gpg-agent"])
        .status()?;
    if !status.success() {
        return Err(Error::CommandFailed(format!(
            "gpgconf --kill gpg-agent exited with {status}"
        )));
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match probe_socket(&paths.gpg_socket_path)? {
            SocketState::Missing | SocketState::Stale => return Ok(()),
            SocketState::Live => std::thread::sleep(Duration::from_millis(25)),
        }
    }

    warn!("native gpg-agent socket remained live after gpgconf --kill");
    Err(Error::SocketInUse(paths.gpg_socket_path.clone()))
}

fn print_env_vars(paths: &SocketPaths) {
    println!("export SSH_AUTH_SOCK={}", paths.ssh_socket_path.display());
    println!(
        "# GPG uses its canonical socket at {}",
        paths.gpg_socket_path.display()
    );
}
