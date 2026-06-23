use std::sync::Arc;

use keyoxide::agent::AgentState;
use keyoxide::config::Config;
use keyoxide::error::Result;
use keyoxide::gpg::keys::load_gpg_keys;
use keyoxide::ssh::keys::load_ssh_keys;
use tokio::net::UnixListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("keyoxide=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            error!("configuration error: {}", e);
            std::process::exit(1);
        }
    };

    cleanup_socket(&config.ssh_socket_path);
    cleanup_socket(&config.gpg_socket_path);

    let state = Arc::new(AgentState::new());

    let ssh_keys = load_ssh_keys(&config.ssh_key_dir, config.passphrase());
    info!("loaded {} SSH keys", ssh_keys.len());
    state.set_ssh_keys(ssh_keys);

    let gpg_keys = load_gpg_keys(&config.gpg_key_dir, config.passphrase());
    info!("loaded {} GPG keys", gpg_keys.len());
    state.set_gpg_keys(gpg_keys);

    let ssh_listener = UnixListener::bind(&config.ssh_socket_path)?;
    info!("SSH agent socket: {:?}", config.ssh_socket_path);

    let gpg_listener = UnixListener::bind(&config.gpg_socket_path)?;
    info!("GPG agent socket: {:?}", config.gpg_socket_path);

    print_env_vars(&config);

    let ssh_state = Arc::clone(&state);
    let ssh_handle = tokio::spawn(async move {
        if let Err(e) = keyoxide::ssh::run_ssh_agent(ssh_listener, ssh_state).await {
            error!("SSH agent error: {}", e);
        }
    });

    let gpg_state = Arc::clone(&state);
    let gpg_handle = tokio::spawn(async move {
        if let Err(e) = keyoxide::gpg::run_gpg_agent(gpg_listener, gpg_state).await {
            error!("GPG agent error: {}", e);
        }
    });

    tokio::select! {
        _ = ssh_handle => {}
        _ = gpg_handle => {}
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
        }
    }

    cleanup_socket(&config.ssh_socket_path);
    cleanup_socket(&config.gpg_socket_path);

    Ok(())
}

fn cleanup_socket(path: &std::path::Path) {
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
}

fn print_env_vars(config: &Config) {
    println!("export SSH_AUTH_SOCK={}", config.ssh_socket_path.display());
    println!(
        "export GPG_AGENT_INFO={}:0:1",
        config.gpg_socket_path.display()
    );
}
