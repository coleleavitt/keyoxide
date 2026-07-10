#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use tracing::debug;

use crate::error::{Error, Result};

pub struct Config {
    pub passphrase: SecretString,
    pub ssh_socket_path: PathBuf,
    pub gpg_socket_path: PathBuf,
    pub ssh_key_dir: PathBuf,
    pub gpg_key_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SocketPaths {
    pub ssh_socket_path: PathBuf,
    pub gpg_socket_path: PathBuf,
}

impl Config {
    pub fn load() -> Result<Self> {
        let socket_paths = Self::socket_paths()?;
        Self::load_with_socket_paths(socket_paths)
    }

    pub fn load_with_socket_paths(socket_paths: SocketPaths) -> Result<Self> {
        let passphrase = Self::load_passphrase()?;
        let keyoxide_dir = socket_paths
            .ssh_socket_path
            .parent()
            .ok_or_else(|| Error::Config("SSH socket has no parent directory".into()))?;
        Self::prepare_runtime_dir(keyoxide_dir)?;

        let home = dirs::home_dir().ok_or_else(|| Error::Config("no home directory".into()))?;

        Ok(Self {
            passphrase,
            ssh_socket_path: socket_paths.ssh_socket_path,
            gpg_socket_path: socket_paths.gpg_socket_path,
            ssh_key_dir: home.join(".ssh"),
            gpg_key_dir: home.join(".gnupg").join("private-keys-v1.d"),
        })
    }

    pub fn socket_paths() -> Result<SocketPaths> {
        let runtime_dir = Self::runtime_dir()?;
        let keyoxide_dir = runtime_dir.join("keyoxide");
        let home = dirs::home_dir().ok_or_else(|| Error::Config("no home directory".into()))?;

        // Bind to the socket path that gpg actually connects to.
        // Modern gpg (2.1+) ignores GPG_AGENT_INFO and always connects
        // to the socket reported by `gpgconf --list-dirs agent-socket`,
        // which is typically ~/.gnupg/S.gpg-agent.
        let gpg_socket_path = Self::gpg_agent_socket_path(&home);

        Ok(SocketPaths {
            ssh_socket_path: keyoxide_dir.join("ssh.sock"),
            gpg_socket_path,
        })
    }

    /// Determine where gpg expects to find the agent socket.
    ///
    /// Queries `gpgconf --list-dirs agent-socket` first; falls back to
    /// `~/.gnupg/S.gpg-agent` if gpgconf isn't available.
    fn gpg_agent_socket_path(home: &std::path::Path) -> PathBuf {
        std::process::Command::new("gpgconf")
            .args(["--list-dirs", "agent-socket"])
            .output()
            .ok()
            .and_then(|out| {
                if out.status.success() {
                    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !path.is_empty() {
                        return Some(PathBuf::from(path));
                    }
                }
                None
            })
            .unwrap_or_else(|| home.join(".gnupg").join("S.gpg-agent"))
    }

    fn load_passphrase() -> Result<SecretString> {
        if let Ok(pass) = std::env::var("KEYOXIDE_PASSPHRASE") {
            debug!("loaded passphrase from KEYOXIDE_PASSPHRASE env var");
            return Ok(SecretString::from(pass));
        }

        let config_dir = dirs::config_dir()
            .ok_or_else(|| Error::Config("no config directory".into()))?
            .join("keyoxide");

        let passphrase_file = config_dir.join("passphrase");
        if passphrase_file.exists() {
            Self::validate_passphrase_file(&passphrase_file)?;
            let content = std::fs::read_to_string(&passphrase_file)?;
            let pass = content.trim().to_string();
            debug!("loaded passphrase from {:?}", passphrase_file);
            return Ok(SecretString::from(pass));
        }

        Err(Error::NoPassphrase)
    }

    #[cfg(unix)]
    fn validate_passphrase_file(path: &std::path::Path) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() {
            return Err(Error::Config(format!(
                "passphrase path is not a regular file: {}",
                path.display()
            )));
        }
        if metadata.uid() != unsafe { libc::getuid() } {
            return Err(Error::Config(format!(
                "passphrase file is not owned by the current user: {}",
                path.display()
            )));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Config(format!(
                "passphrase file must not be accessible by group or others: {}",
                path.display()
            )));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn validate_passphrase_file(_path: &std::path::Path) -> Result<()> {
        Ok(())
    }

    #[cfg(unix)]
    fn prepare_runtime_dir(path: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_dir() {
            return Err(Error::Config(format!(
                "runtime path is not a directory: {}",
                path.display()
            )));
        }
        if metadata.uid() != unsafe { libc::getuid() } {
            return Err(Error::Config(format!(
                "runtime directory is not owned by the current user: {}",
                path.display()
            )));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn prepare_runtime_dir(path: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(path)?;
        Ok(())
    }

    fn runtime_dir() -> Result<PathBuf> {
        if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
            return Ok(PathBuf::from(dir));
        }

        let uid = unsafe { libc::getuid() };
        let fallback = PathBuf::from(format!("/run/user/{}", uid));
        if fallback.exists() {
            return Ok(fallback);
        }

        let tmp_fallback = std::env::temp_dir().join(format!("keyoxide-{}", uid));
        std::fs::create_dir_all(&tmp_fallback)?;
        Ok(tmp_fallback)
    }

    pub fn passphrase(&self) -> &str {
        self.passphrase.expose_secret()
    }
}
