use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::net::UnixListener;

use crate::error::{Error, Result};

static QUARANTINE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketId {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Missing,
    Live,
    Stale,
}

enum InspectedSocket {
    Missing,
    Live,
    Stale(SocketId),
}

pub struct OwnedSocket {
    listener: Option<UnixListener>,
    path: PathBuf,
    id: SocketId,
}

impl OwnedSocket {
    pub fn bind(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        prepare_socket_path(&path)?;

        let listener = UnixListener::bind(&path)?;
        let id = socket_id(&path)?;
        let owned = Self {
            listener: Some(listener),
            path,
            id,
        };
        fs::set_permissions(&owned.path, fs::Permissions::from_mode(0o600))?;
        Ok(owned)
    }

    pub fn listener(&self) -> &UnixListener {
        self.listener.as_ref().expect("owned socket listener")
    }
}

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if socket_id(&self.path).ok() == Some(self.id) {
            let _ = fs::remove_file(&self.path);
        }
        self.listener.take();
    }
}

pub struct AgentSockets {
    pub ssh: OwnedSocket,
    pub gpg: OwnedSocket,
}

impl AgentSockets {
    pub fn bind(ssh_path: &Path, gpg_path: &Path) -> Result<Self> {
        let ssh = OwnedSocket::bind(ssh_path)?;
        let gpg = OwnedSocket::bind(gpg_path)?;
        Ok(Self { ssh, gpg })
    }
}

pub fn probe_socket(path: &Path) -> Result<SocketState> {
    Ok(match inspect_socket(path)? {
        InspectedSocket::Missing => SocketState::Missing,
        InspectedSocket::Live => SocketState::Live,
        InspectedSocket::Stale(_) => SocketState::Stale,
    })
}

fn inspect_socket(path: &Path) -> Result<InspectedSocket> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(InspectedSocket::Missing),
        Err(error) => return Err(error.into()),
    };

    if !metadata.file_type().is_socket() {
        return Err(Error::SocketNotSocket(path.to_path_buf()));
    }

    let id = SocketId {
        device: metadata.dev(),
        inode: metadata.ino(),
    };

    match UnixStream::connect(path) {
        Ok(_) => Ok(InspectedSocket::Live),
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
            if socket_id(path)? == id {
                Ok(InspectedSocket::Stale(id))
            } else {
                Err(Error::SocketChanged(path.to_path_buf()))
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(InspectedSocket::Missing),
        Err(error) => Err(Error::SocketProbe {
            path: path.to_path_buf(),
            source: error,
        }),
    }
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    match inspect_socket(path)? {
        InspectedSocket::Missing => Ok(()),
        InspectedSocket::Live => Err(Error::SocketInUse(path.to_path_buf())),
        InspectedSocket::Stale(id) => remove_stale_socket(path, id),
    }
}

fn remove_stale_socket(path: &Path, expected: SocketId) -> Result<()> {
    let quarantine = quarantine_path(path)?;
    fs::rename(path, &quarantine)?;

    if socket_id(&quarantine)? != expected {
        if !path.exists() {
            let _ = fs::rename(&quarantine, path);
        }
        return Err(Error::SocketChanged(path.to_path_buf()));
    }

    fs::remove_file(quarantine)?;
    Ok(())
}

fn quarantine_path(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::SocketPath(format!("socket has no parent: {}", path.display())))?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::SocketPath(format!("socket has no name: {}", path.display())))?;

    for _ in 0..32 {
        let count = QUARANTINE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut candidate = OsString::from(".");
        candidate.push(name);
        candidate.push(format!(".keyoxide-stale-{}-{count}", std::process::id()));
        let candidate = parent.join(candidate);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(Error::SocketPath(format!(
        "could not allocate quarantine path for {}",
        path.display()
    )))
}

fn socket_id(path: &Path) -> Result<SocketId> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() {
        return Err(Error::SocketNotSocket(path.to_path_buf()));
    }
    Ok(SocketId {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener as StdUnixListener;

    use super::*;

    #[tokio::test]
    async fn stale_socket_is_reclaimed_and_removed_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("agent.sock");
        drop(StdUnixListener::bind(&path).unwrap());
        let stale_id = socket_id(&path).unwrap();

        let owned = OwnedSocket::bind(&path).unwrap();
        assert_ne!(owned.id, stale_id);
        assert!(UnixStream::connect(&path).is_ok());

        drop(owned);
        assert!(!path.exists());
    }

    #[test]
    fn live_socket_is_never_unlinked() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("agent.sock");
        let incumbent = StdUnixListener::bind(&path).unwrap();
        let incumbent_id = socket_id(&path).unwrap();

        assert!(matches!(
            OwnedSocket::bind(&path),
            Err(Error::SocketInUse(ref in_use)) if in_use == &path
        ));
        assert_eq!(socket_id(&path).unwrap(), incumbent_id);
        assert!(UnixStream::connect(&path).is_ok());
        drop(incumbent);
    }

    #[test]
    fn regular_file_at_socket_path_is_never_deleted() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("agent.sock");
        fs::write(&path, b"do not delete").unwrap();

        assert!(matches!(
            OwnedSocket::bind(&path),
            Err(Error::SocketNotSocket(ref not_socket)) if not_socket == &path
        ));
        assert_eq!(fs::read(&path).unwrap(), b"do not delete");
    }

    #[tokio::test]
    async fn drop_does_not_unlink_a_replacement_socket() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("agent.sock");
        let owned = OwnedSocket::bind(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let replacement = StdUnixListener::bind(&path).unwrap();
        let replacement_id = socket_id(&path).unwrap();

        drop(owned);

        assert_eq!(socket_id(&path).unwrap(), replacement_id);
        drop(replacement);
    }
}
