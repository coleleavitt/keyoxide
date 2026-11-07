use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SSH key error: {0}")]
    SshKey(#[from] ssh_key::Error),

    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("ECDSA error")]
    Ecdsa,

    #[error("Ed25519 signature error: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),

    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("S-expression parse error: {0}")]
    SexpParse(String),

    #[error("no passphrase configured")]
    NoPassphrase,

    #[error("key decryption failed")]
    KeyDecryptionFailed,

    #[error("bad passphrase")]
    BadPassphrase,

    #[error("key already exists: {0}")]
    KeyExists(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("signing operation failed")]
    SigningFailed,

    #[error("invalid message format")]
    InvalidMessageFormat,

    #[error("invalid protocol command: {0}")]
    InvalidCommand(String),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("buffer too short")]
    BufferTooShort,

    #[error("message too large: {0} bytes")]
    MessageTooLarge(usize),

    #[error("socket path error: {0}")]
    SocketPath(String),

    #[error("socket is already in use: {0}")]
    SocketInUse(PathBuf),

    #[error("refusing to replace non-socket path: {0}")]
    SocketNotSocket(PathBuf),

    #[error("socket changed while it was being inspected: {0}")]
    SocketChanged(PathBuf),

    #[error("failed to probe socket {path}: {source}")]
    SocketProbe {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("agent health check failed: {0}")]
    AgentUnhealthy(String),

    #[error("command failed: {0}")]
    CommandFailed(String),

    #[error("configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;
