pub mod assuan;
pub mod curve;
pub mod keyfile;
pub mod keygen;
pub mod keygrip;
pub mod keys;
pub mod sexp;
pub mod transfer;

use std::sync::Arc;

use assuan::{Command, Response};
use keys::{GpgKey, GpgKeyType, GpgSignature};
use rand::RngCore;
use secrecy::ExposeSecret;
use sexp::{canonical_len, parse_canonical};
use tokio::io::{
    AsyncBufRead,
    AsyncBufReadExt,
    AsyncReadExt,
    AsyncWrite,
    AsyncWriteExt,
    BufReader,
};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, trace, warn};
use zeroize::Zeroizing;

use crate::agent::AgentState;
use crate::error::{Error, Result};

/// libgpg-error codes, sent with the gpg-agent error source.
mod code {
    pub const BAD_PASSPHRASE: u32 = 11;
    pub const NO_SECKEY: u32 = 17;
    pub const NOT_SUPPORTED: u32 = 60;
    pub const TOO_LARGE: u32 = 67;
    pub const BAD_DATA: u32 = 89;
    pub const CANCELED: u32 = 99;
    pub const INV_LENGTH: u32 = 139;
    pub const MISSING_KEY: u32 = 181;
    pub const FALSE: u32 = 256;
    pub const ASS_UNEXPECTED_CMD: u32 = 274;
    pub const ASS_UNKNOWN_CMD: u32 = 275;
    pub const ASS_PARAMETER: u32 = 280;
    pub const EEXIST: u32 = (1 << 15) | 35;
}

/// An error reply as gpg-agent would send it (`GPG_ERR_SOURCE_GPGAGENT`).
fn gpg_err(code: u32, message: impl Into<String>) -> Response {
    Response::err((4 << 24) | code, message)
}

/// Upper bounds for inquired data, as in gpg-agent (MAXLEN_KEYDATA etc.).
const MAX_CIPHERTEXT: usize = 64 * 1024;
const MAX_KEYDATA: usize = 64 * 1024;
const MAX_PASSPHRASE: usize = 1024;
const MAX_LINE: usize = 64 * 1024;

pub async fn run_gpg_agent(listener: &UnixListener, state: Arc<AgentState>) -> Result<()> {
    info!("GPG agent listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state).await {
                debug!("GPG connection ended: {}", e);
            }
        });
    }
}

#[derive(Default)]
struct SessionState {
    current_keygrip: Option<String>,
    hash_algo: u32,
    hash_data: Vec<u8>,
    /// Key-wrapping keys handed out by `KEYWRAP_KEY --import` / `--export`.
    import_kek: Option<Zeroizing<[u8; 16]>>,
    export_kek: Option<Zeroizing<[u8; 16]>>,
    /// `OPTION pinentry-mode=loopback`: the client answers passphrase
    /// inquiries itself (`gpg --pinentry-mode loopback --passphrase ...`).
    loopback: bool,
}

/// Read one line, as bytes: inquired data may hold any byte value.
async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, line: &mut Vec<u8>) -> Result<bool> {
    line.clear();
    let n = AsyncReadExt::take(&mut *reader, MAX_LINE as u64 + 1)
        .read_until(b'\n', line)
        .await?;
    if n > MAX_LINE {
        return Err(Error::MessageTooLarge(n));
    }
    while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        line.pop();
    }
    Ok(n > 0)
}

/// Run an Assuan INQUIRE and collect the client's `D` lines until `END`.
/// The outer `Err` is an I/O failure; the inner one is the reply to send.
async fn inquire<R, W>(
    reader: &mut R,
    writer: &mut W,
    keyword: &str,
    max: usize,
) -> Result<std::result::Result<Zeroizing<Vec<u8>>, Response>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(format!("INQUIRE {keyword}\n").as_bytes())
        .await?;
    let mut data = Zeroizing::new(Vec::new());
    let mut line = Zeroizing::new(Vec::new());
    loop {
        if !read_line(reader, &mut line).await? {
            return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        match line.as_slice() {
            [b'D', b' ', rest @ ..] => {
                data.extend_from_slice(&assuan::unescape_data(rest));
                if data.len() > max {
                    // Drain the rest of the inquiry before answering.
                    while read_line(reader, &mut line).await?
                        && !matches!(line.as_slice(), b"END" | b"CAN")
                    {}
                    return Ok(Err(gpg_err(code::TOO_LARGE, "inquired data too large")));
                }
            }
            b"D" => {}
            b"END" => return Ok(Ok(data)),
            b"CAN" => return Ok(Err(gpg_err(code::CANCELED, "inquiry canceled"))),
            [b'#', ..] | [] => {}
            _ => {
                return Ok(Err(gpg_err(
                    code::ASS_UNEXPECTED_CMD,
                    "unexpected line during inquiry",
                )));
            }
        }
    }
}

async fn handle_connection(stream: UnixStream, state: Arc<AgentState>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut session = SessionState::default();

    let greeting = "OK Pleased to meet you, keyoxide speaking\n";
    writer.write_all(greeting.as_bytes()).await?;

    let mut raw = Vec::new();
    while read_line(&mut reader, &mut raw).await? {
        let line = String::from_utf8_lossy(&raw);
        // A malformed argument gets an ERR, like gpg-agent; it must not
        // end the session.
        let cmd = match assuan::parse_command(&line) {
            Ok(cmd) => cmd,
            Err(e) => {
                writer
                    .write_all(&gpg_err(code::ASS_PARAMETER, e.to_string()).encode())
                    .await?;
                continue;
            }
        };
        trace!("GPG <- {:?}", cmd);

        let responses = match &cmd {
            Command::PkDecrypt { kem } => {
                pkdecrypt(&mut reader, &mut writer, &state, &session, kem.as_deref()).await?
            }
            Command::Genkey { no_protection } => {
                genkey(&mut reader, &mut writer, &state, *no_protection).await?
            }
            Command::Passwd { verify, keygrip } => {
                passwd(&mut reader, &mut writer, &state, &session, *verify, keygrip).await?
            }
            Command::ImportKey { force, mode1003 } => {
                import_key(
                    &mut reader,
                    &mut writer,
                    &state,
                    &mut session,
                    *force,
                    *mode1003,
                )
                .await?
            }
            _ => handle_command(&cmd, &state, &mut session),
        };

        for response in responses {
            let encoded = response.encode();
            trace!("GPG -> {}", String::from_utf8_lossy(&encoded).trim_end());
            writer.write_all(&encoded).await?;
        }

        if matches!(cmd, Command::Bye) {
            break;
        }
    }

    Ok(())
}

async fn pkdecrypt<R, W>(
    reader: &mut R,
    writer: &mut W,
    state: &AgentState,
    session: &SessionState,
    kem: Option<&str>,
) -> Result<Vec<Response>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if kem.is_some_and(|k| k != "PGP") {
        return Ok(vec![gpg_err(
            code::NOT_SUPPORTED,
            "only --kem=PGP is supported",
        )]);
    }
    let Some(keygrip) = session.current_keygrip.clone() else {
        return Ok(vec![gpg_err(code::NO_SECKEY, "No key set")]);
    };
    let ciphertext = match inquire(reader, writer, "CIPHERTEXT", MAX_CIPHERTEXT).await? {
        Ok(data) => data,
        Err(reply) => return Ok(vec![reply]),
    };
    let gpg_keys = state.gpg_keys.read();
    let Some(key) = gpg_keys.iter().find(|k| k.keygrip == keygrip) else {
        return Ok(vec![gpg_err(code::NO_SECKEY, "No secret key")]);
    };
    let result = if kem.is_some() {
        key.kem_decrypt_pgp(&ciphertext)
    } else {
        key.decrypt(&ciphertext)
    };
    Ok(match result {
        Ok(value) => {
            debug!("decrypted with keygrip {}", keygrip);
            vec![Response::data(value.to_vec()), Response::ok()]
        }
        Err(e) => {
            warn!("decryption with {} failed: {}", keygrip, e);
            vec![gpg_err(code::BAD_DATA, "Decryption failed")]
        }
    })
}

/// Keygrips of the secret keys present: those keyoxide holds plus key files
/// it could not unlock (another passphrase), as gpg-agent reports any key
/// file. gpg asks this before PASSWD, so a foreign key must show up here.
fn known_keygrips(state: &AgentState) -> Vec<String> {
    let mut grips: Vec<String> = state
        .gpg_keys
        .read()
        .iter()
        .map(|k| k.keygrip.clone())
        .collect();
    if let Some(store) = &state.gpg_store {
        if let Ok(entries) = std::fs::read_dir(&store.dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(grip) = name.to_str().and_then(|n| n.strip_suffix(".key")) else {
                    continue;
                };
                let grip = grip.to_uppercase();
                if grip.len() == 40
                    && grip.bytes().all(|b| b.is_ascii_hexdigit())
                    && !grips.contains(&grip)
                {
                    grips.push(grip);
                }
            }
        }
    }
    grips
}

/// The key-store directory and passphrase, or the reply when import,
/// generation and export are disabled (no store configured).
fn store(state: &AgentState) -> std::result::Result<(&crate::agent::GpgStore, &str), Response> {
    state
        .gpg_store
        .as_ref()
        .map(|s| (s, s.passphrase.expose_secret()))
        .ok_or_else(|| gpg_err(code::NOT_SUPPORTED, "no key store configured"))
}

/// GENKEY: generate the key gpg describes, store it under keyoxide's
/// passphrase (gpg-agent would prompt for a new one), serve it at once
/// (gpg signs with it right away), and return the public key.
async fn genkey<R, W>(
    reader: &mut R,
    writer: &mut W,
    state: &AgentState,
    no_protection: bool,
) -> Result<Vec<Response>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (store, passphrase) = match store(state) {
        Ok(s) => s,
        Err(reply) => return Ok(vec![reply]),
    };
    let param = match inquire(reader, writer, "KEYPARAM", 4096).await? {
        Ok(data) => data,
        Err(reply) => return Ok(vec![reply]),
    };
    let parsed =
        parse_canonical(&param).or_else(|_| sexp::parse_gpg_sexp(&String::from_utf8_lossy(&param)));
    let spec = match parsed {
        Ok(spec) => spec,
        Err(e) => return Ok(vec![gpg_err(code::ASS_PARAMETER, e.to_string())]),
    };
    // RSA generation takes seconds; keep it off the async workers.
    let material = match tokio::task::spawn_blocking(move || keygen::generate(&spec)).await {
        Ok(Ok(material)) => material,
        Ok(Err(e)) => return Ok(vec![gpg_err(code::NOT_SUPPORTED, e.to_string())]),
        Err(e) => return Ok(vec![gpg_err(code::NOT_SUPPORTED, e.to_string())]),
    };
    let stored = keygrip::keygrip_hex(&material).and_then(|grip| {
        let key_type = GpgKeyType::from_material(&material)?;
        let file = if no_protection {
            keyfile::unprotected(&material)
        } else {
            keyfile::protect(&material, passphrase, keyfile::DEFAULT_S2K_COUNT)?
        };
        keyfile::write_key_file(&store.dir, &grip, &file, false)?;
        Ok((grip, key_type))
    });
    match stored {
        Ok((keygrip, key_type)) => {
            info!("generated GPG key: {}", keygrip);
            let status = Response::status("KEYGRIP", keygrip.clone());
            state.gpg_keys.write().push(GpgKey { keygrip, key_type });
            Ok(vec![
                status,
                Response::data(keygen::public_key_sexp(&material)),
                Response::ok(),
            ])
        }
        Err(e) => {
            error!("key generation failed: {}", e);
            Ok(vec![gpg_err(code::NOT_SUPPORTED, e.to_string())])
        }
    }
}

/// PASSWD. All keyoxide keys share its one passphrase, so this checks the
/// key is usable (`--verify`) or re-protects its file under that
/// passphrase. A key under another passphrase is brought in when the
/// client supplies the old one (`gpg --pinentry-mode loopback --passphrase OLD
/// --passwd ...`). To change keyoxide's passphrase, run `keyoxide passwd`.
async fn passwd<R, W>(
    reader: &mut R,
    writer: &mut W,
    state: &AgentState,
    session: &SessionState,
    verify: bool,
    keygrip: &str,
) -> Result<Vec<Response>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let loaded = state.gpg_keys.read().iter().any(|k| k.keygrip == keygrip);
    if verify {
        return Ok(vec![if loaded {
            Response::ok()
        } else {
            gpg_err(code::NO_SECKEY, "No secret key")
        }]);
    }
    let (store, passphrase) = match store(state) {
        Ok(s) => s,
        Err(reply) => return Ok(vec![reply]),
    };
    let path = store.dir.join(format!("{keygrip}.key"));
    if !path.exists() {
        return Ok(vec![gpg_err(code::NO_SECKEY, "No secret key")]);
    }
    let mut material = keyfile::read_key_file(&path, passphrase);
    if matches!(material, Err(Error::KeyDecryptionFailed)) && session.loopback {
        match inquire(reader, writer, "PASSPHRASE", MAX_PASSPHRASE).await? {
            Ok(old) => material = keyfile::read_key_file(&path, &String::from_utf8_lossy(&old)),
            Err(reply) => return Ok(vec![reply]),
        }
    }
    let stored = material.and_then(|material| {
        let key_type = GpgKeyType::from_material(&material)?;
        let file = keyfile::protect(&material, passphrase, keyfile::DEFAULT_S2K_COUNT)?;
        keyfile::write_key_file(&store.dir, keygrip, &file, true)?;
        Ok(key_type)
    });
    Ok(match stored {
        Ok(key_type) => {
            info!(
                "re-protected GPG key {} with keyoxide's passphrase",
                keygrip
            );
            let mut keys = state.gpg_keys.write();
            keys.retain(|k| k.keygrip != keygrip);
            keys.push(GpgKey {
                keygrip: keygrip.to_string(),
                key_type,
            });
            vec![Response::ok()]
        }
        Err(Error::KeyDecryptionFailed) => vec![gpg_err(
            code::BAD_PASSPHRASE,
            "key is under another passphrase; pass it with --pinentry-mode loopback",
        )],
        Err(e) => vec![gpg_err(code::NOT_SUPPORTED, e.to_string())],
    })
}

/// EXPORT_KEY --openpgp: the key as an OpenPGP transfer key protected with
/// keyoxide's passphrase (as gpg-agent protects it with the key's own),
/// wrapped with the session's export key.
fn export_key(
    state: &AgentState,
    session: &SessionState,
    openpgp: bool,
    mode1003: bool,
    keygrip: &str,
) -> Vec<Response> {
    if mode1003 || !openpgp {
        return vec![gpg_err(
            code::NOT_SUPPORTED,
            "only EXPORT_KEY --openpgp is supported",
        )];
    }
    let (store, passphrase) = match store(state) {
        Ok(s) => s,
        Err(reply) => return vec![reply],
    };
    let Some(kek) = &session.export_kek else {
        return vec![gpg_err(code::MISSING_KEY, "KEYWRAP_KEY --export first")];
    };
    let path = store.dir.join(format!("{keygrip}.key"));
    let wrapped = keyfile::read_key_file(&path, passphrase)
        .and_then(|material| transfer::to_openpgp(&material, passphrase))
        .and_then(|plain| {
            aes_kw::KekAes128::from(**kek)
                .wrap_vec(&plain)
                .map_err(|_| Error::InvalidMessageFormat)
        });
    match wrapped {
        Ok(data) => {
            info!("exported GPG key {}", keygrip);
            vec![Response::data(data), Response::ok()]
        }
        Err(Error::Io(_)) => vec![gpg_err(code::NO_SECKEY, "No secret key")],
        Err(e) => vec![gpg_err(code::NOT_SUPPORTED, e.to_string())],
    }
}

/// IMPORT_KEY: unwrap the key gpg sends, convert it from OpenPGP transfer
/// form if needed, protect it with keyoxide's passphrase, write it to the
/// key store, and serve it at once.
async fn import_key<R, W>(
    reader: &mut R,
    writer: &mut W,
    state: &AgentState,
    session: &mut SessionState,
    force: bool,
    mode1003: bool,
) -> Result<Vec<Response>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Some(store) = &state.gpg_store else {
        return Ok(vec![gpg_err(code::NOT_SUPPORTED, "key import is disabled")]);
    };
    if mode1003 {
        return Ok(vec![gpg_err(
            code::NOT_SUPPORTED,
            "--mode1003 is not supported",
        )]);
    }
    let Some(kek) = session.import_kek.clone() else {
        return Ok(vec![gpg_err(
            code::MISSING_KEY,
            "KEYWRAP_KEY --import first",
        )]);
    };
    let wrapped = match inquire(reader, writer, "KEYDATA", MAX_KEYDATA).await? {
        Ok(data) => data,
        Err(reply) => return Ok(vec![reply]),
    };
    if wrapped.len() < 24 {
        return Ok(vec![gpg_err(code::INV_LENGTH, "wrapped key too short")]);
    }
    let Ok(key) = aes_kw::KekAes128::from(*kek).unwrap_vec(&wrapped) else {
        return Ok(vec![gpg_err(code::BAD_DATA, "key unwrap failed")]);
    };
    let key = Zeroizing::new(key);
    let root = match canonical_len(&key).and_then(|len| parse_canonical(&key[..len])) {
        Ok(root) => root,
        Err(e) => return Ok(vec![gpg_err(code::BAD_DATA, e.to_string())]),
    };

    let passphrase = store.passphrase.expose_secret();
    let material = match root.name() {
        Some(b"openpgp-private-key") => {
            match transfer::convert(&root, passphrase) {
                Err(Error::BadPassphrase) if session.loopback => {
                    // The key has its own passphrase: ask the client for it.
                    match inquire(reader, writer, "PASSPHRASE", MAX_PASSPHRASE).await? {
                        Ok(pass) => transfer::convert(&root, &String::from_utf8_lossy(&pass)),
                        Err(reply) => return Ok(vec![reply]),
                    }
                }
                other => other,
            }
        }
        Some(b"private-key") => root
            .as_list()
            .and_then(|items| items.get(1)?.as_list())
            .ok_or_else(|| Error::SexpParse("expected (private-key (ALGO ...))".into()))
            .and_then(|key| keyfile::material_from_list(key, Vec::new())),
        _ => Err(Error::UnsupportedKeyType("unknown key data".into())),
    };
    let material = match material {
        Ok(m) => m,
        Err(Error::BadPassphrase) => {
            return Ok(vec![gpg_err(code::BAD_PASSPHRASE, "Bad passphrase")]);
        }
        Err(e) => return Ok(vec![gpg_err(code::NOT_SUPPORTED, e.to_string())]),
    };

    let stored = keygrip::keygrip_hex(&material).and_then(|grip| {
        let key_type = GpgKeyType::from_material(&material)?;
        let protected = keyfile::protect(&material, passphrase, keyfile::DEFAULT_S2K_COUNT)?;
        keyfile::write_key_file(&store.dir, &grip, &protected, force)?;
        Ok((grip, key_type))
    });
    match stored {
        Ok((keygrip, key_type)) => {
            info!("imported GPG key: {}", keygrip);
            let mut keys = state.gpg_keys.write();
            keys.retain(|k| k.keygrip != keygrip);
            keys.push(GpgKey { keygrip, key_type });
            Ok(vec![Response::ok()])
        }
        Err(Error::KeyExists(grip)) => {
            Ok(vec![gpg_err(code::EEXIST, format!("key {grip} exists"))])
        }
        Err(e) => {
            error!("key import failed: {}", e);
            Ok(vec![gpg_err(code::NOT_SUPPORTED, e.to_string())])
        }
    }
}

fn handle_command(cmd: &Command, state: &AgentState, session: &mut SessionState) -> Vec<Response> {
    match cmd {
        Command::Reset => {
            session.current_keygrip = None;
            session.hash_algo = 0;
            session.hash_data.clear();
            vec![Response::ok()]
        }

        Command::Option { name, value } => {
            if name == "pinentry-mode" {
                session.loopback = value == "loopback";
            }
            vec![Response::ok()]
        }

        Command::HaveKey { keygrips, list } => {
            let known = known_keygrips(state);
            if let Some(limit) = list {
                let limit = usize::try_from(*limit).unwrap_or(usize::MAX);
                let binary_grips: Vec<u8> = known
                    .iter()
                    .take(limit)
                    .filter_map(|grip| hex::decode(grip).ok())
                    .flatten()
                    .collect();
                vec![Response::data(binary_grips), Response::ok()]
            } else if keygrips.iter().any(|kg| known.contains(kg)) {
                vec![Response::ok()]
            } else {
                vec![gpg_err(code::NO_SECKEY, "No secret key")]
            }
        }

        Command::KeyInfo {
            list,
            ssh_list: _,
            keygrip,
        } => {
            let known = known_keygrips(state);
            let line = |grip: &str| Response::status("KEYINFO", format!("{grip} D - - - P - - -"));
            if *list {
                let mut responses: Vec<Response> = known.iter().map(|g| line(g)).collect();
                responses.push(Response::ok());
                responses
            } else if let Some(kg) = keygrip {
                let kg = kg.to_uppercase();
                if known.contains(&kg) {
                    vec![line(&kg), Response::ok()]
                } else {
                    vec![gpg_err(code::NO_SECKEY, "No secret key")]
                }
            } else {
                vec![gpg_err(code::ASS_PARAMETER, "Missing keygrip")]
            }
        }

        Command::SigKey { keygrip } => {
            let gpg_keys = state.gpg_keys.read();
            let found = gpg_keys.iter().any(|k| k.keygrip == keygrip.to_uppercase());
            if found {
                session.current_keygrip = Some(keygrip.to_uppercase());
                vec![Response::ok()]
            } else {
                vec![gpg_err(code::NO_SECKEY, "No secret key")]
            }
        }

        Command::SetKeyDesc { .. } => {
            vec![Response::ok()]
        }

        Command::SetHash { algo, hash } => {
            session.hash_algo = *algo;
            session.hash_data = hash.clone();
            vec![Response::ok()]
        }

        Command::PkSign => {
            let keygrip = match &session.current_keygrip {
                Some(k) => k.clone(),
                None => return vec![gpg_err(code::NO_SECKEY, "No key set")],
            };

            if session.hash_data.is_empty() {
                return vec![gpg_err(code::NO_SECKEY, "No hash set")];
            }

            let gpg_keys = state.gpg_keys.read();
            let key = match gpg_keys.iter().find(|k| k.keygrip == keygrip) {
                Some(k) => k,
                None => return vec![gpg_err(code::NO_SECKEY, "Key not found")],
            };

            match key.sign(&session.hash_data, session.hash_algo) {
                Ok(signature) => {
                    let sexp = format_signature_sexp(&signature);
                    debug!("signed with keygrip {}", keygrip);
                    vec![Response::data(sexp), Response::ok()]
                }
                Err(e) => {
                    error!("signing failed: {}", e);
                    vec![gpg_err(code::NO_SECKEY, "Signing failed")]
                }
            }
        }

        Command::PresetPassphrase { .. } => {
            vec![Response::ok()]
        }

        Command::KeywrapKey {
            import,
            export,
            clear,
        } => {
            let slot = match (*import, *export) {
                (true, false) => &mut session.import_kek,
                (false, true) => &mut session.export_kek,
                _ => return vec![gpg_err(code::ASS_PARAMETER, "unknown value for MODE")],
            };
            if *clear {
                *slot = None;
                vec![Response::ok()]
            } else {
                let mut kek = Zeroizing::new([0u8; 16]);
                rand::rngs::OsRng.fill_bytes(&mut *kek);
                let reply = vec![Response::data(kek.to_vec()), Response::ok()];
                *slot = Some(kek);
                reply
            }
        }

        Command::ExportKey {
            openpgp,
            mode1003,
            keygrip,
        } => export_key(state, session, *openpgp, *mode1003, keygrip),

        Command::GetInfo { what } => getinfo(what),

        Command::Bye => {
            vec![Response::ok_with("closing connection")]
        }

        // Handled with an inquiry in handle_connection.
        Command::PkDecrypt { .. }
        | Command::ImportKey { .. }
        | Command::Genkey { .. }
        | Command::Passwd { .. } => {
            vec![gpg_err(code::ASS_UNEXPECTED_CMD, "internal dispatch error")]
        }

        Command::Unknown(line) => {
            if line.is_empty() {
                vec![]
            } else {
                debug!("unknown GPG command: {}", line);
                vec![gpg_err(code::ASS_UNKNOWN_CMD, "Unknown command")]
            }
        }
    }
}

/// GETINFO, answering only what keyoxide really supports. Claiming an
/// option it lacks (e.g. `IMPORT_KEY --mode1003`) would make gpg use it.
fn getinfo(what: &str) -> Vec<Response> {
    let mut words = what.split_whitespace();
    match words.next().unwrap_or_default() {
        "version" => vec![
            Response::data(gpg_compat_version().as_bytes().to_vec()),
            Response::ok(),
        ],
        "pid" => vec![
            Response::data(std::process::id().to_string().into_bytes()),
            Response::ok(),
        ],
        "cmd_has_option" => {
            let supported = matches!(
                (words.next(), words.next()),
                (
                    Some("IMPORT_KEY"),
                    Some("force" | "timestamp" | "unattended")
                ) | (Some("HAVEKEY"), Some("list"))
                    | (Some("KEYINFO"), Some("list"))
                    | (Some("EXPORT_KEY"), Some("openpgp"))
                    | (Some("GENKEY"), Some("no-protection" | "timestamp"))
            );
            if supported {
                vec![Response::ok()]
            } else {
                vec![gpg_err(code::FALSE, "option not supported")]
            }
        }
        // keyoxide is never restricted (gpg-agent --extra-socket).
        "restricted" => vec![gpg_err(code::FALSE, "not restricted")],
        _ => vec![gpg_err(code::ASS_PARAMETER, "unknown value for WHAT")],
    }
}

fn gpg_compat_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        std::process::Command::new("gpg-agent")
            .arg("--version")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| {
                let first_line = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()?
                    .to_owned();
                first_line.split_whitespace().last().map(str::to_owned)
            })
            .unwrap_or_else(|| "2.4.0".to_owned())
    })
}

/// Build the `sig-val` S-expression gpg expects, tagged with the algorithm
/// matching the key type. RSA carries a single `s` MPI; ECDSA/EdDSA carry
/// `r` and `s`. Previously this hardcoded `rsa`, producing invalid sig-vals
/// for every ECC key.
fn format_signature_sexp(signature: &GpgSignature) -> Vec<u8> {
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(b"(7:sig-val(");
    match signature {
        GpgSignature::Rsa(s) => {
            sexp::push_atom(&mut result, b"rsa");
            sexp::push_param(&mut result, b"s", s);
        }
        GpgSignature::Ecdsa { r, s } => {
            sexp::push_atom(&mut result, b"ecdsa");
            sexp::push_param(&mut result, b"r", r);
            sexp::push_param(&mut result, b"s", s);
        }
        GpgSignature::EdDsa { r, s } => {
            sexp::push_atom(&mut result, b"eddsa");
            sexp::push_param(&mut result, b"r", r);
            sexp::push_param(&mut result, b"s", s);
        }
    }
    result.extend_from_slice(b"))");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_sig_val_shape_unchanged() {
        let sexp = format_signature_sexp(&GpgSignature::Rsa(vec![0xAB, 0xCD]));
        assert_eq!(sexp, b"(7:sig-val(3:rsa(1:s2:\xab\xcd)))");
    }

    #[test]
    fn ecdsa_sig_val_uses_ecdsa_tag_with_r_and_s() {
        let sexp = format_signature_sexp(&GpgSignature::Ecdsa {
            r: vec![0x01, 0x02],
            s: vec![0x03],
        });
        assert_eq!(sexp, b"(7:sig-val(5:ecdsa(1:r2:\x01\x02)(1:s1:\x03)))");
    }

    #[test]
    fn eddsa_sig_val_uses_eddsa_tag() {
        let sexp = format_signature_sexp(&GpgSignature::EdDsa {
            r: vec![0x09],
            s: vec![0x08],
        });
        assert_eq!(sexp, b"(7:sig-val(5:eddsa(1:r1:\x09)(1:s1:\x08)))");
    }

    // Extract an MPI value following `(<n>:<name>` in a canonical sexp.
    fn extract_param(sexp: &[u8], name: &[u8]) -> Vec<u8> {
        let mut needle = Vec::new();
        needle.push(b'(');
        needle.extend_from_slice(name.len().to_string().as_bytes());
        needle.push(b':');
        needle.extend_from_slice(name);
        let pos = sexp
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("param present");
        let mut i = pos + needle.len();
        let mut len = 0usize;
        while sexp[i].is_ascii_digit() {
            len = len * 10 + (sexp[i] - b'0') as usize;
            i += 1;
        }
        assert_eq!(sexp[i], b':');
        i += 1;
        sexp[i..i + len].to_vec()
    }

    #[test]
    fn ecdsa_p256_roundtrip_verifies() {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

        let signing_key = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);

        let key = GpgKey {
            keygrip: "A".repeat(40),
            key_type: GpgKeyType::EcdsaP256(signing_key),
        };

        // gpg delivers a pre-computed 32-byte digest via SETHASH (algo 8 = SHA-256).
        let digest = [0x42u8; 32];
        let sig = key.sign(&digest, 8).unwrap();
        let sexp = format_signature_sexp(&sig);

        // The sexp must be ecdsa-tagged, not rsa.
        assert!(
            sexp.windows(5).any(|w| w == b"ecdsa"),
            "expected ecdsa tag, got {:?}",
            String::from_utf8_lossy(&sexp)
        );

        let r = extract_param(&sexp, b"r");
        let s = extract_param(&sexp, b"s");
        let mut raw = r;
        raw.extend_from_slice(&s);
        let rebuilt = Signature::from_slice(&raw).unwrap();

        // Verify against the prehash — proves we signed the digest directly
        // (no double hashing) and the r/s encoding is correct.
        assert!(verifying_key.verify_prehash(&digest, &rebuilt).is_ok());
    }
}
