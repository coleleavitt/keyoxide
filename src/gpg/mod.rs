pub mod assuan;
pub mod keys;
pub mod sexp;

use std::sync::Arc;

use assuan::{Command, Response};
use keys::GpgSignature;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, trace};

use crate::agent::AgentState;
use crate::error::Result;

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
}

async fn handle_connection(stream: UnixStream, state: Arc<AgentState>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut session = SessionState::default();

    let greeting = "OK Pleased to meet you, keyoxide speaking\n";
    writer.write_all(greeting.as_bytes()).await?;

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let cmd = assuan::parse_command(&line)?;
        trace!("GPG <- {:?}", cmd);
        let responses = handle_command(&cmd, &state, &mut session);

        for response in &responses {
            let encoded = response.encode();
            trace!("GPG -> {}", String::from_utf8_lossy(&encoded).trim_end());
        }
        for response in responses {
            let encoded = response.encode();
            writer.write_all(&encoded).await?;
        }

        if matches!(cmd, Command::Bye) {
            break;
        }
    }

    Ok(())
}

fn handle_command(cmd: &Command, state: &AgentState, session: &mut SessionState) -> Vec<Response> {
    match cmd {
        Command::Reset => {
            session.current_keygrip = None;
            session.hash_algo = 0;
            session.hash_data.clear();
            vec![Response::ok()]
        }

        Command::Option { .. } => {
            vec![Response::ok()]
        }

        Command::HaveKey { keygrips, list } => {
            let gpg_keys = state.gpg_keys.read();

            if let Some(limit) = list {
                let limit = if *limit < 0 {
                    usize::MAX
                } else {
                    *limit as usize
                };
                let mut binary_grips = Vec::new();
                for key in gpg_keys.iter().take(limit) {
                    if let Ok(grip_bytes) = hex::decode(&key.keygrip) {
                        binary_grips.extend_from_slice(&grip_bytes);
                    }
                }
                vec![Response::data(binary_grips), Response::ok()]
            } else if keygrips.is_empty() {
                vec![Response::err(67108881, "No secret key")]
            } else {
                let found = keygrips
                    .iter()
                    .any(|kg| gpg_keys.iter().any(|k| k.keygrip == *kg));
                if found {
                    vec![Response::ok()]
                } else {
                    vec![Response::err(67108881, "No secret key")]
                }
            }
        }

        Command::KeyInfo {
            list,
            ssh_list: _,
            keygrip,
        } => {
            let gpg_keys = state.gpg_keys.read();

            if *list {
                let mut responses = Vec::new();
                for key in gpg_keys.iter() {
                    responses.push(Response::status(
                        "KEYINFO",
                        format!("{} D - - - P - - -", key.keygrip),
                    ));
                }
                responses.push(Response::ok());
                responses
            } else if let Some(kg) = keygrip {
                let kg_upper = kg.to_uppercase();
                if gpg_keys.iter().any(|k| k.keygrip == kg_upper) {
                    vec![
                        Response::status("KEYINFO", format!("{} D - - - P - - -", kg_upper)),
                        Response::ok(),
                    ]
                } else {
                    vec![Response::err(67108881, "No secret key")]
                }
            } else {
                vec![Response::err(67109139, "Missing keygrip")]
            }
        }

        Command::SigKey { keygrip } => {
            let gpg_keys = state.gpg_keys.read();
            let found = gpg_keys.iter().any(|k| k.keygrip == keygrip.to_uppercase());
            if found {
                session.current_keygrip = Some(keygrip.to_uppercase());
                vec![Response::ok()]
            } else {
                vec![Response::err(67108881, "No secret key")]
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
                None => return vec![Response::err(67108881, "No key set")],
            };

            if session.hash_data.is_empty() {
                return vec![Response::err(67108881, "No hash set")];
            }

            let gpg_keys = state.gpg_keys.read();
            let key = match gpg_keys.iter().find(|k| k.keygrip == keygrip) {
                Some(k) => k,
                None => return vec![Response::err(67108881, "Key not found")],
            };

            match key.sign(&session.hash_data, session.hash_algo) {
                Ok(signature) => {
                    let sexp = format_signature_sexp(&signature);
                    debug!("signed with keygrip {}", keygrip);
                    vec![Response::data(sexp), Response::ok()]
                }
                Err(e) => {
                    error!("signing failed: {}", e);
                    vec![Response::err(67108881, "Signing failed")]
                }
            }
        }

        Command::PresetPassphrase { .. } => {
            vec![Response::ok()]
        }

        Command::GetInfo { what } => match what.as_str() {
            "version" => vec![
                Response::data(gpg_compat_version().as_bytes().to_vec()),
                Response::ok(),
            ],
            "pid" => {
                let pid = std::process::id().to_string();
                vec![Response::data(pid.into_bytes()), Response::ok()]
            }
            _ => vec![Response::ok()],
        },

        Command::Bye => {
            vec![Response::ok_with("closing connection")]
        }

        Command::Unknown(line) => {
            if line.is_empty() {
                vec![]
            } else {
                debug!("unknown GPG command: {}", line);
                vec![Response::err(67109139, "Unknown command")]
            }
        }
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

/// Append a canonical S-expression atom (`<len>:<bytes>`).
fn push_sexp_atom(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(data);
}

/// Append a `(<name><len>:<value>)` MPI parameter, e.g. `(1:r32:....)`.
fn push_sexp_param(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(b'(');
    push_sexp_atom(out, name);
    push_sexp_atom(out, value);
    out.push(b')');
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
            push_sexp_atom(&mut result, b"rsa");
            push_sexp_param(&mut result, b"s", s);
        }
        GpgSignature::Ecdsa { r, s } => {
            push_sexp_atom(&mut result, b"ecdsa");
            push_sexp_param(&mut result, b"r", r);
            push_sexp_param(&mut result, b"s", s);
        }
        GpgSignature::EdDsa { r, s } => {
            push_sexp_atom(&mut result, b"eddsa");
            push_sexp_param(&mut result, b"r", r);
            push_sexp_param(&mut result, b"s", s);
        }
    }
    result.extend_from_slice(b"))");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::keys::{GpgKey, GpgKeyType};

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
