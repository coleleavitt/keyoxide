pub mod keys;
pub mod protocol;

use std::sync::Arc;

use bytes::BytesMut;
use keys::RsaHash;
use protocol::{Request, Response, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};
use ssh_key::Algorithm;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

use crate::agent::AgentState;
use crate::error::Result;

pub async fn run_ssh_agent(listener: &UnixListener, state: Arc<AgentState>) -> Result<()> {
    info!("SSH agent listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state).await {
                debug!("SSH connection ended: {}", e);
            }
        });
    }
}

async fn handle_connection(mut stream: UnixStream, state: Arc<AgentState>) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(4096);

    loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..n]);

        while let Some((request, consumed)) = protocol::parse_message(&buffer)? {
            let response = handle_request(&request, &state);
            let response_bytes = response.encode();
            stream.write_all(&response_bytes).await?;
            let _ = buffer.split_to(consumed);
        }
    }

    Ok(())
}

fn handle_request(request: &Request, state: &AgentState) -> Response {
    match request {
        Request::RequestIdentities => handle_request_identities(state),
        Request::SignRequest {
            key_blob,
            data,
            flags,
        } => handle_sign_request(state, key_blob, data, *flags),
        // Keys come from ~/.ssh at startup. Reporting success here would tell
        // `ssh-add` a key was added or removed when nothing changed.
        Request::AddIdentity { .. }
        | Request::RemoveIdentity { .. }
        | Request::RemoveAllIdentities => {
            debug!("identity changes are not supported (keys load at startup)");
            Response::Failure
        }
        Request::Unsupported(msg_type) => {
            debug!("unsupported SSH agent request type {}", msg_type);
            Response::Failure
        }
        Request::Malformed(e) => {
            warn!("malformed SSH agent request: {}", e);
            Response::Failure
        }
    }
}

fn handle_request_identities(state: &AgentState) -> Response {
    let ssh_keys = state.ssh_keys.read();
    let keys: Vec<_> = ssh_keys
        .iter()
        .map(|k| (k.public_blob.clone(), k.comment.clone()))
        .collect();

    debug!("returning {} SSH identities", keys.len());
    Response::IdentitiesAnswer { keys }
}

fn handle_sign_request(state: &AgentState, key_blob: &[u8], data: &[u8], flags: u32) -> Response {
    let ssh_keys = state.ssh_keys.read();

    let key = match ssh_keys.iter().find(|k| k.matches_blob(key_blob)) {
        Some(k) => k,
        None => {
            warn!("sign request for unknown key");
            return Response::Failure;
        }
    };

    let (rsa_hash, sig_algorithm) = match key.algorithm() {
        Algorithm::Rsa { .. } => {
            if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                (RsaHash::Sha512, "rsa-sha2-512")
            } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                (RsaHash::Sha256, "rsa-sha2-256")
            } else {
                // No SHA-2 flag: the client wants a legacy SHA-1 "ssh-rsa"
                // signature; anything else would fail to verify.
                (RsaHash::Sha1, "ssh-rsa")
            }
        }
        Algorithm::Ed25519 => (RsaHash::Sha256, "ssh-ed25519"),
        Algorithm::Ecdsa { curve } => {
            let name = match curve.as_str() {
                "nistp256" => "ecdsa-sha2-nistp256",
                "nistp384" => "ecdsa-sha2-nistp384",
                "nistp521" => "ecdsa-sha2-nistp521",
                _ => {
                    warn!("unsupported ECDSA curve: {}", curve);
                    return Response::Failure;
                }
            };
            (RsaHash::Sha256, name)
        }
        alg => {
            warn!("unsupported algorithm: {:?}", alg);
            return Response::Failure;
        }
    };

    match key.sign(data, rsa_hash) {
        Ok(sig_data) => {
            let signature = protocol::encode_signature(sig_algorithm, &sig_data);
            debug!("signed data with {} ({})", key.fingerprint, sig_algorithm);
            Response::SignResponse { signature }
        }
        Err(e) => {
            error!("signing failed: {}", e);
            Response::Failure
        }
    }
}
