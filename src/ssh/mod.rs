pub mod keys;
pub mod protocol;

use std::sync::Arc;

use bytes::BytesMut;
use protocol::{Request, Response, SSH_AGENT_RSA_SHA2_512};
use ssh_key::{Algorithm, HashAlg};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

use crate::agent::AgentState;
use crate::error::Result;

pub async fn run_ssh_agent(listener: UnixListener, state: Arc<AgentState>) -> Result<()> {
    info!("SSH agent listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, state).await {
                        debug!("SSH connection ended: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("failed to accept SSH connection: {}", e);
            }
        }
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
        Request::AddIdentity { .. } => {
            debug!("add identity request ignored (keys loaded at startup)");
            Response::Success
        }
        Request::RemoveIdentity { .. } => {
            debug!("remove identity request ignored");
            Response::Success
        }
        Request::RemoveAllIdentities => {
            debug!("remove all identities request ignored");
            Response::Success
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

    let (hash_alg, sig_algorithm) = match key.algorithm() {
        Algorithm::Rsa { .. } => {
            if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                (Some(HashAlg::Sha512), "rsa-sha2-512")
            } else {
                (Some(HashAlg::Sha256), "rsa-sha2-256")
            }
        }
        Algorithm::Ed25519 => (None, "ssh-ed25519"),
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
            (None, name)
        }
        alg => {
            warn!("unsupported algorithm: {:?}", alg);
            return Response::Failure;
        }
    };

    match key.sign(data, hash_alg) {
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
