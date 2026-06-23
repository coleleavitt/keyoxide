use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH2_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH2_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH2_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;

pub const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

const MAX_MESSAGE_SIZE: usize = 256 * 1024;

#[derive(Debug)]
pub enum Request {
    RequestIdentities,
    SignRequest {
        key_blob: Bytes,
        data: Bytes,
        flags: u32,
    },
    AddIdentity {
        key_type: String,
        key_data: Bytes,
        comment: String,
    },
    RemoveIdentity {
        key_blob: Bytes,
    },
    RemoveAllIdentities,
}

#[derive(Debug)]
pub enum Response {
    Success,
    Failure,
    IdentitiesAnswer { keys: Vec<(Bytes, String)> },
    SignResponse { signature: Bytes },
}

pub fn parse_message(data: &[u8]) -> Result<Option<(Request, usize)>> {
    if data.len() < 5 {
        return Ok(None);
    }

    let msg_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if msg_len > MAX_MESSAGE_SIZE {
        return Err(Error::MessageTooLarge(msg_len));
    }
    // A valid frame carries at least the message-type byte; msg_len == 0 would
    // make `data[4]`/`data[5..]` below index past the frame and panic.
    if msg_len < 1 {
        return Err(Error::InvalidMessageFormat);
    }

    let total_len = 4 + msg_len;
    if data.len() < total_len {
        return Ok(None);
    }

    let msg_type = data[4];
    let payload = &data[5..total_len];

    let request = parse_request(msg_type, payload)?;
    Ok(Some((request, total_len)))
}

fn parse_request(msg_type: u8, payload: &[u8]) -> Result<Request> {
    match msg_type {
        SSH2_AGENTC_REQUEST_IDENTITIES => Ok(Request::RequestIdentities),
        SSH2_AGENTC_SIGN_REQUEST => parse_sign_request(payload),
        SSH2_AGENTC_ADD_IDENTITY => parse_add_identity(payload),
        SSH2_AGENTC_REMOVE_IDENTITY => parse_remove_identity(payload),
        SSH2_AGENTC_REMOVE_ALL_IDENTITIES => Ok(Request::RemoveAllIdentities),
        _ => Err(Error::InvalidCommand(format!(
            "unknown message type: {}",
            msg_type
        ))),
    }
}

fn parse_sign_request(mut payload: &[u8]) -> Result<Request> {
    let key_blob = read_string(&mut payload)?;
    let data = read_string(&mut payload)?;
    let flags = if payload.len() >= 4 {
        payload.get_u32()
    } else {
        0
    };

    Ok(Request::SignRequest {
        key_blob,
        data,
        flags,
    })
}

fn parse_add_identity(mut payload: &[u8]) -> Result<Request> {
    let key_type = read_string_utf8(&mut payload)?;
    let remaining = Bytes::copy_from_slice(payload);

    Ok(Request::AddIdentity {
        key_type,
        key_data: remaining,
        comment: String::new(),
    })
}

fn parse_remove_identity(mut payload: &[u8]) -> Result<Request> {
    let key_blob = read_string(&mut payload)?;
    Ok(Request::RemoveIdentity { key_blob })
}

fn read_string(buf: &mut &[u8]) -> Result<Bytes> {
    if buf.len() < 4 {
        return Err(Error::BufferTooShort);
    }
    let len = buf.get_u32() as usize;
    if buf.len() < len {
        return Err(Error::BufferTooShort);
    }
    let data = Bytes::copy_from_slice(&buf[..len]);
    buf.advance(len);
    Ok(data)
}

fn read_string_utf8(buf: &mut &[u8]) -> Result<String> {
    let bytes = read_string(buf)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidMessageFormat)
}

impl Response {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        match self {
            Response::Success => {
                buf.put_u32(1);
                buf.put_u8(SSH_AGENT_SUCCESS);
            }
            Response::Failure => {
                buf.put_u32(1);
                buf.put_u8(SSH_AGENT_FAILURE);
            }
            Response::IdentitiesAnswer { keys } => {
                let mut payload = BytesMut::new();
                payload.put_u8(SSH2_AGENT_IDENTITIES_ANSWER);
                payload.put_u32(keys.len() as u32);
                for (blob, comment) in keys {
                    put_string(&mut payload, blob);
                    put_string(&mut payload, comment.as_bytes());
                }
                buf.put_u32(payload.len() as u32);
                buf.extend_from_slice(&payload);
            }
            Response::SignResponse { signature } => {
                let mut payload = BytesMut::new();
                payload.put_u8(SSH2_AGENT_SIGN_RESPONSE);
                put_string(&mut payload, signature);
                buf.put_u32(payload.len() as u32);
                buf.extend_from_slice(&payload);
            }
        }

        buf.freeze()
    }
}

fn put_string(buf: &mut BytesMut, data: &[u8]) {
    buf.put_u32(data.len() as u32);
    buf.extend_from_slice(data);
}

pub fn encode_signature(algorithm: &str, sig_data: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    put_string(&mut buf, algorithm.as_bytes());
    put_string(&mut buf, sig_data);
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_length_frame_is_rejected_not_panicking() {
        // Length prefix of 0 used to make `data[5..4]` panic the handler.
        let frame = [0u8, 0, 0, 0, 13];
        let result = parse_message(&frame);
        assert!(matches!(result, Err(Error::InvalidMessageFormat)));
    }

    #[test]
    fn incomplete_frame_returns_none() {
        // Header claims 10 bytes but only the type byte is present.
        let frame = [0u8, 0, 0, 10, SSH2_AGENTC_SIGN_REQUEST];
        assert!(matches!(parse_message(&frame), Ok(None)));
    }

    #[test]
    fn too_short_for_header_returns_none() {
        assert!(matches!(parse_message(&[0u8, 0, 0]), Ok(None)));
    }

    #[test]
    fn oversize_frame_is_rejected() {
        let frame = [0xFFu8, 0xFF, 0xFF, 0xFF, 1];
        assert!(matches!(
            parse_message(&frame),
            Err(Error::MessageTooLarge(_))
        ));
    }

    #[test]
    fn request_identities_parses() {
        let frame = [0u8, 0, 0, 1, SSH2_AGENTC_REQUEST_IDENTITIES];
        let (req, consumed) = parse_message(&frame).unwrap().unwrap();
        assert_eq!(consumed, 5);
        assert!(matches!(req, Request::RequestIdentities));
    }

    #[test]
    fn sign_request_with_truncated_string_errors() {
        // type=SIGN_REQUEST, then a length prefix claiming 99 bytes with none present.
        let mut frame = vec![0u8, 0, 0, 5, SSH2_AGENTC_SIGN_REQUEST];
        frame.extend_from_slice(&[0, 0, 0, 99]);
        assert!(matches!(parse_message(&frame), Err(Error::BufferTooShort)));
    }
}
