use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub enum Command {
    Reset,
    Option {
        name: String,
        value: String,
    },
    HaveKey {
        keygrips: Vec<String>,
        list: Option<i32>,
    },
    KeyInfo {
        list: bool,
        ssh_list: bool,
        keygrip: Option<String>,
    },
    SigKey {
        keygrip: String,
    },
    SetKeyDesc {
        description: String,
    },
    SetHash {
        algo: u32,
        hash: Vec<u8>,
    },
    PkSign,
    PresetPassphrase {
        keygrip: String,
        ttl: i32,
        passphrase: String,
    },
    GetInfo {
        what: String,
    },
    Bye,
    Unknown(String),
}

#[derive(Debug)]
pub enum Response {
    Ok(Option<String>),
    Err { code: u32, message: String },
    Data(Vec<u8>),
    Status { keyword: String, args: String },
    Comment(String),
    Inquire { keyword: String, args: String },
}

impl Response {
    pub fn ok() -> Self {
        Response::Ok(None)
    }

    pub fn ok_with(msg: impl Into<String>) -> Self {
        Response::Ok(Some(msg.into()))
    }

    pub fn err(code: u32, message: impl Into<String>) -> Self {
        Response::Err {
            code,
            message: message.into(),
        }
    }

    pub fn data(data: impl Into<Vec<u8>>) -> Self {
        Response::Data(data.into())
    }

    pub fn status(keyword: impl Into<String>, args: impl Into<String>) -> Self {
        Response::Status {
            keyword: keyword.into(),
            args: args.into(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Response::Ok(None) => b"OK\n".to_vec(),
            Response::Ok(Some(msg)) => format!("OK {}\n", msg).into_bytes(),
            Response::Err { code, message } => format!("ERR {} {}\n", code, message).into_bytes(),
            Response::Data(data) => {
                let encoded = percent_encode_assuan(data);
                if encoded.len() + 3 <= MAX_LINE_LEN {
                    let mut result = Vec::with_capacity(encoded.len() + 4);
                    result.extend_from_slice(b"D ");
                    result.extend_from_slice(&encoded);
                    result.push(b'\n');
                    result
                } else {
                    let mut result = Vec::new();
                    let mut remaining = &encoded[..];
                    while !remaining.is_empty() {
                        let chunk_len = (MAX_LINE_LEN - 3).min(remaining.len());
                        result.extend_from_slice(b"D ");
                        result.extend_from_slice(&remaining[..chunk_len]);
                        result.push(b'\n');
                        remaining = &remaining[chunk_len..];
                    }
                    result
                }
            }
            Response::Status { keyword, args } => {
                if args.is_empty() {
                    format!("S {}\n", keyword).into_bytes()
                } else {
                    format!("S {} {}\n", keyword, args).into_bytes()
                }
            }
            Response::Comment(msg) => format!("# {}\n", msg).into_bytes(),
            Response::Inquire { keyword, args } => {
                if args.is_empty() {
                    format!("INQUIRE {}\n", keyword).into_bytes()
                } else {
                    format!("INQUIRE {} {}\n", keyword, args).into_bytes()
                }
            }
        }
    }
}

const MAX_LINE_LEN: usize = 1000;

fn percent_encode_assuan(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len() * 3);
    for &byte in data {
        match byte {
            b'%' => result.extend_from_slice(b"%25"),
            b'\r' => result.extend_from_slice(b"%0D"),
            b'\n' => result.extend_from_slice(b"%0A"),
            0x00..=0x1F => {
                result.push(b'%');
                result.push(HEX_UPPER[(byte >> 4) as usize]);
                result.push(HEX_UPPER[(byte & 0xF) as usize]);
            }
            _ => result.push(byte),
        }
    }
    result
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

pub fn parse_command(line: &str) -> Result<Command> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(Command::Unknown(String::new()));
    }

    let mut parts = line.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("").to_uppercase();
    let args = parts.next().unwrap_or("").trim();

    match cmd.as_str() {
        "RESET" => Ok(Command::Reset),
        "OPTION" => parse_option(args),
        "HAVEKEY" => parse_havekey(args),
        "KEYINFO" => parse_keyinfo(args),
        "SIGKEY" | "SETKEY" => Ok(Command::SigKey {
            keygrip: args.to_string(),
        }),
        "SETKEYDESC" => Ok(Command::SetKeyDesc {
            description: percent_decode(args),
        }),
        "SETHASH" => parse_sethash(args),
        "PKSIGN" => Ok(Command::PkSign),
        "PRESET_PASSPHRASE" => parse_preset_passphrase(args),
        "GETINFO" => Ok(Command::GetInfo {
            what: args.to_string(),
        }),
        "BYE" => Ok(Command::Bye),
        _ => Ok(Command::Unknown(line.to_string())),
    }
}

fn parse_option(args: &str) -> Result<Command> {
    let (name, value) = args.split_once('=').unwrap_or((args, ""));
    Ok(Command::Option {
        name: name.to_string(),
        value: value.to_string(),
    })
}

fn parse_havekey(args: &str) -> Result<Command> {
    if let Some(rest) = args.strip_prefix("--list") {
        let limit = if let Some(eq_val) = rest.strip_prefix('=') {
            eq_val.trim().parse().unwrap_or(-1)
        } else {
            -1
        };
        return Ok(Command::HaveKey {
            keygrips: Vec::new(),
            list: Some(limit),
        });
    }

    let keygrips: Vec<String> = args
        .split_whitespace()
        .filter(|s| s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|s| s.to_uppercase())
        .collect();

    Ok(Command::HaveKey {
        keygrips,
        list: None,
    })
}

fn parse_keyinfo(args: &str) -> Result<Command> {
    let list = args.contains("--list");
    let ssh_list = args.contains("--ssh-list");

    // Extract keygrip if present (last argument after options)
    let keygrip = args
        .split_whitespace()
        .rfind(|s| !s.starts_with("--"))
        .filter(|s| s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|s| s.to_uppercase());

    Ok(Command::KeyInfo {
        list,
        ssh_list,
        keygrip,
    })
}

fn parse_sethash(args: &str) -> Result<Command> {
    let mut parts = args.split_whitespace();

    let algo_str = parts.next().ok_or(Error::MissingField("algorithm"))?;
    let algo: u32 = if let Some(name) = algo_str.strip_prefix("--hash=") {
        hash_name_to_algo(name)
    } else {
        algo_str
            .parse()
            .map_err(|_| Error::InvalidCommand("invalid algorithm".into()))?
    };

    let hash_hex = parts.next().ok_or(Error::MissingField("hash"))?;
    let hash = hex::decode(hash_hex)?;

    Ok(Command::SetHash { algo, hash })
}

fn hash_name_to_algo(name: &str) -> u32 {
    match name.to_lowercase().as_str() {
        "sha1" => 2,
        "sha256" => 8,
        "sha384" => 9,
        "sha512" => 10,
        "sha224" => 11,
        _ => 0,
    }
}

fn parse_preset_passphrase(args: &str) -> Result<Command> {
    let mut parts = args.split_whitespace();
    let keygrip = parts
        .next()
        .ok_or(Error::MissingField("keygrip"))?
        .to_string();
    let ttl: i32 = parts
        .next()
        .ok_or(Error::MissingField("ttl"))?
        .parse()
        .map_err(|_| Error::InvalidCommand("invalid ttl".into()))?;
    let passphrase_hex = parts.next().unwrap_or("");
    let passphrase = if passphrase_hex.is_empty() {
        String::new()
    } else {
        String::from_utf8(hex::decode(passphrase_hex)?).map_err(|_| Error::InvalidMessageFormat)?
    };

    Ok(Command::PresetPassphrase {
        keygrip,
        ttl,
        passphrase,
    })
}

fn percent_decode(s: &str) -> String {
    // Assuan percent-encodes UTF-8 byte-by-byte, so decode into a byte buffer
    // and convert once at the end. Pushing each decoded byte as a `char`
    // (the previous approach) mangled any byte >= 0x80 into the wrong code
    // point and broke multi-byte UTF-8.
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    bytes.push(byte);
                    continue;
                }
            }
            bytes.push(b'%');
            bytes.extend_from_slice(hex.as_bytes());
        } else if c == '+' {
            bytes.push(b' ');
        } else {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_ascii_and_plus() {
        assert_eq!(percent_decode("hello+world"), "hello world");
        assert_eq!(percent_decode("a%20b"), "a b");
    }

    #[test]
    fn percent_decode_multibyte_utf8_roundtrips() {
        // "é" is UTF-8 0xC3 0xA9; assuan encodes each byte separately.
        assert_eq!(percent_decode("%C3%A9"), "é");
        // A full multibyte string: "café"
        assert_eq!(percent_decode("caf%C3%A9"), "café");
        // Emoji (4-byte): 😀 = F0 9F 98 80
        assert_eq!(percent_decode("%F0%9F%98%80"), "😀");
    }

    #[test]
    fn percent_decode_keeps_literal_percent_on_bad_escape() {
        assert_eq!(percent_decode("100%zz"), "100%zz");
    }

    #[test]
    fn parse_command_setkeydesc_decodes_percent() {
        let cmd = parse_command("SETKEYDESC Enter+pass%C3%A9").unwrap();
        match cmd {
            Command::SetKeyDesc { description } => assert_eq!(description, "Enter passé"),
            other => panic!("expected SetKeyDesc, got {:?}", other),
        }
    }
}
