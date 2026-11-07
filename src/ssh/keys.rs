use std::path::Path;

use bytes::Bytes;
use ed25519_dalek::Signer as _;
use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};
use ssh_key::{Algorithm, HashAlg, PrivateKey};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The hash an RSA signature uses: chosen by the client's flags, with
/// SHA-1 (`ssh-rsa`) when it sets neither SHA-2 flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaHash {
    Sha1,
    Sha256,
    Sha512,
}

pub struct SshKey {
    pub private_key: PrivateKey,
    pub public_blob: Bytes,
    pub comment: String,
    pub fingerprint: String,
}

impl SshKey {
    pub fn algorithm(&self) -> Algorithm {
        self.private_key.algorithm()
    }

    /// Sign data using the underlying crypto libraries directly.
    ///
    /// Returns raw signature bytes suitable for SSH agent protocol (not SshSig format).
    pub fn sign(&self, data: &[u8], rsa_hash: RsaHash) -> Result<Vec<u8>> {
        use ssh_key::private::KeypairData;

        match self.private_key.key_data() {
            KeypairData::Rsa(rsa_keypair) => self.sign_rsa(rsa_keypair, data, rsa_hash),
            KeypairData::Ed25519(ed25519_keypair) => self.sign_ed25519(ed25519_keypair, data),
            KeypairData::Ecdsa(ecdsa_keypair) => self.sign_ecdsa(ecdsa_keypair, data),
            _ => Err(Error::UnsupportedKeyType(format!(
                "{:?}",
                self.private_key.algorithm()
            ))),
        }
    }

    fn sign_rsa(
        &self,
        keypair: &ssh_key::private::RsaKeypair,
        data: &[u8],
        hash: RsaHash,
    ) -> Result<Vec<u8>> {
        // Extract RSA key components from ssh-key's representation
        let p = rsa::BigUint::from_bytes_be(keypair.private.p.as_bytes());
        let q = rsa::BigUint::from_bytes_be(keypair.private.q.as_bytes());
        let e = rsa::BigUint::from_bytes_be(keypair.public.e.as_bytes());

        let rsa_key = rsa::RsaPrivateKey::from_p_q(p, q, e)?;
        let mut rng = rand::rngs::OsRng;

        let sig_bytes = match hash {
            RsaHash::Sha1 => rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(rsa_key)
                .try_sign_with_rng(&mut rng, data)?
                .to_bytes(),
            RsaHash::Sha256 => rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key)
                .try_sign_with_rng(&mut rng, data)?
                .to_bytes(),
            RsaHash::Sha512 => rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(rsa_key)
                .try_sign_with_rng(&mut rng, data)?
                .to_bytes(),
        };

        Ok(sig_bytes.to_vec())
    }

    fn sign_ed25519(
        &self,
        keypair: &ssh_key::private::Ed25519Keypair,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&keypair.private.to_bytes());
        let signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn sign_ecdsa(&self, keypair: &ssh_key::private::EcdsaKeypair, data: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::Signer as _;
        use ssh_key::private::EcdsaKeypair;

        // The SSH agent protocol expects the ECDSA signature blob as
        // `mpint r || mpint s` (RFC 5656 §3.1.2), not ASN.1 DER. The outer
        // `encode_signature` wraps this blob in the signature string.
        match keypair {
            EcdsaKeypair::NistP256 { private, .. } => {
                let secret_key =
                    p256::SecretKey::from_slice(private.as_slice()).map_err(|_| Error::Ecdsa)?;
                let signing_key = p256::ecdsa::SigningKey::from(&secret_key);
                let signature: p256::ecdsa::Signature = signing_key.sign(data);
                let (r, s) = signature.split_bytes();
                Ok(encode_ecdsa_blob(&r, &s))
            }
            EcdsaKeypair::NistP384 { private, .. } => {
                let secret_key =
                    p384::SecretKey::from_slice(private.as_slice()).map_err(|_| Error::Ecdsa)?;
                let signing_key = p384::ecdsa::SigningKey::from(&secret_key);
                let signature: p384::ecdsa::Signature = signing_key.sign(data);
                let (r, s) = signature.split_bytes();
                Ok(encode_ecdsa_blob(&r, &s))
            }
            _ => Err(Error::UnsupportedKeyType("unsupported ECDSA curve".into())),
        }
    }

    pub fn matches_blob(&self, blob: &[u8]) -> bool {
        self.public_blob.as_ref() == blob
    }
}

/// Encode a big-endian field element as an SSH `mpint`: a length-prefixed,
/// two's-complement integer. Leading zero bytes are stripped, and a single
/// 0x00 pad byte is prepended when the high bit is set so the value stays
/// positive (RFC 4251 §5).
fn put_mpint(out: &mut Vec<u8>, be_bytes: &[u8]) {
    let start = be_bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(be_bytes.len());
    let trimmed = &be_bytes[start..];

    let needs_pad = trimmed.first().is_some_and(|&b| b & 0x80 != 0);
    let len = trimmed.len() + usize::from(needs_pad);

    out.extend_from_slice(&(len as u32).to_be_bytes());
    if needs_pad {
        out.push(0);
    }
    out.extend_from_slice(trimmed);
}

/// Encode an ECDSA signature as the SSH blob `mpint r || mpint s`.
fn encode_ecdsa_blob(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(r.len() + s.len() + 8);
    put_mpint(&mut blob, r);
    put_mpint(&mut blob, s);
    blob
}

/// Files in `dir` that look like private keys: not `.pub`, not ssh config
/// files, and either paired with a `.pub` file or containing "PRIVATE KEY".
pub fn key_candidates(dir: &Path) -> Vec<std::path::PathBuf> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("failed to read SSH key directory {:?}: {}", dir, e);
            return Vec::new();
        }
    };

    let mut paths = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "pub") || !path.is_file() {
            continue;
        }
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if matches!(
            filename,
            "config" | "known_hosts" | "known_hosts.old" | "authorized_keys"
        ) || filename.ends_with(".old")
        {
            continue;
        }
        let mut pub_path = path.clone().into_os_string();
        pub_path.push(".pub");
        let paired =
            std::path::Path::new(&pub_path).exists() || path.with_extension("pub").exists();
        let looks_like_key =
            || std::fs::read_to_string(&path).is_ok_and(|content| content.contains("PRIVATE KEY"));
        if paired || looks_like_key() {
            paths.push(path);
        }
    }
    paths
}

pub fn load_ssh_keys(dir: &Path, passphrase: &str) -> Vec<SshKey> {
    let mut keys = Vec::new();
    for path in key_candidates(dir) {
        match load_single_key(&path, passphrase) {
            Ok(key) => {
                debug!("loaded SSH key: {} ({})", key.fingerprint, key.comment);
                keys.push(key);
            }
            Err(e) => {
                debug!("skipping {:?}: {}", path, e);
            }
        }
    }
    keys
}

fn load_single_key(path: &Path, passphrase: &str) -> Result<SshKey> {
    let content = Zeroizing::new(std::fs::read_to_string(path)?);

    let private_key = match PrivateKey::from_openssh(&content) {
        Ok(key) => {
            if key.is_encrypted() {
                key.decrypt(passphrase.as_bytes())
                    .map_err(|_| Error::KeyDecryptionFailed)?
            } else {
                key
            }
        }
        Err(e) => return Err(Error::SshKey(e)),
    };

    let public_key = private_key.public_key();
    let public_blob = Bytes::from(public_key.to_bytes().map_err(Error::SshKey)?);

    let comment = private_key.comment().to_string();

    let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();

    Ok(SshKey {
        private_key,
        public_blob,
        comment,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpint_strips_leading_zeros() {
        let mut out = Vec::new();
        put_mpint(&mut out, &[0x00, 0x00, 0x01, 0x02]);
        assert_eq!(out, vec![0, 0, 0, 2, 0x01, 0x02]);
    }

    #[test]
    fn mpint_pads_high_bit() {
        let mut out = Vec::new();
        put_mpint(&mut out, &[0x80, 0x01]);
        // High bit set -> prepend 0x00 so the integer stays positive.
        assert_eq!(out, vec![0, 0, 0, 3, 0x00, 0x80, 0x01]);
    }

    #[test]
    fn mpint_zero_is_empty() {
        let mut out = Vec::new();
        put_mpint(&mut out, &[0x00, 0x00]);
        assert_eq!(out, vec![0, 0, 0, 0]);
    }

    #[test]
    fn ecdsa_p256_blob_verifies_as_raw_rs() {
        use p256::ecdsa::signature::{Signer, Verifier};
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

        let signing_key = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);
        let data = b"hello keyoxide";

        let sig: Signature = signing_key.sign(data);
        let (r, s) = sig.split_bytes();
        let blob = encode_ecdsa_blob(&r, &s);

        // Re-read the blob the way an SSH client does and rebuild the signature.
        let (r2, rest) = read_ssh_mpint(&blob);
        let (s2, rest) = read_ssh_mpint(rest);
        assert!(rest.is_empty());

        let mut raw = left_pad(&r2, 32);
        raw.extend_from_slice(&left_pad(&s2, 32));
        let rebuilt = Signature::from_slice(&raw).unwrap();
        assert!(verifying_key.verify(data, &rebuilt).is_ok());
    }

    fn read_ssh_mpint(buf: &[u8]) -> (Vec<u8>, &[u8]) {
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        (buf[4..4 + len].to_vec(), &buf[4 + len..])
    }

    fn left_pad(bytes: &[u8], width: usize) -> Vec<u8> {
        let bytes = if bytes.len() > width {
            &bytes[bytes.len() - width..]
        } else {
            bytes
        };
        let mut out = vec![0u8; width - bytes.len()];
        out.extend_from_slice(bytes);
        out
    }
}
