use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::SigningKey as P256SigningKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::PrehashSigner;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use super::sexp::{CanonicalParser, parse_gpg_sexp};
use crate::error::{Error, Result};

#[derive(Clone)]
pub enum GpgKeyType {
    Rsa(Box<RsaPrivateKey>),
    Ed25519(SigningKey),
    EcdsaP256(P256SigningKey),
    EcdsaP384(P384SigningKey),
}

pub struct GpgKey {
    pub keygrip: String,
    pub key_type: GpgKeyType,
}

/// A signature in the shape gpg-agent must return to gpg, carrying enough
/// type information to emit the correct `sig-val` algorithm tag.
pub enum GpgSignature {
    /// Raw RSA signature bytes (single `s` MPI).
    Rsa(Vec<u8>),
    /// ECDSA `(r, s)` as fixed-width big-endian field elements.
    Ecdsa { r: Vec<u8>, s: Vec<u8> },
    /// EdDSA `(r, s)` halves of the 64-byte Ed25519 signature.
    EdDsa { r: Vec<u8>, s: Vec<u8> },
}

impl GpgKey {
    pub fn sign(&self, hash: &[u8], algo: u32) -> Result<GpgSignature> {
        match &self.key_type {
            GpgKeyType::Rsa(key) => sign_rsa(key, hash, algo),
            GpgKeyType::Ed25519(key) => sign_ed25519(key, hash),
            GpgKeyType::EcdsaP256(key) => sign_ecdsa_p256(key, hash),
            GpgKeyType::EcdsaP384(key) => sign_ecdsa_p384(key, hash),
        }
    }
}

fn sign_rsa(key: &RsaPrivateKey, hash: &[u8], algo: u32) -> Result<GpgSignature> {
    match algo {
        8 => {
            let signing_key = RsaSigningKey::<Sha256>::new(key.clone());
            let sig = signing_key
                .sign_prehash(hash)
                .map_err(|_| Error::SigningFailed)?;
            Ok(GpgSignature::Rsa(sig.to_vec()))
        }
        9 => {
            let signing_key = RsaSigningKey::<Sha384>::new(key.clone());
            let sig = signing_key
                .sign_prehash(hash)
                .map_err(|_| Error::SigningFailed)?;
            Ok(GpgSignature::Rsa(sig.to_vec()))
        }
        10 => {
            let signing_key = RsaSigningKey::<Sha512>::new(key.clone());
            let sig = signing_key
                .sign_prehash(hash)
                .map_err(|_| Error::SigningFailed)?;
            Ok(GpgSignature::Rsa(sig.to_vec()))
        }
        _ => Err(Error::UnsupportedAlgorithm(format!("hash algo {}", algo))),
    }
}

fn sign_ed25519(key: &SigningKey, data: &[u8]) -> Result<GpgSignature> {
    let sig = key.sign(data);
    // Ed25519 signature is R (32 bytes) || S (32 bytes); gpg's eddsa sig-val
    // wants them as two separate MPIs.
    let bytes = sig.to_bytes();
    Ok(GpgSignature::EdDsa {
        r: bytes[..32].to_vec(),
        s: bytes[32..].to_vec(),
    })
}

fn sign_ecdsa_p256(key: &P256SigningKey, hash: &[u8]) -> Result<GpgSignature> {
    // SETHASH already delivered the final digest, so sign the prehash directly
    // instead of letting the Signer trait hash it a second time.
    let sig: p256::ecdsa::Signature = key.sign_prehash(hash).map_err(|_| Error::Ecdsa)?;
    let (r, s) = sig.split_bytes();
    Ok(GpgSignature::Ecdsa {
        r: r[..].to_vec(),
        s: s[..].to_vec(),
    })
}

fn sign_ecdsa_p384(key: &P384SigningKey, hash: &[u8]) -> Result<GpgSignature> {
    let sig: p384::ecdsa::Signature = key.sign_prehash(hash).map_err(|_| Error::Ecdsa)?;
    let (r, s) = sig.split_bytes();
    Ok(GpgSignature::Ecdsa {
        r: r[..].to_vec(),
        s: s[..].to_vec(),
    })
}

pub fn load_gpg_keys(dir: &Path, passphrase: &str) -> Vec<GpgKey> {
    let mut keys = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("failed to read GPG key directory {:?}: {}", dir, e);
            return keys;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.extension().map_or(true, |e| e != "key") {
            continue;
        }

        let keygrip = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_uppercase();

        if keygrip.len() != 40 {
            continue;
        }

        match load_single_gpg_key(&path, passphrase) {
            Ok(key_type) => {
                info!("loaded GPG key: {}", keygrip);
                keys.push(GpgKey { keygrip, key_type });
            }
            Err(e) => {
                warn!("skipping GPG key {:?}: {}", path, e);
            }
        }
    }

    keys
}

fn load_single_gpg_key(path: &Path, passphrase: &str) -> Result<GpgKeyType> {
    let content = Zeroizing::new(std::fs::read_to_string(path)?);
    parse_gpg_key_sexp(&content, passphrase)
}

fn parse_gpg_key_sexp(content: &str, passphrase: &str) -> Result<GpgKeyType> {
    let content = content.trim();

    if content.contains("(protected-private-key") && content.contains("(protected ") {
        return parse_protected_key(content, passphrase);
    }

    if content.contains("(private-key") || content.contains("(shadowed-private-key") {
        return parse_unprotected_key(content);
    }

    Err(Error::UnsupportedKeyType("unknown GPG key format".into()))
}

fn parse_unprotected_key(content: &str) -> Result<GpgKeyType> {
    if content.contains("(rsa") {
        return parse_rsa_key(content);
    }

    if content.contains("(ecc") || content.contains("(ecdsa") {
        if content.contains("Ed25519") || content.contains("ed25519") {
            return parse_ed25519_key(content);
        } else if content.contains("nistp256") || content.contains("NIST P-256") {
            return parse_ecdsa_p256_key(content);
        } else if content.contains("nistp384") || content.contains("NIST P-384") {
            return parse_ecdsa_p384_key(content);
        }
    }

    Err(Error::UnsupportedKeyType(
        "unrecognized unprotected key type".into(),
    ))
}

struct ProtectedKeyParams {
    salt: [u8; 8],
    s2k_count: u64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    is_ocb: bool,
}

fn parse_protected_key(content: &str, passphrase: &str) -> Result<GpgKeyType> {
    let sexp_start = content
        .find("(protected-private-key")
        .or_else(|| content.find("(private-key"))
        .ok_or(Error::SexpParse("no S-expression found".into()))?;
    let sexp_content = &content[sexp_start..];

    let sexp = parse_gpg_sexp(sexp_content)?;
    let canonical = sexp.to_canonical();

    let (params, aad1, aad2) = extract_canonical_params(&canonical)?;

    debug!(
        "salt={} s2k={} nonce={} ct_len={} is_ocb={}",
        hex::encode(&params.salt),
        params.s2k_count,
        hex::encode(&params.nonce),
        params.ciphertext.len(),
        params.is_ocb
    );

    let key = derive_s2k_key(passphrase, &params.salt, params.s2k_count, 16);
    debug!("derived key: {}", hex::encode(&*key));

    let decrypted = if params.is_ocb {
        decrypt_ocb(&key, &params.nonce, &aad1, &aad2, &params.ciphertext)?
    } else {
        decrypt_cbc(&key, &params.nonce, &params.ciphertext)?
    };

    debug!("decrypted {} bytes", decrypted.len());
    parse_decrypted_private_key(&decrypted, content)
}

fn extract_canonical_params(canonical: &[u8]) -> Result<(ProtectedKeyParams, Vec<u8>, Vec<u8>)> {
    let mut parser = CanonicalParser::new(canonical);

    parser.expect_list_start()?;
    let outer_name = parser.read_atom()?;
    if outer_name != b"protected-private-key" {
        return Err(Error::SexpParse("expected protected-private-key".into()));
    }

    let aad_begin = parser.position();

    parser.expect_list_start()?;
    let _algo = parser.read_atom()?;

    let mut hole_begin = 0;
    let mut hole_end = 0;
    let mut params = None;

    while !parser.peek_is_list_end() {
        let item_start = parser.position();

        if parser.peek_is_list() {
            parser.expect_list_start()?;

            if !parser.peek_is_list_end() && !parser.peek_is_list() {
                let name = parser.read_atom()?;

                if name == b"protected" {
                    hole_begin = item_start;

                    let method = parser.read_atom()?;
                    let is_ocb = method == b"openpgp-s2k3-ocb-aes";

                    parser.expect_list_start()?;
                    parser.expect_list_start()?;
                    let hash_type = parser.read_atom()?;
                    if hash_type != b"sha1" {
                        return Err(Error::SexpParse("expected sha1".into()));
                    }

                    let salt_data = parser.read_atom()?;
                    if salt_data.len() != 8 {
                        return Err(Error::SexpParse("expected 8-byte salt".into()));
                    }
                    let mut salt = [0u8; 8];
                    salt.copy_from_slice(salt_data);

                    let count_str = parser.read_atom()?;
                    let count_str = std::str::from_utf8(count_str)
                        .map_err(|_| Error::SexpParse("invalid count string".into()))?;
                    let s2k_count: u64 = count_str
                        .parse()
                        .map_err(|_| Error::SexpParse("invalid count".into()))?;

                    parser.expect_list_end()?;

                    let nonce = parser.read_atom()?.to_vec();
                    parser.expect_list_end()?;

                    let ciphertext = parser.read_atom()?.to_vec();

                    params = Some(ProtectedKeyParams {
                        salt,
                        s2k_count,
                        nonce,
                        ciphertext,
                        is_ocb,
                    });
                }
            }

            while !parser.peek_is_list_end() {
                parser.skip_sexp()?;
            }
            parser.expect_list_end()?;

            if hole_begin == item_start {
                hole_end = parser.position();
            }
        } else {
            parser.skip_sexp()?;
        }
    }

    parser.expect_list_end()?;
    let aad_end = parser.position();

    let params = params.ok_or(Error::SexpParse("no protected section found".into()))?;

    let aad1 = canonical[aad_begin..hole_begin].to_vec();
    let aad2 = canonical[hole_end..aad_end].to_vec();

    debug!(
        "AAD: part1={} bytes, hole={} bytes, part2={} bytes",
        aad1.len(),
        hole_end - hole_begin,
        aad2.len()
    );

    Ok((params, aad1, aad2))
}

fn derive_s2k_key(
    passphrase: &str,
    salt: &[u8; 8],
    count: u64,
    key_len: usize,
) -> Zeroizing<Vec<u8>> {
    let mut result = Zeroizing::new(vec![0u8; key_len]);
    let pass_bytes = passphrase.as_bytes();

    let salted_len = salt.len() + pass_bytes.len();
    let mut salted = vec![0u8; salted_len];
    salted[..8].copy_from_slice(salt);
    salted[8..].copy_from_slice(pass_bytes);

    let total_bytes = count.max(salted_len as u64) as usize;

    let mut prefix_byte = 0u8;
    let mut key_offset = 0;

    while key_offset < key_len {
        let mut hasher = Sha1::new();

        for _ in 0..prefix_byte {
            hasher.update([0u8]);
        }

        let mut hashed = 0;
        while hashed < total_bytes {
            let chunk_len = salted_len.min(total_bytes - hashed);
            hasher.update(&salted[..chunk_len]);
            hashed += chunk_len;
        }

        let digest = hasher.finalize();
        let copy_len = (key_len - key_offset).min(digest.len());
        result[key_offset..key_offset + copy_len].copy_from_slice(&digest[..copy_len]);
        key_offset += copy_len;
        prefix_byte += 1;
    }

    result
}

#[allow(deprecated)]
fn decrypt_ocb(
    key: &[u8],
    nonce: &[u8],
    aad1: &[u8],
    aad2: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    use aes::Aes128;

    if ciphertext.len() < 16 {
        return Err(Error::KeyDecryptionFailed);
    }

    let tag_start = ciphertext.len() - 16;
    let ct_data = &ciphertext[..tag_start];
    let tag = &ciphertext[tag_start..];

    let mut aad_combined = Vec::with_capacity(aad1.len() + aad2.len());
    aad_combined.extend_from_slice(aad1);
    aad_combined.extend_from_slice(aad2);

    {
        use ocb3::Ocb3;
        use ocb3::aead::generic_array::GenericArray;
        use ocb3::aead::{AeadInPlace, KeyInit};

        let key_arr: &GenericArray<u8, _> = GenericArray::from_slice(key);
        let ocb: Ocb3<Aes128> = Ocb3::new(key_arr);

        let mut buffer = ct_data.to_vec();
        let nonce_arr = GenericArray::from_slice(nonce);
        let tag_arr = GenericArray::from_slice(tag);

        ocb.decrypt_in_place_detached(nonce_arr, &aad_combined, &mut buffer, tag_arr)
            .map_err(|_| Error::KeyDecryptionFailed)?;

        return Ok(buffer);
    }
}

fn decrypt_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use aes::Aes128;
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;

    type Aes128CbcDec = Decryptor<Aes128>;

    let cipher = Aes128CbcDec::new_from_slices(key, iv).map_err(|_| Error::KeyDecryptionFailed)?;

    let mut buffer = ciphertext.to_vec();
    let decrypted = cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer)
        .map_err(|_| Error::KeyDecryptionFailed)?;

    Ok(decrypted.to_vec())
}

fn parse_decrypted_private_key(decrypted: &[u8], original: &str) -> Result<GpgKeyType> {
    if original.contains("(rsa") {
        parse_rsa_from_canonical(original, decrypted)
    } else if original.contains("(ecc") || original.contains("(ecdsa") {
        parse_ecc_from_canonical(original, decrypted)
    } else {
        Err(Error::UnsupportedKeyType(
            "unknown protected key algorithm".into(),
        ))
    }
}

fn extract_canonical_mpis(decrypted: &[u8]) -> Result<std::collections::HashMap<String, Vec<u8>>> {
    let mut mpis = std::collections::HashMap::new();
    let mut parser = CanonicalParser::new(decrypted);

    parser.expect_list_start()?;
    parser.expect_list_start()?;

    while !parser.peek_is_list_end() {
        parser.expect_list_start()?;
        let name = parser.read_atom()?;
        let value = parser.read_atom()?;
        mpis.insert(String::from_utf8_lossy(name).to_string(), value.to_vec());
        parser.expect_list_end()?;
    }

    Ok(mpis)
}

fn parse_rsa_from_canonical(original: &str, decrypted: &[u8]) -> Result<GpgKeyType> {
    let n = extract_mpi(original, "n")?;
    let e = extract_mpi(original, "e")?;

    let mpis = extract_canonical_mpis(decrypted)?;
    let d = mpis.get("d").ok_or(Error::MissingField("d"))?;
    let p = mpis.get("p").ok_or(Error::MissingField("p"))?;
    let q = mpis.get("q").ok_or(Error::MissingField("q"))?;

    let n_int = rsa::BigUint::from_bytes_be(&n);
    let e_int = rsa::BigUint::from_bytes_be(&e);
    let d_int = rsa::BigUint::from_bytes_be(d);
    let p_int = rsa::BigUint::from_bytes_be(p);
    let q_int = rsa::BigUint::from_bytes_be(q);

    let primes = vec![p_int, q_int];
    let key = RsaPrivateKey::from_components(n_int, e_int, d_int, primes)?;

    Ok(GpgKeyType::Rsa(Box::new(key)))
}

fn parse_ecc_from_canonical(original: &str, decrypted: &[u8]) -> Result<GpgKeyType> {
    let mpis = extract_canonical_mpis(decrypted)?;
    let d = mpis.get("d").ok_or(Error::MissingField("d"))?;

    if original.contains("Ed25519") || original.contains("ed25519") {
        let seed: [u8; 32] = d
            .get(d.len().saturating_sub(32)..)
            .unwrap_or(d)
            .try_into()
            .map_err(|_| Error::InvalidMessageFormat)?;
        let key = SigningKey::from_bytes(&seed);
        Ok(GpgKeyType::Ed25519(key))
    } else if original.contains("nistp256") || original.contains("NIST P-256") {
        let key = P256SigningKey::from_slice(d).map_err(|_| Error::Ecdsa)?;
        Ok(GpgKeyType::EcdsaP256(key))
    } else if original.contains("nistp384") || original.contains("NIST P-384") {
        let key = P384SigningKey::from_slice(d).map_err(|_| Error::Ecdsa)?;
        Ok(GpgKeyType::EcdsaP384(key))
    } else {
        Err(Error::UnsupportedKeyType("unknown ECC curve".into()))
    }
}

fn parse_rsa_key(content: &str) -> Result<GpgKeyType> {
    let n = extract_mpi(content, "n")?;
    let e = extract_mpi(content, "e")?;
    let d = extract_mpi(content, "d")?;
    let p = extract_mpi(content, "p")?;
    let q = extract_mpi(content, "q")?;

    let n_int = rsa::BigUint::from_bytes_be(&n);
    let e_int = rsa::BigUint::from_bytes_be(&e);
    let d_int = rsa::BigUint::from_bytes_be(&d);
    let p_int = rsa::BigUint::from_bytes_be(&p);
    let q_int = rsa::BigUint::from_bytes_be(&q);

    let primes = vec![p_int, q_int];
    let key = RsaPrivateKey::from_components(n_int, e_int, d_int, primes)?;

    Ok(GpgKeyType::Rsa(Box::new(key)))
}

fn parse_ed25519_key(content: &str) -> Result<GpgKeyType> {
    let d = extract_mpi(content, "d")?;

    let seed: [u8; 32] = d
        .get(d.len().saturating_sub(32)..)
        .unwrap_or(&d)
        .try_into()
        .map_err(|_| Error::InvalidMessageFormat)?;

    let key = SigningKey::from_bytes(&seed);
    Ok(GpgKeyType::Ed25519(key))
}

fn parse_ecdsa_p256_key(content: &str) -> Result<GpgKeyType> {
    let d = extract_mpi(content, "d")?;

    let key = P256SigningKey::from_slice(&d).map_err(|_| Error::Ecdsa)?;
    Ok(GpgKeyType::EcdsaP256(key))
}

fn parse_ecdsa_p384_key(content: &str) -> Result<GpgKeyType> {
    let d = extract_mpi(content, "d")?;

    let key = P384SigningKey::from_slice(&d).map_err(|_| Error::Ecdsa)?;
    Ok(GpgKeyType::EcdsaP384(key))
}

fn extract_mpi(content: &str, name: &'static str) -> Result<Vec<u8>> {
    let pattern = format!("({} #", name);
    let start = content.find(&pattern).ok_or(Error::MissingField(name))?;

    let hex_start = start + pattern.len();
    let hex_end = content[hex_start..]
        .find('#')
        .ok_or(Error::InvalidMessageFormat)?;

    let hex_str: String = content[hex_start..hex_start + hex_end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    hex::decode(&hex_str).map_err(Error::HexDecode)
}
