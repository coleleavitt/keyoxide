use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::SigningKey as P256SigningKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::PrehashSigner;
use sha2::{Sha256, Sha384, Sha512};
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::curve::Curve;
use super::keyfile::{KeyMaterial, read_key_file};
use super::sexp::{SexpNode, parse_canonical, push_param};
use crate::error::{Error, Result};

#[derive(Clone)]
pub enum GpgKeyType {
    Rsa(Box<RsaPrivateKey>),
    Ed25519(SigningKey),
    /// Curve25519 ECDH (cv25519 encryption subkeys).
    X25519(x25519_dalek::StaticSecret),
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

impl GpgKeyType {
    pub fn from_material(material: &KeyMaterial) -> Result<Self> {
        if material.algo == "rsa" {
            let int = |name: &'static str| {
                material
                    .get(name)
                    .map(rsa::BigUint::from_bytes_be)
                    .ok_or(Error::MissingField(name))
            };
            let key = RsaPrivateKey::from_components(
                int("n")?,
                int("e")?,
                int("d")?,
                vec![int("p")?, int("q")?],
            )?;
            return Ok(Self::Rsa(Box::new(key)));
        }

        let name = material
            .curve
            .as_deref()
            .ok_or(Error::MissingField("curve"))?;
        let curve = Curve::from_name(name)
            .ok_or_else(|| Error::UnsupportedKeyType(format!("curve {name}")))?;
        let d = material.get("d").ok_or(Error::MissingField("d"))?;
        Ok(match curve {
            Curve::Ed25519 => Self::Ed25519(SigningKey::from_bytes(&*fixed_be::<32>(d)?)),
            // libgcrypt stores the X25519 scalar as a big-endian MPI, the
            // reverse of the native little-endian encoding.
            Curve::Curve25519 => Self::X25519(x25519_secret(d, material.get("q"))?),
            Curve::NistP256 => Self::EcdsaP256(
                P256SigningKey::from_slice(&*fixed_be::<32>(d)?).map_err(|_| Error::Ecdsa)?,
            ),
            Curve::NistP384 => Self::EcdsaP384(
                P384SigningKey::from_slice(&*fixed_be::<48>(d)?).map_err(|_| Error::Ecdsa)?,
            ),
        })
    }
}

/// The X25519 secret, checked against the stored public point when one is
/// present. libgcrypt keeps the scalar as a big-endian MPI, the reverse of
/// the native little-endian encoding.
fn x25519_secret(d: &[u8], q: Option<&[u8]>) -> Result<x25519_dalek::StaticSecret> {
    let mut native = fixed_be::<32>(d)?;
    native.reverse();
    let secret = x25519_dalek::StaticSecret::from(*native);
    if let Some(q) = q {
        let public = x25519_dalek::PublicKey::from(&secret);
        if q.strip_prefix(&[0x40]).unwrap_or(q) != public.as_bytes() {
            return Err(Error::UnsupportedKeyType(
                "Curve25519 secret does not match its public key".into(),
            ));
        }
    }
    Ok(secret)
}

/// A big-endian value as exactly `N` bytes: leading zero bytes dropped
/// (MPIs may carry a sign byte) and short values left-padded.
fn fixed_be<const N: usize>(value: &[u8]) -> Result<Zeroizing<[u8; N]>> {
    let start = value.iter().position(|&b| b != 0).unwrap_or(value.len());
    let digits = &value[start..];
    if digits.len() > N {
        return Err(Error::InvalidMessageFormat);
    }
    let mut out = Zeroizing::new([0u8; N]);
    out[N - digits.len()..].copy_from_slice(digits);
    Ok(out)
}

impl GpgKey {
    pub fn sign(&self, hash: &[u8], algo: u32) -> Result<GpgSignature> {
        match &self.key_type {
            GpgKeyType::Rsa(key) => sign_rsa(key, hash, algo),
            GpgKeyType::Ed25519(key) => Ok(sign_ed25519(key, hash)),
            GpgKeyType::EcdsaP256(key) => sign_ecdsa_p256(key, hash),
            GpgKeyType::EcdsaP384(key) => sign_ecdsa_p384(key, hash),
            GpgKeyType::X25519(_) => Err(Error::UnsupportedAlgorithm(
                "Curve25519 keys only decrypt".into(),
            )),
        }
    }

    /// Answer a classic PKDECRYPT: given gpg's `(enc-val ...)`, return the
    /// `(5:value...)` gpg-agent sends back. For RSA that is the raw PKCS#1
    /// block (gpg removes the padding); for ECDH it is the shared point
    /// (gpg runs the KDF and unwraps the session key).
    pub fn decrypt(&self, enc_val: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let root = parse_canonical(enc_val)?;
        let params = enc_val_params(&root, &[b"rsa", b"ecdh", b"elg"])?;
        let value = match &self.key_type {
            GpgKeyType::Rsa(key) => {
                let c = rsa::BigUint::from_bytes_be(param(params, "a")?);
                let m = rsa::hazmat::rsa_decrypt_and_check(
                    key.as_ref(),
                    Some(&mut rand::rngs::OsRng),
                    &c,
                )?;
                Zeroizing::new(m.to_bytes_be())
            }
            _ => self.ecdh_point(param(params, "e")?)?,
        };
        Ok(value_sexp(&value))
    }

    /// Answer `PKDECRYPT --kem=PGP` (GnuPG 2.5): the agent does the whole
    /// OpenPGP ECDH step (RFC 6637) and returns the unwrapped session key,
    /// as `ecc_kem_decrypt` in gpg-agent's `pkdecrypt.c`.
    pub fn kem_decrypt_pgp(&self, enc_val: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let root = parse_canonical(enc_val)?;
        let params = enc_val_params(&root, &[b"ecc"])?;
        let number = |name: &'static str| -> Result<u32> {
            std::str::from_utf8(param(params, name)?)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or(Error::InvalidMessageFormat)
        };
        let point = self.ecdh_point(param(params, "e")?)?;
        // Z: the X25519 output, or a NIST point's x-coordinate.
        let z = match point.split_first() {
            Some((0x40, rest)) => rest,
            Some((0x04, rest)) => &rest[..rest.len() / 2],
            _ => return Err(Error::InvalidMessageFormat),
        };

        let kek_len = match number("c")? {
            7 => 16,
            8 => 24,
            9 => 32,
            other => return Err(Error::UnsupportedAlgorithm(format!("KEK cipher {other}"))),
        };
        let kdf_params = param(params, "kdf-params")?;
        let kek = match number("h")? {
            8 => one_step_kdf::<Sha256>(z, kdf_params, kek_len),
            9 => one_step_kdf::<Sha384>(z, kdf_params, kek_len),
            10 => one_step_kdf::<Sha512>(z, kdf_params, kek_len),
            other => return Err(Error::UnsupportedAlgorithm(format!("KDF hash {other}"))),
        };

        // `s` is a length octet followed by the AES-wrapped session key.
        let wrapped = param(params, "s")?;
        let (&len, wrapped) = wrapped.split_first().ok_or(Error::InvalidMessageFormat)?;
        if usize::from(len) != wrapped.len() {
            return Err(Error::InvalidMessageFormat);
        }
        let unwrapped = match kek_len {
            16 => aes_kw::KekAes128::from(<[u8; 16]>::try_from(&kek[..]).expect("16-byte KEK"))
                .unwrap_vec(wrapped),
            24 => aes_kw::KekAes192::from(<[u8; 24]>::try_from(&kek[..]).expect("24-byte KEK"))
                .unwrap_vec(wrapped),
            _ => aes_kw::KekAes256::from(<[u8; 32]>::try_from(&kek[..]).expect("32-byte KEK"))
                .unwrap_vec(wrapped),
        }
        .map_err(|_| Error::KeyDecryptionFailed)?;
        Ok(value_sexp(&Zeroizing::new(unwrapped)))
    }

    /// ECDH with the ephemeral point `e`, in the agent's point format:
    /// `0x40 || x` for Curve25519, `0x04 || X || Y` for NIST curves.
    fn ecdh_point(&self, e: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(match &self.key_type {
            GpgKeyType::X25519(secret) => {
                let point: [u8; 32] = e
                    .strip_prefix(&[0x40])
                    .unwrap_or(e)
                    .try_into()
                    .map_err(|_| Error::InvalidMessageFormat)?;
                let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(point));
                if !shared.was_contributory() {
                    return Err(Error::InvalidMessageFormat);
                }
                Zeroizing::new([&[0x40][..], shared.as_bytes()].concat())
            }
            GpgKeyType::EcdsaP256(key) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                let point = p256::PublicKey::from_sec1_bytes(e).map_err(|_| Error::Ecdsa)?;
                let shared = (point.to_projective() * **key.as_nonzero_scalar()).to_affine();
                Zeroizing::new(shared.to_encoded_point(false).as_bytes().to_vec())
            }
            GpgKeyType::EcdsaP384(key) => {
                use p384::elliptic_curve::sec1::ToEncodedPoint;
                let point = p384::PublicKey::from_sec1_bytes(e).map_err(|_| Error::Ecdsa)?;
                let shared = (point.to_projective() * **key.as_nonzero_scalar()).to_affine();
                Zeroizing::new(shared.to_encoded_point(false).as_bytes().to_vec())
            }
            GpgKeyType::Rsa(_) | GpgKeyType::Ed25519(_) => {
                return Err(Error::UnsupportedAlgorithm("not an ECDH key".into()));
            }
        })
    }
}

/// The algorithm list inside `(enc-val ... (ALGO (NAME VALUE)...))`.
fn enc_val_params<'a>(root: &'a SexpNode, algos: &[&[u8]]) -> Result<&'a [SexpNode]> {
    if root.name() != Some(b"enc-val") {
        return Err(Error::SexpParse("expected enc-val".into()));
    }
    root.as_list()
        .unwrap_or_default()
        .iter()
        .skip(1)
        .find(|item| item.name().is_some_and(|name| algos.contains(&name)))
        .and_then(SexpNode::as_list)
        .ok_or_else(|| Error::SexpParse("unsupported enc-val algorithm".into()))
}

fn param<'a>(params: &'a [SexpNode], name: &'static str) -> Result<&'a [u8]> {
    params
        .iter()
        .find(|item| item.name() == Some(name.as_bytes()))
        .and_then(|item| item.as_list()?.get(1)?.as_atom())
        .ok_or(Error::MissingField(name))
}

fn value_sexp(value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len() + 16));
    push_param(&mut out, b"value", value);
    out
}

/// NIST SP 800-56C one-step KDF as OpenPGP ECDH uses it (RFC 6637
/// section 7): `Hash(counter || Z || params)` with a 32-bit big-endian
/// counter from 1, concatenated until `len` bytes.
fn one_step_kdf<D: sha2::Digest>(z: &[u8], params: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    let mut counter = 1u32;
    while out.len() < len {
        let mut hasher = D::new();
        hasher.update(counter.to_be_bytes());
        hasher.update(z);
        hasher.update(params);
        let digest = hasher.finalize();
        let take = (len - out.len()).min(digest.len());
        out.extend_from_slice(&digest[..take]);
        counter += 1;
    }
    out
}

fn sign_rsa(key: &RsaPrivateKey, hash: &[u8], algo: u32) -> Result<GpgSignature> {
    let sig = match algo {
        8 => RsaSigningKey::<Sha256>::new(key.clone()).sign_prehash(hash),
        9 => RsaSigningKey::<Sha384>::new(key.clone()).sign_prehash(hash),
        10 => RsaSigningKey::<Sha512>::new(key.clone()).sign_prehash(hash),
        _ => return Err(Error::UnsupportedAlgorithm(format!("hash algo {algo}"))),
    }
    .map_err(|_| Error::SigningFailed)?;
    Ok(GpgSignature::Rsa(sig.to_vec()))
}

fn sign_ed25519(key: &SigningKey, data: &[u8]) -> GpgSignature {
    // Ed25519 signature is R (32 bytes) || S (32 bytes); gpg's eddsa sig-val
    // wants them as two separate MPIs.
    let bytes = key.sign(data).to_bytes();
    GpgSignature::EdDsa {
        r: bytes[..32].to_vec(),
        s: bytes[32..].to_vec(),
    }
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
        if path.extension().is_none_or(|extension| extension != "key") {
            continue;
        }
        let keygrip = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_uppercase();
        if keygrip.len() != 40 || !keygrip.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }

        match read_key_file(&path, passphrase).and_then(|m| GpgKeyType::from_material(&m)) {
            Ok(key_type) => {
                info!("loaded GPG key: {}", keygrip);
                keys.push(GpgKey { keygrip, key_type });
            }
            Err(e) => warn!("skipping GPG key {:?}: {}", path, e),
        }
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_be_strips_sign_bytes_and_pads() {
        assert_eq!(*fixed_be::<4>(&[0, 0, 1, 2]).unwrap(), [0, 0, 1, 2]);
        assert_eq!(
            *fixed_be::<4>(&[0, 0xAA, 1, 2, 3]).unwrap(),
            [0xAA, 1, 2, 3]
        );
        assert_eq!(*fixed_be::<4>(&[7]).unwrap(), [0, 0, 0, 7]);
        assert!(fixed_be::<2>(&[1, 2, 3]).is_err());
    }

    #[test]
    fn x25519_secret_must_match_its_public_key() {
        let d = [0x11u8; 32];
        let wrong_q = [&[0x40][..], &[0u8; 32]].concat();
        assert!(x25519_secret(&d, Some(&wrong_q)).is_err());
        let mut native = d;
        native.reverse();
        let right = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(native));
        let right_q = [&[0x40][..], right.as_bytes()].concat();
        assert!(x25519_secret(&d, Some(&right_q)).is_ok());
    }

    #[test]
    fn one_step_kdf_matches_rfc6637_construction() {
        use sha2::Digest;
        let expected = Sha256::digest([&[0, 0, 0, 1][..], b"Z", b"P"].concat());
        assert_eq!(*one_step_kdf::<Sha256>(b"Z", b"P", 16), expected[..16]);
    }

    #[test]
    fn x25519_decrypt_returns_prefixed_shared_point() {
        let our_native = [0x11u8; 32];
        let mut stored = our_native;
        stored.reverse();
        let material = KeyMaterial {
            algo: "ecc".into(),
            curve: Some("Curve25519".into()),
            flags: vec!["djb-tweak".into()],
            params: vec![("d".into(), Zeroizing::new(stored.to_vec()))],
        };
        let key = GpgKey {
            keygrip: "A".repeat(40),
            key_type: GpgKeyType::from_material(&material).unwrap(),
        };
        let ephemeral = x25519_dalek::StaticSecret::from([0x22u8; 32]);
        let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral);
        let ours_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(our_native));

        let mut enc = b"(7:enc-val(4:ecdh(1:s2:\x01\x02)".to_vec();
        push_param(
            &mut enc,
            b"e",
            &[&[0x40][..], ephemeral_pub.as_bytes()].concat(),
        );
        enc.extend_from_slice(b"))");

        let out = key.decrypt(&enc).unwrap();
        let expected = ephemeral.diffie_hellman(&ours_pub);
        let mut want = b"(5:value33:\x40".to_vec();
        want.extend_from_slice(expected.as_bytes());
        want.push(b')');
        assert_eq!(*out, want);
    }
}
