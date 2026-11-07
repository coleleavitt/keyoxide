//! GENKEY: create agent keys the way libgcrypt's `gcry_pk_genkey` lays
//! them out, so gpg-agent can use the files keyoxide writes.

use ed25519_dalek::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use super::curve::Curve;
use super::keyfile::KeyMaterial;
use super::sexp::{SexpNode, push_atom, push_param};
use crate::error::{Error, Result};

/// Generate a key from gpg's `(genkey (ALGO ...))` parameters, e.g.
/// `(genkey(ecc(curve 7:Ed25519)(flags eddsa comp)))` or
/// `(genkey(rsa(nbits 4:3072)))`.
pub fn generate(keyparam: &SexpNode) -> Result<KeyMaterial> {
    if keyparam.name() != Some(b"genkey") {
        return Err(Error::SexpParse("expected (genkey ...)".into()));
    }
    let spec = keyparam
        .as_list()
        .and_then(|items| items.get(1))
        .and_then(SexpNode::as_list)
        .ok_or_else(|| Error::SexpParse("expected (genkey (ALGO ...))".into()))?;
    let value = |name: &str| -> Option<String> {
        spec.iter()
            .find(|item| item.name() == Some(name.as_bytes()))
            .and_then(|item| item.as_list()?.get(1)?.as_atom())
            .map(|v| String::from_utf8_lossy(v).into_owned())
    };
    let algo = spec.first().and_then(SexpNode::as_atom).unwrap_or_default();
    match algo {
        b"rsa" => {
            let bits: usize = value("nbits")
                .and_then(|n| n.parse().ok())
                .ok_or(Error::MissingField("nbits"))?;
            if !(2048..=8192).contains(&bits) {
                return Err(Error::UnsupportedAlgorithm(format!("RSA with {bits} bits")));
            }
            generate_rsa(bits)
        }
        b"ecc" | b"ecdsa" | b"eddsa" | b"ecdh" => {
            let name = value("curve").ok_or(Error::MissingField("curve"))?;
            let curve = Curve::from_name(&name)
                .ok_or_else(|| Error::UnsupportedKeyType(format!("curve {name}")))?;
            Ok(generate_ecc(curve))
        }
        other => Err(Error::UnsupportedAlgorithm(format!(
            "key algorithm {}",
            String::from_utf8_lossy(other)
        ))),
    }
}

fn generate_ecc(curve: Curve) -> KeyMaterial {
    let (q, d): (Vec<u8>, Zeroizing<Vec<u8>>) = match curve {
        Curve::Ed25519 => {
            let key = SigningKey::generate(&mut OsRng);
            let q = [&[0x40][..], key.verifying_key().as_bytes()].concat();
            (q, Zeroizing::new(key.to_bytes().to_vec()))
        }
        Curve::Curve25519 => {
            let mut native = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *native);
            native[0] &= 248;
            native[31] &= 127;
            native[31] |= 64;
            let secret = x25519_dalek::StaticSecret::from(*native);
            let q = [
                &[0x40][..],
                x25519_dalek::PublicKey::from(&secret).as_bytes(),
            ]
            .concat();
            // Stored big-endian, the reverse of the native encoding.
            let mut d = Zeroizing::new(native.to_vec());
            d.reverse();
            (q, d)
        }
        Curve::NistP256 => {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let key = p256::SecretKey::random(&mut OsRng);
            let q = key.public_key().to_encoded_point(false).as_bytes().to_vec();
            (q, std_mpi(&key.to_bytes()))
        }
        Curve::NistP384 => {
            use p384::elliptic_curve::sec1::ToEncodedPoint;
            let key = p384::SecretKey::random(&mut OsRng);
            let q = key.public_key().to_encoded_point(false).as_bytes().to_vec();
            (q, std_mpi(&key.to_bytes()))
        }
    };
    KeyMaterial {
        algo: "ecc".into(),
        curve: Some(curve.name().into()),
        flags: curve.flags().iter().map(ToString::to_string).collect(),
        params: vec![("q".into(), Zeroizing::new(q)), ("d".into(), d)],
    }
}

/// RSA in libgcrypt's layout: p < q and u = p^-1 mod q.
fn generate_rsa(bits: usize) -> Result<KeyMaterial> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};

    let key = rsa::RsaPrivateKey::new(&mut OsRng, bits)?;
    let primes = key.primes();
    let (p, q) = if primes[0] < primes[1] {
        (&primes[0], &primes[1])
    } else {
        (&primes[1], &primes[0])
    };
    // q is prime, so p^(q-2) mod q is p's inverse (Fermat).
    let u = p.modpow(&(q - 2u32), q);
    let param =
        |name: &str, value: &rsa::BigUint| (name.to_string(), std_mpi(&value.to_bytes_be()));
    Ok(KeyMaterial {
        algo: "rsa".into(),
        curve: None,
        flags: Vec::new(),
        params: vec![
            param("n", key.n()),
            param("e", key.e()),
            param("d", key.d()),
            param("p", p),
            param("q", q),
            param("u", &u),
        ],
    })
}

/// The `(public-key (ALGO ...))` GENKEY returns to gpg.
pub fn public_key_sexp(material: &KeyMaterial) -> Vec<u8> {
    let public: &[&str] = if material.algo == "rsa" {
        &["n", "e"]
    } else {
        &["q"]
    };
    let mut out = b"(10:public-key(".to_vec();
    push_atom(&mut out, material.algo.as_bytes());
    if let Some(curve) = &material.curve {
        push_param(&mut out, b"curve", curve.as_bytes());
    }
    if !material.flags.is_empty() {
        out.push(b'(');
        push_atom(&mut out, b"flags");
        for flag in &material.flags {
            push_atom(&mut out, flag.as_bytes());
        }
        out.push(b')');
    }
    for name in public {
        if let Some(value) = material.get(name) {
            push_param(&mut out, name.as_bytes(), value);
        }
    }
    out.extend_from_slice(b"))");
    out
}

/// An unsigned big-endian value in libgcrypt's STD form: a 0x00 sign byte
/// in front when the top bit is set, so it is not read as negative.
pub fn std_mpi(value: &[u8]) -> Zeroizing<Vec<u8>> {
    let start = value.iter().position(|&b| b != 0).unwrap_or(value.len());
    let digits = &value[start..];
    let mut out = Zeroizing::new(Vec::with_capacity(digits.len() + 1));
    if digits.first().is_some_and(|b| b & 0x80 != 0) {
        out.push(0);
    }
    out.extend_from_slice(digits);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::keys::GpgKeyType;
    use crate::gpg::sexp::parse_gpg_sexp;

    #[test]
    fn generated_keys_load_as_agent_keys() {
        for param in [
            "(genkey(ecc(curve 7:Ed25519)(flags eddsa comp)))",
            "(genkey(ecc(curve 10:Curve25519)(flags djb-tweak comp)))",
            "(genkey(ecc(curve 10:NIST P-256)(flags nocomp)))",
            "(genkey(ecc(curve 10:NIST P-384)))",
            "(genkey(rsa(nbits 4:2048)))",
        ] {
            let material = generate(&parse_gpg_sexp(param).unwrap()).unwrap();
            GpgKeyType::from_material(&material).unwrap_or_else(|e| panic!("{param}: {e}"));
            let public = public_key_sexp(&material);
            assert!(public.starts_with(b"(10:public-key("), "{param}");
        }
    }

    #[test]
    fn rsa_coefficient_is_p_inverse_mod_q() {
        let material = generate_rsa(2048).unwrap();
        let int = |n| rsa::BigUint::from_bytes_be(material.get(n).unwrap());
        let (p, q, u) = (int("p"), int("q"), int("u"));
        assert!(p < q);
        assert_eq!((p * u) % q, rsa::BigUint::from(1u32));
    }

    #[test]
    fn std_mpi_adds_sign_byte_only_when_needed() {
        assert_eq!(*std_mpi(&[0x80, 1]), [0, 0x80, 1]);
        assert_eq!(*std_mpi(&[0, 0x7f]), [0x7f]);
    }
}
