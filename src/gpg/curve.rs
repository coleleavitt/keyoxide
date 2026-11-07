//! The elliptic curves keyoxide supports, by GnuPG/libgcrypt name.

/// Curves gpg-agent keys may use that keyoxide can serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    Ed25519,
    Curve25519,
    NistP256,
    NistP384,
}

impl Curve {
    /// Map a libgcrypt curve name, alias, or OID (`find_domain_parms_idx`).
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "Ed25519" | "ed25519" | "1.3.6.1.4.1.11591.15.1" | "1.3.101.112" => Self::Ed25519,
            "Curve25519" | "cv25519" | "X25519" | "1.3.6.1.4.1.3029.1.5.1" | "1.3.101.110" => {
                Self::Curve25519
            }
            "NIST P-256" | "nistp256" | "prime256v1" | "secp256r1" | "1.2.840.10045.3.1.7" => {
                Self::NistP256
            }
            "NIST P-384" | "nistp384" | "secp384r1" | "1.3.132.0.34" => Self::NistP384,
            _ => return None,
        })
    }

    /// The canonical name gpg-agent writes into key files.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Curve25519 => "Curve25519",
            Self::NistP256 => "NIST P-256",
            Self::NistP384 => "NIST P-384",
        }
    }

    /// The `(flags ...)` gpg-agent records for this curve (`convert_secret_key`).
    pub fn flags(self) -> &'static [&'static str] {
        match self {
            Self::Ed25519 => &["eddsa"],
            Self::Curve25519 => &["djb-tweak"],
            Self::NistP256 | Self::NistP384 => &[],
        }
    }

    /// Domain parameters p, a, b, n, gx, gy as hex, from libgcrypt's
    /// `cipher/ecc-curves.c` (signs dropped: keygrips hash magnitudes).
    pub(crate) fn domain(self) -> [&'static str; 6] {
        match self {
            Self::Ed25519 => [
                "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
                "01",
                "2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A",
                "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
                "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A",
                "6666666666666666666666666666666666666666666666666666666666666658",
            ],
            Self::Curve25519 => [
                "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
                "01DB41",
                "01",
                "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
                "0000000000000000000000000000000000000000000000000000000000000009",
                // The pre-errata g_y libgcrypt keeps so keygrips stay stable.
                "20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9",
            ],
            Self::NistP256 => [
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            ],
            Self::NistP384 => [
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
                "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
                "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
                "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
                "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
            ],
        }
    }
}
