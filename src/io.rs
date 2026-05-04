//! On-disk wire formats for keys and ciphertexts.
//!
//! `homo` stores keys and ciphertexts as small JSON envelopes that begin with
//! a magic line — like `-----BEGIN HOMO PAILLIER PUBLIC KEY-----`. This makes
//! files self-describing, easy to grep, and compatible with anything that can
//! handle text. Inside the envelope, the payload is base64-encoded `bincode`.

use crate::schemes::{bfv, bgn, ckks, paillier, Scheme};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Discriminator for the four kinds of objects we put on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    /// A public key.
    PublicKey,
    /// A secret key.
    SecretKey,
    /// A ciphertext.
    Ciphertext,
    /// A circuit description.
    Circuit,
}

impl Kind {
    fn label(&self) -> &'static str {
        match self {
            Kind::PublicKey => "PUBLIC KEY",
            Kind::SecretKey => "SECRET KEY",
            Kind::Ciphertext => "CIPHERTEXT",
            Kind::Circuit => "CIRCUIT",
        }
    }
}

/// The on-disk envelope. `kind` and `scheme` are written into the BEGIN/END
/// markers; `data` is the base64'd `bincode` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Format version (currently 1).
    pub version: u32,
    /// Which scheme produced this object.
    pub scheme: Scheme,
    /// What kind of object this is.
    pub kind: Kind,
    /// Base64'd bincode payload.
    pub data: String,
    /// First 8 hex chars of SHA-256(payload), for human-friendly identifying.
    pub fingerprint: String,
}

impl Envelope {
    /// Serialise the envelope as a PEM-style block.
    pub fn to_pem(&self) -> String {
        let json = serde_json::to_string(self).expect("serde_json");
        let label = self.kind.label();
        let scheme = self.scheme.short().to_uppercase();
        format!(
            "-----BEGIN HOMO {scheme} {label}-----\n\
             {body}\n\
             -----END HOMO {scheme} {label}-----\n",
            body = wrap_64(&B64.encode(json.as_bytes())),
        )
    }

    /// Parse a PEM-style block back into an envelope.
    pub fn from_pem(text: &str) -> Result<Self, String> {
        let mut lines = text.lines().filter(|l| !l.is_empty());
        let header = lines.next().ok_or("empty input")?;
        if !header.starts_with("-----BEGIN HOMO ") {
            return Err(format!("bad header: {header}"));
        }
        let body: String = lines.take_while(|l| !l.starts_with("-----END")).collect();
        let raw = B64.decode(body.trim()).map_err(|e| e.to_string())?;
        let json = std::str::from_utf8(&raw).map_err(|e| e.to_string())?;
        serde_json::from_str(json).map_err(|e| e.to_string())
    }
}

fn wrap_64(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 64);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && i % 64 == 0 {
            out.push('\n');
        }
        out.push(ch);
    }
    out
}

fn fingerprint(payload: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(payload);
    let digest = h.finalize();
    let hex: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    hex
}

fn pack<T: Serialize>(scheme: Scheme, kind: Kind, value: &T) -> Envelope {
    let bytes = bincode::serialize(value).expect("bincode");
    Envelope {
        version: 1,
        scheme,
        kind,
        fingerprint: fingerprint(&bytes),
        data: B64.encode(&bytes),
    }
}

fn unpack<T: for<'de> Deserialize<'de>>(env: &Envelope, expected: Kind) -> Result<T, String> {
    if env.kind != expected {
        return Err(format!("expected {:?}, got {:?}", expected, env.kind));
    }
    let bytes = B64.decode(&env.data).map_err(|e| e.to_string())?;
    bincode::deserialize(&bytes).map_err(|e| e.to_string())
}

/// Save bytes to a path, creating parent directories if needed.
pub fn write_file(path: impl AsRef<Path>, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, contents)
}

/// Read a UTF-8 file from disk.
pub fn read_file(path: impl AsRef<Path>) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

// --- Paillier ----------------------------------------------------------------

/// Wrap a Paillier public key into an envelope.
pub fn pack_paillier_pk(pk: &paillier::PublicKey) -> Envelope {
    pack(Scheme::Paillier, Kind::PublicKey, pk)
}
/// Unwrap a Paillier public key from an envelope.
pub fn unpack_paillier_pk(env: &Envelope) -> Result<paillier::PublicKey, String> {
    unpack(env, Kind::PublicKey)
}
/// Wrap a Paillier secret key into an envelope.
pub fn pack_paillier_sk(sk: &paillier::SecretKey) -> Envelope {
    pack(Scheme::Paillier, Kind::SecretKey, sk)
}
/// Unwrap a Paillier secret key from an envelope.
pub fn unpack_paillier_sk(env: &Envelope) -> Result<paillier::SecretKey, String> {
    unpack(env, Kind::SecretKey)
}
/// Wrap a Paillier ciphertext into an envelope.
pub fn pack_paillier_ct(ct: &paillier::Ciphertext) -> Envelope {
    pack(Scheme::Paillier, Kind::Ciphertext, ct)
}
/// Unwrap a Paillier ciphertext from an envelope.
pub fn unpack_paillier_ct(env: &Envelope) -> Result<paillier::Ciphertext, String> {
    unpack(env, Kind::Ciphertext)
}

// --- BFV ---------------------------------------------------------------------

/// Wrap a BFV public key into an envelope.
pub fn pack_bfv_pk(pk: &bfv::PublicKey) -> Envelope {
    pack(Scheme::Bfv, Kind::PublicKey, pk)
}
/// Unwrap a BFV public key from an envelope.
pub fn unpack_bfv_pk(env: &Envelope) -> Result<bfv::PublicKey, String> {
    unpack(env, Kind::PublicKey)
}
/// Wrap a BFV secret key into an envelope.
pub fn pack_bfv_sk(sk: &bfv::SecretKey) -> Envelope {
    pack(Scheme::Bfv, Kind::SecretKey, sk)
}
/// Unwrap a BFV secret key from an envelope.
pub fn unpack_bfv_sk(env: &Envelope) -> Result<bfv::SecretKey, String> {
    unpack(env, Kind::SecretKey)
}
/// Wrap a BFV ciphertext into an envelope.
pub fn pack_bfv_ct(ct: &bfv::Ciphertext) -> Envelope {
    pack(Scheme::Bfv, Kind::Ciphertext, ct)
}
/// Unwrap a BFV ciphertext from an envelope.
pub fn unpack_bfv_ct(env: &Envelope) -> Result<bfv::Ciphertext, String> {
    unpack(env, Kind::Ciphertext)
}

// --- BGN ---------------------------------------------------------------------

/// Wrap a BGN public key into an envelope.
pub fn pack_bgn_pk(pk: &bgn::PublicKey) -> Envelope {
    pack(Scheme::Bgn, Kind::PublicKey, pk)
}
/// Unwrap a BGN public key from an envelope.
pub fn unpack_bgn_pk(env: &Envelope) -> Result<bgn::PublicKey, String> {
    unpack(env, Kind::PublicKey)
}
/// Wrap a BGN secret key into an envelope.
pub fn pack_bgn_sk(sk: &bgn::SecretKey) -> Envelope {
    pack(Scheme::Bgn, Kind::SecretKey, sk)
}
/// Unwrap a BGN secret key from an envelope.
pub fn unpack_bgn_sk(env: &Envelope) -> Result<bgn::SecretKey, String> {
    unpack(env, Kind::SecretKey)
}
/// Wrap a BGN level-1 ciphertext into an envelope.
pub fn pack_bgn_ct(ct: &bgn::CiphertextL1) -> Envelope {
    pack(Scheme::Bgn, Kind::Ciphertext, ct)
}
/// Unwrap a BGN level-1 ciphertext from an envelope.
pub fn unpack_bgn_ct(env: &Envelope) -> Result<bgn::CiphertextL1, String> {
    unpack(env, Kind::Ciphertext)
}

// --- CKKS --------------------------------------------------------------------

/// Wrap a CKKS public key into an envelope.
pub fn pack_ckks_pk(pk: &ckks::PublicKey) -> Envelope {
    pack(Scheme::Ckks, Kind::PublicKey, pk)
}
/// Unwrap a CKKS public key from an envelope.
pub fn unpack_ckks_pk(env: &Envelope) -> Result<ckks::PublicKey, String> {
    unpack(env, Kind::PublicKey)
}
/// Wrap a CKKS secret key into an envelope.
pub fn pack_ckks_sk(sk: &ckks::SecretKey) -> Envelope {
    pack(Scheme::Ckks, Kind::SecretKey, sk)
}
/// Unwrap a CKKS secret key from an envelope.
pub fn unpack_ckks_sk(env: &Envelope) -> Result<ckks::SecretKey, String> {
    unpack(env, Kind::SecretKey)
}
/// Wrap a CKKS ciphertext into an envelope.
pub fn pack_ckks_ct(ct: &ckks::Ciphertext) -> Envelope {
    pack(Scheme::Ckks, Kind::Ciphertext, ct)
}
/// Unwrap a CKKS ciphertext from an envelope.
pub fn unpack_ckks_ct(env: &Envelope) -> Result<ckks::Ciphertext, String> {
    unpack(env, Kind::Ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paillier_envelope_roundtrip() {
        let (pk, _sk) = paillier::keygen(64);
        let env = pack_paillier_pk(&pk);
        let pem = env.to_pem();
        let back = Envelope::from_pem(&pem).unwrap();
        let pk2 = unpack_paillier_pk(&back).unwrap();
        assert_eq!(pk.n, pk2.n);
    }
}
