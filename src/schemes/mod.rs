//! Homomorphic encryption schemes implemented from scratch.
//!
//! Each submodule is self-contained and over-commented so it doubles as
//! lecture notes. Performance is a non-goal here — clarity is.

pub mod paillier;
pub mod bfv;
pub mod bgn;
pub mod ckks;

use serde::{Deserialize, Serialize};

/// The set of schemes the CLI knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scheme {
    /// Paillier (1999) — additively homomorphic over ℤ_n.
    Paillier,
    /// BFV-lite — RLWE-based, supports + and a bounded number of ×.
    Bfv,
    /// Boneh–Goh–Nissim — one × then many +. We provide a simplified
    /// non-pairing version for illustration.
    Bgn,
    /// CKKS-lite — approximate arithmetic on real/complex vectors.
    Ckks,
}

impl Scheme {
    /// All schemes supported by this build of `homo`.
    pub fn all() -> &'static [Scheme] {
        &[Scheme::Paillier, Scheme::Bfv, Scheme::Bgn, Scheme::Ckks]
    }

    /// Short, lower-case name used in CLI flags and on disk.
    pub fn short(&self) -> &'static str {
        match self {
            Scheme::Paillier => "paillier",
            Scheme::Bfv => "bfv",
            Scheme::Bgn => "bgn",
            Scheme::Ckks => "ckks",
        }
    }

    /// Human-readable description for `homo schemes`.
    pub fn describe(&self) -> &'static str {
        match self {
            Scheme::Paillier => "additively homomorphic; encrypts integers mod n",
            Scheme::Bfv => "leveled SHE over polynomial rings; supports + and ×",
            Scheme::Bgn => "one multiplication, unlimited additions",
            Scheme::Ckks => "approximate arithmetic on real/complex vectors (the ML scheme)",
        }
    }
}

impl std::str::FromStr for Scheme {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "paillier" => Ok(Scheme::Paillier),
            "bfv" => Ok(Scheme::Bfv),
            "bgn" => Ok(Scheme::Bgn),
            "ckks" => Ok(Scheme::Ckks),
            other => Err(format!("unknown scheme: {other}")),
        }
    }
}
