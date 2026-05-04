//! # homo — a homomorphic encryption tool
//!
//! `homo` is a command-line utility for homomorphic encryption, designed
//! to be both a *practical* tool (like `openssl` or `gpg`) and a *teaching*
//! instrument that exposes every step of the math.
//!
//! ## Schemes
//!
//! - [`schemes::paillier`] — additively homomorphic, based on the decisional
//!   composite residuosity assumption. Encrypts integers; supports Enc(a)+Enc(b)
//!   and Enc(a)*k for plaintext k.
//! - [`schemes::bfv`] — a simplified BFV/RLWE somewhat-homomorphic scheme
//!   that supports both addition and a bounded number of multiplications.
//!   Operates on polynomial slots.
//! - [`schemes::bgn`] — Boneh–Goh–Nissim style scheme illustrating the
//!   "one multiplication then unlimited additions" trade-off.
//!
//! ## Crate layout
//!
//! - [`schemes`]   — the cryptosystems themselves
//! - [`viz`]       — ASCII diagrams, traces, noise plots
//! - [`playground`] — REPL & circuit evaluator
//! - [`attacks`]   — textbook attacks for educational use
//! - [`bench`]     — micro-benchmarks
//! - [`io`]        — wire formats for keys & ciphertexts
//! - [`util`]      — shared utilities (RNG, modular arith helpers)

#![warn(missing_docs)]
#![allow(clippy::needless_range_loop)]

pub mod schemes;
pub mod viz;
pub mod playground;
pub mod attacks;
pub mod bench;
pub mod io;
pub mod util;

/// The crate version, exposed as a string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A short tagline shown in `homo --version` and on the REPL banner.
pub const TAGLINE: &str = "homomorphic encryption, made tangible";
