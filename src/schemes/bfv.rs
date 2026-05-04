//! # BFV-lite — a leveled somewhat-homomorphic scheme
//!
//! This is a stripped-down implementation of the Brakerski–Fan–Vercauteren
//! cryptosystem (Fan & Vercauteren, *"Somewhat Practical Fully Homomorphic
//! Encryption"*, 2012). It supports both addition and a small, bounded
//! number of multiplications before noise overwhelms the message.
//!
//! ## What "lite" means here
//!
//! Real BFV implementations (SEAL, OpenFHE) include:
//!
//! * RNS / double-CRT representation
//! * Number-theoretic transform (NTT) for fast polynomial multiplication
//! * Relinearization keys, modulus switching, automorphisms for batching
//!
//! We skip all of that. Polynomials are stored as plain coefficient
//! vectors and multiplied with schoolbook O(n²). The point is that you
//! can read the whole scheme in 200 lines and trust every step.
//!
//! ## Parameters
//!
//! | symbol | meaning                            | typical value here |
//! |--------|------------------------------------|--------------------|
//! | `n`    | ring degree, a power of 2          | 1024               |
//! | `q`    | ciphertext modulus                 | ~60-bit prime      |
//! | `t`    | plaintext modulus                  | 256 or 1024        |
//! | `Δ`    | scaling factor `⌊q/t⌋`             | derived            |
//! | `χ`    | error distribution (small Gaussian)| η = 6              |
//!
//! ## The scheme in five formulas
//!
//! * **KeyGen**: secret `s ← R₂` (ternary). Public key
//!   `pk = (b = -(a·s + e), a)` for random `a` and small error `e`.
//! * **Encrypt(m)**: pick small `u, e₁, e₂`, return
//!   `(c₀, c₁) = (b·u + e₁ + Δ·m, a·u + e₂)`.
//! * **Decrypt**: `m = ⌊ t · (c₀ + c₁·s) / q ⌉ mod t`.
//! * **Add**: component-wise.
//! * **Mul**: tensor product, then rescale by `t/q`. Output has 3 components
//!   `(d₀, d₁, d₂)`; without a relin key we keep it that way and decryption
//!   uses `d₀ + d₁·s + d₂·s²`.

use crate::util;
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// BFV parameter set. Public, no secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Params {
    /// Ring degree `n`. Must be a power of two.
    pub n: usize,
    /// Ciphertext modulus `q`.
    pub q: BigInt,
    /// Plaintext modulus `t`.
    pub t: BigInt,
    /// Noise distribution parameter (binomial η).
    pub eta: u32,
}

impl Params {
    /// A small toy parameter set good for tests, traces, and lecture demos.
    /// 60-bit `q`, n = 1024, t = 256. Not secure — for teaching only.
    pub fn toy() -> Self {
        Self {
            n: 1024,
            q: BigInt::from(1152921504606846883u64), // ~2^60 prime
            t: BigInt::from(256u32),
            eta: 6,
        }
    }

    /// A slightly larger demo parameter set: n = 2048, ~120-bit q.
    /// Still not production-secure, but slow enough that students can
    /// see the cost.
    pub fn medium() -> Self {
        // 120-bit-ish prime; built as 2^120 - some small offset that we
        // verified primality on once. For a real library we'd generate
        // these via a parameter-selection routine.
        let q = (BigInt::from(1u64) << 120) - BigInt::from(243u32);
        Self {
            n: 2048,
            q,
            t: BigInt::from(1024u32),
            eta: 6,
        }
    }

    /// `Δ = ⌊q / t⌋`, the scaling factor that lifts plaintexts into the
    /// ciphertext space.
    pub fn delta(&self) -> BigInt {
        &self.q / &self.t
    }
}

/// A polynomial in `R_q = ℤ_q[X]/(X^n + 1)`, stored as coefficients of
/// degree 0..n-1. We use signed `BigInt` and keep coefficients in centred
/// form `(-q/2, q/2]` to make noise analysis natural.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poly {
    /// The coefficients, length exactly `params.n`.
    pub coeffs: Vec<BigInt>,
}

impl Poly {
    /// All-zero polynomial.
    pub fn zero(n: usize) -> Self {
        Self {
            coeffs: vec![BigInt::zero(); n],
        }
    }

    /// Sample a uniformly random polynomial in `R_q`.
    pub fn rand_uniform<R: RngCore>(rng: &mut R, params: &Params) -> Self {
        let q_u = params.q.to_biguint().expect("q is non-negative");
        let mut out = Vec::with_capacity(params.n);
        for _ in 0..params.n {
            let r = util::rand_below(rng, &q_u);
            out.push(centre(&BigInt::from(r), &params.q));
        }
        Self { coeffs: out }
    }

    /// Sample a small noise polynomial (binomial-distributed coefficients).
    pub fn rand_noise<R: RngCore>(rng: &mut R, params: &Params) -> Self {
        let mut out = Vec::with_capacity(params.n);
        for _ in 0..params.n {
            out.push(BigInt::from(util::sample_small_noise(rng, params.eta)));
        }
        Self { coeffs: out }
    }

    /// Sample a ternary polynomial in `{-1, 0, 1}^n`. Used for secret keys.
    pub fn rand_ternary<R: RngCore>(rng: &mut R, params: &Params) -> Self {
        let mut out = Vec::with_capacity(params.n);
        for _ in 0..params.n {
            let bits = rng.next_u32();
            let v = match bits & 0b11 {
                0 => -1,
                1 => 1,
                _ => 0,
            };
            out.push(BigInt::from(v));
        }
        Self { coeffs: out }
    }

    /// Lift a small plaintext (coefficients in `[0, t)`) into `R_q`.
    pub fn from_plain(plain: &[u64], params: &Params) -> Self {
        let mut coeffs = vec![BigInt::zero(); params.n];
        for (i, &v) in plain.iter().enumerate().take(params.n) {
            coeffs[i] = BigInt::from(v);
        }
        Self { coeffs }
    }

    /// Reduce all coefficients into the centred range `(-q/2, q/2]`.
    pub fn reduce(&mut self, q: &BigInt) {
        for c in &mut self.coeffs {
            *c = centre(c, q);
        }
    }

    /// The infinity norm — i.e. the largest absolute coefficient. This is
    /// the standard "noise size" measure for BFV/BGV schemes.
    pub fn inf_norm(&self) -> BigInt {
        self.coeffs
            .iter()
            .map(|c| c.abs())
            .max()
            .unwrap_or_else(BigInt::zero)
    }
}

/// Reduce `x` into the centred residue system `(-q/2, q/2]`.
fn centre(x: &BigInt, q: &BigInt) -> BigInt {
    let half = q / 2;
    let mut r = x % q;
    if r > half {
        r -= q;
    } else if r <= -&half {
        r += q;
    }
    r
}

/// Polynomial addition mod `q` in `R_q`.
pub fn poly_add(a: &Poly, b: &Poly, q: &BigInt) -> Poly {
    let n = a.coeffs.len();
    debug_assert_eq!(n, b.coeffs.len());
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(centre(&(&a.coeffs[i] + &b.coeffs[i]), q));
    }
    Poly { coeffs: out }
}

/// Polynomial subtraction mod `q`.
pub fn poly_sub(a: &Poly, b: &Poly, q: &BigInt) -> Poly {
    let n = a.coeffs.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(centre(&(&a.coeffs[i] - &b.coeffs[i]), q));
    }
    Poly { coeffs: out }
}

/// Schoolbook polynomial multiplication in `R_q = ℤ_q[X]/(X^n + 1)`.
///
/// The negacyclic reduction `X^n = -1` is handled by subtracting wrap-around
/// terms. O(n²) — the simplest possible implementation.
pub fn poly_mul(a: &Poly, b: &Poly, q: &BigInt) -> Poly {
    let n = a.coeffs.len();
    debug_assert_eq!(n, b.coeffs.len());
    let mut acc = vec![BigInt::zero(); n];
    for i in 0..n {
        if a.coeffs[i].is_zero() {
            continue;
        }
        for j in 0..n {
            let prod = &a.coeffs[i] * &b.coeffs[j];
            let k = i + j;
            if k < n {
                acc[k] += prod;
            } else {
                // Negacyclic wrap: X^n ≡ -1.
                acc[k - n] -= prod;
            }
        }
    }
    for c in &mut acc {
        *c = centre(c, q);
    }
    Poly { coeffs: acc }
}

/// Multiply every coefficient by a scalar then reduce.
pub fn poly_scalar(a: &Poly, k: &BigInt, q: &BigInt) -> Poly {
    let mut out = Vec::with_capacity(a.coeffs.len());
    for c in &a.coeffs {
        out.push(centre(&(c * k), q));
    }
    Poly { coeffs: out }
}

/// BFV public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// First component, `b = -(a·s + e)`.
    pub b: Poly,
    /// Second component, uniform random `a`.
    pub a: Poly,
    /// Parameters in use.
    pub params: Params,
}

/// BFV secret key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKey {
    /// The ternary secret `s`.
    pub s: Poly,
    /// Parameters in use.
    pub params: Params,
}

/// A BFV ciphertext. Ordinarily two components; after multiplication and
/// before relinearisation it grows to three.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    /// The polynomial components, length 2 (fresh) or 3 (post-mul).
    pub parts: Vec<Poly>,
    /// Parameters used. Stored on the ciphertext so a recipient who has
    /// the secret key can verify they match.
    pub params: Params,
}

impl Ciphertext {
    /// How many polynomial components this ciphertext currently has.
    pub fn size(&self) -> usize {
        self.parts.len()
    }
}

/// Generate a fresh BFV key pair under the given parameters.
pub fn keygen(params: &Params) -> (PublicKey, SecretKey) {
    let mut rng = util::rng();
    let s = Poly::rand_ternary(&mut rng, params);
    let a = Poly::rand_uniform(&mut rng, params);
    let e = Poly::rand_noise(&mut rng, params);
    let a_s = poly_mul(&a, &s, &params.q);
    let a_s_plus_e = poly_add(&a_s, &e, &params.q);
    let b = poly_neg(&a_s_plus_e, &params.q);
    (
        PublicKey {
            b,
            a,
            params: params.clone(),
        },
        SecretKey {
            s,
            params: params.clone(),
        },
    )
}

/// Negate every coefficient of `p` in `R_q`.
pub fn poly_neg(p: &Poly, q: &BigInt) -> Poly {
    let mut out = Vec::with_capacity(p.coeffs.len());
    for c in &p.coeffs {
        out.push(centre(&-c, q));
    }
    Poly { coeffs: out }
}

/// Encrypt a vector of plaintext coefficients (each in `[0, t)`).
///
/// Plaintext shorter than `n` is zero-padded; longer is truncated.
pub fn encrypt(pk: &PublicKey, plain: &[u64]) -> Ciphertext {
    let mut rng = util::rng();
    let params = &pk.params;
    let m = Poly::from_plain(plain, params);
    let delta = params.delta();
    let delta_m = poly_scalar(&m, &delta, &params.q);

    let u = Poly::rand_ternary(&mut rng, params);
    let e1 = Poly::rand_noise(&mut rng, params);
    let e2 = Poly::rand_noise(&mut rng, params);

    let bu = poly_mul(&pk.b, &u, &params.q);
    let au = poly_mul(&pk.a, &u, &params.q);

    // c0 = b·u + e1 + Δ·m
    let c0 = poly_add(&poly_add(&bu, &e1, &params.q), &delta_m, &params.q);
    // c1 = a·u + e2
    let c1 = poly_add(&au, &e2, &params.q);

    Ciphertext {
        parts: vec![c0, c1],
        params: params.clone(),
    }
}

/// Decrypt a ciphertext back to plaintext coefficients in `[0, t)`.
///
/// Works on ciphertexts of size 2 (fresh) or size 3 (after one multiplication
/// without relinearisation).
pub fn decrypt(sk: &SecretKey, ct: &Ciphertext) -> Vec<u64> {
    let params = &sk.params;
    // Compute c₀ + c₁·s + c₂·s² + ...
    let mut acc = ct.parts[0].clone();
    let mut s_power = ct.parts[0].coeffs.clone(); // placeholder
    if ct.parts.len() >= 2 {
        s_power = sk.s.coeffs.clone();
        let term = poly_mul(&ct.parts[1], &sk.s, &params.q);
        acc = poly_add(&acc, &term, &params.q);
    }
    if ct.parts.len() >= 3 {
        let s_sq_poly = poly_mul(&Poly { coeffs: s_power }, &sk.s, &params.q);
        let term = poly_mul(&ct.parts[2], &s_sq_poly, &params.q);
        acc = poly_add(&acc, &term, &params.q);
    }
    if ct.parts.len() >= 4 {
        // We don't support cubic+ ciphertexts — that would mean two un-relinearised
        // multiplications, which BFV-lite doesn't aim to handle.
        panic!("ciphertext degree too high; not supported in BFV-lite");
    }

    // Scale by t/q and round to nearest integer, then reduce mod t.
    let t = &params.t;
    let q = &params.q;
    let mut out = Vec::with_capacity(params.n);
    for coeff in &acc.coeffs {
        // Round to nearest: ⌊(t · coeff + q/2) / q⌉
        let scaled = coeff * t;
        let rounded = round_div(&scaled, q);
        let mut reduced = &rounded % t;
        if reduced < BigInt::zero() {
            reduced += t;
        }
        out.push(reduced.try_into().unwrap_or(0u64));
    }
    out
}

/// Round `num / den` to nearest integer (toward +∞ on tie).
fn round_div(num: &BigInt, den: &BigInt) -> BigInt {
    let half = den / 2;
    if num >= &BigInt::zero() {
        (num + &half) / den
    } else {
        (num - &half) / den
    }
}

/// Homomorphic addition: component-wise sum.
///
/// Returns a ciphertext of size = max(len(a), len(b)). Both must use the
/// same parameter set.
pub fn add(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    let q = &a.params.q;
    let n = a.parts.len().max(b.parts.len());
    let mut parts = Vec::with_capacity(n);
    for i in 0..n {
        match (a.parts.get(i), b.parts.get(i)) {
            (Some(x), Some(y)) => parts.push(poly_add(x, y, q)),
            (Some(x), None) | (None, Some(x)) => parts.push(x.clone()),
            (None, None) => unreachable!(),
        }
    }
    Ciphertext {
        parts,
        params: a.params.clone(),
    }
}

/// Homomorphic multiplication of two size-2 ciphertexts. Produces a size-3
/// ciphertext that decrypts under `(s, s²)`.
///
/// We follow the textbook tensor formula:
///
/// ```text
///   d_0 = round((t/q) · c₀·c₀')
///   d_1 = round((t/q) · (c₀·c₁' + c₁·c₀'))
///   d_2 = round((t/q) · c₁·c₁')
/// ```
///
/// Without a relinearisation key we can't bring it back down to size 2,
/// so a second homomorphic multiplication is not supported.
pub fn mul(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    assert_eq!(
        a.parts.len(),
        2,
        "BFV-lite only multiplies fresh ciphertexts"
    );
    assert_eq!(
        b.parts.len(),
        2,
        "BFV-lite only multiplies fresh ciphertexts"
    );
    let params = &a.params;
    let q = &params.q;
    let t = &params.t;

    // Tensor over the integers — we do NOT reduce mod q yet, since the
    // intermediate values can exceed q before the rescale.
    let d0 = poly_mul_unreduced(&a.parts[0], &b.parts[0], params.n);
    let d1_a = poly_mul_unreduced(&a.parts[0], &b.parts[1], params.n);
    let d1_b = poly_mul_unreduced(&a.parts[1], &b.parts[0], params.n);
    let d1: Vec<BigInt> = d1_a.iter().zip(d1_b.iter()).map(|(x, y)| x + y).collect();
    let d2 = poly_mul_unreduced(&a.parts[1], &b.parts[1], params.n);

    // Rescale: multiply by t, divide by q with rounding, reduce mod q.
    let d0 = rescale(&d0, t, q);
    let d1 = rescale(&d1, t, q);
    let d2 = rescale(&d2, t, q);

    Ciphertext {
        parts: vec![d0, d1, d2],
        params: params.clone(),
    }
}

/// Schoolbook multiplication *without* any modular reduction. Output is the
/// "true" integer polynomial in `ℤ[X]/(X^n + 1)`.
fn poly_mul_unreduced(a: &Poly, b: &Poly, n: usize) -> Vec<BigInt> {
    let mut acc = vec![BigInt::zero(); n];
    for i in 0..n {
        if a.coeffs[i].is_zero() {
            continue;
        }
        for j in 0..n {
            let prod = &a.coeffs[i] * &b.coeffs[j];
            let k = i + j;
            if k < n {
                acc[k] += prod;
            } else {
                acc[k - n] -= prod;
            }
        }
    }
    acc
}

/// Apply the BFV rescale: `out = round(t · in / q) mod q`, coefficient-wise.
fn rescale(coeffs: &[BigInt], t: &BigInt, q: &BigInt) -> Poly {
    let mut out = Vec::with_capacity(coeffs.len());
    for c in coeffs {
        let scaled = c * t;
        let rounded = round_div(&scaled, q);
        out.push(centre(&rounded, q));
    }
    Poly { coeffs: out }
}

/// Estimate the noise inside a ciphertext, given the secret key.
///
/// Returns `(noise_size, log2_noise, log2_budget)` where `log2_budget` is
/// roughly how many bits of headroom remain before decryption fails.
///
/// This routine *uses* the secret key, so it's only safe to call from the
/// owner — the CLI wires it behind `homo inspect --secret`.
pub fn noise_estimate(sk: &SecretKey, ct: &Ciphertext) -> (BigInt, f64, f64) {
    let params = &sk.params;
    // m_lift = c₀ + c₁·s + c₂·s²  (mod q)
    let mut acc = ct.parts[0].clone();
    if ct.parts.len() >= 2 {
        acc = poly_add(&acc, &poly_mul(&ct.parts[1], &sk.s, &params.q), &params.q);
    }
    if ct.parts.len() >= 3 {
        let s_sq = poly_mul(&sk.s, &sk.s, &params.q);
        acc = poly_add(&acc, &poly_mul(&ct.parts[2], &s_sq, &params.q), &params.q);
    }
    // Compare against the nearest multiple of Δ: noise = acc - Δ·round(acc/Δ).
    let delta = params.delta();
    let mut max_noise = BigInt::zero();
    for c in &acc.coeffs {
        let q = round_div(c, &delta);
        let noise = c - &q * &delta;
        let abs = noise.abs();
        if abs > max_noise {
            max_noise = abs;
        }
    }

    let log2_noise = bigint_log2(&max_noise);
    let log2_q = bigint_log2(&params.q);
    let log2_t = bigint_log2(&params.t);
    // Decryption succeeds while noise < Δ/2 ≈ q/(2t). So budget ≈ log2(q) - log2(t) - 1 - log2(noise).
    let budget = (log2_q - log2_t - 1.0) - log2_noise;
    (max_noise, log2_noise, budget.max(0.0))
}

/// Approximate `log2(|x|)` for educational displays. Returns 0 for `x = 0`.
pub fn bigint_log2(x: &BigInt) -> f64 {
    let abs = x.abs();
    if abs.is_zero() {
        return 0.0;
    }
    let bits = abs.bits() as i64;
    // We could refine via leading bytes but bit count is enough for a
    // human-readable noise display.
    (bits - 1) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_params() -> Params {
        Params {
            n: 64,
            q: BigInt::from(1099511627791u64),
            t: BigInt::from(16u32),
            eta: 4,
        }
    }

    #[test]
    fn enc_dec_roundtrip_small() {
        let params = small_params();
        let (pk, sk) = keygen(&params);
        let plain: Vec<u64> = vec![1, 2, 3, 4, 5];
        let ct = encrypt(&pk, &plain);
        let out = decrypt(&sk, &ct);
        assert_eq!(&out[..plain.len()], &plain[..]);
    }

    #[test]
    fn homomorphic_add() {
        let params = small_params();
        let (pk, sk) = keygen(&params);
        let a: Vec<u64> = vec![1, 2, 3];
        let b: Vec<u64> = vec![4, 5, 6];
        let ct_a = encrypt(&pk, &a);
        let ct_b = encrypt(&pk, &b);
        let sum = add(&ct_a, &ct_b);
        let out = decrypt(&sk, &sum);
        assert_eq!(&out[..3], &[5, 7, 9]);
    }

    #[test]
    fn homomorphic_mul() {
        let params = small_params();
        let (pk, sk) = keygen(&params);
        let a: Vec<u64> = vec![2, 0, 0, 0];
        let b: Vec<u64> = vec![3, 0, 0, 0];
        let ct_a = encrypt(&pk, &a);
        let ct_b = encrypt(&pk, &b);
        let prod = mul(&ct_a, &ct_b);
        let out = decrypt(&sk, &prod);
        assert_eq!(out[0], 6);
    }
}
