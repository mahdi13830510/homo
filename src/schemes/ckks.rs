//! # CKKS-lite — approximate-arithmetic homomorphic encryption
//!
//! Cheon, Kim, Kim & Song, *"Homomorphic Encryption for Arithmetic of
//! Approximate Numbers"*, ASIACRYPT 2017.
//!
//! CKKS is the scheme that powers most "ML on encrypted data" demos in the
//! wild: it natively encrypts **vectors of real (or complex) numbers** and
//! supports approximate addition and multiplication. Its defining trick is
//! that messages live in the *same* space as noise, so noise just becomes
//! "rounding error" — and after each multiplication you *rescale* to keep
//! magnitudes manageable.
//!
//! ## What this implementation covers
//!
//! * Slot encoding via the canonical embedding (DFT on `n/2` complex slots)
//! * Symmetric-key encryption (the standard textbook starting point)
//! * Add, scalar mul, ciphertext × ciphertext, **rescale** (the level drop)
//! * Levels, recorded on the ciphertext, decremented by `mul`
//!
//! ## What we deliberately omit (and why)
//!
//! * Public-key encryption — symmetric keeps the introduction cleaner
//! * Relinearisation — would need an extra key and another 200 lines
//! * NTT / RNS — every other scheme here is schoolbook too
//! * Bootstrapping — out of scope
//!
//! Despite "lite", the encode→encrypt→eval→decrypt→decode round-trip is
//! complete and works on real vectors.
//!
//! ## Parameters
//!
//! | symbol | meaning                      | toy value          |
//! |--------|------------------------------|--------------------|
//! | `n`    | ring degree (power of 2)     | 8                  |
//! | `q0`   | base modulus                 | ~2^45              |
//! | `levels` | how many rescales fit     | 3                  |
//! | `q`    | starting modulus  q0·Δ^L     | derived            |
//! | `Δ`    | scale factor per level       | ~2^30              |
//! | `η`    | noise distribution width     | 6                  |

use crate::util;
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use serde::{Deserialize, Serialize};
use std::f64::consts::PI;

/// Public parameters for CKKS-lite. Stored on every key & ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Params {
    /// Ring degree `n`, a power of 2. Plaintext slot count is `n/2`.
    pub n: usize,
    /// The base modulus `q0` (kept after all rescales).
    pub q0: BigInt,
    /// Scale factor `Δ` (a single mul-then-rescale removes one factor of `Δ`).
    pub delta: BigInt,
    /// Maximum number of rescales / levels.
    pub levels: u32,
    /// Noise distribution parameter (binomial η).
    pub eta: u32,
}

impl Params {
    /// A toy parameter set: `n=8`, 3 levels, ~45-bit base modulus, ~30-bit Δ.
    /// Tiny — a CKKS slot-vector here has 4 complex / real entries.
    pub fn toy() -> Self {
        let q0 = BigInt::from(1u64 << 45) - BigInt::from(229u32); // a 45-bit prime-ish
        let delta = BigInt::from(1u64 << 30);
        Self {
            n: 8,
            q0,
            delta,
            levels: 3,
            eta: 6,
        }
    }

    /// A medium parameter set: `n=64`, 4 levels, more headroom.
    pub fn medium() -> Self {
        let q0 = BigInt::from(1u64 << 50) - BigInt::from(569u32);
        let delta = BigInt::from(1u64 << 35);
        Self {
            n: 64,
            q0,
            delta,
            levels: 4,
            eta: 6,
        }
    }

    /// The starting (top-of-modulus-chain) modulus: `q0 · Δ^levels`.
    pub fn q_top(&self) -> BigInt {
        let mut q = self.q0.clone();
        for _ in 0..self.levels {
            q *= &self.delta;
        }
        q
    }

    /// The modulus at a given level (level=0 is the bottom).
    pub fn q_at(&self, level: u32) -> BigInt {
        let mut q = self.q0.clone();
        for _ in 0..level {
            q *= &self.delta;
        }
        q
    }

    /// How many real/complex slots an encoded message has.
    pub fn slot_count(&self) -> usize {
        self.n / 2
    }
}

/// A polynomial in `R_q = ℤ[X]/(X^n + 1)` mod the *current* modulus.
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

    /// Sample a uniform random polynomial mod `q`.
    pub fn rand_uniform(rng: &mut rand_chacha::ChaCha20Rng, n: usize, q: &BigInt) -> Self {
        let q_u = q.to_biguint().expect("q non-negative");
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let r = util::rand_below(rng, &q_u);
            out.push(centre(&BigInt::from(r), q));
        }
        Self { coeffs: out }
    }

    /// Sample a small noise polynomial.
    pub fn rand_noise(rng: &mut rand_chacha::ChaCha20Rng, n: usize, eta: u32) -> Self {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(BigInt::from(util::sample_small_noise(rng, eta)));
        }
        Self { coeffs: out }
    }

    /// Sample a ternary `{-1,0,1}` polynomial. Used for secret keys.
    pub fn rand_ternary(rng: &mut rand_chacha::ChaCha20Rng, n: usize) -> Self {
        use rand::RngCore;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
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

    /// Largest absolute coefficient.
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

/// Negate every coefficient in `R_q`.
pub fn poly_neg(p: &Poly, q: &BigInt) -> Poly {
    let mut out = Vec::with_capacity(p.coeffs.len());
    for c in &p.coeffs {
        out.push(centre(&-c, q));
    }
    Poly { coeffs: out }
}

/// Schoolbook polynomial multiplication in `R_q = ℤ_q[X]/(X^n + 1)`.
pub fn poly_mul(a: &Poly, b: &Poly, q: &BigInt) -> Poly {
    let n = a.coeffs.len();
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
                acc[k - n] -= prod; // negacyclic wrap: X^n = -1
            }
        }
    }
    for c in &mut acc {
        *c = centre(c, q);
    }
    Poly { coeffs: acc }
}

/// Multiply by a scalar.
pub fn poly_scalar(a: &Poly, k: &BigInt, q: &BigInt) -> Poly {
    let mut out = Vec::with_capacity(a.coeffs.len());
    for c in &a.coeffs {
        out.push(centre(&(c * k), q));
    }
    Poly { coeffs: out }
}

// =============================================================================
// Slot encoding via canonical embedding
// =============================================================================

/// A complex number used during encoding/decoding.
#[derive(Debug, Clone, Copy)]
struct C {
    re: f64,
    im: f64,
}

impl C {
    fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }
    fn add(self, o: C) -> C {
        C::new(self.re + o.re, self.im + o.im)
    }
    #[allow(dead_code)]
    fn sub(self, o: C) -> C {
        C::new(self.re - o.re, self.im - o.im)
    }
    fn mul(self, o: C) -> C {
        C::new(
            self.re * o.re - self.im * o.im,
            self.re * o.im + self.im * o.re,
        )
    }
    fn conj(self) -> C {
        C::new(self.re, -self.im)
    }
    fn neg(self) -> C {
        C::new(-self.re, -self.im)
    }
    fn inv(self) -> C {
        let d = self.re * self.re + self.im * self.im;
        C::new(self.re / d, -self.im / d)
    }
}

/// The `n` evaluation points used by the CKKS canonical embedding.
///
/// For ring degree `n` and `m = 2n`, the points are `ζ_m^{5^j}` for
/// `j = 0..n/2-1` (the slots) followed by their complex conjugates
/// `ζ_m^{-5^j}` (which corresponds to `5^j` reflected through `m`).
fn eval_points(n: usize) -> Vec<C> {
    let m = 2 * n;
    let half = n / 2;
    let zeta = |k: i64| -> C {
        let theta = 2.0 * PI * (k as f64) / m as f64;
        C::new(theta.cos(), theta.sin())
    };
    let mut pts = Vec::with_capacity(n);
    let mut powers = Vec::with_capacity(half);
    let mut p: i64 = 1;
    for _ in 0..half {
        powers.push(p);
        p = (p * 5) % m as i64;
    }
    for &p in &powers {
        pts.push(zeta(p));
    }
    for &p in &powers {
        let neg = (m as i64 - p) % m as i64;
        pts.push(zeta(neg));
    }
    pts
}

/// Solve a complex linear system `A·x = b` by Gaussian elimination with
/// partial pivoting. `n ≤ 64` so the cubic cost is negligible.
fn solve(mut a: Vec<Vec<C>>, mut b: Vec<C>) -> Vec<C> {
    let n = b.len();
    for i in 0..n {
        // Partial pivoting on |a[i][i]|.
        let mut best = i;
        let mut best_mag = a[i][i].re * a[i][i].re + a[i][i].im * a[i][i].im;
        for k in i + 1..n {
            let mag = a[k][i].re * a[k][i].re + a[k][i].im * a[k][i].im;
            if mag > best_mag {
                best_mag = mag;
                best = k;
            }
        }
        if best != i {
            a.swap(i, best);
            b.swap(i, best);
        }
        let pinv = a[i][i].inv();
        for j in 0..n {
            a[i][j] = a[i][j].mul(pinv);
        }
        b[i] = b[i].mul(pinv);
        for k in 0..n {
            if k == i {
                continue;
            }
            let f = a[k][i];
            for j in 0..n {
                let term = a[i][j].mul(f).neg();
                a[k][j] = a[k][j].add(term);
            }
            b[k] = b[k].add(b[i].mul(f).neg());
        }
    }
    b
}

/// Encode a real-valued slot vector of length up to `n/2` into a polynomial in
/// `ℤ[X]/(X^n+1)`, scaled by `Δ` and rounded to integers.
///
/// We use the *canonical embedding*: solve the Vandermonde system
/// `V · coeffs = (slots, conj(slots))` where `V[k][i] = ζ_k^i`. The
/// coefficients come out essentially real (imaginary parts are FP noise).
pub fn encode(slots: &[f64], params: &Params) -> Poly {
    let n = params.n;
    let half = n / 2;
    assert!(slots.len() <= half, "too many slots");

    let pts = eval_points(n);

    // Build Vandermonde V[k][i] = pts[k]^i
    let mut v = vec![vec![C::new(0.0, 0.0); n]; n];
    for k in 0..n {
        let mut acc = C::new(1.0, 0.0);
        for i in 0..n {
            v[k][i] = acc;
            acc = acc.mul(pts[k]);
        }
    }

    // RHS: pad slots to half-length, then mirror with conjugates
    let mut rhs = Vec::with_capacity(n);
    for i in 0..half {
        rhs.push(C::new(slots.get(i).copied().unwrap_or(0.0), 0.0));
    }
    for i in 0..half {
        let v = slots.get(i).copied().unwrap_or(0.0);
        rhs.push(C::new(v, 0.0).conj());
    }

    let coeffs_c = solve(v, rhs);
    let delta_f = bigint_to_f64(&params.delta);
    let coeffs: Vec<BigInt> = coeffs_c
        .iter()
        .map(|c| BigInt::from((c.re * delta_f).round() as i128))
        .collect();
    Poly { coeffs }
}

/// Decode a polynomial back to slot values. Inverse of `encode`.
///
/// Evaluates `p(ζ^{5^j})` at each slot point and divides by the scale.
pub fn decode(poly: &Poly, params: &Params, scale: &BigInt) -> Vec<f64> {
    let n = params.n;
    let half = n / 2;
    let scale_f = bigint_to_f64(scale).max(1.0);
    let pts = eval_points(n);

    let mut out = Vec::with_capacity(half);
    for j in 0..half {
        let pt = pts[j];
        let mut acc = C::new(0.0, 0.0);
        let mut x = C::new(1.0, 0.0);
        for i in 0..n {
            let coeff_f = bigint_to_f64(&poly.coeffs[i]);
            acc = acc.add(C::new(coeff_f, 0.0).mul(x));
            x = x.mul(pt);
        }
        out.push(acc.re / scale_f);
    }
    out
}

fn bigint_to_f64(x: &BigInt) -> f64 {
    // For values that fit in i128 we go through that route; otherwise fall back
    // to a string parse. f64 precision (53 bits) is the natural ceiling for
    // CKKS-lite anyway.
    if let Ok(small) = i128::try_from(x.clone()) {
        small as f64
    } else {
        x.to_string().parse::<f64>().unwrap_or(0.0)
    }
}

// =============================================================================
// Keys, ciphertexts
// =============================================================================

/// CKKS-lite public key. We keep params here so a recipient with the secret
/// key can sanity-check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// `b = -(a·s + e)` mod `q_top`.
    pub b: Poly,
    /// Uniform random `a`.
    pub a: Poly,
    /// Parameters in use.
    pub params: Params,
}

/// CKKS-lite secret key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKey {
    /// Ternary secret `s`.
    pub s: Poly,
    /// Parameters in use.
    pub params: Params,
}

/// A CKKS ciphertext. Two components after a fresh encryption, three after
/// a multiplication (since we don't relinearise). Each carries a `level` and
/// a current `scale` — these are the central CKKS book-keeping fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    /// Polynomial components.
    pub parts: Vec<Poly>,
    /// Current modulus level (counts down: `levels` at fresh, `0` after all rescales used).
    pub level: u32,
    /// Current message scale (mul doubles it; rescale divides it back to ~Δ).
    pub scale: BigInt,
    /// Parameters.
    pub params: Params,
}

impl Ciphertext {
    /// The current ciphertext modulus.
    pub fn q(&self) -> BigInt {
        self.params.q_at(self.level)
    }
}

/// Generate a CKKS-lite key pair.
pub fn keygen(params: &Params) -> (PublicKey, SecretKey) {
    let mut rng = util::rng();
    let q = params.q_top();
    let s = Poly::rand_ternary(&mut rng, params.n);
    let a = Poly::rand_uniform(&mut rng, params.n, &q);
    let e = Poly::rand_noise(&mut rng, params.n, params.eta);
    let a_s = poly_mul(&a, &s, &q);
    let b = poly_neg(&poly_add(&a_s, &e, &q), &q);
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

/// Encrypt an already-encoded plaintext polynomial.
pub fn encrypt_poly(pk: &PublicKey, m: &Poly) -> Ciphertext {
    let mut rng = util::rng();
    let params = &pk.params;
    let q = params.q_top();

    let u = Poly::rand_ternary(&mut rng, params.n);
    let e1 = Poly::rand_noise(&mut rng, params.n, params.eta);
    let e2 = Poly::rand_noise(&mut rng, params.n, params.eta);

    // c0 = b·u + e1 + m       (note: no Δ here — m already has Δ baked in)
    // c1 = a·u + e2
    let bu = poly_mul(&pk.b, &u, &q);
    let au = poly_mul(&pk.a, &u, &q);
    let c0 = poly_add(&poly_add(&bu, &e1, &q), m, &q);
    let c1 = poly_add(&au, &e2, &q);

    Ciphertext {
        parts: vec![c0, c1],
        level: params.levels,
        scale: params.delta.clone(),
        params: params.clone(),
    }
}

/// Convenience: encode a real vector and encrypt in one step.
pub fn encrypt(pk: &PublicKey, slots: &[f64]) -> Ciphertext {
    let m = encode(slots, &pk.params);
    encrypt_poly(pk, &m)
}

/// Decrypt to the underlying plaintext polynomial (still scaled).
pub fn decrypt_poly(sk: &SecretKey, ct: &Ciphertext) -> Poly {
    let q = ct.q();
    let mut acc = ct.parts[0].clone();
    if ct.parts.len() >= 2 {
        acc = poly_add(&acc, &poly_mul(&ct.parts[1], &sk.s, &q), &q);
    }
    if ct.parts.len() >= 3 {
        let s_sq = poly_mul(&sk.s, &sk.s, &q);
        acc = poly_add(&acc, &poly_mul(&ct.parts[2], &s_sq, &q), &q);
    }
    if ct.parts.len() > 3 {
        panic!("CKKS-lite does not support cubic+ ciphertexts");
    }
    acc
}

/// Decrypt and decode to a slot vector.
pub fn decrypt(sk: &SecretKey, ct: &Ciphertext) -> Vec<f64> {
    let m = decrypt_poly(sk, ct);
    decode(&m, &sk.params, &ct.scale)
}

/// Homomorphic addition: component-wise, requires same level.
pub fn add(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    assert_eq!(
        a.level, b.level,
        "ciphertexts must be at the same level to add"
    );
    assert_eq!(
        a.scale, b.scale,
        "ciphertexts must have the same scale to add"
    );
    let q = a.q();
    let n = a.parts.len().max(b.parts.len());
    let mut parts = Vec::with_capacity(n);
    for i in 0..n {
        match (a.parts.get(i), b.parts.get(i)) {
            (Some(x), Some(y)) => parts.push(poly_add(x, y, &q)),
            (Some(x), None) | (None, Some(x)) => parts.push(x.clone()),
            (None, None) => unreachable!(),
        }
    }
    Ciphertext {
        parts,
        level: a.level,
        scale: a.scale.clone(),
        params: a.params.clone(),
    }
}

/// Homomorphic addition of a *plaintext* slot vector to a ciphertext.
pub fn add_plain(ct: &Ciphertext, slots: &[f64]) -> Ciphertext {
    // Encode the plaintext at the same scale as the ciphertext.
    let mut m = encode(slots, &ct.params);
    // The encoded polynomial has scale Δ; if the ciphertext's scale differs,
    // adjust by multiplying coefficients.
    let factor = &ct.scale / &ct.params.delta;
    if factor != BigInt::from(1u32) {
        m = poly_scalar(&m, &factor, &ct.q());
    }
    let q = ct.q();
    let mut parts = ct.parts.clone();
    parts[0] = poly_add(&parts[0], &m, &q);
    Ciphertext {
        parts,
        level: ct.level,
        scale: ct.scale.clone(),
        params: ct.params.clone(),
    }
}

/// Homomorphic multiplication of a ciphertext by a *plaintext* slot vector.
///
/// The plaintext is encoded at scale Δ and multiplied into every component of
/// the ciphertext. The resulting ciphertext has its scale multiplied by Δ;
/// the caller will typically follow with [`rescale`] to bring it back. This
/// operation works on ciphertexts of any size (2 or 3 components), so it's
/// useful for stitching back to the standard pipeline.
pub fn mul_plain(ct: &Ciphertext, slots: &[f64]) -> Ciphertext {
    let m = encode(slots, &ct.params);
    let q = ct.q();
    let new_parts: Vec<Poly> = ct.parts.iter().map(|p| poly_mul(p, &m, &q)).collect();
    let new_scale = &ct.scale * &ct.params.delta;
    Ciphertext {
        parts: new_parts,
        level: ct.level,
        scale: new_scale,
        params: ct.params.clone(),
    }
}

/// Homomorphic multiplication: tensor product producing a 3-component ct.
/// The result's scale doubles; you'll typically `rescale` afterwards.
pub fn mul(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    assert_eq!(
        a.level, b.level,
        "ciphertexts must be at the same level to multiply"
    );
    assert_eq!(
        a.parts.len(),
        2,
        "CKKS-lite multiplies fresh (size-2) ciphertexts"
    );
    assert_eq!(
        b.parts.len(),
        2,
        "CKKS-lite multiplies fresh (size-2) ciphertexts"
    );
    let q = a.q();

    let d0 = poly_mul(&a.parts[0], &b.parts[0], &q);
    let d1_a = poly_mul(&a.parts[0], &b.parts[1], &q);
    let d1_b = poly_mul(&a.parts[1], &b.parts[0], &q);
    let d1 = poly_add(&d1_a, &d1_b, &q);
    let d2 = poly_mul(&a.parts[1], &b.parts[1], &q);

    let new_scale = &a.scale * &b.scale;
    Ciphertext {
        parts: vec![d0, d1, d2],
        level: a.level,
        scale: new_scale,
        params: a.params.clone(),
    }
}

/// **Modulus switch** — drop one level *without* changing the message scale.
///
/// Unlike [`rescale`], which is paired with a multiplication and normalises
/// the message scale back to `Δ`, `mod_switch` is purely a book-keeping move:
/// it reduces coefficients into the smaller modulus `q_{L-1}` without
/// dividing the message. Use this to bring a ciphertext to a lower level so
/// it can be combined with another ciphertext that already lives there.
pub fn mod_switch(ct: &Ciphertext) -> Ciphertext {
    assert!(ct.level > 0, "no levels left to mod-switch");
    let new_level = ct.level - 1;
    let new_q = ct.params.q_at(new_level);
    let mut new_parts = Vec::with_capacity(ct.parts.len());
    for part in &ct.parts {
        let switched: Vec<BigInt> = part.coeffs.iter().map(|c| centre(c, &new_q)).collect();
        new_parts.push(Poly { coeffs: switched });
    }
    Ciphertext {
        parts: new_parts,
        level: new_level,
        scale: ct.scale.clone(),
        params: ct.params.clone(),
    }
}

/// **Rescale** — the central CKKS operation.
///
/// Divides every coefficient by `Δ` (with rounding), drops the level, and
/// brings the message scale back to `Δ`. This is what makes CKKS depth-bounded
/// rather than blowing up.
pub fn rescale(ct: &Ciphertext) -> Ciphertext {
    assert!(ct.level > 0, "no levels left to rescale");
    let new_level = ct.level - 1;
    let new_q = ct.params.q_at(new_level);
    let delta = &ct.params.delta;

    let mut new_parts = Vec::with_capacity(ct.parts.len());
    for part in &ct.parts {
        let scaled: Vec<BigInt> = part
            .coeffs
            .iter()
            .map(|c| {
                let q = round_div(c, delta);
                centre(&q, &new_q)
            })
            .collect();
        new_parts.push(Poly { coeffs: scaled });
    }

    let new_scale = &ct.scale / delta;
    Ciphertext {
        parts: new_parts,
        level: new_level,
        scale: new_scale,
        params: ct.params.clone(),
    }
}

fn round_div(num: &BigInt, den: &BigInt) -> BigInt {
    let half = den / 2;
    if num >= &BigInt::zero() {
        (num + &half) / den
    } else {
        (num - &half) / den
    }
}

/// Estimate noise in a CKKS ciphertext, in bits.
///
/// Returns `(log2_noise, log2_q, headroom_bits)`.
pub fn noise_estimate(sk: &SecretKey, ct: &Ciphertext) -> (f64, f64, f64) {
    let m = decrypt_poly(sk, ct);
    // CKKS doesn't have a clean message/noise split — we treat the recovered
    // polynomial's max absolute coefficient as the magnitude, and the scale
    // tells us roughly how many of those bits are "signal".
    let inf = m.inf_norm();
    let log_m = if inf.is_zero() {
        0.0
    } else {
        (inf.bits() - 1) as f64
    };
    let log_q = (ct.q().bits() - 1) as f64;
    let headroom = log_q - log_m;
    (log_m, log_q, headroom.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() < tol
    }

    #[test]
    fn encode_decode_roundtrip() {
        let params = Params::toy();
        let slots = vec![1.0, 2.5, -0.75, 4.0];
        let p = encode(&slots, &params);
        let back = decode(&p, &params, &params.delta);
        for (i, &v) in slots.iter().enumerate() {
            assert!(
                approx_eq(back[i], v, 0.01),
                "slot {i}: got {} want {}",
                back[i],
                v
            );
        }
    }

    #[test]
    fn enc_dec_roundtrip() {
        let params = Params::toy();
        let (pk, sk) = keygen(&params);
        let slots = vec![1.5, -2.25, 0.0, 3.125];
        let ct = encrypt(&pk, &slots);
        let back = decrypt(&sk, &ct);
        for (i, &v) in slots.iter().enumerate() {
            assert!(
                approx_eq(back[i], v, 0.05),
                "slot {i}: got {} want {}",
                back[i],
                v
            );
        }
    }

    #[test]
    fn homomorphic_add() {
        let params = Params::toy();
        let (pk, sk) = keygen(&params);
        let a = vec![1.0, 2.0, 3.0, 4.0];
        let b = vec![0.5, 1.5, -1.0, 0.25];
        let ct_a = encrypt(&pk, &a);
        let ct_b = encrypt(&pk, &b);
        let sum = add(&ct_a, &ct_b);
        let back = decrypt(&sk, &sum);
        for i in 0..4 {
            assert!(approx_eq(back[i], a[i] + b[i], 0.05), "slot {i}");
        }
    }

    #[test]
    fn homomorphic_mul_with_rescale() {
        let params = Params::toy();
        let (pk, sk) = keygen(&params);
        let a = vec![2.0, 3.0, -1.0, 0.5];
        let b = vec![4.0, 0.5, 2.0, 6.0];
        let ct_a = encrypt(&pk, &a);
        let ct_b = encrypt(&pk, &b);
        let prod = mul(&ct_a, &ct_b);
        let prod = rescale(&prod);
        let back = decrypt(&sk, &prod);
        for i in 0..4 {
            assert!(
                approx_eq(back[i], a[i] * b[i], 0.5),
                "slot {i}: got {} want {}",
                back[i],
                a[i] * b[i]
            );
        }
    }
}
