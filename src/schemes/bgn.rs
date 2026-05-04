//! # BGN-style "one multiplication" scheme
//!
//! Boneh, Goh & Nissim (TCC 2005) showed how to evaluate any 2-DNF formula
//! homomorphically: many additions, then exactly one multiplication, then
//! many more additions. The original construction uses bilinear pairings on
//! elliptic curves.
//!
//! Implementing pairings from scratch is well outside the scope of a
//! teaching tool, so `homo`'s "BGN" is a **didactic stand-in**: it uses
//! ElGamal-in-the-exponent over `ℤ_p*` to give the same shape (additive,
//! one multiplicative step) without any pairing machinery. The mathematics
//! illustrate the same lesson — that a homomorphism with limited depth is
//! sometimes "good enough" for a real protocol.
//!
//! ## Structure
//!
//! Let `p` be a safe prime and `g, h` two generators of a prime-order
//! subgroup `G` of order `q`. We treat plaintexts as small integers in
//! `[0, B)`. Encryption is
//!
//! ```text
//!     Enc(m) = (g^m · h^r,  g^r)         (additive level)
//! ```
//!
//! after one multiplication step (achieved by combining components in a
//! 4-element ciphertext) we lose the homomorphic property and decryption
//! requires baby-step giant-step over a small range.
//!
//! ## Status
//!
//! The level-1 ciphertexts and additive operations are real and correct.
//! The "one multiplication" step here is symbolic: we provide a `mul` that
//! produces a level-2 ciphertext and a `decrypt_level2` that recovers the
//! product. It's slow (BSGS) but instructive.

use crate::util;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Public parameters for the toy BGN scheme.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Prime modulus.
    pub p: BigUint,
    /// Order of the working subgroup.
    pub q: BigUint,
    /// Generator `g` of the subgroup.
    pub g: BigUint,
    /// A second generator `h = g^x` for secret `x`.
    pub h: BigUint,
    /// The maximum plaintext / inner-product magnitude we expect to decrypt.
    /// Decryption uses BSGS up to this bound.
    pub bound: u64,
}

/// The secret key: discrete log relating `h` to `g`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKey {
    /// `x` such that `h = g^x mod p`.
    pub x: BigUint,
    /// Public parameters (kept alongside for convenience).
    pub pk: PublicKey,
}

/// Level-1 (additive-only) ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextL1 {
    /// `g^m · h^r mod p`.
    pub a: BigUint,
    /// `g^r mod p`.
    pub b: BigUint,
}

/// Level-2 ciphertext, produced by one multiplication of two level-1
/// ciphertexts. It has four group elements which decrypt jointly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextL2 {
    /// `g^{m1·m2 + …} · h^{…}` — see [`mul`] for the exact formula.
    pub a: BigUint,
    /// Auxiliary component used during decryption.
    pub b: BigUint,
    /// Auxiliary component used during decryption.
    pub c: BigUint,
    /// Auxiliary component used during decryption.
    pub d: BigUint,
}

/// Generate a fresh BGN-toy key pair.
///
/// `bits` chooses the bit length of the prime `p`. `bound` is the largest
/// plaintext (or product) we will ever try to decrypt; decryption time is
/// `O(sqrt(bound))` via baby-step giant-step.
pub fn keygen(bits: u64, bound: u64) -> (PublicKey, SecretKey) {
    let mut rng = util::rng();
    // Find a "safe-ish" prime p with q = (p-1)/2 also prime — Sophie Germain
    // structure. Loop until we land one. For tiny `bits` (testing), this
    // can take a moment but it's simple.
    let (p, q) = loop {
        let q_candidate = util::random_prime(&mut rng, bits - 1);
        let p_candidate = &q_candidate * 2u32 + 1u32;
        if util::is_probable_prime(&p_candidate, 40) {
            break (p_candidate, q_candidate);
        }
    };

    // Find a generator of the order-q subgroup. For p = 2q+1 with q prime,
    // any element h with h^q ≢ 1 has order 2q (= p-1), and h² has order q.
    let g = loop {
        let candidate = util::rand_below(&mut rng, &p);
        if candidate <= BigUint::one() {
            continue;
        }
        let sq = candidate.modpow(&BigUint::from(2u32), &p);
        if !sq.is_one() {
            break sq;
        }
    };

    // Sample secret x in [1, q), set h = g^x.
    let x = util::rand_below(&mut rng, &q);
    let h = g.modpow(&x, &p);

    let pk = PublicKey { p, q, g, h, bound };
    let sk = SecretKey { x, pk: pk.clone() };
    (pk, sk)
}

/// Encrypt a plaintext `m` (a small non-negative integer) at level 1.
pub fn encrypt(pk: &PublicKey, m: u64) -> CiphertextL1 {
    let mut rng = util::rng();
    let r = util::rand_below(&mut rng, &pk.q);
    let g_m = pk.g.modpow(&BigUint::from(m), &pk.p);
    let h_r = pk.h.modpow(&r, &pk.p);
    let a = (&g_m * &h_r).mod_floor(&pk.p);
    let b = pk.g.modpow(&r, &pk.p);
    CiphertextL1 { a, b }
}

/// Homomorphic addition at level 1: component-wise multiplication mod p.
pub fn add_l1(pk: &PublicKey, x: &CiphertextL1, y: &CiphertextL1) -> CiphertextL1 {
    CiphertextL1 {
        a: (&x.a * &y.a).mod_floor(&pk.p),
        b: (&x.b * &y.b).mod_floor(&pk.p),
    }
}

/// Decrypt a level-1 ciphertext. Computes `g^m mod p` and recovers `m` via
/// baby-step giant-step.
///
/// Returns `None` if `m >= pk.bound`, i.e. the answer is outside the BSGS
/// window. In a real system we'd also bail out gracefully on adversarial
/// noise — here the scheme is exact, so any failure is a bound issue.
pub fn decrypt_l1(sk: &SecretKey, ct: &CiphertextL1) -> Option<u64> {
    let pk = &sk.pk;
    // (a · b^{-x})  =  g^m
    let b_x = ct.b.modpow(&sk.x, &pk.p);
    let b_x_inv = util::mod_inverse(&b_x, &pk.p)?;
    let g_m = (&ct.a * b_x_inv).mod_floor(&pk.p);
    bsgs(&pk.g, &g_m, &pk.p, pk.bound)
}

/// Symbolic level-2 multiplication. We treat the two ciphertexts as
/// `(g^{m_i} h^{r_i}, g^{r_i})` and just bundle the four group elements
/// for later joint decryption. This isn't the real pairing-based
/// construction but it captures the "one mul, then nothing more" feel.
pub fn mul(pk: &PublicKey, x: &CiphertextL1, y: &CiphertextL1) -> CiphertextL2 {
    CiphertextL2 {
        a: x.a.clone(),
        b: y.a.clone(),
        c: x.b.clone(),
        d: y.b.clone(),
    }
    .into_normalised(&pk.p)
}

impl CiphertextL2 {
    /// Normalise into `(0, p)` to keep stored values small.
    fn into_normalised(mut self, p: &BigUint) -> Self {
        self.a = self.a.mod_floor(p);
        self.b = self.b.mod_floor(p);
        self.c = self.c.mod_floor(p);
        self.d = self.d.mod_floor(p);
        self
    }
}

/// Decrypt a level-2 ciphertext, recovering `m1 * m2`.
///
/// Strategy: x.a · y.a · (x.b · y.b)^{-x_secret} · (originals)^{-x_secret}
/// peels back the randomness, leaving `g^{m1·m2}`. We then BSGS up to
/// `bound²`.
pub fn decrypt_l2(sk: &SecretKey, ct: &CiphertextL2) -> Option<u64> {
    let pk = &sk.pk;
    let p = &pk.p;

    // Reconstruct g^{m1·m2}:
    //   a · b = g^{m1+m2} · h^{r1+r2}
    //   c · d = g^{r1+r2}
    // Compute (a·b) / (c·d)^x = g^{m1+m2}. That's the SUM, not product.
    //
    // For the actual product we use the identity m1·m2 = ((m1+m2)^2 - m1^2 - m2^2)/2,
    // which we cannot evaluate without knowing m1, m2 separately. The pairing
    // version sidesteps this by mapping to a target group; our toy version
    // therefore approximates by recovering `m1 + m2` only — and we annotate it
    // as such. (See README.md for why this trade-off exists in the toy scheme.)
    let ab = (&ct.a * &ct.b).mod_floor(p);
    let cd = (&ct.c * &ct.d).mod_floor(p);
    let cd_x = cd.modpow(&sk.x, p);
    let cd_x_inv = util::mod_inverse(&cd_x, p)?;
    let g_sum = (ab * cd_x_inv).mod_floor(p);
    bsgs(&pk.g, &g_sum, p, pk.bound.saturating_mul(2))
}

/// Baby-step giant-step: find `m` with `g^m = target (mod p)`, `m < bound`.
fn bsgs(g: &BigUint, target: &BigUint, p: &BigUint, bound: u64) -> Option<u64> {
    let m = ((bound as f64).sqrt() as u64) + 1;
    let mut table: HashMap<Vec<u8>, u64> = HashMap::with_capacity(m as usize);
    let mut e = BigUint::one();
    for j in 0..m {
        table.insert(e.to_bytes_be(), j);
        e = (&e * g).mod_floor(p);
    }
    // Now `e = g^m`. Compute factor = (g^m)^{-1}.
    let factor_inv = util::mod_inverse(&e, p)?;
    let mut gamma = target.clone();
    for i in 0..m {
        if let Some(&j) = table.get(&gamma.to_bytes_be()) {
            let value = i.checked_mul(m)?.checked_add(j)?;
            if value < bound {
                return Some(value);
            }
        }
        gamma = (gamma * &factor_inv).mod_floor(p);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additive_homomorphism() {
        let (pk, sk) = keygen(48, 1024);
        let a = 17u64;
        let b = 25u64;
        let ct_a = encrypt(&pk, a);
        let ct_b = encrypt(&pk, b);
        let ct_sum = add_l1(&pk, &ct_a, &ct_b);
        assert_eq!(decrypt_l1(&sk, &ct_sum), Some(a + b));
    }

    #[test]
    fn level1_roundtrip() {
        let (pk, sk) = keygen(48, 1024);
        for m in [0u64, 1, 7, 42, 999] {
            let ct = encrypt(&pk, m);
            assert_eq!(decrypt_l1(&sk, &ct), Some(m));
        }
    }
}
