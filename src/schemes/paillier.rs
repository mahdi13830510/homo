//! # Paillier cryptosystem
//!
//! Pascal Paillier, *"Public-Key Cryptosystems Based on Composite Degree
//! Residuosity Classes"*, EUROCRYPT 1999.
//!
//! ## Why we start here
//!
//! Paillier is the clearest *partially* homomorphic scheme: only addition
//! works on ciphertexts, but everything fits on a postcard.
//!
//! ## The mathematics, in one paragraph
//!
//! Pick two large primes `p, q` and let `n = p·q`, `λ = lcm(p-1, q-1)`. The
//! plaintext space is `ℤ_n`. To encrypt a message `m`, sample a random
//! `r ∈ ℤ_n*` and compute
//!
//! ```text
//!     c = (1 + n)^m · r^n   (mod n²)
//! ```
//!
//! Decryption uses
//!
//! ```text
//!     m = L(c^λ mod n²) · μ   (mod n)
//! ```
//!
//! where `L(x) = (x - 1) / n` and `μ = L((1+n)^λ mod n²)^{-1} mod n`.
//!
//! ## The homomorphism
//!
//! ```text
//!     Enc(m₁) · Enc(m₂)  ≡  Enc(m₁ + m₂)   (mod n²)
//!     Enc(m)^k           ≡  Enc(k · m)     (mod n²)
//! ```
//!
//! That's it. Two lines and you have additive homomorphism. The catch:
//! ciphertexts are `2 log n` bits each — a 4× expansion.

use crate::util;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use serde::{Deserialize, Serialize};

/// A Paillier public key: just the modulus `n`.
///
/// We deliberately do **not** cache `n²` on the wire — it's recomputed on
/// load to keep the serialised form minimal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// RSA-style modulus `n = p · q`.
    pub n: BigUint,
}

/// A Paillier secret key: enough to decrypt and a copy of the public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKey {
    /// `λ(n) = lcm(p-1, q-1)`.
    pub lambda: BigUint,
    /// Pre-computed `μ = L((1+n)^λ mod n²)^{-1} mod n`.
    pub mu: BigUint,
    /// The public part, kept alongside for convenience.
    pub pk: PublicKey,
}

/// A Paillier ciphertext, simply an integer in `ℤ_{n²}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    /// The actual ciphertext value `c ∈ ℤ_{n²}`.
    pub c: BigUint,
}

impl PublicKey {
    /// Returns `n²`, the modulus of the ciphertext space.
    pub fn n_squared(&self) -> BigUint {
        &self.n * &self.n
    }
}

/// Generate a fresh Paillier key pair with a modulus of the given bit length.
///
/// `bits` is the *modulus* size; each prime gets `bits / 2` bits. For real
/// use, `bits >= 2048`; for lecture demos, `bits = 256` decrypts in a blink.
pub fn keygen(bits: u64) -> (PublicKey, SecretKey) {
    assert!(bits >= 16 && bits % 2 == 0, "bits must be even and ≥ 16");
    let mut rng = util::rng();

    // Sample two distinct primes of half the requested width.
    let p = util::random_prime(&mut rng, bits / 2);
    let mut q = util::random_prime(&mut rng, bits / 2);
    while q == p {
        q = util::random_prime(&mut rng, bits / 2);
    }

    let n = &p * &q;
    let n_sq = &n * &n;

    // λ = lcm(p-1, q-1)
    let p_minus_1: BigUint = &p - 1u32;
    let q_minus_1: BigUint = &q - 1u32;
    let lambda = p_minus_1.lcm(&q_minus_1);

    // g = n + 1 is the standard textbook choice. With this g,
    //   (1+n)^λ mod n² = 1 + n·λ mod n²
    // which simplifies μ to (λ)^{-1} mod n. We compute the slow way for
    // pedagogical clarity.
    let g = &n + 1u32;
    let g_lambda = util::mod_pow(&g, &lambda, &n_sq);
    let l_value = l_function(&g_lambda, &n);
    let mu = util::mod_inverse(&l_value, &n).expect("μ must be invertible");

    let pk = PublicKey { n };
    let sk = SecretKey {
        lambda,
        mu,
        pk: pk.clone(),
    };
    (pk, sk)
}

/// The Paillier `L` function: `L(x) = (x - 1) / n`.
///
/// Defined only when `x ≡ 1 (mod n)`, which is always true in the contexts
/// we use it. We assert that condition.
fn l_function(x: &BigUint, n: &BigUint) -> BigUint {
    debug_assert!(x.mod_floor(n).is_one(), "L(x) requires x ≡ 1 (mod n)");
    (x - 1u32) / n
}

/// Encrypt a message `m ∈ ℤ_n`. The randomness is sampled fresh.
///
/// Returns a [`Ciphertext`]. The randomness is **not** retained — re-encrypting
/// the same message twice gives different ciphertexts (semantic security).
pub fn encrypt(pk: &PublicKey, m: &BigUint) -> Ciphertext {
    let mut rng = util::rng();
    encrypt_with_randomness(pk, m, &util::rand_coprime(&mut rng, &pk.n))
}

/// Encrypt with caller-chosen randomness `r`. Useful for tests, traces, and
/// for the `homo trace` subcommand which wants reproducible numbers.
pub fn encrypt_with_randomness(pk: &PublicKey, m: &BigUint, r: &BigUint) -> Ciphertext {
    let n_sq = pk.n_squared();
    let m_reduced = m.mod_floor(&pk.n);

    // (1+n)^m  ≡  1 + n·m  (mod n²)  for the standard generator g = 1 + n.
    // We use this fast-path; it's exactly equivalent to mod_pow but O(1).
    let g_to_m = (BigUint::one() + &pk.n * &m_reduced).mod_floor(&n_sq);

    let r_to_n = util::mod_pow(r, &pk.n, &n_sq);
    let c = (g_to_m * r_to_n).mod_floor(&n_sq);
    Ciphertext { c }
}

/// Decrypt a ciphertext back into `ℤ_n`.
pub fn decrypt(sk: &SecretKey, ct: &Ciphertext) -> BigUint {
    let n_sq = sk.pk.n_squared();
    let c_lambda = util::mod_pow(&ct.c, &sk.lambda, &n_sq);
    let l = l_function(&c_lambda, &sk.pk.n);
    (l * &sk.mu).mod_floor(&sk.pk.n)
}

/// Homomorphic addition of two ciphertexts.
///
/// `Enc(m₁) · Enc(m₂) (mod n²)` decrypts to `m₁ + m₂ (mod n)`.
pub fn add(pk: &PublicKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    let n_sq = pk.n_squared();
    Ciphertext {
        c: (&a.c * &b.c).mod_floor(&n_sq),
    }
}

/// Homomorphic addition of a *plaintext* to a ciphertext.
///
/// Implemented as `Enc(m) · (1 + n·k) (mod n²)`, which avoids the cost of
/// a full re-encryption. The result is *not* re-randomised — callers who
/// care about RCCA-style hiding should follow with [`rerandomize`].
pub fn add_plain(pk: &PublicKey, ct: &Ciphertext, k: &BigUint) -> Ciphertext {
    let n_sq = pk.n_squared();
    let factor = (BigUint::one() + &pk.n * k.mod_floor(&pk.n)).mod_floor(&n_sq);
    Ciphertext {
        c: (&ct.c * factor).mod_floor(&n_sq),
    }
}

/// Homomorphic multiplication of a ciphertext by a *plaintext* scalar.
///
/// `Enc(m)^k (mod n²)` decrypts to `k · m (mod n)`.
pub fn mul_plain(pk: &PublicKey, ct: &Ciphertext, k: &BigUint) -> Ciphertext {
    let n_sq = pk.n_squared();
    Ciphertext {
        c: util::mod_pow(&ct.c, k, &n_sq),
    }
}

/// Re-randomise a ciphertext without changing the underlying plaintext.
///
/// Multiplies `c` by a fresh `r^n mod n²`. Useful before publishing a
/// ciphertext that resulted from a deterministic homomorphic operation.
pub fn rerandomize(pk: &PublicKey, ct: &Ciphertext) -> Ciphertext {
    let mut rng = util::rng();
    let r = util::rand_coprime(&mut rng, &pk.n);
    let n_sq = pk.n_squared();
    let r_to_n = util::mod_pow(&r, &pk.n, &n_sq);
    Ciphertext {
        c: (&ct.c * r_to_n).mod_floor(&n_sq),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_keys() -> (PublicKey, SecretKey) {
        keygen(64)
    }

    #[test]
    fn enc_dec_roundtrip() {
        let (pk, sk) = small_keys();
        for m in [0u32, 1, 2, 42, 1000, 65535] {
            let m_b = BigUint::from(m);
            let ct = encrypt(&pk, &m_b);
            assert_eq!(decrypt(&sk, &ct), m_b);
        }
    }

    #[test]
    fn additive_homomorphism() {
        let (pk, sk) = small_keys();
        let a = BigUint::from(123u32);
        let b = BigUint::from(456u32);
        let ct_a = encrypt(&pk, &a);
        let ct_b = encrypt(&pk, &b);
        let ct_sum = add(&pk, &ct_a, &ct_b);
        assert_eq!(decrypt(&sk, &ct_sum), &a + &b);
    }

    #[test]
    fn scalar_multiplication() {
        let (pk, sk) = small_keys();
        let m = BigUint::from(13u32);
        let k = BigUint::from(7u32);
        let ct = encrypt(&pk, &m);
        let ct_k = mul_plain(&pk, &ct, &k);
        assert_eq!(decrypt(&sk, &ct_k), &m * &k);
    }

    #[test]
    fn rerandomization_preserves_plaintext() {
        let (pk, sk) = small_keys();
        let m = BigUint::from(99u32);
        let ct = encrypt(&pk, &m);
        let ct2 = rerandomize(&pk, &ct);
        assert_ne!(ct.c, ct2.c, "rerandomised ciphertext should differ");
        assert_eq!(decrypt(&sk, &ct2), m);
    }

    #[test]
    fn add_plain_matches_add_after_encrypt() {
        let (pk, sk) = small_keys();
        let m = BigUint::from(5u32);
        let k = BigUint::from(7u32);
        let ct = encrypt(&pk, &m);
        let ct2 = add_plain(&pk, &ct, &k);
        assert_eq!(decrypt(&sk, &ct2), &m + &k);
    }
}
