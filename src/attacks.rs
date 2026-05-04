//! Textbook attacks.
//!
//! This module implements *deliberately weak* configurations and the attacks
//! that break them. The point is pedagogical: students should see *why*
//! the standard parameter choices exist.
//!
//! None of the routines here let you attack a properly-parameterised key
//! pair; they only succeed when the key is intentionally tiny.

use crate::schemes::paillier;
use crate::util;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};

/// Result of a factoring attempt.
pub struct Factorisation {
    /// First prime factor.
    pub p: BigUint,
    /// Second prime factor.
    pub q: BigUint,
    /// How many trial-division steps were taken.
    pub steps: u64,
}

/// Trial-division factorisation. Practical only for `n` up to ~50 bits;
/// included so students can watch a small Paillier modulus shatter.
pub fn factor_trial_division(n: &BigUint, max_steps: u64) -> Option<Factorisation> {
    let mut d = BigUint::from(3u32);
    let two = BigUint::from(2u32);
    if n.is_even() {
        let q = n / &two;
        return Some(Factorisation { p: two, q, steps: 1 });
    }
    let mut steps = 1u64;
    while &d * &d <= *n && steps < max_steps {
        if n.mod_floor(&d).is_zero() {
            let q = n / &d;
            return Some(Factorisation { p: d, q, steps });
        }
        d += 2u32;
        steps += 1;
    }
    None
}

/// Pollard's rho — the next step up. Practical to maybe 80 bits in seconds.
pub fn factor_pollard_rho(n: &BigUint, max_steps: u64) -> Option<Factorisation> {
    if n.is_even() {
        let two = BigUint::from(2u32);
        return Some(Factorisation { p: two.clone(), q: n / &two, steps: 1 });
    }
    let mut rng = util::rng();
    for _outer in 0..8 {
        let mut x = util::rand_below(&mut rng, n);
        let mut y = x.clone();
        let c = util::rand_below(&mut rng, n);
        let mut d = BigUint::one();
        let mut steps = 0u64;
        while d.is_one() && steps < max_steps {
            x = (&x * &x + &c) % n;
            y = (&y * &y + &c) % n;
            y = (&y * &y + &c) % n;
            let diff = if x > y { &x - &y } else { &y - &x };
            d = diff.gcd(n);
            steps += 1;
        }
        if !d.is_one() && d != *n {
            let q = n / &d;
            return Some(Factorisation { p: d, q, steps });
        }
    }
    None
}

/// Recover a Paillier secret key given a successful factorisation of `n`.
///
/// This is the obvious lesson: factor `n` and the whole thing falls.
pub fn recover_paillier_sk(pk: &paillier::PublicKey, fact: &Factorisation) -> paillier::SecretKey {
    assert_eq!(&fact.p * &fact.q, pk.n, "factorisation must match the modulus");
    let p_minus_1: BigUint = &fact.p - 1u32;
    let q_minus_1: BigUint = &fact.q - 1u32;
    let lambda = p_minus_1.lcm(&q_minus_1);
    // μ = L((1+n)^λ mod n²)^{-1} mod n
    let n_sq = pk.n_squared();
    let g = &pk.n + 1u32;
    let g_lambda = util::mod_pow(&g, &lambda, &n_sq);
    let l_value = (&g_lambda - 1u32) / &pk.n;
    let mu = util::mod_inverse(&l_value, &pk.n).expect("μ must invert");
    paillier::SecretKey { lambda, mu, pk: pk.clone() }
}

/// Brute-force search for a small plaintext.
///
/// Naive Paillier with a *deterministic* encryption (no fresh randomness)
/// is broken when the message space is tiny: anyone can re-encrypt every
/// candidate and compare. Here we model the deterministic-encryption mistake
/// by re-encrypting with a *known* `r` and comparing.
///
/// Returns `Some(m)` if `m < bound` and the encryption used randomness `r`;
/// `None` otherwise.
pub fn brute_force_paillier(
    pk: &paillier::PublicKey,
    target: &paillier::Ciphertext,
    r: &BigUint,
    bound: u64,
) -> Option<u64> {
    for m in 0..bound {
        let m_b = BigUint::from(m);
        let test = paillier::encrypt_with_randomness(pk, &m_b, r);
        if test.c == target.c {
            return Some(m);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factor_small_modulus() {
        let n = BigUint::from(15u32);
        let f = factor_trial_division(&n, 100).expect("should factor");
        assert_eq!(&f.p * &f.q, n);
    }

    #[test]
    fn pollard_rho_factors_modest_modulus() {
        // 15 = 3*5; tiny, but exercises the path
        let n = BigUint::from(35u32);
        let f = factor_pollard_rho(&n, 1000).expect("should factor");
        assert_eq!(&f.p * &f.q, n);
    }

    #[test]
    fn recover_paillier_secret_after_factoring() {
        let (pk, _real_sk) = paillier::keygen(32);
        // 32-bit n → trial division finishes fast
        let fact = factor_trial_division(&pk.n, 1_000_000)
            .or_else(|| factor_pollard_rho(&pk.n, 100_000))
            .expect("should factor a 32-bit n");
        let recovered = recover_paillier_sk(&pk, &fact);
        let m = BigUint::from(123u32);
        let ct = paillier::encrypt(&pk, &m);
        assert_eq!(paillier::decrypt(&recovered, &ct), m);
    }
}
