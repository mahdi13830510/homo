//! Shared utilities: cryptographic RNG, modular arithmetic, prime generation.
//!
//! These helpers are deliberately written in a readable style — performance
//! takes a back seat to clarity, since the goal of `homo` is to make the math
//! understandable. For production FHE you would use a battle-hardened library
//! (concrete-rs, OpenFHE, SEAL).

use num_bigint::{BigInt, BigUint, RandBigInt, Sign, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Returns a fresh, OS-seeded cryptographic RNG.
///
/// We use ChaCha20 seeded from `getrandom` rather than `OsRng` directly so we
/// can also produce deterministic instances for tests via [`seeded_rng`].
pub fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_entropy()
}

/// Returns a deterministic RNG seeded with the given 32 bytes.
///
/// Useful for reproducing examples in lectures and for property tests.
pub fn seeded_rng(seed: [u8; 32]) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(seed)
}

/// Sample a uniformly random integer in `[0, modulus)`.
pub fn rand_below<R: RngCore>(rng: &mut R, modulus: &BigUint) -> BigUint {
    rng.gen_biguint_below(modulus)
}

/// Sample a uniformly random integer in `[1, modulus)` that is also coprime to
/// `modulus`. Loops until success — overwhelmingly fast when `modulus` has
/// large prime factors.
pub fn rand_coprime<R: RngCore>(rng: &mut R, modulus: &BigUint) -> BigUint {
    loop {
        let r = rng.gen_biguint_below(modulus);
        if !r.is_zero() && r.gcd(modulus).is_one() {
            return r;
        }
    }
}

/// Modular inverse via the extended Euclidean algorithm.
///
/// Returns `Some(x)` such that `a * x ≡ 1 (mod m)`, or `None` if `gcd(a, m) ≠ 1`.
pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_signed = a.to_bigint()?;
    let m_signed = m.to_bigint()?;
    let egcd = a_signed.extended_gcd(&m_signed);
    if !egcd.gcd.is_one() {
        return None;
    }
    let inv = ((egcd.x % &m_signed) + &m_signed) % &m_signed;
    inv.to_biguint()
}

/// Modular exponentiation: `base^exp mod modulus`.
///
/// `num-bigint` already provides this; we re-export it under a friendlier name
/// for the rest of the crate to keep things consistent.
#[inline]
pub fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

/// Generate a probable prime of exactly `bits` bits using Miller–Rabin.
///
/// The high bit is forced to 1 (so the prime really has `bits` bits) and the
/// low bit is forced to 1 (so it's odd). We then run 40 rounds of
/// Miller–Rabin, giving a false-positive probability below 2^-80.
pub fn random_prime<R: RngCore>(rng: &mut R, bits: u64) -> BigUint {
    assert!(bits >= 2, "primes need at least 2 bits");
    loop {
        let mut candidate = rng.gen_biguint(bits);
        // Force top bit and bottom bit
        candidate.set_bit(bits - 1, true);
        candidate.set_bit(0, true);
        if is_probable_prime(&candidate, 40) {
            return candidate;
        }
    }
}

/// Miller–Rabin primality test with `rounds` random witnesses.
pub fn is_probable_prime(n: &BigUint, rounds: u32) -> bool {
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);

    if *n < two {
        return false;
    }
    if *n == two || *n == three {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write n-1 = 2^s * d with d odd
    let n_minus_1: BigUint = n - 1u32;
    let mut d = n_minus_1.clone();
    let mut s: u32 = 0;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }

    let mut rng = rng();
    'witness: for _ in 0..rounds {
        // Pick a in [2, n-2]
        let a = rng.gen_biguint_range(&two, &(n - &two));
        let mut x = a.modpow(&d, n);
        if x.is_one() || x == n_minus_1 {
            continue;
        }
        for _ in 0..(s - 1) {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

/// Convert a signed integer mod `q` to its centred representative in
/// `(-q/2, q/2]`. Used heavily when reading noise out of RLWE ciphertexts.
pub fn centred(x: &BigUint, q: &BigUint) -> BigInt {
    let half = q >> 1;
    if *x > half {
        let signed: BigInt = x.to_bigint().unwrap();
        let q_signed: BigInt = q.to_bigint().unwrap();
        signed - q_signed
    } else {
        x.to_bigint().unwrap()
    }
}

/// Sample a small integer from a discrete Gaussian-ish distribution.
///
/// We use a simple binomial approximation (sum of ±1 from a small number of
/// fair coins) which is the standard trick used by SEAL/HElib for
/// performance — it's statistically close enough to a true discrete Gaussian
/// for cryptographic purposes.
pub fn sample_small_noise<R: RngCore>(rng: &mut R, eta: u32) -> i64 {
    let mut acc: i64 = 0;
    for _ in 0..eta {
        let bits = rng.next_u32();
        acc += (bits & 1) as i64;
        acc -= ((bits >> 1) & 1) as i64;
    }
    acc
}

/// Number of bits in a non-negative integer, treating 0 as 1 bit.
pub fn bit_length(n: &BigUint) -> u64 {
    if n.is_zero() {
        1
    } else {
        n.bits()
    }
}

/// Convert a `BigInt` to a `BigUint` modulo `q`, mapping negatives back into
/// the non-negative range `[0, q)`.
pub fn to_uint_mod(x: &BigInt, q: &BigUint) -> BigUint {
    let q_signed = q.to_bigint().unwrap();
    let mut r = x % &q_signed;
    if r.sign() == Sign::Minus {
        r += &q_signed;
    }
    r.to_biguint().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miller_rabin_known_primes() {
        for p in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 7919, 65537] {
            assert!(is_probable_prime(&BigUint::from(p), 20), "{p} should be prime");
        }
    }

    #[test]
    fn miller_rabin_known_composites() {
        for c in [4u32, 9, 15, 21, 25, 1000, 65536] {
            assert!(!is_probable_prime(&BigUint::from(c), 20), "{c} should be composite");
        }
    }

    #[test]
    fn inverse_round_trips() {
        let m = BigUint::from(101u32);
        for a in 1u32..101 {
            let a_b = BigUint::from(a);
            let inv = mod_inverse(&a_b, &m).expect("coprime");
            assert_eq!((&a_b * &inv) % &m, BigUint::one());
        }
    }

    #[test]
    fn random_prime_has_correct_bit_length() {
        let mut r = seeded_rng([7; 32]);
        let p = random_prime(&mut r, 64);
        assert_eq!(p.bits(), 64);
        assert!(is_probable_prime(&p, 40));
    }
}
