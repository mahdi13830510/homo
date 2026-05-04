//! End-to-end integration tests for the public API.
//!
//! These tests don't shell out to the binary; they call the library
//! directly. Use `cargo test --test integration` to run.

use homo::io as wire;
use homo::schemes::{bfv, bgn, ckks, paillier};
use num_bigint::BigUint;

#[test]
fn paillier_full_pipeline() {
    let (pk, sk) = paillier::keygen(128);
    let m_a = BigUint::from(123u32);
    let m_b = BigUint::from(456u32);

    let ct_a = paillier::encrypt(&pk, &m_a);
    let ct_b = paillier::encrypt(&pk, &m_b);

    // Round-trip via PEM
    let env = wire::pack_paillier_ct(&ct_a);
    let pem = env.to_pem();
    let env2 = wire::Envelope::from_pem(&pem).unwrap();
    let ct_a_back = wire::unpack_paillier_ct(&env2).unwrap();
    assert_eq!(paillier::decrypt(&sk, &ct_a_back), m_a);

    // Homomorphic addition
    let sum = paillier::add(&pk, &ct_a_back, &ct_b);
    assert_eq!(paillier::decrypt(&sk, &sum), &m_a + &m_b);
}

#[test]
fn bfv_homomorphic_polynomial() {
    let params = bfv::Params::toy();
    let (pk, sk) = bfv::keygen(&params);
    // Compute (2 + 3) * 4 = 20 homomorphically
    let a = bfv::encrypt(&pk, &[2]);
    let b = bfv::encrypt(&pk, &[3]);
    let c = bfv::encrypt(&pk, &[4]);
    let s = bfv::add(&a, &b);
    let p = bfv::mul(&s, &c);
    let out = bfv::decrypt(&sk, &p);
    assert_eq!(out[0], 20, "got {out:?}");
}

#[test]
fn bgn_addition_only() {
    let (pk, sk) = bgn::keygen(48, 4096);
    let ct1 = bgn::encrypt(&pk, 100);
    let ct2 = bgn::encrypt(&pk, 250);
    let ct3 = bgn::encrypt(&pk, 7);
    let sum = bgn::add_l1(&pk, &bgn::add_l1(&pk, &ct1, &ct2), &ct3);
    assert_eq!(bgn::decrypt_l1(&sk, &sum), Some(357));
}

#[test]
fn envelope_self_describing() {
    let (pk, _sk) = paillier::keygen(64);
    let pem = wire::pack_paillier_pk(&pk).to_pem();
    assert!(pem.starts_with("-----BEGIN HOMO PAILLIER PUBLIC KEY-----"));
    assert!(pem.contains("END HOMO PAILLIER PUBLIC KEY"));
}

#[test]
fn ckks_full_pipeline() {
    let params = ckks::Params::toy();
    let (pk, sk) = ckks::keygen(&params);
    // Compute (a + b) * c slot-wise
    let a = vec![1.0, 2.0, 3.0, 4.0];
    let b = vec![0.5, 1.5, -1.0, 2.0];
    let c = vec![2.0, 1.0, 0.5, 3.0];
    let ct_a = ckks::encrypt(&pk, &a);
    let ct_b = ckks::encrypt(&pk, &b);
    let ct_c = ckks::encrypt(&pk, &c);
    let s = ckks::add(&ct_a, &ct_b);
    let p = ckks::rescale(&ckks::mul(&s, &ct_c));
    let back = ckks::decrypt(&sk, &p);
    for i in 0..4 {
        let expected = (a[i] + b[i]) * c[i];
        let err = (back[i] - expected).abs();
        assert!(err < 0.05, "slot {i}: got {} want {} (err {})", back[i], expected, err);
    }
}

#[test]
fn ckks_envelope_roundtrip() {
    let params = ckks::Params::toy();
    let (pk, _sk) = ckks::keygen(&params);
    let ct = ckks::encrypt(&pk, &[1.5, -2.5, 0.25, 4.0]);
    let env = wire::pack_ckks_ct(&ct);
    let pem = env.to_pem();
    assert!(pem.starts_with("-----BEGIN HOMO CKKS CIPHERTEXT-----"));
    let back = wire::Envelope::from_pem(&pem).unwrap();
    let ct2 = wire::unpack_ckks_ct(&back).unwrap();
    assert_eq!(ct.level, ct2.level);
    assert_eq!(ct.parts.len(), ct2.parts.len());
}

#[test]
fn ckks_mod_switch_preserves_message() {
    let params = ckks::Params::toy();
    let (pk, sk) = ckks::keygen(&params);
    let slots = vec![3.14, -2.71, 1.41, 0.577];
    let ct = ckks::encrypt(&pk, &slots);
    let switched = ckks::mod_switch(&ct);
    assert_eq!(switched.level, ct.level - 1);
    assert_eq!(switched.scale, ct.scale, "mod-switch must preserve message scale");
    let back = ckks::decrypt(&sk, &switched);
    for i in 0..4 {
        assert!((back[i] - slots[i]).abs() < 0.05, "slot {i}: got {} want {}", back[i], slots[i]);
    }
}
