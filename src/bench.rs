//! Lightweight micro-benchmarks for each scheme.
//!
//! We intentionally avoid pulling in `criterion` — it would dwarf the rest of
//! the crate. Instead we time `n` iterations with `std::time::Instant`, report
//! mean and standard deviation, and draw a tiny ASCII bar.

use crate::schemes::{bfv, ckks, paillier};
use colored::Colorize;
use num_bigint::BigUint;
use std::time::{Duration, Instant};

/// Result of one benchmark.
pub struct BenchResult {
    /// Human-readable name.
    pub name: String,
    /// Number of iterations measured.
    pub iters: u32,
    /// Mean wall-clock time per iteration.
    pub mean: Duration,
    /// Standard deviation.
    pub stddev: Duration,
}

fn measure<F: FnMut()>(name: &str, iters: u32, mut f: F) -> BenchResult {
    let mut samples = Vec::with_capacity(iters as usize);
    // 1 warm-up
    f();
    for _ in 0..iters {
        let t0 = Instant::now();
        f();
        samples.push(t0.elapsed());
    }
    let mean_nanos: u128 = samples.iter().map(|d| d.as_nanos()).sum::<u128>() / iters as u128;
    let var: f64 = samples
        .iter()
        .map(|d| (d.as_nanos() as f64 - mean_nanos as f64).powi(2))
        .sum::<f64>()
        / iters as f64;
    let stddev = Duration::from_nanos(var.sqrt() as u64);
    BenchResult {
        name: name.to_string(),
        iters,
        mean: Duration::from_nanos(mean_nanos as u64),
        stddev,
    }
}

/// Benchmark Paillier at the requested key size.
pub fn bench_paillier(bits: u64, iters: u32) -> Vec<BenchResult> {
    let mut results = Vec::new();
    let (pk, sk) = paillier::keygen(bits);
    let m = BigUint::from(42u32);

    results.push(measure("paillier:keygen", (iters / 4).max(1), || {
        let _ = paillier::keygen(bits);
    }));
    results.push(measure("paillier:encrypt", iters, || {
        let _ = paillier::encrypt(&pk, &m);
    }));
    let ct = paillier::encrypt(&pk, &m);
    let ct2 = paillier::encrypt(&pk, &m);
    results.push(measure("paillier:add", iters, || {
        let _ = paillier::add(&pk, &ct, &ct2);
    }));
    results.push(measure("paillier:decrypt", iters, || {
        let _ = paillier::decrypt(&sk, &ct);
    }));
    results
}

/// Benchmark BFV-lite under the toy parameter set.
pub fn bench_bfv(iters: u32) -> Vec<BenchResult> {
    let mut results = Vec::new();
    let params = bfv::Params::toy();
    let (pk, sk) = bfv::keygen(&params);
    let plain = vec![1u64, 2, 3, 4, 5];

    results.push(measure("bfv:keygen", (iters / 4).max(1), || {
        let _ = bfv::keygen(&params);
    }));
    results.push(measure("bfv:encrypt", iters, || {
        let _ = bfv::encrypt(&pk, &plain);
    }));
    let a = bfv::encrypt(&pk, &plain);
    let b = bfv::encrypt(&pk, &plain);
    results.push(measure("bfv:add", iters, || {
        let _ = bfv::add(&a, &b);
    }));
    // Multiplication is the slow one — fewer iterations.
    let mul_iters = (iters / 8).max(1);
    results.push(measure("bfv:mul", mul_iters, || {
        let _ = bfv::mul(&a, &b);
    }));
    results.push(measure("bfv:decrypt", iters, || {
        let _ = bfv::decrypt(&sk, &a);
    }));
    results
}

/// Benchmark CKKS-lite under the toy parameter set.
pub fn bench_ckks(iters: u32) -> Vec<BenchResult> {
    let mut results = Vec::new();
    let params = ckks::Params::toy();
    let (pk, sk) = ckks::keygen(&params);
    let slots = vec![1.5_f64, -0.25, 3.0, 2.125];

    results.push(measure("ckks:keygen", (iters / 4).max(1), || {
        let _ = ckks::keygen(&params);
    }));
    results.push(measure("ckks:encrypt", iters, || {
        let _ = ckks::encrypt(&pk, &slots);
    }));
    let a = ckks::encrypt(&pk, &slots);
    let b = ckks::encrypt(&pk, &slots);
    results.push(measure("ckks:add", iters, || {
        let _ = ckks::add(&a, &b);
    }));
    let mul_iters = (iters / 4).max(1);
    results.push(measure("ckks:mul", mul_iters, || {
        let _ = ckks::mul(&a, &b);
    }));
    let prod = ckks::mul(&a, &b);
    results.push(measure("ckks:rescale", iters, || {
        let _ = ckks::rescale(&prod);
    }));
    results.push(measure("ckks:decrypt", iters, || {
        let _ = ckks::decrypt(&sk, &a);
    }));
    results
}

/// Render benchmark results as a coloured table.
pub fn render(results: &[BenchResult]) -> String {
    let max = results.iter().map(|r| r.mean.as_nanos()).max().unwrap_or(1) as f64;
    let mut out = String::new();
    out.push_str(&format!(
        "\n{:<22}  {:>12}  {:>12}  {:>5}  {}\n",
        "operation".bold(),
        "mean".bold(),
        "± stddev".bold(),
        "iters".bold(),
        "relative".bold()
    ));
    out.push_str(&format!("{}\n", "─".repeat(78).dimmed()));
    for r in results {
        let frac = r.mean.as_nanos() as f64 / max;
        let bar_len = (frac * 28.0) as usize;
        let bar = format!(
            "{}{}",
            "█".repeat(bar_len).cyan(),
            "░".repeat(28 - bar_len).dimmed()
        );
        out.push_str(&format!(
            "{:<22}  {:>12}  {:>12}  {:>5}  {}\n",
            r.name,
            humanise(r.mean),
            humanise(r.stddev),
            r.iters,
            bar
        ));
    }
    out
}

fn humanise(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{nanos} ns")
    } else if nanos < 1_000_000 {
        format!("{:.2} µs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.2} ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.2}  s", nanos as f64 / 1_000_000_000.0)
    }
}
