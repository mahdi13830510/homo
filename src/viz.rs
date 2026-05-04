//! Educational visualisations: traces, ASCII noise plots, ciphertext anatomy
//! diagrams.
//!
//! These modules don't add any cryptographic capability — they're entirely
//! about helping a student *see* what's happening. Every function here is
//! pure: input data in, terminal-ready string out.

use crate::schemes::{bfv, paillier};
use colored::Colorize;
use num_bigint::{BigInt, BigUint};
use num_traits::Signed;

/// A single step in a homomorphic-operation trace.
pub struct TraceStep {
    /// Short label (`"keygen"`, `"enc(a)"`, `"add"`).
    pub label: String,
    /// Multi-line description of what happened.
    pub detail: String,
    /// Optional numeric snapshot (e.g. cipher value) shown collapsed to ~30 chars.
    pub snapshot: Option<String>,
}

impl TraceStep {
    /// Build a new step.
    pub fn new(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            detail: detail.into(),
            snapshot: None,
        }
    }

    /// Attach a value snapshot (will be truncated for display).
    pub fn with_snapshot(mut self, snapshot: impl Into<String>) -> Self {
        self.snapshot = Some(snapshot.into());
        self
    }
}

/// Render a sequence of trace steps as a coloured, indented terminal block.
pub fn render_trace(title: &str, steps: &[TraceStep]) -> String {
    let mut out = String::new();
    out.push_str(&format!("\n{}\n", title.bold().underline()));
    for (i, step) in steps.iter().enumerate() {
        let marker = format!("[{:>2}]", i + 1).cyan().bold();
        out.push_str(&format!("\n  {marker} {}\n", step.label.bold()));
        for line in step.detail.lines() {
            out.push_str(&format!("       {}\n", line.dimmed()));
        }
        if let Some(snap) = &step.snapshot {
            let pretty = truncate(snap, 78);
            out.push_str(&format!("       {} {}\n", "→".green(), pretty.yellow()));
        }
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let head = &s[..max / 2 - 2];
    let tail = &s[s.len() - (max / 2 - 2)..];
    format!("{head} … {tail}")
}

/// Format a `BigUint` shortened to "first8…last8 (Nbits)".
pub fn short_uint(x: &BigUint) -> String {
    let s = x.to_str_radix(10);
    if s.len() <= 20 {
        format!("{s} ({}bits)", x.bits())
    } else {
        format!("{}…{} ({}bits)", &s[..8], &s[s.len() - 8..], x.bits())
    }
}

/// Format a `BigInt` shortened similarly.
pub fn short_int(x: &BigInt) -> String {
    let abs = x.abs();
    let s = abs.to_str_radix(10);
    let sign = if x.is_negative() { "-" } else { "" };
    if s.len() <= 20 {
        format!("{sign}{s}")
    } else {
        format!("{sign}{}…{}", &s[..8], &s[s.len() - 8..])
    }
}

/// Build a trace for a Paillier add: keygen → enc(a) → enc(b) → add → decrypt.
pub fn trace_paillier_add(a: u64, b: u64, bits: u64) -> Vec<TraceStep> {
    let mut steps = Vec::new();

    let (pk, sk) = paillier::keygen(bits);
    steps.push(
        TraceStep::new(
            "keygen",
            format!("Generated a {bits}-bit Paillier key pair."),
        )
        .with_snapshot(format!("n = {}", short_uint(&pk.n))),
    );

    let m_a = BigUint::from(a);
    let m_b = BigUint::from(b);
    let ct_a = paillier::encrypt(&pk, &m_a);
    steps.push(
        TraceStep::new(
            "enc(a)",
            format!("Encrypted a = {a}.\nFresh randomness sampled from ℤ_n*."),
        )
        .with_snapshot(format!("c_a = {}", short_uint(&ct_a.c))),
    );

    let ct_b = paillier::encrypt(&pk, &m_b);
    steps.push(
        TraceStep::new("enc(b)", format!("Encrypted b = {b}."))
            .with_snapshot(format!("c_b = {}", short_uint(&ct_b.c))),
    );

    let ct_sum = paillier::add(&pk, &ct_a, &ct_b);
    steps.push(
        TraceStep::new(
            "homomorphic add",
            "c_sum = c_a · c_b mod n²\n\
             The product of ciphertexts decrypts to the sum of plaintexts.\n\
             No secret key was used — anyone can do this."
                .to_string(),
        )
        .with_snapshot(format!("c_sum = {}", short_uint(&ct_sum.c))),
    );

    let m_sum = paillier::decrypt(&sk, &ct_sum);
    steps.push(
        TraceStep::new("decrypt", format!("Recovered plaintext.")).with_snapshot(format!(
            "m_sum = {} (expected {})",
            m_sum,
            a + b
        )),
    );
    steps
}

/// Build a trace for a BFV add: same shape, plus a noise readout.
pub fn trace_bfv_add(a: u64, b: u64) -> Vec<TraceStep> {
    let mut steps = Vec::new();
    let params = bfv::Params::toy();
    let (pk, sk) = bfv::keygen(&params);
    steps.push(
        TraceStep::new(
            "keygen",
            format!(
                "Toy BFV parameters:\n  n = {}\n  log₂ q ≈ {}\n  t = {}\n  η = {}",
                params.n,
                params.q.bits(),
                params.t,
                params.eta
            ),
        )
        .with_snapshot("Δ = ⌊q/t⌋".to_string()),
    );

    let ct_a = bfv::encrypt(&pk, &[a]);
    let (n_a, log_a, budget_a) = bfv::noise_estimate(&sk, &ct_a);
    steps.push(
        TraceStep::new("enc(a)", format!("Encrypted vector [{a}].")).with_snapshot(format!(
            "noise ≈ 2^{:.1}, budget ≈ {:.1} bits ({})",
            log_a,
            budget_a,
            short_int(&n_a)
        )),
    );

    let ct_b = bfv::encrypt(&pk, &[b]);
    steps.push(
        TraceStep::new("enc(b)", format!("Encrypted vector [{b}]."))
            .with_snapshot("noise ~ same order as enc(a)".to_string()),
    );

    let ct_sum = bfv::add(&ct_a, &ct_b);
    let (n_s, log_s, budget_s) = bfv::noise_estimate(&sk, &ct_sum);
    steps.push(
        TraceStep::new(
            "add",
            "Add: component-wise polynomial addition.\nNoise grows by ~1 bit.".to_string(),
        )
        .with_snapshot(format!(
            "noise ≈ 2^{:.1}, budget ≈ {:.1} bits ({})",
            log_s,
            budget_s,
            short_int(&n_s)
        )),
    );

    let out = bfv::decrypt(&sk, &ct_sum);
    steps.push(
        TraceStep::new("decrypt", "Scaled rounding back to ℤ_t.".to_string())
            .with_snapshot(format!("recovered = {}, expected {}", out[0], a + b)),
    );

    steps
}

/// Render a noise-budget series as an ASCII bar chart.
///
/// Each entry is `(label, budget_bits)`. The bar is drawn proportional to
/// `max_budget`. Useful for showing how multiplications eat noise budget.
pub fn render_noise_chart(series: &[(String, f64)], max_budget: f64) -> String {
    let bar_width = 50usize;
    let mut out = String::new();
    out.push_str(&format!(
        "\n{}\n",
        format!("Noise budget (out of {:.0} bits):", max_budget).bold()
    ));
    for (label, value) in series {
        let frac = (value / max_budget).clamp(0.0, 1.0);
        let filled = (frac * bar_width as f64).round() as usize;
        let empty = bar_width - filled;
        let bar = format!(
            "{}{}",
            "█".repeat(filled).green(),
            "░".repeat(empty).dimmed()
        );
        out.push_str(&format!(
            "  {label:<14} │{bar}│ {value:>5.1} bits\n",
            label = label
        ));
    }
    out
}

/// Render a side-by-side anatomy diagram of a Paillier ciphertext.
pub fn anatomy_paillier(pk: &paillier::PublicKey, ct: &paillier::Ciphertext) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "\n{}\n",
        "Paillier ciphertext anatomy".bold().underline()
    ));
    out.push_str(&format!(
        "\n  modulus n²       = {}\n  ciphertext c     = {}\n  ratio c/n²       ≈ {:.3}\n",
        short_uint(&pk.n_squared()),
        short_uint(&ct.c),
        ratio(&ct.c, &pk.n_squared())
    ));
    out.push_str("\n  ┌─────────────────────────────────────────┐\n");
    out.push_str("  │ c = (1 + n)^m · r^n   (mod n²)          │\n");
    out.push_str("  │       └──┬──┘  └───┬───┘                │\n");
    out.push_str("  │      message   randomness               │\n");
    out.push_str("  └─────────────────────────────────────────┘\n");
    out
}

fn ratio(num: &BigUint, den: &BigUint) -> f64 {
    if den == &BigUint::from(0u32) {
        return 0.0;
    }
    let bits_n = num.bits() as f64;
    let bits_d = den.bits() as f64;
    2f64.powf(bits_n - bits_d)
}

/// Render the BFV ciphertext anatomy: number of components, log₂ q, log₂ t, etc.
pub fn anatomy_bfv(ct: &bfv::Ciphertext) -> String {
    let p = &ct.params;
    let mut out = String::new();
    out.push_str(&format!(
        "\n{}\n",
        "BFV ciphertext anatomy".bold().underline()
    ));
    out.push_str(&format!(
        "\n  ring degree n  = {}\n  ciphertext mod = 2^{}  (q has {} bits)\n  plaintext mod  = {}\n  components     = {}\n",
        p.n,
        p.q.bits(),
        p.q.bits(),
        p.t,
        ct.parts.len()
    ));
    out.push_str("\n  components:\n");
    for (i, part) in ct.parts.iter().enumerate() {
        let inf = part.inf_norm();
        out.push_str(&format!(
            "    c_{i}  ‖·‖∞ ≈ {} (≈ 2^{:.1} of q)\n",
            short_int(&inf),
            bfv::bigint_log2(&inf)
        ));
    }
    out.push_str("\n  decrypts as:  m = ⌊ t · (c₀ + c₁·s");
    if ct.parts.len() >= 3 {
        out.push_str(" + c₂·s²");
    }
    out.push_str(") / q ⌉  mod t\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_trace_does_not_panic() {
        let steps = trace_paillier_add(3, 5, 64);
        let s = render_trace("Paillier addition", &steps);
        assert!(s.contains("homomorphic add"));
    }

    #[test]
    fn noise_chart_basic() {
        let series = vec![
            ("fresh".to_string(), 50.0),
            ("after add".to_string(), 49.0),
            ("after mul".to_string(), 25.0),
        ];
        let s = render_noise_chart(&series, 50.0);
        assert!(s.contains("fresh"));
    }
}
