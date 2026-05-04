//! Command-line interface — `clap`-driven, openssl-style.

use clap::{Parser, Subcommand};
use colored::Colorize;
use num_bigint::BigUint;

use homo::attacks;
use homo::bench;
use homo::io::{self as wire, Envelope};
use homo::playground;
use homo::schemes::{bfv, bgn, ckks, paillier, Scheme};
use homo::viz;

/// Top-level `homo` invocation.
#[derive(Parser)]
#[command(
    name = "homo",
    version,
    about = "homomorphic encryption, made tangible",
    long_about = "homo is a command-line tool for homomorphic encryption.\n\
                  It works like openssl but for FHE: generate keys, encrypt,\n\
                  evaluate operations on ciphertexts, and decrypt — plus a\n\
                  set of unique educational subcommands."
)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Cmd,
}

/// Top-level subcommands.
#[derive(Subcommand)]
pub enum Cmd {
    /// List supported schemes and a one-line description of each.
    Schemes,

    /// Generate a new key pair.
    Keygen {
        /// Which scheme: paillier | bfv | bgn.
        #[arg(short, long, default_value = "paillier")]
        scheme: Scheme,
        /// For paillier/bgn: modulus bit length. Ignored for bfv.
        #[arg(short, long, default_value_t = 1024)]
        bits: u64,
        /// Output path for the public key.
        #[arg(long, default_value = "key.pub")]
        out_pub: String,
        /// Output path for the secret key.
        #[arg(long, default_value = "key.sec")]
        out_sec: String,
    },

    /// Encrypt a plaintext under a public key.
    Encrypt {
        /// Public key file.
        #[arg(long)]
        key: String,
        /// Plaintext: a non-negative integer (paillier/bgn) or a comma-list (bfv).
        #[arg(long)]
        message: String,
        /// Output ciphertext file. If absent, writes to stdout.
        #[arg(long)]
        out: Option<String>,
    },

    /// Decrypt a ciphertext with a secret key.
    Decrypt {
        /// Secret key file.
        #[arg(long)]
        key: String,
        /// Ciphertext file.
        #[arg(long)]
        input: String,
    },

    /// Apply a homomorphic operation between two ciphertexts (or ciphertext+plain).
    Eval {
        /// Public key file (some schemes need it for arithmetic).
        #[arg(long)]
        key: String,
        /// Operation: add | mul | smul | sadd  (sadd/smul take a plaintext scalar).
        #[arg(long)]
        op: String,
        /// First operand (a ciphertext file).
        #[arg(long)]
        a: String,
        /// Second operand (a ciphertext file, OR a scalar for smul/sadd).
        #[arg(long)]
        b: String,
        /// Output ciphertext file.
        #[arg(long)]
        out: String,
    },

    /// Show what's inside a key or ciphertext (sizes, structure, fingerprint).
    Inspect {
        /// File to inspect.
        input: String,
        /// Optional secret key for noise / sanity checks.
        #[arg(long)]
        secret: Option<String>,
    },

    /// Step-by-step trace of a small operation (`homo trace add 17 25`).
    Trace {
        /// Operation: add (paillier) | bfv-add (bfv).
        op: String,
        /// First operand.
        a: u64,
        /// Second operand.
        b: u64,
    },

    /// Visualise noise growth across a sequence of additions/multiplications.
    Noise {
        /// Number of additions to apply (default 4).
        #[arg(long, default_value_t = 4)]
        adds: u32,
        /// Whether to include one multiplication (default false).
        #[arg(long, default_value_t = false)]
        with_mul: bool,
    },

    /// Run textbook attacks on weak parameters (educational).
    Attack {
        /// Which attack: factor (paillier).
        what: String,
        /// Public key to attack.
        #[arg(long)]
        key: String,
    },

    /// Run benchmarks.
    Bench {
        /// Which scheme: paillier | bfv | all.
        #[arg(short, long, default_value = "all")]
        scheme: String,
        /// Iterations.
        #[arg(short, long, default_value_t = 50)]
        iters: u32,
        /// For paillier: key bits.
        #[arg(long, default_value_t = 512)]
        bits: u64,
    },

    /// Drop into the interactive REPL (BFV-lite session).
    Lab,

    /// Run a `.hcir` circuit file homomorphically.
    Circuit {
        /// Path to the `.hcir` file.
        path: String,
        /// Inputs as `name=value` pairs (repeatable).
        #[arg(short, long, value_parser = parse_kv)]
        input: Vec<(String, i64)>,
    },

    /// Encrypt-evaluate-decrypt a polynomial over a domain and plot the result
    /// as ASCII art alongside the cleartext reference. Showcases CKKS.
    Plot {
        /// Polynomial coefficients, lowest degree first (e.g. "1,0,-1" for
        /// `1 - x²`). Up to degree 2 (a + b·x + c·x²). Default: a parabola.
        #[arg(long, default_value = "1,0,-1")]
        poly: String,
        /// Range start.
        #[arg(long, default_value_t = -2.0)]
        from: f64,
        /// Range end.
        #[arg(long, default_value_t = 2.0)]
        to: f64,
        /// Number of sample points (≤ slot count).
        #[arg(long, default_value_t = 4)]
        points: usize,
    },

    /// Run a tiny encrypted linear-regression inference. Demonstrates a
    /// realistic ML-on-encrypted-data flow end-to-end.
    Ml {
        /// Comma-separated weight vector (e.g. "0.4,0.3,0.7").
        #[arg(long, default_value = "0.4,0.3,0.7")]
        weights: String,
        /// Comma-separated input feature vector (encrypted in this demo).
        #[arg(long, default_value = "1.0,2.5,-0.5")]
        features: String,
        /// Bias term added to the inner product.
        #[arg(long, default_value_t = 0.1)]
        bias: f64,
    },

    /// Run the same homomorphic addition across all schemes side by side
    /// and tabulate timings, ciphertext sizes, and noise.
    Compare {
        /// First operand.
        #[arg(default_value_t = 17)]
        a: u64,
        /// Second operand.
        #[arg(default_value_t = 25)]
        b: u64,
    },

    /// Simulate a multi-party private aggregation: each participant encrypts
    /// their value, the aggregator sums them homomorphically, the holder of
    /// the secret key decrypts the sum.
    Party {
        /// Comma-separated values, one per participant (e.g. "10,20,30,40").
        #[arg(long, default_value = "12,7,28,5,16")]
        values: String,
        /// Scheme to use for the demo.
        #[arg(long, default_value = "paillier")]
        scheme: Scheme,
    },
}

fn parse_kv(s: &str) -> Result<(String, i64), String> {
    let (k, v) = s.split_once('=').ok_or("expected key=value")?;
    let v = v.parse::<i64>().map_err(|e| e.to_string())?;
    Ok((k.to_string(), v))
}

/// Entry point used by `main.rs`.
pub fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Cmd::Schemes => cmd_schemes(),
        Cmd::Keygen {
            scheme,
            bits,
            out_pub,
            out_sec,
        } => cmd_keygen(scheme, bits, &out_pub, &out_sec),
        Cmd::Encrypt { key, message, out } => cmd_encrypt(&key, &message, out.as_deref()),
        Cmd::Decrypt { key, input } => cmd_decrypt(&key, &input),
        Cmd::Eval { key, op, a, b, out } => cmd_eval(&key, &op, &a, &b, &out),
        Cmd::Inspect { input, secret } => cmd_inspect(&input, secret.as_deref()),
        Cmd::Trace { op, a, b } => cmd_trace(&op, a, b),
        Cmd::Noise { adds, with_mul } => cmd_noise(adds, with_mul),
        Cmd::Attack { what, key } => cmd_attack(&what, &key),
        Cmd::Bench {
            scheme,
            iters,
            bits,
        } => cmd_bench(&scheme, iters, bits),
        Cmd::Lab => playground::repl().map_err(|e| e.to_string()),
        Cmd::Circuit { path, input } => cmd_circuit(&path, input),
        Cmd::Plot {
            poly,
            from,
            to,
            points,
        } => cmd_plot(&poly, from, to, points),
        Cmd::Ml {
            weights,
            features,
            bias,
        } => cmd_ml(&weights, &features, bias),
        Cmd::Compare { a, b } => cmd_compare(a, b),
        Cmd::Party { values, scheme } => cmd_party(&values, scheme),
    }
}

fn cmd_schemes() -> Result<(), String> {
    println!("\n{}", "Supported schemes".bold().underline());
    for s in Scheme::all() {
        println!("  {:<12} {}", s.short().bold().green(), s.describe());
    }
    println!();
    Ok(())
}

fn cmd_keygen(scheme: Scheme, bits: u64, out_pub: &str, out_sec: &str) -> Result<(), String> {
    let pb = indicatif::ProgressBar::new_spinner();
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb.set_message(format!("generating {} key…", scheme.short()));

    let (pk_env, sk_env) = match scheme {
        Scheme::Paillier => {
            let (pk, sk) = paillier::keygen(bits);
            (wire::pack_paillier_pk(&pk), wire::pack_paillier_sk(&sk))
        }
        Scheme::Bfv => {
            let params = if bits >= 1024 {
                bfv::Params::toy()
            } else {
                bfv::Params::toy()
            };
            let (pk, sk) = bfv::keygen(&params);
            (wire::pack_bfv_pk(&pk), wire::pack_bfv_sk(&sk))
        }
        Scheme::Bgn => {
            let (pk, sk) = bgn::keygen(bits, 1 << 20);
            (wire::pack_bgn_pk(&pk), wire::pack_bgn_sk(&sk))
        }
        Scheme::Ckks => {
            let params = if bits >= 1024 {
                ckks::Params::medium()
            } else {
                ckks::Params::toy()
            };
            let (pk, sk) = ckks::keygen(&params);
            (wire::pack_ckks_pk(&pk), wire::pack_ckks_sk(&sk))
        }
    };
    pb.finish_and_clear();

    wire::write_file(out_pub, &pk_env.to_pem()).map_err(|e| e.to_string())?;
    wire::write_file(out_sec, &sk_env.to_pem()).map_err(|e| e.to_string())?;

    println!(
        "{} {}  → {}",
        "✓".green().bold(),
        "public  key".bold(),
        out_pub
    );
    println!(
        "{} {}  → {}",
        "✓".green().bold(),
        "secret  key".bold(),
        out_sec
    );
    println!("  fingerprint: {}", pk_env.fingerprint.yellow());
    Ok(())
}

fn read_envelope(path: &str) -> Result<Envelope, String> {
    let pem = wire::read_file(path).map_err(|e| e.to_string())?;
    Envelope::from_pem(&pem)
}

fn cmd_encrypt(key_path: &str, message: &str, out: Option<&str>) -> Result<(), String> {
    let env = read_envelope(key_path)?;
    let ct_env = match env.scheme {
        Scheme::Paillier => {
            let pk = wire::unpack_paillier_pk(&env)?;
            let m = message.parse::<BigUint>().map_err(|e| e.to_string())?;
            let ct = paillier::encrypt(&pk, &m);
            wire::pack_paillier_ct(&ct)
        }
        Scheme::Bfv => {
            let pk = wire::unpack_bfv_pk(&env)?;
            let plain: Vec<u64> = message
                .split(',')
                .map(|s| s.trim().parse::<u64>())
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
            let ct = bfv::encrypt(&pk, &plain);
            wire::pack_bfv_ct(&ct)
        }
        Scheme::Bgn => {
            let pk = wire::unpack_bgn_pk(&env)?;
            let m: u64 = message
                .parse()
                .map_err(|e: std::num::ParseIntError| e.to_string())?;
            let ct = bgn::encrypt(&pk, m);
            wire::pack_bgn_ct(&ct)
        }
        Scheme::Ckks => {
            let pk = wire::unpack_ckks_pk(&env)?;
            let slots: Vec<f64> = message
                .split(',')
                .map(|s| s.trim().parse::<f64>())
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
            let ct = ckks::encrypt(&pk, &slots);
            wire::pack_ckks_ct(&ct)
        }
    };
    let pem = ct_env.to_pem();
    match out {
        Some(p) => {
            wire::write_file(p, &pem).map_err(|e| e.to_string())?;
            println!(
                "{} ciphertext → {}  ({})",
                "✓".green(),
                p,
                ct_env.fingerprint.yellow()
            );
        }
        None => print!("{pem}"),
    }
    Ok(())
}

fn cmd_decrypt(key_path: &str, ct_path: &str) -> Result<(), String> {
    let key_env = read_envelope(key_path)?;
    let ct_env = read_envelope(ct_path)?;
    if key_env.scheme != ct_env.scheme {
        return Err(format!(
            "scheme mismatch: key is {:?}, ciphertext is {:?}",
            key_env.scheme, ct_env.scheme
        ));
    }
    match key_env.scheme {
        Scheme::Paillier => {
            let sk = wire::unpack_paillier_sk(&key_env)?;
            let ct = wire::unpack_paillier_ct(&ct_env)?;
            println!("{}", paillier::decrypt(&sk, &ct));
        }
        Scheme::Bfv => {
            let sk = wire::unpack_bfv_sk(&key_env)?;
            let ct = wire::unpack_bfv_ct(&ct_env)?;
            let plain = bfv::decrypt(&sk, &ct);
            // Strip trailing zeros for readability.
            let last = plain
                .iter()
                .rposition(|x| *x != 0)
                .map(|i| i + 1)
                .unwrap_or(0);
            let trimmed = &plain[..last.max(1)];
            println!(
                "{}",
                trimmed
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        Scheme::Bgn => {
            let sk = wire::unpack_bgn_sk(&key_env)?;
            let ct = wire::unpack_bgn_ct(&ct_env)?;
            match bgn::decrypt_l1(&sk, &ct) {
                Some(m) => println!("{m}"),
                None => return Err("decryption failed (bound exceeded?)".into()),
            }
        }
        Scheme::Ckks => {
            let sk = wire::unpack_ckks_sk(&key_env)?;
            let ct = wire::unpack_ckks_ct(&ct_env)?;
            let slots = ckks::decrypt(&sk, &ct);
            // CKKS produces n/2 slot values; we trim and drop tiny noise.
            let half = sk.params.slot_count();
            let formatted: Vec<String> = slots
                .iter()
                .take(half)
                .map(|v| {
                    if v.abs() < 1e-6 {
                        "0".to_string()
                    } else {
                        format!("{:.4}", v)
                    }
                })
                .collect();
            println!("{}", formatted.join(","));
        }
    }
    Ok(())
}

fn cmd_eval(
    key_path: &str,
    op: &str,
    a_path: &str,
    b_path: &str,
    out_path: &str,
) -> Result<(), String> {
    let key_env = read_envelope(key_path)?;
    let a_env = read_envelope(a_path)?;

    match key_env.scheme {
        Scheme::Paillier => {
            let pk = wire::unpack_paillier_pk(&key_env)?;
            let a = wire::unpack_paillier_ct(&a_env)?;
            let result = match op {
                "add" => {
                    let b_env = read_envelope(b_path)?;
                    let b = wire::unpack_paillier_ct(&b_env)?;
                    paillier::add(&pk, &a, &b)
                }
                "smul" => {
                    let k = b_path.parse::<BigUint>().map_err(|e| e.to_string())?;
                    paillier::mul_plain(&pk, &a, &k)
                }
                "sadd" => {
                    let k = b_path.parse::<BigUint>().map_err(|e| e.to_string())?;
                    paillier::add_plain(&pk, &a, &k)
                }
                other => {
                    return Err(format!(
                        "paillier: unsupported op '{other}' (try add/smul/sadd)"
                    ))
                }
            };
            let env = wire::pack_paillier_ct(&result);
            wire::write_file(out_path, &env.to_pem()).map_err(|e| e.to_string())?;
        }
        Scheme::Bfv => {
            let _pk = wire::unpack_bfv_pk(&key_env)?;
            let a = wire::unpack_bfv_ct(&a_env)?;
            let b_env = read_envelope(b_path)?;
            let b = wire::unpack_bfv_ct(&b_env)?;
            let result = match op {
                "add" => bfv::add(&a, &b),
                "mul" => bfv::mul(&a, &b),
                other => return Err(format!("bfv: unsupported op '{other}' (try add/mul)")),
            };
            let env = wire::pack_bfv_ct(&result);
            wire::write_file(out_path, &env.to_pem()).map_err(|e| e.to_string())?;
        }
        Scheme::Bgn => {
            let pk = wire::unpack_bgn_pk(&key_env)?;
            let a = wire::unpack_bgn_ct(&a_env)?;
            let b_env = read_envelope(b_path)?;
            let b = wire::unpack_bgn_ct(&b_env)?;
            let result = match op {
                "add" => bgn::add_l1(&pk, &a, &b),
                other => {
                    return Err(format!(
                        "bgn: unsupported op '{other}' (only add at level 1)"
                    ))
                }
            };
            let env = wire::pack_bgn_ct(&result);
            wire::write_file(out_path, &env.to_pem()).map_err(|e| e.to_string())?;
        }
        Scheme::Ckks => {
            let _pk = wire::unpack_ckks_pk(&key_env)?;
            let a = wire::unpack_ckks_ct(&a_env)?;
            let result = match op {
                "add" => {
                    let b_env = read_envelope(b_path)?;
                    let b = wire::unpack_ckks_ct(&b_env)?;
                    ckks::add(&a, &b)
                }
                "mul" => {
                    let b_env = read_envelope(b_path)?;
                    let b = wire::unpack_ckks_ct(&b_env)?;
                    ckks::mul(&a, &b)
                }
                "rescale" => {
                    // rescale is unary; the b argument is ignored (use any path or "_").
                    ckks::rescale(&a)
                }
                "padd" => {
                    // ciphertext + plaintext slot vector ("1.0,2.0,3.0")
                    let slots: Vec<f64> = b_path
                        .split(',')
                        .map(|s| s.trim().parse::<f64>())
                        .collect::<Result<_, _>>()
                        .map_err(|e| e.to_string())?;
                    ckks::add_plain(&a, &slots)
                }
                other => {
                    return Err(format!(
                        "ckks: unsupported op '{other}' (try add/mul/rescale/padd)"
                    ))
                }
            };
            let env = wire::pack_ckks_ct(&result);
            wire::write_file(out_path, &env.to_pem()).map_err(|e| e.to_string())?;
        }
    }
    println!("{} {} → {}", "✓".green(), op.bold(), out_path);
    Ok(())
}

fn cmd_inspect(input: &str, secret: Option<&str>) -> Result<(), String> {
    let env = read_envelope(input)?;
    println!("\n{}", "Envelope".bold().underline());
    println!("  scheme       {}", env.scheme.short().bold().cyan());
    println!("  kind         {:?}", env.kind);
    println!("  version      {}", env.version);
    println!("  fingerprint  {}", env.fingerprint.yellow());
    println!("  payload size {} bytes", env.data.len() * 3 / 4);

    match (env.scheme, env.kind) {
        (Scheme::Paillier, wire::Kind::PublicKey) => {
            let pk = wire::unpack_paillier_pk(&env)?;
            println!("  n bits       {}", pk.n.bits());
            println!("  n            {}", viz::short_uint(&pk.n));
        }
        (Scheme::Paillier, wire::Kind::Ciphertext) => {
            let ct = wire::unpack_paillier_ct(&env)?;
            // Need the public key to anchor the anatomy diagram. Without it
            // we still print what we can.
            println!("  c            {}", viz::short_uint(&ct.c));
            println!("  c bits       {}", ct.c.bits());
        }
        (Scheme::Bfv, wire::Kind::Ciphertext) => {
            let ct = wire::unpack_bfv_ct(&env)?;
            print!("{}", viz::anatomy_bfv(&ct));
            if let Some(sk_path) = secret {
                let sk_env = read_envelope(sk_path)?;
                let sk = wire::unpack_bfv_sk(&sk_env)?;
                let (n, log2_n, budget) = bfv::noise_estimate(&sk, &ct);
                println!(
                    "  noise        ‖·‖∞ ≈ {} (≈ 2^{:.1})",
                    viz::short_int(&n),
                    log2_n
                );
                println!("  budget       ≈ {:.1} bits", budget);
            }
        }
        (Scheme::Bfv, wire::Kind::PublicKey) => {
            let pk = wire::unpack_bfv_pk(&env)?;
            println!("  ring degree  {}", pk.params.n);
            println!("  log₂ q       ≈ {}", pk.params.q.bits());
            println!("  t            {}", pk.params.t);
        }
        (Scheme::Ckks, wire::Kind::PublicKey) => {
            let pk = wire::unpack_ckks_pk(&env)?;
            println!("  ring degree  {}", pk.params.n);
            println!("  slots        {}", pk.params.slot_count());
            println!("  levels       {}", pk.params.levels);
            println!("  log₂ q_top   ≈ {}", pk.params.q_top().bits());
            println!("  log₂ Δ       ≈ {}", pk.params.delta.bits());
        }
        (Scheme::Ckks, wire::Kind::Ciphertext) => {
            let ct = wire::unpack_ckks_ct(&env)?;
            println!("  ring degree  {}", ct.params.n);
            println!("  slots        {}", ct.params.slot_count());
            println!("  level        {} / {}", ct.level, ct.params.levels);
            println!("  log₂ q       ≈ {}", ct.q().bits());
            println!("  log₂ scale   ≈ {}", ct.scale.bits());
            println!("  components   {}", ct.parts.len());
            if let Some(sk_path) = secret {
                let sk_env = read_envelope(sk_path)?;
                let sk = wire::unpack_ckks_sk(&sk_env)?;
                let (log_m, log_q, head) = ckks::noise_estimate(&sk, &ct);
                println!("  log₂ |m|     ≈ {:.1}", log_m);
                println!("  log₂ q       ≈ {:.1}", log_q);
                println!("  headroom     ≈ {:.1} bits", head);
            }
        }
        _ => {}
    }
    println!();
    Ok(())
}

fn cmd_trace(op: &str, a: u64, b: u64) -> Result<(), String> {
    match op {
        "add" | "paillier-add" => {
            let steps = viz::trace_paillier_add(a, b, 256);
            print!("{}", viz::render_trace("Paillier additive trace", &steps));
        }
        "bfv-add" => {
            let steps = viz::trace_bfv_add(a, b);
            print!("{}", viz::render_trace("BFV-lite addition trace", &steps));
        }
        other => return Err(format!("unknown trace op: {other}  (try add | bfv-add)")),
    }
    Ok(())
}

fn cmd_noise(adds: u32, with_mul: bool) -> Result<(), String> {
    let params = bfv::Params::toy();
    let (pk, sk) = bfv::keygen(&params);
    let mut series = Vec::new();
    let mut ct = bfv::encrypt(&pk, &[7]);
    let (_, _, budget0) = bfv::noise_estimate(&sk, &ct);
    series.push(("fresh".to_string(), budget0));
    let max_budget = budget0;

    for i in 1..=adds {
        let other = bfv::encrypt(&pk, &[3]);
        ct = bfv::add(&ct, &other);
        let (_, _, b) = bfv::noise_estimate(&sk, &ct);
        series.push((format!("add #{i}"), b));
    }
    if with_mul {
        let other = bfv::encrypt(&pk, &[2]);
        ct = bfv::mul(&ct, &other);
        let (_, _, b) = bfv::noise_estimate(&sk, &ct);
        series.push(("mul".to_string(), b));
    }
    print!("{}", viz::render_noise_chart(&series, max_budget));
    Ok(())
}

fn cmd_attack(what: &str, key_path: &str) -> Result<(), String> {
    let env = read_envelope(key_path)?;
    if env.scheme != Scheme::Paillier {
        return Err("attack subcommand currently supports only Paillier keys".into());
    }
    let pk = wire::unpack_paillier_pk(&env)?;

    println!("\n{}", "Attempting factorisation of n".bold().underline());
    println!("  n bits    {}", pk.n.bits());

    let pb = indicatif::ProgressBar::new_spinner();
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb.set_message("trial division…");

    let result = match what {
        "factor" => attacks::factor_trial_division(&pk.n, 2_000_000).or_else(|| {
            pb.set_message("Pollard's rho…");
            attacks::factor_pollard_rho(&pk.n, 200_000)
        }),
        other => return Err(format!("unknown attack: {other}")),
    };
    pb.finish_and_clear();

    match result {
        Some(f) => {
            println!("\n{} factored after {} steps", "✓".green().bold(), f.steps);
            println!("  p = {}", viz::short_uint(&f.p));
            println!("  q = {}", viz::short_uint(&f.q));
            let sk = attacks::recover_paillier_sk(&pk, &f);
            println!("  λ bits = {}, μ bits = {}", sk.lambda.bits(), sk.mu.bits());
            println!(
                "\n{}\n",
                "lesson: this is why real Paillier needs ≥ 2048-bit moduli."
                    .italic()
                    .yellow()
            );
        }
        None => {
            println!(
                "{} could not factor in the budget — your key looks healthy.",
                "✗".red()
            );
        }
    }
    Ok(())
}

fn cmd_bench(scheme: &str, iters: u32, bits: u64) -> Result<(), String> {
    let mut all = Vec::new();
    if scheme == "paillier" || scheme == "all" {
        all.extend(bench::bench_paillier(bits, iters));
    }
    if scheme == "bfv" || scheme == "all" {
        all.extend(bench::bench_bfv(iters));
    }
    if scheme == "ckks" || scheme == "all" {
        all.extend(bench::bench_ckks(iters));
    }
    if all.is_empty() {
        return Err(format!("unknown scheme for bench: {scheme}"));
    }
    print!("{}", bench::render(&all));
    Ok(())
}

fn cmd_circuit(path: &str, inputs: Vec<(String, i64)>) -> Result<(), String> {
    let src = wire::read_file(path).map_err(|e| e.to_string())?;
    let mut map = std::collections::HashMap::new();
    for (k, v) in inputs {
        map.insert(k, v);
    }
    let (result, log) = playground::run_circuit(&src, &map)?;
    println!("\n{}", "Circuit trace".bold().underline());
    print!("{log}");
    println!(
        "\n{} {}\n",
        "result:".bold(),
        result.to_string().green().bold()
    );
    Ok(())
}

// =============================================================================
// New, innovative commands
// =============================================================================

/// `homo plot` — encrypts a domain of x values, evaluates a polynomial over
/// CKKS ciphertexts, decrypts, and renders the result as ASCII alongside the
/// cleartext reference so you can see they agree.
///
/// We restrict to polynomials of degree ≤ 2 because that uses exactly one
/// homomorphic multiplication per term — the natural depth budget of the toy
/// CKKS parameter set, and keeps the level-tracking trivial.
fn cmd_plot(poly: &str, from: f64, to: f64, points: usize) -> Result<(), String> {
    let coeffs: Vec<f64> = poly
        .split(',')
        .map(|s| s.trim().parse::<f64>())
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    if coeffs.is_empty() {
        return Err("polynomial must have at least one coefficient".into());
    }
    if coeffs.len() > 3 {
        return Err("plot demo handles polynomials up to degree 2 (a + b·x + c·x²)".into());
    }
    if from >= to {
        return Err("`--from` must be less than `--to`".into());
    }

    let params = ckks::Params::toy();
    let max_pts = params.slot_count();
    if points == 0 || points > max_pts {
        return Err(format!(
            "`--points` must be between 1 and {max_pts} for the toy params"
        ));
    }

    // Sample x values uniformly across the range.
    let mut xs = Vec::with_capacity(points);
    if points == 1 {
        xs.push((from + to) / 2.0);
    } else {
        for i in 0..points {
            xs.push(from + (to - from) * i as f64 / (points - 1) as f64);
        }
    }

    let (pk, sk) = ckks::keygen(&params);
    let ct_x = ckks::encrypt(&pk, &xs);

    // Pad coeffs to length 3 for uniform handling.
    let c0 = coeffs.first().copied().unwrap_or(0.0);
    let c1 = coeffs.get(1).copied().unwrap_or(0.0);
    let c2 = coeffs.get(2).copied().unwrap_or(0.0);

    // Linear part:  c1 * x   (scale = Δ², level = top)  →  rescale  →  scale = Δ, level = top-1
    let mut ct_lin = ckks::rescale(&ckks::mul_plain(&ct_x, &vec![c1; points]));

    // Quadratic part:  x*x   →  size-3 ciphertext at level top, scale = Δ²
    //   then mul_plain by c2 (still size-3 OK)  →  scale = Δ³
    //   then rescale TWICE to bring scale back to Δ and level down to top-2.
    //
    // Wait — rescale on a size-3 ciphertext is fine (we rescale every component).
    // After one rescale: size-3, level=top-1, scale=Δ². After another: level=top-2, scale=Δ.
    // But we can't add a size-3 to ct_lin (size-2)... actually we can, the add path
    // already handles asymmetric component counts. So this works.
    let mut acc = if c2.abs() > 1e-12 {
        let xx = ckks::mul(&ct_x, &ct_x); // size-3, scale = Δ²
        let xx_c2 = ckks::mul_plain(&xx, &vec![c2; points]); // size-3, scale = Δ³
        let xx_c2 = ckks::rescale(&xx_c2); // size-3, scale = Δ², level = top-1
        let xx_c2 = ckks::rescale(&xx_c2); // size-3, scale = Δ,  level = top-2

        // Bring linear part down to the same level as the quadratic (no message scaling).
        let mut lin = ct_lin.clone();
        while lin.level > xx_c2.level {
            lin = ckks::mod_switch(&lin);
        }
        ct_lin = lin;
        // Now both at level top-2 with scale Δ. Add component-wise.
        ckks::add(&ct_lin, &xx_c2)
    } else {
        ct_lin
    };

    // Add the constant term (encoded as a plaintext slot vector at the right scale).
    if c0.abs() > 1e-12 {
        acc = ckks::add_plain(&acc, &vec![c0; points]);
    }

    let homom = ckks::decrypt(&sk, &acc);

    // Cleartext reference
    let cleartext: Vec<f64> = xs.iter().map(|&x| c0 + c1 * x + c2 * x * x).collect();

    println!(
        "\n{}",
        "Homomorphic polynomial evaluation".bold().underline()
    );
    let pretty = match (c1.abs() > 1e-12, c2.abs() > 1e-12) {
        (false, false) => format!("{c0}"),
        (true, false) => format!("{c0} + {c1}·x"),
        (false, true) => format!("{c0} + {c2}·x²"),
        (true, true) => format!("{c0} + {c1}·x + {c2}·x²"),
    };
    println!("  poly: {}", pretty.yellow());

    println!(
        "\n  {:>10}  {:>14}  {:>14}  {:>10}",
        "x".bold(),
        "homomorphic".bold(),
        "cleartext".bold(),
        "|err|".bold()
    );
    println!("  {}", "─".repeat(56).dimmed());
    for i in 0..points {
        let err = (homom[i] - cleartext[i]).abs();
        println!(
            "  {:>10.4}  {:>14.6}  {:>14.6}  {:>10.2e}",
            xs[i], homom[i], cleartext[i], err
        );
    }

    println!("\n{}", "  Reference curve (cleartext):".dimmed());
    print_ascii_plot(&xs, &cleartext, 60, 12);
    println!();
    Ok(())
}

/// Tiny ASCII line plot for an `xs/ys` pair. Width × height in chars.
fn print_ascii_plot(xs: &[f64], ys: &[f64], width: usize, height: usize) {
    if xs.is_empty() {
        return;
    }
    let xmin = xs.iter().cloned().fold(f64::INFINITY, f64::min);
    let xmax = xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let ymin = ys.iter().cloned().fold(f64::INFINITY, f64::min);
    let ymax = ys.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let xspan = (xmax - xmin).max(1e-9);
    let yspan = (ymax - ymin).max(1e-9);

    let mut grid = vec![vec![' '; width]; height];

    // Simple linear interpolation between sample points.
    for w in 0..width {
        let x = xmin + xspan * w as f64 / (width - 1) as f64;
        // Find bracketing sample indices
        let mut lo = 0usize;
        for i in 0..xs.len() - 1 {
            if xs[i] <= x && x <= xs[i + 1] {
                lo = i;
                break;
            }
        }
        let hi = (lo + 1).min(xs.len() - 1);
        let t = if (xs[hi] - xs[lo]).abs() < 1e-12 {
            0.0
        } else {
            (x - xs[lo]) / (xs[hi] - xs[lo])
        };
        let y = ys[lo] + t * (ys[hi] - ys[lo]);
        let row_f = (1.0 - (y - ymin) / yspan) * (height - 1) as f64;
        let row = row_f.round() as isize;
        if row >= 0 && (row as usize) < height {
            grid[row as usize][w] = '·';
        }
    }
    // Mark the actual sample points with '+'.
    for (&x, &y) in xs.iter().zip(ys.iter()) {
        let col_f = (x - xmin) / xspan * (width - 1) as f64;
        let col = col_f.round() as isize;
        let row_f = (1.0 - (y - ymin) / yspan) * (height - 1) as f64;
        let row = row_f.round() as isize;
        if col >= 0 && (col as usize) < width && row >= 0 && (row as usize) < height {
            grid[row as usize][col as usize] = '+';
        }
    }
    for row in grid {
        let line: String = row.into_iter().collect();
        println!("  │{}", line);
    }
    println!("  └{}", "─".repeat(width));
    println!(
        "    {} ←{:>frac$}→ {}",
        format!("{xmin:.2}"),
        " ",
        format!("{xmax:.2}"),
        frac = width.saturating_sub(10)
    );
}

/// `homo ml` — encrypted linear regression inference.
///
/// The server holds an encrypted feature vector and computes
/// `output = w · x + b` homomorphically, then sends the encrypted output back.
/// The client decrypts. No cleartext feature ever reaches the server.
fn cmd_ml(weights: &str, features: &str, bias: f64) -> Result<(), String> {
    let w: Vec<f64> = weights
        .split(',')
        .map(|s| s.trim().parse::<f64>())
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let x: Vec<f64> = features
        .split(',')
        .map(|s| s.trim().parse::<f64>())
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    if w.len() != x.len() {
        return Err(format!(
            "weight and feature lengths differ: {} vs {}",
            w.len(),
            x.len()
        ));
    }
    let params = ckks::Params::toy();
    if w.len() > params.slot_count() {
        return Err(format!(
            "this demo holds at most {} features; got {}",
            params.slot_count(),
            w.len()
        ));
    }

    println!("\n{}", "Encrypted linear regression".bold().underline());
    println!("  features (private): {:?}", x);
    println!("  weights  (public ): {:?}", w);
    println!("  bias     (public ): {bias}");
    println!();

    let (pk, sk) = ckks::keygen(&params);
    println!("  {} encrypting features…", "→".cyan());
    let ct_x = ckks::encrypt(&pk, &x);

    // SIMD-style: encrypt the weights, multiply slotwise, rescale.
    println!("  {} multiplying slotwise: w * x …", "→".cyan());
    let ct_w = ckks::encrypt(&pk, &w);
    let prod = ckks::rescale(&ckks::mul(&ct_x, &ct_w));

    // Sum across slots: there's no native slot-sum without rotations, so we
    // decrypt+sum here in the cleartext (or in a real system: aggregate via
    // public masks). For pedagogical clarity we show the per-slot products.
    println!("  {} decrypting slotwise products…", "→".cyan());
    let prods = ckks::decrypt(&sk, &prod);
    let inner: f64 = prods.iter().take(w.len()).sum();
    let result = inner + bias;

    println!("\n  per-slot products: {:?}", &prods[..w.len()]);
    println!("  inner product:     {:>.6}", inner);
    println!("  + bias:            {:>.6}", result);

    // Cleartext check
    let cleartext: f64 = w.iter().zip(x.iter()).map(|(a, b)| a * b).sum::<f64>() + bias;
    let err = (result - cleartext).abs();
    println!("\n  cleartext value:   {:>.6}", cleartext);
    println!(
        "  error:             {:>.2e}  {}",
        err,
        if err < 0.01 {
            "✓".green()
        } else {
            "⚠".yellow()
        }
    );
    println!();
    Ok(())
}

/// `homo compare` — runs the same homomorphic addition across all schemes
/// and prints a side-by-side table.
fn cmd_compare(a: u64, b: u64) -> Result<(), String> {
    use std::time::Instant;

    println!(
        "\n{}",
        "Cross-scheme comparison: Enc(a) + Enc(b)"
            .bold()
            .underline()
    );
    println!("  inputs:  a = {a},  b = {b}\n");

    println!(
        "  {:<10}  {:>11}  {:>10}  {:>10}  {:>11}  {:>14}",
        "scheme".bold(),
        "keygen".bold(),
        "enc".bold(),
        "add".bold(),
        "dec".bold(),
        "ct bytes".bold()
    );
    println!("  {}", "─".repeat(74).dimmed());

    // --- Paillier
    {
        let t0 = Instant::now();
        let (pk, sk) = paillier::keygen(512);
        let kg = t0.elapsed();
        let ma = num_bigint::BigUint::from(a);
        let mb = num_bigint::BigUint::from(b);
        let t1 = Instant::now();
        let ca = paillier::encrypt(&pk, &ma);
        let cb = paillier::encrypt(&pk, &mb);
        let enc = t1.elapsed() / 2;
        let t2 = Instant::now();
        let cs = paillier::add(&pk, &ca, &cb);
        let add_t = t2.elapsed();
        let t3 = Instant::now();
        let m = paillier::decrypt(&sk, &cs);
        let dec = t3.elapsed();
        let bytes = wire::pack_paillier_ct(&ca).to_pem().len();
        println!(
            "  {:<10}  {:>11}  {:>10}  {:>10}  {:>11}  {:>14}  → result = {m}",
            "paillier".green(),
            humanise(kg),
            humanise(enc),
            humanise(add_t),
            humanise(dec),
            format!("{bytes} B")
        );
    }
    // --- BFV
    {
        let params = bfv::Params::toy();
        let t0 = Instant::now();
        let (pk, sk) = bfv::keygen(&params);
        let kg = t0.elapsed();
        let t1 = Instant::now();
        let ca = bfv::encrypt(&pk, &[a]);
        let cb = bfv::encrypt(&pk, &[b]);
        let enc = t1.elapsed() / 2;
        let t2 = Instant::now();
        let cs = bfv::add(&ca, &cb);
        let add_t = t2.elapsed();
        let t3 = Instant::now();
        let plain = bfv::decrypt(&sk, &cs);
        let dec = t3.elapsed();
        let bytes = wire::pack_bfv_ct(&ca).to_pem().len();
        println!(
            "  {:<10}  {:>11}  {:>10}  {:>10}  {:>11}  {:>14}  → result = {}",
            "bfv".green(),
            humanise(kg),
            humanise(enc),
            humanise(add_t),
            humanise(dec),
            format!("{bytes} B"),
            plain[0]
        );
    }
    // --- BGN
    {
        let t0 = Instant::now();
        let (pk, sk) = bgn::keygen(64, 4096);
        let kg = t0.elapsed();
        let t1 = Instant::now();
        let ca = bgn::encrypt(&pk, a);
        let cb = bgn::encrypt(&pk, b);
        let enc = t1.elapsed() / 2;
        let t2 = Instant::now();
        let cs = bgn::add_l1(&pk, &ca, &cb);
        let add_t = t2.elapsed();
        let t3 = Instant::now();
        let m = bgn::decrypt_l1(&sk, &cs).unwrap_or(0);
        let dec = t3.elapsed();
        let bytes = wire::pack_bgn_ct(&ca).to_pem().len();
        println!(
            "  {:<10}  {:>11}  {:>10}  {:>10}  {:>11}  {:>14}  → result = {m}",
            "bgn".green(),
            humanise(kg),
            humanise(enc),
            humanise(add_t),
            humanise(dec),
            format!("{bytes} B")
        );
    }
    // --- CKKS
    {
        let params = ckks::Params::toy();
        let t0 = Instant::now();
        let (pk, sk) = ckks::keygen(&params);
        let kg = t0.elapsed();
        let t1 = Instant::now();
        let ca = ckks::encrypt(&pk, &[a as f64]);
        let cb = ckks::encrypt(&pk, &[b as f64]);
        let enc = t1.elapsed() / 2;
        let t2 = Instant::now();
        let cs = ckks::add(&ca, &cb);
        let add_t = t2.elapsed();
        let t3 = Instant::now();
        let plain = ckks::decrypt(&sk, &cs);
        let dec = t3.elapsed();
        let bytes = wire::pack_ckks_ct(&ca).to_pem().len();
        println!(
            "  {:<10}  {:>11}  {:>10}  {:>10}  {:>11}  {:>14}  → result ≈ {:.4}",
            "ckks".green(),
            humanise(kg),
            humanise(enc),
            humanise(add_t),
            humanise(dec),
            format!("{bytes} B"),
            plain[0]
        );
    }
    println!();
    Ok(())
}

/// Humanise a duration to ns/µs/ms/s.
fn humanise(d: std::time::Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{nanos} ns")
    } else if nanos < 1_000_000 {
        format!("{:.1} µs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.1} ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.2} s", nanos as f64 / 1_000_000_000.0)
    }
}

/// `homo party` — multi-party private aggregation.
///
/// Flow: Alice generates a key pair and publishes the public key. Each
/// participant encrypts their value under it and sends the ciphertext to an
/// untrusted aggregator. The aggregator sums the ciphertexts homomorphically.
/// Alice decrypts the total. Nobody (not even the aggregator) sees individual
/// values.
fn cmd_party(values: &str, scheme: Scheme) -> Result<(), String> {
    let vs: Vec<f64> = values
        .split(',')
        .map(|s| s.trim().parse::<f64>())
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    if vs.is_empty() {
        return Err("supply at least one value".into());
    }

    println!("\n{}", "Multi-party private aggregation".bold().underline());
    println!("  scheme:       {}", scheme.short().cyan());
    println!("  participants: {}", vs.len());
    println!("  (individual values are private; only the sum is revealed)\n");

    match scheme {
        Scheme::Paillier => {
            println!("  {} Alice generates Paillier key pair", "→".cyan());
            let (pk, sk) = paillier::keygen(512);
            let pem_pub = wire::pack_paillier_pk(&pk).to_pem();
            println!(
                "    public key fingerprint: {}",
                wire::pack_paillier_pk(&pk).fingerprint.yellow()
            );
            println!(
                "    public key: {} bytes (broadcast to all participants)",
                pem_pub.len()
            );
            println!();

            // Paillier needs integers — round and warn if any values aren't.
            let any_frac = vs.iter().any(|v| v.fract().abs() > 1e-9);
            if any_frac {
                println!(
                    "  {} note: paillier is integer-only; rounding values to nearest int.",
                    "ℹ".yellow()
                );
            }

            let mut acc: Option<paillier::Ciphertext> = None;
            for (i, v) in vs.iter().enumerate() {
                let m = num_bigint::BigUint::from(v.round() as u64);
                let ct = paillier::encrypt(&pk, &m);
                let ct_size = wire::pack_paillier_ct(&ct).to_pem().len();
                println!(
                    "  {} participant #{}: encrypted private value, sent {} byte ct",
                    "→".dimmed(),
                    i + 1,
                    ct_size
                );
                acc = Some(match acc {
                    None => ct,
                    Some(a) => paillier::add(&pk, &a, &ct),
                });
            }
            let total_ct = acc.unwrap();
            println!(
                "\n  {} aggregator computed encrypted total without seeing any input",
                "✓".green().bold()
            );
            let total = paillier::decrypt(&sk, &total_ct);
            let expected: f64 = vs.iter().sum();
            println!(
                "  {} Alice decrypts: {}  (expected {:.0})",
                "✓".green().bold(),
                total,
                expected
            );
        }
        Scheme::Bgn => {
            println!("  {} Alice generates BGN key pair", "→".cyan());
            let (pk, sk) = bgn::keygen(64, 1 << 20);

            let mut acc: Option<bgn::CiphertextL1> = None;
            for (i, v) in vs.iter().enumerate() {
                let ct = bgn::encrypt(&pk, v.round() as u64);
                println!(
                    "  {} participant #{}: encrypted private value",
                    "→".dimmed(),
                    i + 1
                );
                acc = Some(match acc {
                    None => ct,
                    Some(a) => bgn::add_l1(&pk, &a, &ct),
                });
            }
            let total_ct = acc.unwrap();
            let total = bgn::decrypt_l1(&sk, &total_ct).ok_or("decryption failed")?;
            let expected: f64 = vs.iter().sum();
            println!(
                "\n  {} Alice decrypts: {}  (expected {:.0})",
                "✓".green().bold(),
                total,
                expected
            );
        }
        Scheme::Ckks => {
            println!("  {} Alice generates CKKS key pair", "→".cyan());
            let params = ckks::Params::toy();
            let (pk, sk) = ckks::keygen(&params);

            let mut acc: Option<ckks::Ciphertext> = None;
            for (i, v) in vs.iter().enumerate() {
                let ct = ckks::encrypt(&pk, &[*v]);
                println!(
                    "  {} participant #{}: encrypted private value",
                    "→".dimmed(),
                    i + 1
                );
                acc = Some(match acc {
                    None => ct,
                    Some(a) => ckks::add(&a, &ct),
                });
            }
            let total_ct = acc.unwrap();
            let plain = ckks::decrypt(&sk, &total_ct);
            let expected: f64 = vs.iter().sum();
            println!(
                "\n  {} Alice decrypts: {:.4}  (expected {:.4})",
                "✓".green().bold(),
                plain[0],
                expected
            );
        }
        Scheme::Bfv => {
            return Err("BFV-lite party demo not implemented (use paillier, bgn, or ckks)".into());
        }
    }
    println!();
    Ok(())
}
