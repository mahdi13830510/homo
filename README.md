# homo

> Homomorphic encryption, made tangible.

`homo` is a command-line tool for homomorphic encryption. Think of it as
**`openssl` for FHE**: you generate keys, encrypt, evaluate operations on
ciphertexts, and decrypt — all from the shell, all inspectable, with files
you can `cat` and pipe.

It is *also* a teaching instrument. Every scheme is implemented from
scratch in commented Rust, and there are subcommands (`trace`, `noise`,
`attack`, `lab`, `circuit`) that exist for no reason other than to make the
mathematics legible to a student.

## Table of contents

- [Why another HE tool?](#why-another-he-tool)
- [Install](#install)
- [Quick tour](#quick-tour)
- [Schemes](#schemes)
- [Command reference](#command-reference)
- [The educational subcommands](#the-educational-subcommands)
- [Circuit files (`.hcir`)](#circuit-files-hcir)
- [Project layout](#project-layout)
- [Security caveat](#security-caveat)
- [References](#references)

## Why another HE tool?

Most production homomorphic encryption libraries — SEAL, OpenFHE,
concrete-rs, lattigo, HElib — are excellent, but they're libraries. You
write C++ or Rust against them. There is no *standalone executable* that
gives you HE the way `openssl` or `gpg` give you classical crypto.

`homo` fills that gap, with two design goals:

1. **A real CLI.** You can `homo keygen`, `homo encrypt`, `homo eval add`,
   `homo decrypt` — the verbs you'd expect, with PEM-style files on disk
   that are readable, copyable, and diff-able.
2. **An academic backbone.** The schemes are written for clarity, not
   speed. You can read them in an afternoon. Subcommands like `homo trace`
   walk through the math step by step, `homo noise` plots noise growth as
   ASCII bars, and `homo attack` shatters intentionally-weak parameters in
   front of you.

## Install

You need a recent Rust toolchain (`rustup`, edition 2021).

```sh
git clone https://github.com/mahdi13830510/homo
cd homo
cargo build --release
# Binary lands at ./target/release/homo
```

For convenience:

```sh
cargo install --path .
```

## Quick tour

```sh
# 1. See what schemes are available.
homo schemes

# 2. Make a Paillier key pair.
homo keygen --scheme paillier --bits 1024 \
    --out-pub alice.pub --out-sec alice.sec

# 3. Encrypt two numbers.
homo encrypt --key alice.pub --message 17  --out a.ct
homo encrypt --key alice.pub --message 25  --out b.ct

# 4. Add them homomorphically — without alice.sec.
homo eval --key alice.pub --op add --a a.ct --b b.ct --out sum.ct

# 5. Decrypt the result.
homo decrypt --key alice.sec --input sum.ct
# → 42
```

The encrypted files look like this:

```text
-----BEGIN HOMO PAILLIER CIPHERTEXT-----
eyJ2ZXJzaW9uIjoxLCJzY2hlbWUiOiJQYWlsbGllciIsImtpbmQiOiJDaXBoZXJ0
ZXh0IiwiZGF0YSI6IjI4MzcxNDM2OTI...
-----END HOMO PAILLIER CIPHERTEXT-----
```

You can `cat` them, mail them, paste them, store them. The first line
identifies the scheme and object kind; the body is base64'd `bincode`.

## Schemes

| short name | full name      | what it does                                       |
| ---------- | -------------- | -------------------------------------------------- |
| `paillier` | Paillier 1999  | additively homomorphic over ℤ_n                    |
| `bfv`      | BFV-lite       | leveled SHE; supports + and one ×                  |
| `bgn`      | BGN (toy)      | many +; conceptual one-multiplication step         |
| `ckks`     | CKKS-lite      | approximate arithmetic on real/complex vectors — the scheme behind ML-on-encrypted-data |

`bfv` is implemented as a textbook BFV without NTT, RNS, or relinearisation
keys. Performance is *deliberately* humble — you can read the entire scheme
in `src/schemes/bfv.rs` and follow every line. The `bgn` scheme here is a
**didactic** stand-in for the original pairing-based Boneh–Goh–Nissim
construction; see the comments in `src/schemes/bgn.rs` for the details and
limitations. `ckks` is a from-scratch CKKS-lite with proper canonical
embedding (Vandermonde-solve over the `m`-th roots of unity), `mul`,
`add`, `rescale`, and `mod_switch`. It supports float vectors and is what
the `homo plot` and `homo ml` demos run on.

## Command reference

```text
homo schemes                              list schemes
homo keygen   --scheme S --bits N         generate a key pair
homo encrypt  --key K --message M [--out] encrypt (M is `int` for paillier/bgn,
                                          `i,j,k` comma-list for bfv,
                                          `f,g,h` float comma-list for ckks)
homo decrypt  --key K --input C           decrypt
homo eval     --key K --op OP             homomorphic operation:
              --a A --b B --out O           paillier: add | smul | sadd
                                            bfv:      add | mul
                                            bgn:      add
                                            ckks:     add | mul | rescale | padd
homo inspect  PATH [--secret SK]          show structure & fingerprint of a file
homo trace    OP A B                      step-by-step math trace
homo noise    --adds N [--with-mul]       ASCII noise-budget chart
homo attack   factor --key PK             try to factor a Paillier modulus
homo bench    [--scheme S] [--iters N]    micro-benchmarks
homo lab                                  interactive REPL
homo circuit  PATH -i name=value …        evaluate a .hcir circuit
homo plot     --poly … --from … --to …    encrypted polynomial evaluation + ASCII plot
homo ml       --weights … --features …    encrypted linear regression inference
homo compare  A B                         side-by-side: same op across all schemes
homo party    --values … --scheme …       multi-party private aggregation simulation
```

### Paillier examples

```sh
# Encrypted scalar multiplication: Enc(7) * 6 → Enc(42)
homo encrypt --key alice.pub --message 7 --out seven.ct
homo eval --key alice.pub --op smul --a seven.ct --b 6 --out forty_two.ct
homo decrypt --key alice.sec --input forty_two.ct
# → 42
```

### BFV examples

```sh
homo keygen --scheme bfv --out-pub bfv.pub --out-sec bfv.sec

# A vector of plaintext slots
homo encrypt --key bfv.pub --message "1,2,3,4,5" --out v.ct
homo encrypt --key bfv.pub --message "10,20,30,40,50" --out w.ct

# Add — fast and noise-cheap
homo eval --key bfv.pub --op add --a v.ct --b w.ct --out sum.ct
homo decrypt --key bfv.sec --input sum.ct
# → 11,22,33,44,55

# Multiply — once
homo eval --key bfv.pub --op mul --a v.ct --b w.ct --out prod.ct
homo decrypt --key bfv.sec --input prod.ct
```

### CKKS examples

CKKS is the scheme you'd reach for to do real-valued arithmetic — averages,
inner products, polynomial regression, neural-network inference. The `homo`
toy parameters give you `n/2` slots of ~30-bit precision and 3 levels of
multiplication depth.

```sh
homo keygen --scheme ckks --out-pub k.pub --out-sec k.sec

# Encrypt a real-valued vector
homo encrypt --key k.pub --message "1.5,2.25,-0.75,3.125" --out v.ct

# Add another vector
homo encrypt --key k.pub --message "0.5,1.0,2.0,0.25" --out w.ct
homo eval --key k.pub --op add --a v.ct --b w.ct --out sum.ct
homo decrypt --key k.sec --input sum.ct
# → 2.0000,3.2500,1.2500,3.3750

# Multiply (slot-wise) and rescale
homo eval --key k.pub --op mul --a v.ct --b w.ct --out prod.ct
homo eval --key k.pub --op rescale --a prod.ct --b _ --out prod_r.ct
homo decrypt --key k.sec --input prod_r.ct
# → 0.7500,2.2500,-1.5000,0.7813
```

CKKS results carry a small approximation error (~10⁻⁶ for the toy params),
which is the defining feature of the scheme — `homo inspect --secret`
will tell you the current message magnitude, scale, and headroom.

## The educational subcommands

These are the unique features. They're not strictly necessary for "doing
HE" but they make the tool genuinely useful for a course or self-study.

### `homo trace`

Walks through an operation step-by-step:

```sh
homo trace add 17 25
```

You get a numbered log: keygen → enc(a) → enc(b) → homomorphic add →
decrypt, each step annotated with the math and a snapshot of the value
involved.

### `homo noise`

Encrypts a value and applies a sequence of operations, plotting the noise
budget as an ASCII bar chart at every step:

```sh
homo noise --adds 6 --with-mul
```

Sample output:

```text
Noise budget (out of 50 bits):
  fresh          │██████████████████████████████████████████████████│ 50.0 bits
  add #1         │█████████████████████████████████████████████████░│ 49.0 bits
  add #2         │█████████████████████████████████████████████████░│ 49.0 bits
  …
  mul            │██████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░│ 26.0 bits
```

### `homo attack`

Runs a chosen attack against a key file. Today `factor` is implemented:
trial division then Pollard's rho. Point a `homo attack factor --key
small.pub` at a *deliberately small* Paillier key and watch it fall, then
read the closing line: "*lesson: this is why real Paillier needs ≥
2048-bit moduli.*"

### `homo lab`

A REPL with a fresh BFV-lite session in memory:

```text
homo lab
homo> a = enc 17
homo> b = enc 25
homo> c = a + b
homo> dec c
42
homo> noise c
c: ‖·‖∞ ≈ 14238 (≈ 2^13.8), budget ≈ 38.2 bits
homo> d = c * (enc 2)
homo> dec d
84
homo> noise d
d: ‖·‖∞ ≈ … budget ≈ 23.1 bits
```

Mix plaintexts and ciphertexts, observe noise after each line, build
intuition.

### `homo plot` — encrypted polynomial evaluation, ASCII-plotted

Encrypt a vector of x-values, evaluate a polynomial homomorphically over
CKKS, decrypt, and render the cleartext reference curve. The output table
shows you `|homom − cleartext|` so you can see CKKS approximation in action.

```sh
homo plot --poly "1,0,-1" --from=-2 --to=2 --points 4
```

```text
Homomorphic polynomial evaluation
  poly: 1 + -1·x²

           x     homomorphic       cleartext       |err|
  ────────────────────────────────────────────────────────
     -2.0000       -3.000000       -3.000000     1.60e-8
     -0.6667        0.555556        0.555556    7.34e-10
      0.6667        0.555556        0.555556    5.27e-10
      2.0000       -3.000000       -3.000000     1.02e-8

  Reference curve (cleartext):
  │                   ·+··················+·
  │                 ··                      ··
  │              ··                            ··
  │           ··                                  ··
  │        ··                                        ··
  │      ··                                            ··
  │    ··                                                ··
  │  ··                                                    ··
  │+                                                          +
  └────────────────────────────────────────────────────────────
```

Errors are around `10⁻⁸` — that's the CKKS approximation showing through.

### `homo ml` — encrypted linear regression inference

The canonical "ML on encrypted data" demo. The "server" sees only a
ciphertext, performs `w · x + b` homomorphically (slot-wise multiply,
rescale, sum), and returns an encrypted result. The "client" decrypts.

```sh
homo ml --weights "0.4,0.3,0.7" --features "1.0,2.5,-0.5" --bias 0.1
```

```text
Encrypted linear regression
  features (private): [1.0, 2.5, -0.5]
  weights  (public ): [0.4, 0.3, 0.7]
  bias     (public ): 0.1

  → encrypting features…
  → multiplying slotwise: w * x …
  → decrypting slotwise products…

  inner product:     0.800000
  + bias:            0.900000
  cleartext value:   0.900000
  error:             3.17e-08  ✓
```

### `homo compare` — every scheme, side by side

Runs the same `Enc(a) + Enc(b)` operation across all four schemes and
prints a table of timings + ciphertext sizes. Great for showing students
that "homomorphic encryption" isn't one thing — the schemes differ by 5+
orders of magnitude in encryption cost and ciphertext size.

```sh
homo compare 17 25
```

```text
Cross-scheme comparison: Enc(a) + Enc(b)
  inputs:  a = 17,  b = 25

  scheme         keygen     enc      add      dec   ct bytes
  ──────────────────────────────────────────────────────────
  paillier      16.2 ms  295 µs   1.7 µs   289 µs       450  → 42
  bfv           42.0 ms   68 ms   267 µs    33 ms     63169  → 42
  bgn           61.4 ms   17 µs   655 ns    74 µs       245  → 42
  ckks          17.0 µs   26 µs   4.1 µs    10 µs      1186  → 42.0000
```

### `homo party` — multi-party private aggregation

Simulates a privacy-preserving sum: each participant encrypts their value
under Alice's public key, an untrusted aggregator sums the ciphertexts
homomorphically, Alice decrypts the total. **No participant sees any
other participant's value, and the aggregator sees nothing.** This is the
canonical "encrypted analytics" pattern — health surveys, salary surveys,
federated stats.

```sh
homo party --values "12,7,28,5,16" --scheme paillier
```

```text
Multi-party private aggregation
  scheme:       paillier
  participants: 5
  (individual values are private; only the sum is revealed)

  → Alice generates Paillier key pair
    public key fingerprint: b4d1d176
    public key: 328 bytes (broadcast to all participants)

  → participant #1: encrypted private value, sent 450 byte ct
  → participant #2: encrypted private value, sent 450 byte ct
  → participant #3: encrypted private value, sent 450 byte ct
  → participant #4: encrypted private value, sent 450 byte ct
  → participant #5: encrypted private value, sent 450 byte ct

  ✓ aggregator computed encrypted total without seeing any input
  ✓ Alice decrypts: 68  (expected 68)
```

Works with `paillier`, `bgn`, and `ckks` (the last gives you private sums
of *floats*).

### `homo bench`

```sh
homo bench --scheme all --iters 100
```

prints a coloured table of operation timings with relative bars. Good for
showing the wild gap between Paillier (tiny additions, slow keygen) and
BFV (heavy keygen, expensive multiplication, cheap-ish addition).

## Circuit files (`.hcir`)

A `.hcir` file is a tiny single-static-assignment description of an
arithmetic circuit:

```text
input age
input income
input score
boosted  = age + score
adjusted = income + 10
final    = boosted * adjusted
return final
```

You evaluate it homomorphically:

```sh
homo circuit examples/score.hcir -i age=25 -i income=60 -i score=8
```

Inputs are encrypted on load, intermediate values stay ciphertexts, the
final `return` decrypts. The trace prints the noise budget after every
line so you can see exactly where headroom is consumed.

## Project layout

```
homo/
├── Cargo.toml
├── README.md
├── docs/
│   └── THEORY.md            scheme math + reading list
├── examples/                .hcir programs you can run today
│   ├── score.hcir
│   └── inner_product.hcir
├── src/
│   ├── main.rs              binary entry point
│   ├── lib.rs               crate root
│   ├── cli/mod.rs           clap subcommands (incl. plot/ml/compare/party)
│   ├── schemes/
│   │   ├── mod.rs           Scheme enum
│   │   ├── paillier.rs      Paillier 1999, ~250 lines
│   │   ├── bfv.rs           BFV-lite, ~400 lines
│   │   ├── bgn.rs           BGN-toy, ~200 lines
│   │   └── ckks.rs          CKKS-lite with canonical embedding, ~500 lines
│   ├── viz.rs               traces, ASCII noise plots, anatomy diagrams
│   ├── playground.rs        REPL + .hcir evaluator
│   ├── attacks.rs           factoring, brute force
│   ├── bench.rs             micro-benchmarks (paillier/bfv/ckks)
│   ├── io.rs                PEM-style envelopes
│   └── util.rs              RNG, modular arith, primes
└── tests/
    └── integration.rs
```└── tests/
    └── integration.rs
```

## Security caveat

`homo` is **a teaching tool**. It implements correct mathematics but it is
not constant-time, not side-channel-hardened, has not been audited, and
the parameter sets it ships are conservative for *clarity*, not for
*production security*.

If you need real homomorphic encryption in a real system, use
[concrete-rs](https://github.com/zama-ai/concrete), [SEAL](https://github.com/microsoft/SEAL),
[OpenFHE](https://www.openfhe.org), [HElib](https://github.com/homenc/HElib),
or [lattigo](https://github.com/tuneinsight/lattigo).

If you want to *understand* homomorphic encryption — read the source.

## References

The schemes implemented here are described in:

- Pascal Paillier, *Public-Key Cryptosystems Based on Composite Degree
  Residuosity Classes*, EUROCRYPT 1999.
- Junfeng Fan and Frederik Vercauteren, *Somewhat Practical Fully
  Homomorphic Encryption*, IACR ePrint 2012/144.
- Dan Boneh, Eu-Jin Goh, and Kobbi Nissim, *Evaluating 2-DNF Formulas on
  Ciphertexts*, TCC 2005.
- Jung Hee Cheon, Andrey Kim, Miran Kim, Yongsoo Song, *Homomorphic
  Encryption for Arithmetic of Approximate Numbers*, ASIACRYPT 2017.

For background the standard references are Craig Gentry's PhD thesis
(2009) and the [Homomorphic Encryption Standard](https://homomorphicencryption.org/).

## License

Dual-licensed under MIT or Apache-2.0, your choice.
