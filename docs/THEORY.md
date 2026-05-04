# Theory notes

These are the essentials of what each scheme does and why. They go a step
beyond the README without becoming a textbook.

## 1. Paillier (1999)

### Setting

Pick large primes `p, q`, set `n = pq` and `λ = lcm(p−1, q−1)`. The
plaintext space is `ℤ_n`; ciphertext space is `ℤ_{n²}*`.

### Encrypt / decrypt

```
Enc(m; r) = (1 + n)^m · r^n   mod n²
Dec(c)    = L(c^λ mod n²) · μ mod n,    L(x) = (x − 1)/n,   μ = L((1+n)^λ)^{-1}
```

### Why it's homomorphic

Multiplying ciphertexts mod `n²` adds the exponents on the `(1+n)` part:

```
Enc(m₁; r₁) · Enc(m₂; r₂) = (1+n)^{m₁+m₂} · (r₁ r₂)^n  mod n²
                          = Enc(m₁ + m₂; r₁ r₂)
```

That's the whole magic. There is no noise — Paillier is *exactly* additive
for as many additions as you like.

### Security

Decisional composite residuosity (DCR): given `n`, distinguishing `n`-th
residues mod `n²` from random elements is hard. This implies factoring,
but not vice versa. `homo attack factor` shows what happens when `n` is
small enough to factor.

## 2. BFV (Fan–Vercauteren 2012)

### Setting

Ring `R = ℤ[X]/(X^n + 1)`, `n` a power of 2. Reduce mod `q` for ciphertexts
(`R_q`), mod `t` for plaintexts (`R_t`), with `t ≪ q`. Define `Δ = ⌊q/t⌋`.

### Encrypt / decrypt

```
keygen  : s ← R₂ (ternary),  e ← χ,  a ← R_q
          pk = (b = −(a·s + e),  a)
encrypt : u ← R₂,  e₁,e₂ ← χ
          (c₀, c₁) = (b·u + e₁ + Δ·m,  a·u + e₂)
decrypt : m = ⌊ (t/q)·(c₀ + c₁·s) ⌉  mod t
```

The decrypt formula is the key insight: `c₀ + c₁·s` evaluates to
`Δ·m + small_noise`. Dividing by `q/t = Δ` and rounding lifts `m` back
into `R_t` *as long as the noise is below `Δ/2`*.

### Why noise grows

* **add** : noise sums coefficient-wise → grows by a small constant.
* **mul** : the tensor product of two ciphertexts produces a polynomial
  of larger coefficients, then we rescale by `t/q`. Net: noise roughly
  squares.

This is what `homo noise` shows pictorially.

### Why we don't relinearise here

After one multiplication, the ciphertext has three components and
decrypts under `(s, s²)`. To fold it back to two components you publish a
*relinearisation key* — basically `Enc(s²)` under a special sub-scheme.
We skip it because (a) it doubles the implementation size and (b) for a
teaching tool the three-component ciphertext is a feature, not a bug:
students see exactly what multiplication produces.

## 3. BGN (toy)

The original Boneh–Goh–Nissim scheme uses a bilinear pairing
`e: G₁ × G₁ → G_T`. A level-1 ciphertext lives in `G₁`, addition is the
group operation. *One* multiplication is performed by pairing two
level-1 ciphertexts, giving a level-2 ciphertext in `G_T` where addition
still works but no further multiplication is possible.

Implementing pairings from scratch would dwarf the rest of `homo`, so we
ship a **didactic** non-pairing variant: ElGamal-in-the-exponent over
`ℤ_p*` where addition is real and multiplication is symbolic. The shape
matches — many additions, then a "level boundary" — which is the
take-away lesson.

## 4. CKKS (Cheon–Kim–Kim–Song 2017)

### Setting

Same RLWE ring as BFV: `R = ℤ[X]/(X^n+1)` with `n` a power of 2.
Plaintexts live in `ℂ^{n/2}` (or `ℝ^{n/2}` for real-valued data).
Ciphertexts in `R_q²`, with a chain of moduli `q_0 < q_1 < … < q_L`.

### Encoding

The defining trick. Map a slot vector `z ∈ ℂ^{n/2}` to a polynomial by
solving the Vandermonde system
```
V · m = (z, conj(z))
```
where `V[k][i] = ζ_k^i` and `ζ_k = exp(2πi · 5^k / 2n)` are the primitive
`2n`-th roots of unity at indices `5^k mod 2n` (and their conjugates).
The resulting `m ∈ ℂ^n` has essentially-real coefficients (imaginary parts
are floating-point noise) which we round and scale by `Δ`.

### Encrypt / decrypt

Same recipe as BFV (RLWE pair `(b, a)` with `b = -(a·s + e)`), but the
plaintext is added *without* a separate scaling factor — the encoding
already multiplied by `Δ`:
```
encrypt(m) = (b·u + e₁ + m,  a·u + e₂)
decrypt(c) = (c₀ + c₁·s) / scale  →  decode
```

### Why this is the key scheme for ML

CKKS does *approximate* arithmetic on real numbers natively — the
"noise" in a CKKS ciphertext is just rounding error in the floating-point
sense. This means:

* You can encrypt feature vectors directly.
* Slot-wise addition / multiplication is "for free" (no encoding).
* Polynomial activations (squaring, low-degree polynomials approximating
  sigmoid/ReLU) work directly.
* Inner products fall out of slot-wise mul + slot-rotation.

### Rescale

The central CKKS operation. After `mul`, the message scale doubled
(from `Δ` to `Δ²`) and the noise grew. **Rescale** divides every
coefficient by `Δ` and drops to the next-smaller modulus `q_{L-1}`. This
brings the message scale back to `Δ` and effectively halves the noise.
You can do this `L` times before running out of moduli.

### Mod-switch (book-keeping only)

Sometimes you want to drop a level *without* doing a multiplication —
e.g. to align two ciphertexts at different levels for an addition. That's
**modulus switching**: you reduce coefficients into `q_{L-1}` without
dividing by `Δ`. The message stays the same; only the headroom shrinks.

### Limitations of CKKS-lite

Real CKKS ships with relinearisation keys (so multiplications stay
size-2), Galois rotation keys (so you can do slot rotations / inner
products inside the ciphertext), and a key-switching infrastructure that
lets you change which secret a ciphertext decrypts under. We omit all of
this. As a result `homo`'s CKKS:

* Multiplications grow the ciphertext to size 3; a second hom-mul
  isn't supported.
* Sums-across-slots are done *outside* the ciphertext (decrypt the slot
  vector then sum) — this is fine for the `homo ml` demo because the
  client decrypts at the end anyway.

## 5. Why four schemes?

A homomorphic-encryption course typically shows the spectrum:

| capability                                    | scheme    |
| --------------------------------------------- | --------- |
| only addition                                 | Paillier  |
| addition + one multiplication                 | BGN       |
| addition + bounded multiplications, integers  | BFV/BGV   |
| addition + bounded multiplications, reals     | CKKS      |
| arbitrary depth (with bootstrapping)          | TFHE      |

`homo` covers the first four. The fifth — *fully* homomorphic, unbounded
depth — is left as future work. Bootstrapping is a tour-de-force of
cryptography but adds at least 2,000 lines and a different LWE
parameterisation; it would compromise the "read the source in an
afternoon" property.

## Reading list

* Gentry, *A Fully Homomorphic Encryption Scheme*, PhD thesis 2009.
* Halevi, *Homomorphic Encryption*, in *Tutorials on the Foundations of
  Cryptography* (2017).
* Cheon, Kim, Kim, Song, *Homomorphic Encryption for Arithmetic of
  Approximate Numbers*, ASIACRYPT 2017.
* Albrecht et al., *Homomorphic Encryption Standard* (homomorphicencryption.org).
* Brakerski, Gentry, Vaikuntanathan, *Leveled Fully Homomorphic Encryption
  without Bootstrapping*, ITCS 2012.
