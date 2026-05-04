//! Interactive playground: a tiny REPL and a circuit-file evaluator.
//!
//! ## REPL
//!
//! `homo lab` drops you into a session where you can do things like:
//!
//! ```text
//! homo> a = enc 17
//! homo> b = enc 25
//! homo> c = a + b
//! homo> dec c
//! 42
//! homo> noise c
//! noise ≈ 2^14.3, budget ≈ 38.7 bits
//! ```
//!
//! It speaks the BFV scheme by default (so you can mix + and ×). The session
//! holds a fresh key pair in memory; you exit with `quit` or Ctrl-D.
//!
//! ## Circuit files
//!
//! `homo circuit run prog.hcir` reads a tiny `.hcir` file:
//!
//! ```text
//! # Compute (a + b) * (c + 3)
//! input a
//! input b
//! input c
//! t1 = a + b
//! t2 = c + 3
//! out = t1 * t2
//! return out
//! ```
//!
//! and evaluates it homomorphically, reporting noise after every line.

use crate::schemes::bfv;
use crate::viz;
use colored::Colorize;
use std::collections::HashMap;
use std::io::{BufRead, Write};

/// One value in a session: either a plaintext scalar or a BFV ciphertext.
pub enum Value {
    /// Cleartext integer.
    Plain(i64),
    /// Encrypted vector.
    Cipher(bfv::Ciphertext),
}

/// Session state for the REPL or circuit evaluator.
pub struct Session {
    /// Current BFV parameter set.
    pub params: bfv::Params,
    /// Public key.
    pub pk: bfv::PublicKey,
    /// Secret key (kept locally — this is a teaching tool).
    pub sk: bfv::SecretKey,
    /// Named values.
    pub env: HashMap<String, Value>,
}

impl Session {
    /// Create a session with the toy parameters.
    pub fn toy() -> Self {
        let params = bfv::Params::toy();
        let (pk, sk) = bfv::keygen(&params);
        Self { params, pk, sk, env: HashMap::new() }
    }

    /// Encrypt a single integer.
    pub fn enc_one(&self, m: i64) -> bfv::Ciphertext {
        let m_pos = if m >= 0 { m as u64 } else {
            // map negatives into [0, t) the standard way
            let t = self.params.t.to_string().parse::<i64>().unwrap_or(256);
            ((m % t + t) % t) as u64
        };
        bfv::encrypt(&self.pk, &[m_pos])
    }

    /// Decrypt and read the first slot.
    pub fn dec_one(&self, ct: &bfv::Ciphertext) -> u64 {
        let v = bfv::decrypt(&self.sk, ct);
        v.first().copied().unwrap_or(0)
    }

    /// Run one REPL command. Returns a string to print and a flag indicating
    /// whether the session should exit.
    pub fn run_line(&mut self, line: &str) -> (String, bool) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return (String::new(), false);
        }
        if trimmed == "quit" || trimmed == "exit" {
            return ("bye.\n".to_string(), true);
        }
        if trimmed == "help" {
            return (HELP.to_string(), false);
        }
        if trimmed == "vars" {
            let mut s = String::from("\nDefined variables:\n");
            for (k, v) in &self.env {
                let kind = match v {
                    Value::Plain(_) => "plain",
                    Value::Cipher(_) => "cipher",
                };
                s.push_str(&format!("  {k}  ({kind})\n"));
            }
            return (s, false);
        }
        // Pattern: dec <name>
        if let Some(name) = trimmed.strip_prefix("dec ") {
            return match self.env.get(name.trim()) {
                Some(Value::Cipher(ct)) => (format!("{}\n", self.dec_one(ct)), false),
                Some(Value::Plain(p)) => (format!("{p}\n"), false),
                None => (format!("error: '{name}' not defined\n"), false),
            };
        }
        // noise <name>
        if let Some(name) = trimmed.strip_prefix("noise ") {
            return match self.env.get(name.trim()) {
                Some(Value::Cipher(ct)) => {
                    let (n, log, budget) = bfv::noise_estimate(&self.sk, ct);
                    (
                        format!(
                            "{}: ‖·‖∞ ≈ {} (≈ 2^{:.1}), budget ≈ {:.1} bits\n",
                            name.trim(),
                            viz::short_int(&n),
                            log,
                            budget
                        ),
                        false,
                    )
                }
                _ => (format!("'{name}' is not a ciphertext\n"), false),
            };
        }

        // Assignment: name = expr
        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            let name = lhs.trim().to_string();
            match self.eval_expr(rhs.trim()) {
                Ok(v) => {
                    self.env.insert(name.clone(), v);
                    (format!("{} = …\n", name).dimmed().to_string(), false)
                }
                Err(e) => (format!("error: {e}\n"), false),
            }
        } else {
            // Bare expression — evaluate and try to decrypt.
            match self.eval_expr(trimmed) {
                Ok(Value::Plain(p)) => (format!("{p}\n"), false),
                Ok(Value::Cipher(ct)) => (format!("(ciphertext, dec → {})\n", self.dec_one(&ct)), false),
                Err(e) => (format!("error: {e}\n"), false),
            }
        }
    }

    /// Tiny expression evaluator: literals, names, +, -, *, and `enc <expr>`.
    fn eval_expr(&self, expr: &str) -> Result<Value, String> {
        // Strip "enc"
        if let Some(inner) = expr.strip_prefix("enc ") {
            let v = self.eval_expr(inner.trim())?;
            return match v {
                Value::Plain(p) => Ok(Value::Cipher(self.enc_one(p))),
                Value::Cipher(_) => Err("enc: argument is already encrypted".into()),
            };
        }

        // Look for top-level + - * (left-associative, no precedence — toy).
        // We scan the string and split on the *last* such operator that
        // isn't immediately preceded by another operator (handles "-3").
        for op in ['+', '-', '*'] {
            if let Some(pos) = find_top_level_op(expr, op) {
                let (l, r) = expr.split_at(pos);
                let left = self.eval_expr(l.trim())?;
                let right = self.eval_expr(r[1..].trim())?;
                return self.apply(op, left, right);
            }
        }

        // Otherwise: literal or variable.
        if let Ok(n) = expr.parse::<i64>() {
            return Ok(Value::Plain(n));
        }
        match self.env.get(expr) {
            Some(Value::Plain(p)) => Ok(Value::Plain(*p)),
            Some(Value::Cipher(c)) => Ok(Value::Cipher(c.clone())),
            None => Err(format!("undefined: {expr}")),
        }
    }

    fn apply(&self, op: char, a: Value, b: Value) -> Result<Value, String> {
        match (op, a, b) {
            ('+', Value::Plain(x), Value::Plain(y)) => Ok(Value::Plain(x + y)),
            ('-', Value::Plain(x), Value::Plain(y)) => Ok(Value::Plain(x - y)),
            ('*', Value::Plain(x), Value::Plain(y)) => Ok(Value::Plain(x * y)),
            ('+', Value::Cipher(a), Value::Cipher(b)) => Ok(Value::Cipher(bfv::add(&a, &b))),
            ('+', Value::Cipher(a), Value::Plain(p)) | ('+', Value::Plain(p), Value::Cipher(a)) => {
                let pp = self.enc_one(p);
                Ok(Value::Cipher(bfv::add(&a, &pp)))
            }
            ('*', Value::Cipher(a), Value::Cipher(b)) => Ok(Value::Cipher(bfv::mul(&a, &b))),
            ('*', Value::Cipher(a), Value::Plain(p)) | ('*', Value::Plain(p), Value::Cipher(a)) => {
                let pp = self.enc_one(p);
                Ok(Value::Cipher(bfv::mul(&a, &pp)))
            }
            ('-', _, _) => Err("subtraction on ciphertexts not yet implemented".into()),
            (op, _, _) => Err(format!("unsupported op {op} for these types")),
        }
    }
}

/// Find the rightmost top-level occurrence of `op` not at the very start.
fn find_top_level_op(s: &str, op: char) -> Option<usize> {
    let bytes = s.as_bytes();
    for i in (1..bytes.len()).rev() {
        if bytes[i] as char == op {
            // skip if it's part of a unary "-" e.g. " -3"
            let prev = bytes[i - 1] as char;
            if op == '-' && (prev == ' ' || prev == '+' || prev == '*' || prev == '-') {
                continue;
            }
            return Some(i);
        }
    }
    None
}

/// Run the interactive REPL on stdin/stdout.
pub fn repl() -> std::io::Result<()> {
    println!("\n{}", "homo lab — interactive playground".bold());
    println!("{}", "BFV-lite parameters loaded. Type 'help' or 'quit'.".dimmed());
    let mut session = Session::toy();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    loop {
        write!(out, "{} ", "homo>".green().bold())?;
        out.flush()?;
        let mut line = String::new();
        let n = stdin.lock().read_line(&mut line)?;
        if n == 0 {
            println!();
            break;
        }
        let (response, exit) = session.run_line(&line);
        if !response.is_empty() {
            write!(out, "{response}")?;
            out.flush()?;
        }
        if exit {
            break;
        }
    }
    Ok(())
}

const HELP: &str = "
Commands:
  <name> = <expr>     assign a value to a name
  dec <name>          decrypt a ciphertext and print
  noise <name>        report current noise budget
  vars                list named values
  enc <expr>          encrypt the result of an expression
  help                this message
  quit                exit

Expressions:
  integer literals, variable names, + - *
  ciphertext + ciphertext  → ciphertext (cheap)
  ciphertext * ciphertext  → ciphertext (size grows; one mul max in BFV-lite)

Examples:
  a = enc 17
  b = enc 25
  c = a + b
  dec c
  noise c
";

/// A line in a `.hcir` circuit description.
enum CircuitLine {
    Input(String),
    Assign(String, String),
    Return(String),
}

/// Run a `.hcir` circuit file homomorphically. `inputs` provides the value
/// for each declared `input`. Returns the final cleartext result and a log
/// of noise observations.
pub fn run_circuit(source: &str, inputs: &HashMap<String, i64>) -> Result<(u64, String), String> {
    let mut session = Session::toy();
    let mut log = String::new();

    for (lineno, raw) in source.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let parsed = parse_line(line)
            .ok_or_else(|| format!("line {}: cannot parse '{}'", lineno + 1, raw))?;
        match parsed {
            CircuitLine::Input(name) => {
                let v = *inputs
                    .get(&name)
                    .ok_or_else(|| format!("missing input: {name}"))?;
                session.env.insert(name.clone(), Value::Cipher(session.enc_one(v)));
                log.push_str(&format!("input {name} ← enc({v})\n"));
            }
            CircuitLine::Assign(name, expr) => {
                let v = session.eval_expr(&expr)
                    .map_err(|e| format!("line {}: {e}", lineno + 1))?;
                if let Value::Cipher(ref ct) = v {
                    let (_, log2_n, budget) = bfv::noise_estimate(&session.sk, ct);
                    log.push_str(&format!(
                        "{name} = {expr}     noise≈2^{:.1} budget≈{:.1}\n",
                        log2_n, budget
                    ));
                } else {
                    log.push_str(&format!("{name} = {expr}    (plain)\n"));
                }
                session.env.insert(name, v);
            }
            CircuitLine::Return(name) => {
                let v = session.env.get(&name)
                    .ok_or_else(|| format!("return of undefined: {name}"))?;
                let result = match v {
                    Value::Cipher(ct) => session.dec_one(ct),
                    Value::Plain(p) => *p as u64,
                };
                log.push_str(&format!("return {name} → {result}\n"));
                return Ok((result, log));
            }
        }
    }
    Err("circuit ended without return".into())
}

fn parse_line(line: &str) -> Option<CircuitLine> {
    if let Some(name) = line.strip_prefix("input ") {
        return Some(CircuitLine::Input(name.trim().to_string()));
    }
    if let Some(name) = line.strip_prefix("return ") {
        return Some(CircuitLine::Return(name.trim().to_string()));
    }
    let (lhs, rhs) = line.split_once('=')?;
    Some(CircuitLine::Assign(lhs.trim().to_string(), rhs.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repl_can_add() {
        let mut s = Session::toy();
        s.run_line("a = enc 3");
        s.run_line("b = enc 4");
        s.run_line("c = a + b");
        let (out, _) = s.run_line("dec c");
        assert!(out.trim() == "7", "got {out}");
    }

    #[test]
    fn circuit_evaluates_simple_expression() {
        let src = "input a\ninput b\nt = a + b\nreturn t\n";
        let mut inputs = HashMap::new();
        inputs.insert("a".to_string(), 5);
        inputs.insert("b".to_string(), 11);
        let (result, _log) = run_circuit(src, &inputs).unwrap();
        assert_eq!(result, 16);
    }
}
