# Rust (Actix, Axum) — Misconfigurations & Common Vulnerabilities

Defensive reference for Rust HTTP services (Actix-web, Axum, Rocket).

---

## Misconfigurations

### 1. Serving project root as static

**What:** `Files::new("/", ".")` (Actix) or `ServeDir::new(".")` (Axum) exposes source and config.

**Fix:** Serve only a dedicated `static/` dir; never the crate root.

**Detection:** `rg -n "Files::new|ServeDir::new|ServeFile::new" src/`

---

### 2. Verbose error responses

**What:** Returning `err.to_string()` or `format!("{err:?}")` to the client leaks internals.

**Fix:** Log full error server-side (`tracing::error!`); return generic messages.

**Detection:** `rg -n "to_string\(\)|format!\(\"\{.*:\?\}\"|HttpResponse::.*err" src/`

---

### 3. Unsafe `unwrap`/`expect` in request paths

**What:** `.unwrap()` on user-driven `Option`/`Result` panics the worker thread → DoS.

**Fix:** Handle errors explicitly; use `?` with proper error types; avoid `unwrap` in handlers.

**Detection:** `rg -n "\.unwrap\(\)|\.expect\(" src/`

---

### 4. CORS allow-all

**What:** `Cors::allow_any_origin()` with credentials.

**Fix:** Allowlist origins; credentials only with explicit origins.

**Detection:** `rg -n "allow_any|allow_origin|CorsLayer" src/`

---

### 5. Exposed tracing/metrics endpoints

**What:** `/metrics` (Prometheus) or tracing endpoints reachable publicly leak route/latency data.

**Fix:** Bind to internal listener or gate behind auth.

**Detection:** `rg -n "prometheus|/metrics|tracing" src/`

---

## Common Vulnerabilities

### 6. SQL injection via `format!` in queries

**What:** `format!("... WHERE id = {}", id)` passed to `query` (non-parameterized).

**Fix:** Use bound params: `sqlx::query("... WHERE id = ?").bind(id)`; or `query_as!` macros.

**Detection:** `rg -n "format!\(.*WHERE|query\(.*format|query_as\(.*format" src/`

---

### 7. Command injection

**What:** `Command::new("sh").arg("-c").arg(format!("convert {}", name))` runs shell with input.

**Fix:** `Command::new("convert").arg(name)` (no shell); validate input.

**Detection:** `rg -n "Command::new\(\"sh\"|arg\(\"-c\"\)|Command::new\(\"/bin/sh\"\)" src/`

---

### 8. Path traversal in file serving

**What:** `Path::new(base).join(user_path)` without bounds check.

**Fix:** Canonicalize and verify the result starts with the canonical base; reject `..`.

**Detection:** `rg -n "Path::new\(.*req|\.join\(.*req|read\(.*req" src/`

---

### 9. SSRF via `reqwest::get(user_url)`

**What:** Outbound HTTP to user URLs hits internal metadata.

**Fix:** Allowlist hosts; block link-local/RFC1918.

**Detection:** `rg -n "reqwest::get\(|Client::new\(\)\.get\(" src/`

---

### 10. Insecure randomness

**What:** Using `rand` crate's non-CSPRNG for tokens.

**Fix:** Use `rand::rngs::OsRng` or `getrandom` for tokens/IDs.

**Detection:** `rg -n "thread_rng|StdRng|SmallRng" src/`

---

### 11. Deserialization RCE via `serde_yaml` / unsafe `Deserialize`

**What:** While `serde` is generally safe, deserializing into overly permissive types (`serde_json::Value` then downcasting) can enable logic bugs; `serde_yaml` historically had issues.

**Fix:** Deserialize into strict typed structs; validate after load.

**Detection:** `rg -n "serde_json::Value|from_str\(.*req|from_reader" src/`

---

### 12. `unsafe` blocks / FFI with untrusted input

**What:** `unsafe` parsing or FFI calls with untrusted input can cause memory unsafety.

**Fix:** Avoid `unsafe` on untrusted input; fuzz any `unsafe` path.

**Detection:** `rg -n "unsafe " src/`

---

## Checklist

- [ ] Static serving scoped to `static/`
- [ ] Generic error messages; full errors logged
- [ ] No `unwrap`/`expect` in request paths
- [ ] CORS allowlist explicit
- [ ] Metrics/tracing on internal listener
- [ ] Parameterized SQL (`bind`)
- [ ] No shell with user input
- [ ] File paths bounds-checked
- [ ] Outbound HTTP allowlisted
- [ ] CSPRNG for tokens
- [ ] Strict typed deserialization
- [ ] No `unsafe` on untrusted input

## Quick detection bundle

```bash
rg -n "Files::new|ServeDir::new" src/
rg -n "\.unwrap\(\)|\.expect\(" src/
rg -n "allow_any|CorsLayer" src/
rg -n "format!\(.*WHERE|query\(.*format" src/
rg -n "Command::new\(\"sh\"|arg\(\"-c\"\)" src/
rg -n "reqwest::get\(|Client::new\(\)\.get\(" src/
rg -n "thread_rng|StdRng|SmallRng" src/
rg -n "unsafe " src/
```
