# Redis — Misconfigurations & Common Vulnerabilities

Defensive reference for Redis deployments.

---

## Misconfigurations

### 1. Bound to `0.0.0.0` with no auth

**What:** `bind 0.0.0.0` + no `requirepass` exposes Redis to the network. Redis has historically been abused for RCE (CONFIG SET dir + dbfilename + SAVE to write webshells/SSH keys) and as a cryptomining pivot.

**Fix:** `bind 127.0.0.1` or internal interface; `requirepass`/ACL; never expose to the public internet.

**Detection:** `rg -n "^bind|^requirepass|^protected-mode" redis.conf`

---

### 2. `protected-mode no`

**What:** Disables the built-in protection that blocks external access when no password is set.

**Fix:** Keep `protected-mode yes`; set a password if external access is needed.

**Detection:** `rg -n "protected-mode no" redis.conf`

---

### 3. Dangerous commands enabled

**What:** `CONFIG`, `FLUSHALL`, `KEYS`, `DEBUG` reachable by app users can be abused.

**Fix:** Rename/disable in config: `rename-command CONFIG ""`, `rename-command FLUSHALL ""`.

**Detection:** `rg -n "rename-command" redis.conf`

---

### 4. No TLS

**What:** Traffic (including the password) is cleartext on the wire.

**Fix:** Enable TLS (`port 0`, `tls-port 6379`, certs) for any non-loopback traffic.

**Detection:** `rg -n "tls-port|tls-cert-file" redis.conf`

---

### 5. No maxmemory / eviction policy

**What:** Unbounded growth → OOM and DoS.

**Fix:** `maxmemory <bytes>`, `maxmemory-policy allkeys-lru` (or as appropriate).

**Detection:** `rg -n "maxmemory|maxmemory-policy" redis.conf`

---

## Common Vulnerabilities

### 6. Storing sensitive data unencrypted

**What:** PII, tokens, session data stored in plaintext; a Redis breach = direct data leak.

**Fix:** Don't store secrets you can't afford to leak; encrypt sensitive values at the app layer; keep sessions short-lived.

**Detection:** review app code for what is written to Redis.

---

### 7. Trusting client-supplied keys for sensitive ops

**What:** App uses `GET <user_key>` without authz → BOLA via cache.

**Fix:** Scope cache keys by tenant/user; validate access before returning.

**Detection:** review cache access patterns in app code.

---

### 8. Lua script injection

**What:** `EVAL` with user input concatenated into the script → script injection / logic bypass.

**Fix:** Use `EVALSHA` with parameterized `KEYS`/`ARGV`; never interpolate user input into the script body.

**Detection:** `rg -n "EVAL|eval\(|redis\.eval" app/`

---

### 9. Session fixation via predictable session IDs

**What:** Using predictable keys for sessions enables session hijacking.

**Fix:** Use cryptographically random session IDs (`crypto.randomBytes`/`secrets.tokenBytes`).

**Detection:** review session ID generation.

---

### 10. No authentication on Sentinel / Cluster bus

**What:** Sentinel/Cluster nodes communicating without auth can be hijacked to redirect clients.

**Fix:** Set `requirepass` and `masterauth`; restrict cluster bus port to internal network.

**Detection:** `rg -n "masterauth|requirepass|cluster" redis.conf`

---

### 11. Default port + no firewall

**What:** 6379 reachable from the internet gets scanned and abused within minutes.

**Fix:** Firewall to internal-only; use a non-default port as defense-in-depth (not primary).

**Detection:** check security groups / iptables for 6379 exposure.

---

### 12. No audit / monitoring

**What:** Abuse goes undetected.

**Fix:** Monitor `INFO`, slowlog, connected clients; alert on `CONFIG SET`, large `KEYS`, unexpected `SAVE`.

**Detection:** check monitoring config.

---

## Checklist

- [ ] Bound to loopback/internal; not on `0.0.0.0`
- [ ] `requirepass`/ACL set; strong password from secret store
- [ ] `protected-mode yes`
- [ ] Dangerous commands renamed/disabled
- [ ] TLS for non-loopback traffic
- [ ] `maxmemory` + eviction policy set
- [ ] No secrets you can't afford to lose stored unencrypted
- [ ] Cache access scoped by tenant/user
- [ ] Lua scripts parameterized; no user input in script body
- [ ] Cryptographically random session IDs
- [ ] Sentinel/Cluster auth set; bus port internal-only
- [ ] 6379 firewalled; monitoring + alerting on abuse patterns

## Quick detection bundle

```bash
rg -n "^bind|^requirepass|^protected-mode" redis.conf
rg -n "protected-mode no" redis.conf
rg -n "rename-command" redis.conf
rg -n "tls-port|tls-cert-file" redis.conf
rg -n "maxmemory|maxmemory-policy" redis.conf
rg -n "masterauth|requirepass|cluster" redis.conf
rg -n "EVAL|eval\(|redis\.eval" app/
```
