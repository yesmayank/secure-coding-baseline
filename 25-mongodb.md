# MongoDB — Misconfigurations & Common Vulnerabilities

Defensive reference for MongoDB deployments.

---

## Misconfigurations

### 1. `bindIp: 0.0.0.0` with no auth

**What:** MongoDB historically shipped with auth disabled and bound to all interfaces; unauthenticated instances are routinely ransomwared and data-exfiltrated within hours.

**Fix:** `net.bindIp: 127.0.0.1` or internal interface; `security.authorization: enabled`; firewall 27017.

**Detection:** `rg -n "bindIp|authorization" mongod.conf`

---

### 2. No authentication / authorization

**What:** `security.authorization: disabled` lets any connected client read/write any DB.

**Fix:** Enable auth; create admin user + least-privilege app users; use SCRAM-SHA-256.

**Detection:** `rg -n "authorization" mongod.conf`

---

### 3. App using root / over-broad role

**What:** App connecting with `root` or `dbOwner` on the cluster can drop DBs and read all collections.

**Fix:** Dedicated role with `readWrite` on the specific DB only; no cluster-wide privileges.

**Detection:** review connection strings / created users.

---

### 4. No TLS

**What:** Cleartext credentials and data on the wire.

**Fix:** `net.tls.mode: requireTLS` + certs; `tlsAllowInvalidCertificates: false`.

**Detection:** `rg -n "tls|ssl" mongod.conf`

---

### 5. No network isolation / exposed port

**What:** 27017 reachable from the internet.

**Fix:** Security group / firewall to internal-only; VPN or private subnet for app access.

**Detection:** check security groups / iptables for 27017.

---

### 6. Verbose logging / query logging with PII

**What:** `operationProfiling.mode: all` logs every operation including sensitive fields.

**Fix:** Profile only when needed; avoid logging full documents in prod; ship to secured SIEM.

**Detection:** `rg -n "operationProfiling|slowOpThresholdMs" mongod.conf`

---

## Common Vulnerabilities

### 7. NoSQL injection via `$where` / `$func`

**What:** `db.col.find({ $where: "this.name == '" + input + "'" })` runs JS in the DB → injection.

**Fix:** Never use `$where` with user input; use structured query operators (`$eq`, `$in`).

**Detection:** `rg -n "\$where|\$func|new Function" app/`

---

### 8. Operator injection via merged query objects

**What:** `db.col.find({ ...req.body })` lets attackers inject operators like `{"username": {"$ne": null}, "password": {"$ne": null}}` to bypass auth.

**Fix:** Validate and cast inputs; never spread raw request body into a query; allowlist fields and operators.

**Detection:** `rg -n "find\(.*req\.|find\(.*\.\.\.req|find\(.*body" app/`

---

### 9. BOLA / IDOR

**What:** `findOne({ _id: id })` without ownership filter.

**Fix:** `findOne({ _id: id, ownerId: userId })`; use tenant-scoped queries.

**Detection:** `rg -n "findOne\(|find\(\{ ?_id" app/`

---

### 10. Mass assignment

**What:** `col.updateOne({ _id }, { $set: req.body })` overwrites privileged fields like `role`.

**Fix:** Allowlist fields; never `$set` raw body.

**Detection:** `rg -n "\$set.*req|updateOne\(.*req|update\(.*body" app/`

---

### 11. ReDoS / unbounded queries

**What:** Queries without limits/projection return huge result sets → memory/DoS.

**Fix:** Always `.limit()`; project only needed fields; use indexes; paginate.

**Detection:** `rg -n "\.find\(\{" app/` (check for `.limit`/`.project`)

---

### 12. Weak password storage / plaintext

**What:** Storing app-user passwords in plaintext or with weak hashes in a collection.

**Fix:** Hash with bcrypt/argon2 in the app; store only the digest; never log it.

**Detection:** `rg -n "password.*insert|insertOne\(.*password|createHash\('md5'" app/`

---

## Checklist

- [ ] `bindIp` restricted; not `0.0.0.0`
- [ ] `security.authorization: enabled`
- [ ] Least-privilege app role; no `root`
- [ ] TLS required; invalid certs rejected
- [ ] 27017 firewalled to internal
- [ ] Profiling not logging full documents in prod
- [ ] No `$where`/JS with user input
- [ ] Request body validated; no raw spread into queries
- [ ] Queries scoped by owner/tenant
- [ ] `$set` allowlisted; no raw body
- [ ] Queries limited + projected + indexed
- [ ] Passwords hashed with bcrypt/argon2

## Quick detection bundle

```bash
rg -n "bindIp|authorization" mongod.conf
rg -n "tls|ssl" mongod.conf
rg -n "\$where|\$func|new Function" app/
rg -n "find\(.*req\.|find\(.*\.\.\.req|find\(.*body" app/
rg -n "findOne\(|find\(\{ ?_id" app/
rg -n "\$set.*req|updateOne\(.*req" app/
rg -n "createHash\('md5'|createHash\('sha1'" app/
```
