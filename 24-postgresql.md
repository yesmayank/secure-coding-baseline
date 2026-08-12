# PostgreSQL — Misconfigurations & Common Vulnerabilities

Defensive reference for PostgreSQL deployments.

---

## Misconfigurations

### 1. `trust` / `md5` auth in `pg_hba.conf`

**What:** `trust` allows passwordless connections; `md5` is weak. With `trust` on `0.0.0.0/0`, anyone on the network gets full DB access.

**Fix:** `scram-sha-256` everywhere; restrict by IP/network; never `trust` for remote.

**Detection:** `rg -n "trust|md5|0\.0\.0\.0" pg_hba.conf`

---

### 2. Superuser used by app

**What:** App connecting as `postgres` superuser means any SQLi or logic bug can `COPY` files, create functions, read `pg_shadow`.

**Fix:** Dedicated least-privilege role per app; no `SUPERUSER`, `CREATEDB`, `CREATEROLE`.

**Detection:** check connection strings / K8s secrets for the app DB role.

---

### 3. Listening on `0.0.0.0`

**What:** `listen_addresses = '*'` exposes Postgres to the network.

**Fix:** `listen_addresses = 'localhost'` or internal interface; firewall 5432.

**Detection:** `rg -n "listen_addresses" postgresql.conf`

---

### 4. Over-granted privileges (`GRANT ALL`)

**What:** `GRANT ALL ON DATABASE x TO app;` lets the app drop tables, write to any schema.

**Fix:** `GRANT SELECT, INSERT, UPDATE, DELETE ON schema.* TO app;` only what's needed; revoke `CREATE` on public schema.

**Detection:** `\du+` / `rg -n "GRANT ALL" migrations/`

---

### 5. No TLS

**What:** Cleartext credentials and data on the wire.

**Fix:** `ssl = on`; require `hostssl` + `sslmode=verify-full` in `pg_hba.conf` and client DSN.

**Detection:** `rg -n "^ssl|hostssl|sslmode" postgresql.conf pg_hba.conf`

---

### 6. Logging disabled / passwords in logs

**What:** No audit trail, or `log_statement = 'all'` logging sensitive data.

**Fix:** Enable connection logging; avoid logging full statements with bind values; ship logs to SIEM.

**Detection:** `rg -n "log_statement|log_connections|log_disconnections" postgresql.conf`

---

## Common Vulnerabilities

### 7. SQL injection in app

**What:** String-concatenated queries (`"... WHERE id = " + id`) reach the DB.

**Fix:** Parameterized queries / prepared statements / ORM; never interpolate.

**Detection:** `rg -n "execute\(.*\+|query\(.*\+|fmt\.Sprintf.*WHERE" app/`

---

### 8. `COPY`/`pg_read_file` abuse via SQLi

**What:** With superuser, an attacker can `COPY (SELECT ...) TO PROGRAM '...'` (RCE) or read files.

**Fix:** App role is not superuser; restrict `pg_read_file`, `pg_ls_dir`; revoke dangerous functions.

**Detection:** check role privileges; `rg -n "COPY|pg_read_file|pg_ls_dir" app/`

---

### 9. Mass assignment / over-broad `INSERT`/`UPDATE`

**What:** App updates all columns from request body, including `role`/`is_admin`.

**Fix:** Allowlist columns in app code; use column-level privileges to enforce at DB too.

**Detection:** review ORM update calls.

---

### 10. BOLA / IDOR in queries

**What:** `SELECT * FROM items WHERE id = $1` without `AND owner_id = $2`.

**Fix:** Always scope by tenant/owner; use RLS (Row-Level Security) as defense-in-depth.

**Detection:** `rg -n "FROM .* WHERE id" app/`; `rg -n "ENABLE ROW LEVEL SECURITY" migrations/`

---

### 11. Weak password storage / `md5`/`crypt`

**What:** Storing app-user passwords with weak hashes inside Postgres.

**Fix:** Hash with bcrypt/argon2 in the app; store only the digest.

**Detection:** `rg -n "md5\(|crypt\(|password" app/ migrations/`

---

### 12. Unpatched server / extensions

**What:** Known CVEs in Postgres or extensions (e.g., `pg_cron`, `plpythonu`).

**Fix:** Stay on supported major; patch promptly; remove untrusted-language extensions (`plpythonu`, `plperlu`) from app DB.

**Detection:** `SELECT version();`; `\dx`.

---

## Checklist

- [ ] `scram-sha-256` auth; no `trust`/`md5` for remote
- [ ] App uses a least-privilege non-superuser role
- [ ] `listen_addresses` restricted; 5432 firewalled
- [ ] Minimal grants; no `GRANT ALL`; `CREATE` revoked on public schema
- [ ] TLS on; `hostssl` + `sslmode=verify-full`
- [ ] Connection logging on; sensitive values not logged
- [ ] Parameterized queries everywhere
- [ ] App role can't `COPY`/read files
- [ ] Column allowlists on writes
- [ ] Queries scoped by owner; RLS enabled
- [ ] Passwords hashed with bcrypt/argon2 in app
- [ ] Server patched; untrusted-language extensions removed

## Quick detection bundle

```bash
rg -n "trust|md5|0\.0\.0\.0" pg_hba.conf
rg -n "listen_addresses" postgresql.conf
rg -n "^ssl|hostssl|sslmode" postgresql.conf pg_hba.conf
rg -n "GRANT ALL" migrations/
rg -n "execute\(.*\+|query\(.*\+|fmt\.Sprintf.*WHERE" app/
rg -n "COPY|pg_read_file|pg_ls_dir" app/
rg -n "ENABLE ROW LEVEL SECURITY" migrations/
```
