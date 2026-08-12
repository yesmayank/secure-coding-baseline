# GraphQL (Apollo, Hasura) — Misconfigurations & Common Vulnerabilities

Defensive reference for GraphQL APIs.

---

## Misconfigurations

### 1. Introspection enabled in production

**What:** `introspection: true` lets attackers enumerate the entire schema — types, fields, mutations, enum values — a recon goldmine.

**Fix:** Disable in prod: `ApolloServer({ introspection: false })`; or gate behind auth.

**Detection:** `rg -n "introspection" server/`

---

### 2. No depth/complexity limits

**What:** Nested queries (`user{friends{friends{...}}}`) exhaust CPU/DB → DoS.

**Fix:** Use `graphql-depth-limit` and `graphql-cost-analysis` with a max cost.

**Detection:** `rg -n "depthLimit|costAnalysis|depthLimit|complexity" server/`

---

### 3. Over-fetching via permissive resolvers

**What:** Resolvers returning full objects without field-level authz leak sensitive fields (`email`, `passwordHash`).

**Fix:** Field-level authz; return only requested fields; use `@auth` directives.

**Detection:** review resolvers for `return user;` without field filtering.

---

### 4. CORS allow-all

**What:** `cors: { origin: '*' }` with credentials.

**Fix:** Allowlist origins.

**Detection:** `rg -n "cors|origin" server/`

---

### 5. Verbose error responses

**What:** Returning full `error.message` and extensions leaks internals.

**Fix:** `formatError` to sanitize; log full errors server-side.

**Detection:** `rg -n "formatError|formatResponse" server/`

---

## Common Vulnerabilities

### 6. BOLA / IDOR in resolvers

**What:** `user(id: $id)` resolver returns any user without ownership check.

**Fix:** Verify caller owns resource; scope by `context.user.id`.

**Detection:** `rg -n "args\.id|parent\.id" server/`

---

### 7. SQL injection in resolvers

**What:** `db.query("... WHERE id = " + args.id)`.

**Fix:** Parameterized queries / ORM.

**Detection:** `rg -n "query\(.*\+|raw\(.*\+" server/`

---

### 8. Mutation authz missing

**What:** Mutations like `deleteUser`, `updateRole` with no auth check.

**Fix:** Auth directives or middleware on every mutation.

**Detection:** `rg -n "Mutation|@auth|@requireAuth" server/`

---

### 9. Batch / aliasing abuse

**What:** Aliased queries (`a: user(id:1), b: user(id:2), ...`) bypass rate limits.

**Fix:** Limit aliases; per-query cost limits; rate limit by cost.

**Detection:** review middleware for alias limits.

---

### 10. SSRF in file/URL fetch resolvers

**What:** Resolvers fetching user-supplied URLs.

**Fix:** Allowlist hosts; block link-local/RFC1918.

**Detection:** `rg -n "axios|fetch\(|request\(" server/`

---

### 11. Hasura admin secret exposed / default

**What:** `HASURA_GRAPHQL_ADMIN_SECRET` committed or weak; `/v1/query` and metadata APIs reachable.

**Fix:** Strong admin secret from env; restrict metadata/admin endpoints to internal; disable `HASURA_GRAPHQL_ENABLE_CONSOLE` in prod or gate it.

**Detection:** `rg -n "admin_secret|admin-secret|HASURA" config/ docker-compose*.yml`

---

### 12. Subscription authz gaps

**What:** Subscriptions authenticated only on connect, not per-event.

**Fix:** Authorize each emitted event.

**Detection:** `rg -n "subscribe|Subscription|withFilter" server/`

---

## Checklist

- [ ] Introspection disabled in prod
- [ ] Depth and cost limits enforced
- [ ] Field-level authz
- [ ] CORS allowlist explicit
- [ ] Errors sanitized
- [ ] Object-level authz in resolvers
- [ ] Parameterized SQL
- [ ] Auth on every mutation
- [ ] Alias/batch limits
- [ ] Outbound HTTP allowlisted
- [ ] Hasura admin secret strong; console/metadata gated
- [ ] Subscription authz per-event

## Quick detection bundle

```bash
rg -n "introspection" server/
rg -n "depthLimit|costAnalysis|complexity" server/
rg -n "cors|origin" server/
rg -n "formatError|formatResponse" server/
rg -n "query\(.*\+|raw\(.*\+" server/
rg -n "Mutation|@auth" server/
rg -n "admin_secret|HASURA" config/ docker-compose*.yml
```
