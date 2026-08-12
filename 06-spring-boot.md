# Java + Spring Boot — Misconfigurations & Common Vulnerabilities

Defensive reference for Spring Boot services.

---

## Misconfigurations

### 1. Actuator endpoints exposed and unauthenticated

**What:** Spring Boot Actuator's `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings` leak environment variables (secrets), heap (which contains secrets in memory), and full route maps.

**Dangerous pattern:**
```properties
management.endpoints.web.exposure.include=*
management.endpoints.web.exposure.include=env,heapdump
```

**Leaks:** DB credentials, API keys, JWT secrets, full route inventory.

**Fix:** Expose only `health` and `info` over the web; restrict the rest to an internal management port with auth.
```properties
management.endpoints.web.exposure.include=health,info
management.endpoint.env.enabled=false
management.endpoint.heapdump.enabled=false
```

**Detection:** `rg -n "management.endpoints.web.exposure" src/main/resources/`

---

### 2. Stack traces in error responses

**What:** Default `server.error.include-stacktrace` may leak traces; `include-exception` leaks class names.

**Fix:**
```properties
server.error.include-stacktrace=never
server.error.include-exception=false
server.error.include-message=never
```

**Detection:** `rg -n "include-stacktrace|include-exception|include-message" src/main/resources/`

---

### 3. H2 console enabled in production

**What:** `/h2-console` lets attackers connect to the in-memory/real DB and run arbitrary SQL.

**Fix:** `spring.h2.console.enabled=false` in prod.

**Detection:** `rg -n "h2.console.enabled" src/main/resources/`

---

### 4. Devtools active in prod

**What:** `spring-boot-devtools` enables live reload and a restart listener; reachable in prod = remote code execution risk.

**Fix:** Exclude devtools from the prod jar (it's excluded by default, but verify custom builds).

**Detection:** `rg -n "spring-boot-devtools" pom.xml build.gradle`

---

### 5. Swagger/OpenAPI exposed in prod

**What:** `/swagger-ui.html` and `/v3/api-docs` leak route/schema inventory.

**Fix:** Disable or gate behind auth in prod.

**Detection:** `rg -n "springdoc|swagger" pom.xml build.gradle src/`

---

## Common Vulnerabilities

### 6. SpEL injection

**What:** `SpelExpressionParser` on user input evaluates arbitrary expressions → RCE.

**Dangerous pattern:**
```java
Expression exp = parser.parseExpression(userInput);
```

**Fix:** Never parse untrusted input as SpEL; use a safe template engine with escaping.

**Detection:** `rg -n "SpelExpressionParser|parseExpression" src/`

---

### 7. SQL injection via string concatenation

**What:** `jdbcTemplate.query("... WHERE id = " + id)` or `@Query("... :?#{#user}")` misuse.

**Fix:** Use `?` placeholders or named parameters (`:id`), or JPA derived queries.

**Detection:** `rg -n "jdbcTemplate.query\(.*\+|@Query\(.*\+|createQuery\(.*\+" src/`

---

### 8. Mass assignment via `@ModelAttribute` / direct binding

**What:** Binding request params to an entity with setters lets attackers set `role`, `isAdmin`.

**Fix:** Use dedicated DTOs; `@JsonIgnore` privileged fields; `@InitBinder` allowlist.

**Detection:** `rg -n "@ModelAttribute|@InitBinder" src/`

---

### 9. BOLA / IDOR

**What:** `@PathVariable Long id` used without ownership check.

**Fix:** Verify ownership in the service; use `@PreAuthorize` with method security.

**Detection:** `rg -n "@PathVariable.*id" src/`

---

### 10. Deserialization RCE (Jackson, ObjectInputStream)

**What:** `ObjectInputStream.readObject` on untrusted data, or Jackson with polymorphic typing enabled on attacker-controlled `@class`, is RCE.

**Fix:** Avoid native Java serialization for untrusted input; disable `enableDefaultTyping`; use `@JsonTypeInfo` explicitly.

**Detection:** `rg -n "ObjectInputStream|enableDefaultTyping|readObject" src/`

---

### 11. SSRF via `RestTemplate`/`WebClient`

**What:** Outbound HTTP to user URLs hits internal metadata.

**Fix:** Allowlist hosts; block link-local/RFC1918.

**Detection:** `rg -n "RestTemplate|WebClient" src/`

---

### 12. XXE via XML parsing

**What:** `DocumentBuilderFactory` without disabling DTDs reads external entities → SSRF/file read.

**Fix:** `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`; disable external entities.

**Detection:** `rg -n "DocumentBuilderFactory|SAXParserFactory|XMLInputFactory" src/`

---

## Checklist

- [ ] Actuator limited to `health,info`; sensitive endpoints disabled or on internal port
- [ ] No stack traces/exceptions/messages in responses
- [ ] H2 console off in prod
- [ ] Devtools excluded from prod jar
- [ ] Swagger disabled/gated in prod
- [ ] No SpEL on user input
- [ ] Parameterized SQL
- [ ] DTOs for binding; privileged fields ignored
- [ ] Object-level authorization
- [ ] No native deserialization of untrusted data
- [ ] Outbound HTTP allowlisted
- [ ] XML parsers hardened against XXE

## Quick detection bundle

```bash
rg -n "management.endpoints.web.exposure" src/main/resources/
rg -n "include-stacktrace|include-exception|include-message" src/main/resources/
rg -n "h2.console.enabled" src/main/resources/
rg -n "SpelExpressionParser|parseExpression" src/
rg -n "jdbcTemplate.query\(.*\+|@Query\(.*\+|createQuery\(.*\+" src/
rg -n "ObjectInputStream|enableDefaultTyping|readObject" src/
rg -n "DocumentBuilderFactory|SAXParserFactory" src/
```
