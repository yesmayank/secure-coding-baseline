# NestJS — Misconfigurations & Common Vulnerabilities

Defensive reference for Node.js services built on NestJS. NestJS sits on top of Express (or Fastify), so the Node/Express risks apply too; this file covers NestJS-specific issues.

---

## Misconfigurations

### 1. ValidationPipe not enabled globally / no whitelist

**What:** Without a global `ValidationPipe` with `whitelist: true`, DTOs accept arbitrary fields and unvalidated payloads reach services.

**Dangerous pattern:**
```ts
// main.ts with no pipe, or:
app.useGlobalPipes(new ValidationPipe());
```

**Leaks/Impact:** Mass assignment (overwriting `role`, `isAdmin`), type confusion, unexpected fields persisted.

**Fix:**
```ts
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
  disableErrorMessages: process.env.NODE_ENV === 'production',
}));
```

**Detection:** `rg -n "ValidationPipe" src/main.ts`

---

### 2. DTOs without class-validator decorators

**What:** A DTO class with no `@IsString` / `@IsInt` etc. validates nothing even with the pipe enabled.

**Dangerous pattern:**
```ts
export class CreateUserDto {
  name: string;
  email: string;
  role: string; // attacker-controlled
}
```

**Fix:** Decorate every property; use `@Matches`, `@IsEnum`, `@Max`, `@Min`. Strip privileged fields into a separate DTO used only by admins.

**Detection:** `rg -n "class \w+Dto" src/` then confirm decorators exist.

---

### 3. `forRoot` config leaking via Swagger in production

**What:** Swagger UI exposed in prod leaks route names, DTO shapes, and enum values — a recon goldmine.

**Dangerous pattern:**
```ts
SwaggerModule.setup('api', app, document); // unconditional
```

**Fix:** Gate behind env.
```ts
if (process.env.NODE_ENV !== 'production') {
  SwaggerModule.setup('api', app, document);
}
```

**Detection:** `rg -n "SwaggerModule.setup" src/`

---

### 4. Exposed actuator / termination endpoints

**What:** NestJS microservices or `@nestjs/terminus` health endpoints sometimes return internal dependency info (DB host, redis URL) when misconfigured.

**Fix:** Health checks should return only status; never include connection strings or hostnames in the response.

**Detection:** `rg -n "@Controller\('health'\)|HealthIndicator|terminus" src/`

---

### 5. Global `useGlobalFilters` that leak exceptions

**What:** A custom exception filter that returns `exception.message` or stack leaks internals.

**Dangerous pattern:**
```ts
res.status(500).json({ message: exception.message, stack: exception.stack });
```

**Fix:** Log full exception server-side; return generic message. Use `HttpException` subclasses for client-visible errors only.

**Detection:** `rg -n "ExceptionFilter|useGlobalFilters" src/`

---

### 6. `e2e`/test modules shipped or mounted

**What:** Test controllers or `@nestjs/testing` modules accidentally imported in prod bootstrap expose mock endpoints.

**Fix:** Keep test modules out of `app.module.ts` imports; separate `AppModule` from `TestModule`.

**Detection:** `rg -n "Test, TestingModule" src/app.module.ts`

---

## Common Vulnerabilities

### 7. Mass assignment via `plainToInstance` / `new User(dto)`

**What:** Spreading request body into an entity (`{ ...user, ...dto }`) overwrites privileged columns.

**Fix:** Use `class-transformer` `plainToInstance` with `excludeExtraneousValues: true` and `@Expose` only on intended fields. Never `Object.assign(entity, dto)`.

**Detection:** `rg -n "Object\.assign\(.*dto|\.\.\.dto|plainToInstance" src/`

---

### 8. Broken object-level authorization (BOLA/IDOR)

**What:** `@Param('id')` used directly to fetch an entity without checking ownership.

**Dangerous pattern:**
```ts
@Get(':id')
findOne(@Param('id') id: string) { return this.users.findOne(id); }
```

**Fix:** Verify the caller owns the resource; prefer UUIDs over sequential IDs; add a guard that checks `req.user.id === resource.ownerId`.

**Detection:** `rg -n "@Param\('id'\)" src/`

---

### 9. JWT in `localStorage` / long-lived tokens

**What:** Storing JWTs in browser `localStorage` exposes them to XSS exfiltration.

**Fix:** Short-lived access token + httpOnly, Secure, SameSite=Strict cookie; refresh-token rotation.

**Detection:** Frontend: `rg -n "localStorage\.setItem.*token" `

---

### 10. SSRF via `HttpModule` / `axios`

**What:** `HttpService.get(url)` with user-controlled `url` reaches internal services and cloud metadata.

**Fix:** Allowlist hosts; block link-local/RFC1918; validate scheme.

**Detection:** `rg -n "HttpService|axios\.get\(.*req\." src/`

---

### 11. Unsafe `@Render` with user input (SSTI / XSS)

**What:** Passing unvalidated data into a template without escaping or using `<%- %>` style interpolation.

**Fix:** Use auto-escaping engines; never `disableEscaping`; sanitize HTML with DOMPurify before `dangerouslySetInnerHTML`-equivalent renders.

**Detection:** `rg -n "@Render\(|<%- " src/`

---

### 12. Event loop blocking (sync CPU work)

**What:** Sync crypto/regex/JSON on large payloads blocks the single-threaded event loop, causing DoS.

**Fix:** Move heavy work to a worker thread or queue; use streaming parsers.

**Detection:** review hot paths for `readFileSync`, `bcrypt.compareSync`, `crypto.pbkdf2Sync`.

---

## Checklist

- [ ] Global `ValidationPipe` with `whitelist` + `forbidNonWhitelisted`
- [ ] Every DTO property decorated
- [ ] Swagger disabled in production
- [ ] Health endpoints return status only
- [ ] Exception filters never send stack traces
- [ ] Test modules excluded from prod bootstrap
- [ ] No mass assignment; `excludeExtraneousValues`
- [ ] Object-level authorization on every `:id` route
- [ ] JWTs in httpOnly cookies, short TTL, refresh rotation
- [ ] Outbound HTTP allowlisted (SSRF)
- [ ] Templates auto-escape
- [ ] `helmet` enabled; `x-powered-by` disabled

## Quick detection bundle

```bash
rg -n "ValidationPipe" src/main.ts
rg -n "class \w+Dto" src/
rg -n "SwaggerModule.setup" src/
rg -n "ExceptionFilter|useGlobalFilters" src/
rg -n "Object\.assign\(.*dto|\.\.\.dto|plainToInstance" src/
rg -n "@Param\('id'\)" src/
rg -n "HttpService|axios\.get\(.*req\." src/
rg -n "@Render\(|<%- " src/
```
