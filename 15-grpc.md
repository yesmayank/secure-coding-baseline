# gRPC — Misconfigurations & Common Vulnerabilities

Defensive reference for gRPC services.

---

## Misconfigurations

### 1. Plaintext (no TLS)

**What:** `grpc.NewServer()` with `grpc.Creds(insecure.NewCredentials())` sends everything in cleartext, including auth tokens.

**Fix:** Use TLS: `creds.NewServerTLSFromFile(certFile, keyFile)`; enforce mTLS for service-to-service.

**Detection:** `rg -n "insecure.NewCredentials|grpc.NewServer\(\)" *.go`

---

### 2. Reflection enabled in production

**What:** `reflection.Register(s)` exposes the full service/method schema to any caller — recon aid.

**Fix:** Disable reflection in prod or gate behind mTLS.

**Detection:** `rg -n "reflection.Register|grpc/reflection" *.go`

---

### 3. No per-method authz

**What:** A single interceptor applies auth to all or none; privileged RPCs callable by any authenticated caller.

**Fix:** Per-method authz interceptor; map method names to required roles.

**Detection:** `rg -n "UnaryServerInterceptor|StreamServerInterceptor|auth" *.go`

---

### 4. No message size limits

**What:** Default max receive can be raised to large values; huge messages exhaust memory → DoS.

**Fix:** Set `grpc.MaxRecvMsgSizeSize` to a sane cap; validate payload sizes.

**Detection:** `rg -n "MaxRecvMsgSize|MaxSendMsgSize" *.go`

---

### 5. Verbose error codes/messages

**What:** Returning `status.Error(codes.Internal, err.Error())` leaks internals.

**Fix:** Log full error; return `status.Error(codes.Internal, "internal error")`.

**Detection:** `rg -n "codes.Internal, err|status.Errorf\(.*err\.Error" *.go`

---

## Common Vulnerabilities

### 6. Missing deadline/timeout propagation

**What:** Clients without `context.WithTimeout` hang; servers without deadlines hold resources → DoS.

**Fix:** Always set deadlines; propagate via context; enforce server-side max age.

**Detection:** `rg -n "context.WithTimeout|context.WithDeadline|grpc.WithTimeout" *.go`

---

### 7. BOLA in handlers

**What:** `GetResource(id)` without ownership check.

**Fix:** Verify caller (from metadata/context) owns resource.

**Detection:** review handler methods for ID params without authz.

---

### 8. SSRF / outbound calls from handlers

**What:** Handlers fetching user-supplied URLs.

**Fix:** Allowlist hosts; block link-local/RFC1918.

**Detection:** `rg -n "http.Get|reqwest|client.Get" *.go`

---

### 9. Deserialization of untrusted proto

**What:** While protobuf is typed, custom `Any` payloads or JSON-gateway transcoding can inject unexpected types.

**Fix:** Restrict `google.protobuf.Any` type URLs; validate transcoded JSON.

**Detection:** `rg -n "google.protobuf.Any|anypb|UnmarshalAny" *.go`

---

### 10. Gateway/transcoding without input validation

**What:** grpc-gateway maps REST to RPC; missing field validation lets bad input reach services.

**Fix:** Validate in handlers (not only in proto `validate`); enable `protoc-gen-validate`.

**Detection:** `rg -n "validate|gvValidate|Validate\(" *.go`

---

### 11. Token in metadata without rotation / weak

**What:** Static bearer tokens in metadata, never rotated.

**Fix:** Short-lived tokens; rotation; mTLS for internal.

**Detection:** `rg -n "metadata.FromIncomingContext|authorization" *.go`

---

### 12. Unbounded streaming

**What:** Server-streaming or bidi-streaming without per-stream quotas → resource exhaustion.

**Fix:** Cap concurrent streams per peer; set `MaxConcurrentStreams`; timeouts.

**Detection:** `rg -n "MaxConcurrentStreams|StreamServerInterceptor" *.go`

---

## Checklist

- [ ] TLS enforced; mTLS for internal
- [ ] Reflection disabled/gated in prod
- [ ] Per-method authz interceptor
- [ ] Message size limits set
- [ ] Generic error messages
- [ ] Deadlines on clients and servers
- [ ] Object-level authz in handlers
- [ ] Outbound HTTP allowlisted
- [ ] `Any` payloads restricted
- [ ] Input validation on gateway
- [ ] Short-lived tokens; rotation
- [ ] Concurrent stream caps

## Quick detection bundle

```bash
rg -n "insecure.NewCredentials|grpc.NewServer\(\)" *.go
rg -n "reflection.Register" *.go
rg -n "MaxRecvMsgSize|MaxConcurrentStreams" *.go
rg -n "codes.Internal, err|status.Errorf\(.*err\.Error" *.go
rg -n "context.WithTimeout|context.WithDeadline" *.go
rg -n "google.protobuf.Any|anypb|UnmarshalAny" *.go
```
