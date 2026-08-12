# Docker — Misconfigurations & Common Vulnerabilities

Defensive reference for Docker images and the Docker daemon.

---

## Misconfigurations

### 1. Running as root

**What:** Default container user is root. A container escape or vulnerable process runs with root inside.

**Fix:** Create a non-root user and `USER` it.
```dockerfile
RUN addgroup -S app && adduser -S app -G app
USER app
```

**Detection:** `rg -n "^USER|user:" Dockerfile`

---

### 2. `:latest` / unpinned tags

**What:** `FROM node:latest` pulls whatever is current → supply-chain drift, unreviewed base changes.

**Fix:** Pin to a digest or specific minor tag: `FROM node:20.17-alpine@sha256:...`.

**Detection:** `rg -n "^FROM" Dockerfile`

---

### 3. Secrets baked into image

**What:** `COPY .env /app/.env`, `ENV API_KEY=...`, or `RUN` with credentials leaks them to anyone with the image (and to layer history).

**Fix:** Mount secrets at runtime via env/K8s secrets or `docker secret`; use BuildKit `--mount=type=secret`.

**Detection:** `rg -n "ENV .*KEY|ENV .*SECRET|ENV .*PASSWORD|COPY .*env" Dockerfile`

---

### 4. No `.dockerignore` / copying whole repo

**What:** `COPY . /app` includes `.git`, `node_modules`, `coverage`, `.env`, test fixtures — bloating and leaking.

**Fix:** Use a `.dockerignore` excluding `.git`, `node_modules`, `.env*`, `coverage`, `*.log`.

**Detection:** `cat .dockerignore`; `rg -n "COPY \. |COPY \./" Dockerfile`

---

### 5. Privileged mode / excessive capabilities

**What:** `docker run --privileged` grants all caps + devices; near-host access.

**Fix:** Drop all caps and add only needed ones: `--cap-drop=ALL --cap-add=NET_BIND_SERVICE`; use `--security-opt=no-new-privileges`.

**Detection:** check run commands/compose for `privileged: true` / `cap_add`.

---

### 6. Exposed Docker daemon socket

**What:** Mounting `/var/run/docker.sock` into a container gives that container root on the host. Binding the daemon to `0.0.0.0` without TLS exposes it to the network.

**Fix:** Never mount the socket into untrusted containers; bind daemon to a unix socket or TLS-protected TCP with auth.

**Detection:** `rg -n "docker.sock|/var/run/docker" docker-compose*.yml k8s/`; check `dockerd` flags.

---

## Common Vulnerabilities

### 7. Insecure image / no scanning

**What:** Base images with known CVEs.

**Fix:** Scan with `trivy`/`grype`/Snyk in CI; auto-rebuild on base updates.

**Detection:** run `trivy image <image>`.

---

### 8. Layer history leaks secrets

**What:** Secrets added in an early layer and "removed" later still exist in intermediate layers.

**Fix:** Use multi-stage builds; never put secrets in layers; use BuildKit secrets.

**Detection:** `docker history --no-trunc <image>`.

---

### 9. Writable filesystem / no `read-only`

**What:** Default rootfs is writable → attackers can drop payloads.

**Fix:** `docker run --read-only`; mount only needed writable paths as tmpfs/volumes.

**Detection:** check run flags for `--read-only`.

---

### 10. No resource limits

**What:** No `--memory`/`--cpus` → a single container can starve the host (DoS).

**Fix:** Set memory and CPU limits in compose/K8s.

**Detection:** `rg -n "mem_limit|cpus|resources:" docker-compose*.yml`

---

### 11. Build context injection via untrusted Dockerfile / remote context

**What:** Building untrusted `Dockerfile` or `git+ssh://` contexts can run arbitrary commands during build.

**Fix:** Only build trusted Dockerfiles; pin contexts; review `RUN` lines.

**Detection:** review CI build inputs.

---

### 12. Default seccomp/AppArmor disabled

**What:** `--security-opt seccomp=unconfined` removes syscall filtering.

**Fix:** Keep default seccomp profile; apply an AppArmor profile.

**Detection:** `rg -n "seccomp=unconfined|apparmor=unconfined" `

---

## Checklist

- [ ] Non-root `USER` in Dockerfile
- [ ] Base image pinned to digest/minor tag
- [ ] No secrets in image layers/env
- [ ] `.dockerignore` excludes `.git`, `node_modules`, `.env*`, logs
- [ ] No `--privileged`; caps dropped; `no-new-privileges`
- [ ] Docker socket never mounted into untrusted containers; daemon not on `0.0.0.0` unauthenticated
- [ ] Images scanned in CI
- [ ] Multi-stage builds; secrets via BuildKit
- [ ] `--read-only` rootfs
- [ ] Memory/CPU limits set
- [ ] Only trusted Dockerfiles built
- [ ] Default seccomp/AppArmor enabled

## Quick detection bundle

```bash
rg -n "^USER" Dockerfile
rg -n "^FROM" Dockerfile
rg -n "ENV .*KEY|ENV .*SECRET|ENV .*PASSWORD|COPY .*env" Dockerfile
rg -n "COPY \. |COPY \./" Dockerfile
rg -n "privileged: true|cap_add|docker.sock|seccomp=unconfined" docker-compose*.yml
cat .dockerignore 2>/dev/null
```
