# Kubernetes — Misconfigurations & Common Vulnerabilities

Defensive reference for Kubernetes clusters and workloads.

---

## Misconfigurations

### 1. Privileged containers

**What:** `securityContext.privileged: true` grants the pod near-host access (devices, kernel).

**Fix:** Never set privileged; use specific capabilities only.

**Detection:** `rg -n "privileged: true" k8s/ charts/ *.yaml`

---

### 2. `runAsUser: 0` / no non-root enforcement

**What:** Pods running as root can be hijacked to attack the node.

**Fix:** `runAsNonRoot: true`, `runAsUser: <non-zero>`, `readOnlyRootFilesystem: true`.

**Detection:** `rg -n "runAsUser: 0|runAsNonRoot" k8s/ charts/ *.yaml`

---

### 3. No resource limits / requests

**What:** Without limits a pod can exhaust node resources → DoS and noisy-neighbor issues.

**Fix:** Set `resources.requests` and `resources.limits` for CPU/memory.

**Detection:** `rg -n "resources:|limits:|requests:" k8s/ charts/ *.yaml`

---

### 4. Overly permissive RBAC / default ServiceAccount

**What:** Pods using the default SA with cluster-wide `cluster-admin` or broad `*` verbs on `*` resources.

**Fix:** Least-privilege roles; disable SA automount for pods that don't call the API: `automountServiceAccountToken: false`.

**Detection:** `rg -n "cluster-admin|verbs:.*\*|resources:.*\*|automountServiceAccountToken" k8s/ charts/ *.yaml`

---

### 5. Secrets in plaintext ConfigMaps / env

**What:** DB passwords, API keys in `ConfigMap` or plain `Secret` (base64 is not encryption) committed to git.

**Fix:** Use a sealed-secrets / external-secrets / Vault integration; encrypt etcd at rest; restrict Secret access via RBAC.

**Detection:** `rg -n "kind: ConfigMap" -A5 k8s/`; `git ls-files | rg -i secret`

---

### 6. Exposed `LoadBalancer` / `NodePort` to 0.0.0.0

**What:** Internal services exposed publicly.

**Fix:** Use `ClusterIP` + Ingress with auth for internal services; restrict `externalIPs`/`loadBalancerSourceRanges`.

**Detection:** `rg -n "type: LoadBalancer|type: NodePort|loadBalancerSourceRanges" k8s/ charts/ *.yaml`

---

## Common Vulnerabilities

### 7. No network policies (flat cluster)

**What:** Any pod can reach any pod by default.

**Fix:** Apply default-deny NetworkPolicies; allow only required flows.

**Detection:** `rg -n "kind: NetworkPolicy" k8s/ charts/`

---

### 8. No Pod Security Admission / old PodSecurityPolicy gaps

**What:** Pods can request privileged/hostPath/hostNetwork without enforcement.

**Fix:** Enforce `restricted` Pod Security Admission label on namespaces; ban `hostPath`, `hostNetwork`, `hostPID`.

**Detection:** `rg -n "pod-security.kubernetes.io|hostPath|hostNetwork|hostPID" k8s/ charts/ *.yaml`

---

### 9. Public API server / anonymous auth

**What:** `--anonymous-auth=true` and broad `system:anonymous` RBAC; API server exposed to `0.0.0.0`.

**Fix:** Disable anonymous auth; restrict API server to private network + authorized networks; enable RBAC + audit logs.

**Detection:** check API server flags and `system:anonymous` bindings.

---

### 10. etcd unauthenticated / unencrypted

**What:** etcd stores all cluster state + secrets; without TLS + auth it's a one-stop data leak.

**Fix:** TLS to etcd; client cert auth; encrypt secrets at rest (`EncryptionConfiguration`).

**Detection:** check etcd flags; `rg -n "encryption" k8s/`.

---

### 11. Image pull from public / no admission control

**What:** `imagePullPolicy: Always` with mutable tags + no image policy allows tampered images.

**Fix:** Pin image digests; use an admission controller (Kyverno/OPA Gatekeeper) to require signatures and disallow latest.

**Detection:** `rg -n "image:" k8s/ charts/`; check for admission policies.

---

### 12. No audit logging / no monitoring

**What:** Without audit logs and monitoring, breaches go undetected.

**Fix:** Enable audit logging; ship to SIEM; alert on privilege escalations and unusual API calls.

**Detection:** check API server `--audit-log-*` flags.

---

## Checklist

- [ ] No privileged containers
- [ ] `runAsNonRoot: true`; non-zero `runAsUser`; `readOnlyRootFilesystem`
- [ ] CPU/memory requests and limits on all workloads
- [ ] Least-privilege RBAC; SA token automount disabled where unused
- [ ] Secrets via external-secrets/Vault; not in ConfigMaps/git
- [ ] Internal services on `ClusterIP` + Ingress; source ranges restricted
- [ ] Default-deny NetworkPolicies
- [ ] Pod Security Admission `restricted` enforced; no `hostPath`/`hostNetwork`
- [ ] API server private; anonymous auth off; audit logging on
- [ ] etcd TLS + client cert auth; secrets encrypted at rest
- [ ] Images pinned by digest; admission policy enforces signatures
- [ ] Audit logs to SIEM; alerting on privilege escalation

## Quick detection bundle

```bash
rg -n "privileged: true" k8s/ charts/ *.yaml
rg -n "runAsUser: 0|runAsNonRoot" k8s/ charts/ *.yaml
rg -n "cluster-admin|verbs:.*\*|automountServiceAccountToken" k8s/ charts/ *.yaml
rg -n "type: LoadBalancer|type: NodePort" k8s/ charts/ *.yaml
rg -n "kind: NetworkPolicy" k8s/ charts/
rg -n "hostPath|hostNetwork|hostPID" k8s/ charts/ *.yaml
```
