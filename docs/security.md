# Security Model & Threat Analysis

## Threat model

**Assets (on the platform):** master encryption key, Ed25519 signing key,
license state, customer project sources, admin credentials.

**Assets (in a distributed package):** ciphertext blobs, public verification
key, signed manifest, runtime. **No private material by construction.**

**Adversaries considered:**

1. **A customer with a valid license** who wants to pirate the deployment to
   another domain, mirror the code, or strip the guard.
2. **An attacker of the deployment host** (unprivileged web user) who tampers
   with package files to bypass authorization or read plaintext.
3. **An insider with root on the deployment host** (see *Honest limitations*).
4. **An attacker of the platform** (network-level): replaying verification
   requests, probing the licensing API, attempting to exfiltrate keys via
   responses/logs/backups.

## Defenses per adversary

### 1. Piracy / re-deployment by a licensed customer

- **Domain binding, server-side.** The deployment's claimed host is taken
  from the HTTP request context on the deployment (`HTTP_HOST`), normalized
  (scheme/port/case/trailing dot/`www`), and checked against the license's
  allow-list **on the platform**. Client-side claims are never trusted.
  A copy served from another domain → `DOMAIN_NOT_AUTHORIZED`, app stops.
- **No decryption material ships.** Components are AES-256-GCM under a
  per-build key that is stored only wrapped by the master key. The package
  cannot decrypt its own blobs; plaintext is streamed from the platform per
  request under a signed, live-verified license. Copying the package to
  another host gives you ciphertext + public key — nothing executable.
- **Revocation is immediate.** Every runtime fetch re-checks the license
  state live on the platform (`/runtime/file`), so suspend/revoke takes
  effect on the next request — the cached token cannot outlive the license
  state (cache TTL only paces re-verification; the fetch itself is always
  re-authorized).
- **Integrity of the enforcement path.** The runtime verifies its own files
  (manifest signature + per-file hashes) on every request before doing
  anything, so stripping/patching `guard/`, the manifest, or a component
  blob → `INTEGRITY_FAILED`/`SIGNATURE_INVALID`, app stops, event reported.
- **Honest boundary:** client-side files (HTML/CSS/JS/images) are public —
  that is how the web works; the platform explicitly leaves them public and
  never claims otherwise.

### 2. Deployment-host attacker (unprivileged)

- **Tamper → fail closed + observable.** Modified component blob, runtime
  file, or signature → HTTP 503 with a professional error (no internals),
  a `security_events` record, and a best-effort report to the platform
  (`integrity_failure` / `invalid_signature` / `authorization_failed`).
- **No destructive anti-tamper.** The runtime never deletes files, damages
  databases, or creates persistence. Stopping functionality + logging is the
  entire response, by design.
- **Secrets on the host:** protected plaintext exists transiently in 0600
  temp files during a request (removed at shutdown) — the minimum needed to
  execute PHP. The on-disk steady state is ciphertext + public key only.
  `license.key` (0600) is a *reference*, not a secret: it authorizes nothing
  without a live platform check from an authorized domain.
- **Fail counters:** repeated verification failures per license+IP are
  throttled; the platform sees each attempt in `verification_logs`.

### 3. Root on the deployment host

**Cannot be defended against — and we say so in the package README and UI.**
A root user can read temp files during a request, delete everything, or run
no web server at all. The guarantee is scoped: *unauthorized modification or
copying does not result in successful authorized execution.*

### 4. Platform-level attacks

- **Replay:** `ts` window (default ±300 s) + unique memoized `nonce`.
- **Rate limiting:** per-IP buckets on every public endpoint (including
  login, 5/60 s) and on the runtime file stream.
- **No key exfiltration via responses:** licenses store SHA-256 of keys;
  plaintext key returned once; settings never return the raw AI key (stored
  wrapped by the master key); health/settings/events expose no private
  material; backups are metadata-only **and** signed — restoring a tampered
  bundle is rejected (`RESTORE_REJECTED`).
- **Error hygiene:** unhandled server errors → generic `SERVER_ERROR`;
  stack traces and internal paths never reach clients; secrets are masked in
  every scan/analysis/report surface.
- **Crypto:** established primitives only — scrypt (passwords), Ed25519
  (signatures, verified by the runtime with libsodium), AES-256-GCM
  (data keys), canonical-JSON signing (recursive key sort, compact
  separators, byte-identical on both sides). No custom ciphers.
- **Upload safety:** traversal (`../`), symlink/device entries, zip bombs
  (ratio + absolute limits), duplicates, and entry counts are rejected;
  archives are fully validated *before* the workspace is replaced, so a
  rejected upload can never destroy a previous one; per-project isolated
  workspaces; uploaded code is never executed.
- **Session/CSRF:** http-only `sfg_session` cookie (12 h) + per-session CSRF
  token enforced on all mutating session endpoints; roles + ownership
  enforced server-side on every endpoint (a developer cannot read, build,
  or license another user's project — verified by E2E).

## Key management

| Key | Storage | Exposure |
|---|---|---|
| Master key | `data/keys/master.key` (0600) | never leaves the host; wraps build keys + AI key |
| Signing private key | `data/keys/signing.key` (0600) | never leaves the host; never in packages, logs, backups, or responses |
| Signing public key | `data/keys/signing.pub` + shipped in packages (PEM + raw b64) | public |
| Per-build data key | wrapped in `builds.config_json` only | never written unwrapped, never shipped |
| License keys | SHA-256 hash only | plaintext shown once at creation |
| Passwords | scrypt(N=2¹⁴, r=8, p=1) + 16 B salt | never plaintext |

**Operational rule:** treat `data/` as the crown jewels. Back it up
encrypted; restoring `data/keys/` is what keeps existing builds decryptable
and signatures verifiable. The signed metadata backup does **not** contain
keys — it restores catalog state, not trust material.

## Verification & test coverage

The security claims above are exercised, not assumed, by the E2E suites:

- `tests/e2e_api.py` — upload guards (traversal ZIP rejected, source
  preserved), secret masking (raw values absent from reports **and** the
  package), key shown once, public-verify decision matrix (authorized /
  unauthorized domain / unknown key / stale timestamp replay), token
  signature verified against the *package's* public key, suspend→resume,
  domain add/block, tampered backup rejected, RBAC isolation (developer
  cannot cross ownership), CSRF enforcement.
- `tests/e2e_deploy.py` — a real `php -S` deployment of the real package:
  activation (wrong key, wrong domain, correct key), real page rendering
  through the streaming gateway, unauthorized domain blocked at runtime,
  www normalization, **tamper component → 503 INTEGRITY_FAILED**, **tamper
  runtime → 503**, **tamper signature → 503**, revocation → execution
  blocked, runtime events received by the platform, license re-issuance
  restores service.

## Honest limitations (repeated deliberately)

1. Root on the deployment host can read or delete anything. Nothing can stop
   that; the product promises fail-closed integrity + license enforcement,
   not physical security.
2. Client-side code is public by nature of the web.
3. Obfuscation is a readability reduction, not encryption.
4. The licensing server is a dependency of runtime operation (mitigated by
   an explicit, bounded offline grace window for *network* failures only —
   never for explicit denials).
5. The builtin analysis engine is heuristic and advisory; it is not a
   vulnerability scanner and makes no security guarantees.
