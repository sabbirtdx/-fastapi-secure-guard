# Deploying a Protected Package

This guide is what you (the customer) do with a `protected-build.zip`
delivered by the licensing platform. It mirrors the `README-deploy.md`
shipped inside `guard/` in every package.

## Prerequisites on the deployment host

- **PHP 8.1+** with the **openssl** and **sodium** (libsodium) extensions —
  the runtime verifies Ed25519 signatures with libsodium.
  (`apt install php8.x-cli php8.x-sodium` etc., depending on distro.)
- A web server (Apache/Nginx + PHP-FPM, or plain `php -S` for local
  checks) whose **document root is the extracted package directory**.
- Outbound HTTPS from the host to the licensing server
  (the `license_server` URL is baked into `guard/config.json` at build time).
- The domain must be authorized on your license (see *Domain verification*).

## Install

```bash
unzip protected-build.zip -d /var/www/shop
cd /var/www/shop
ls guard/            # guard.php, activate.php, config.json,
                     # manifest.json, manifest.sig, cache/, README-deploy.md
```

Point the vhost at the package directory. No other configuration is needed —
every protected PHP entry point is already a stub that boots the guard.

For entry points you add later, either:

- make them protected in a new build (recommended), or
- add `require __DIR__ . '/path/to/guard/guard.php';` at the top (use
  `auto_prepend_file guard/guard.php` to cover *all* PHP requests).

### Apache

```apache
DocumentRoot /var/www/shop
<Directory /var/www/shop>
    AllowOverride None
    Require all granted
</Directory>
# optional: force HTTPS everywhere if the license requires it
```

### Nginx + PHP-FPM

```nginx
root /var/www/shop;
index index.php;
location ~ \.php$ {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_pass unix:/run/php/php8.4-fpm.sock;
}
```

> The guard reads the deployment domain from the request's `Host` header
> (port stripped, lowercased). Serve the site on its real authorized domain —
> proxying through a different external host name will fail the domain check.

### Local smoke test (no domain yet)

```bash
php -S 127.0.0.1:8080 -t /var/www/shop
curl -H "Host: shop.example.com" http://127.0.0.1:8080/
```

You should get the **activation page** (302 → `/guard/activate.php`) —
proof the runtime boots and fails closed before activation.

## Activation

1. Open `https://your-authorized-domain/guard/activate.php` (works from any
   browser; the server decides the domain, not the client).
2. Enter the license key `SFG-XXXX-XXXX-XXXX-XXXX`.
3. On success you are redirected to the site and the key is stored in
   `guard/license.key` (mode 0600). The site is now live.
   The key is written only after the license server fully accepts the
   activation — a failed attempt never leaves a key stored.

If activation fails, the page shows the **real** reason as a stable code
(`LICENSE_INVALID`, `LICENSE_EXPIRED`, `LICENSE_REVOKED`,
`LICENSE_SUSPENDED`, `DOMAIN_NOT_AUTHORIZED`, `SERVER_UNAVAILABLE`, …).
A failed attempt never leaves a key stored.

## What happens on every request

1. The runtime re-verifies the signed manifest and re-hashes its own files
   (tamper → 503 `INTEGRITY_FAILED` / `SIGNATURE_INVALID`, event reported).
2. It confirms the request domain is the authorized one and the license is
   active (cached signed token, refreshed per `verify_ttl`; every protected
   file fetch is re-authorized live, so **revocation stops the site on the
   next request**).
3. Protected files are fetched from the licensing server over an
   authenticated channel, hash-verified, and executed from a 0600 temp file
   (deleted at shutdown). `__DIR__`/`__FILE__` in your code resolve to the
   package root as usual.

If the licensing server is briefly unreachable, a previously successful
authorization continues for `grace_seconds` (0 = none). Explicit denials
(revoked/suspended/domain) never get grace.

## Domain verification (done by the platform admin)

- The admin adds each domain to the license; the platform issues a DNS TXT
  record: `_sfg-verify.<domain>  TXT  "sfg-verify=<token>"`.
- After you publish the record, the admin clicks **Verify** — a real DNS
  lookup confirms it (if the platform's DNS is unreachable it offers manual
  approval, which is audited).
- Domains can be blocked individually; blocked domains always fail.
- Optional: allow subdomains per domain; `www`/non-`www` are normalized in
  both directions.

## Operational checklist

- [ ] `php -m | grep -E 'openssl|sodium'` → both present
- [ ] Document root = package directory; PHP entry points reach the stubs
- [ ] HTTPS configured (if the build requires it) — the guard 301-redirects
      and halts `HTTP_REQUIRED` otherwise
- [ ] Outbound connectivity to the license server (test: `curl -s
      https://license.host/api/v1/public/info`)
- [ ] Activation page reachable on the exact authorized domain
- [ ] Firewall/hosting allows the PHP process to reach the license server
      (streaming of protected files goes through it)
- [ ] Monitor: the platform's **Security events** page shows runtime
      reports (`integrity_failure`, `authorization_failed`, …) when
      something fights the guard

## Troubleshooting

| Symptom | Meaning / action |
|---|---|
| 503 `INTEGRITY_FAILED` | A file in the package was modified/missing (or disk corruption). Re-extract a fresh copy of the delivered ZIP; check `Security events` on the platform |
| 503 `SIGNATURE_INVALID` | Manifest or signature file altered. Same remedy; treat as a tamper incident |
| 503 `DOMAIN_NOT_AUTHORIZED` | Site is being served from a host name that is not on the license. Serve from the authorized domain (or have the admin add/verify it) |
| 503 `LICENSE_REVOKED` / `_SUSPENDED` / `_EXPIRED` | License state on the platform. Contact the party that issued it; re-activation with a fresh key after re-issuance |
| 503 `SERVER_UNAVAILABLE` | Can't reach the license server (DNS/firewall/cert). Fix connectivity; grace window applies if configured |
| 503 `ACTIVATION_FAILED` | Not activated yet — open `/guard/activate.php` and enter the key |
| 503 `HTTP_REQUIRED` | Build requires HTTPS; configure a TLS termination |
| 500 `BUILD_INVALID` (sodium) | PHP on this host lacks the sodium extension — install `php-sodium` |
| Activation 4xx with `REPLAY_REJECTED` | System clock on the host is skewed > tolerance — fix NTP |

## Uninstall

Delete the package directory and `guard/`. There is nothing else on the
host: no agents, no cron, no persistence — the guard is a request-time
bootstrap and the only state it keeps is `guard/cache/` (authz token +
counters) and `guard/license.key`, both inside the package directory.
