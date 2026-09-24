<?php
/**
 * Secure File Guard — protected runtime (v1)
 * ============================================================
 * This bootstrap is included at the top of the protected application's
 * entry point(s). It performs, in order:
 *
 *   1. Self-integrity check   — verifies the Ed25519 signature of the build
 *                               manifest, then hashes the runtime files it
 *                               lists. Any mismatch => INTEGRITY_FAILED.
 *   2. Domain / transport     — resolves the deployment domain server-side
 *                               (HTTP_HOST / SERVER_NAME, never client form
 *                               fields) and enforces HTTPS policy.
 *   3. Authorization check    — uses a locally cached signed authorization
 *                               token (re-verified with the embedded public
 *                               key); refreshes it from the licensing server
 *                               when stale. Revoked/expired/suspended
 *                               licenses and unauthorized domains fail here.
 *   4. Protected file gateway — protected components exist on disk only as
 *                               AES-256-GCM ciphertext. sfg_include() /
 *                               sfg_env() / sfg_fetch_file() fetch plaintext
 *                               from the licensing server over TLS and verify
 *                               it against the signed manifest hashes.
 *
 * Honest limitations: a party with root access to this host can always read
 * or delete these files. The goal is that unauthorized modification or
 * copying does not result in successful authorized execution.
 *
 * Compatibility: written for PHP 7.4+ (ProFreeHost and similar free hosts)
 * with polyfills for 8.x helpers. sodium (libsodium) is required at runtime.
 */
declare(strict_types=1);

// Double-include guard: index.php + activate.php / auto_prepend may both load this file.
if (defined('SFG_GUARD_BOOTSTRAPPED')) {
    return;
}
define('SFG_GUARD_BOOTSTRAPPED', 1);

if (!function_exists('array_is_list')) {
    function array_is_list(array $array): bool
    {
        if ($array === []) {
            return true;
        }
        return array_keys($array) === range(0, count($array) - 1);
    }
}
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool
    {
        return $needle === '' || strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}
if (!function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle): bool
    {
        if ($needle === '') {
            return true;
        }
        $len = strlen($needle);
        return substr($haystack, -$len) === $needle;
    }
}

final class SFG
{
    private const TOKEN_TOLERANCE = 120;      // seconds of clock skew
    private const HTTP_TIMEOUT = 8;           // seconds
    private const REPEAT_FAIL_LIMIT = 5;      // consecutive failures before reporting

    /** @var array<string,mixed> */
    private static array $cfg = [];
    /** @var array<string,mixed>|null */
    private static ?array $manifest = null;
    private static string $lastHost = '';
    private static ?array $authzPayload = null;
    private static int $failStreak = 0;
    private static ?string $failCode = null;

    public static function start(): void
    {
        self::$lastHost = self::host();
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            self::halt('BUILD_INVALID',
                'This protected runtime requires the PHP sodium extension (libsodium). Install php-sodium and retry.', 500);
        }
        self::selfIntegrityCheck();

        $uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
        // Accept activation under any install prefix (/, /subdir/, subdomain
        // root) and with or without .php / rewrite. Exact-only matching broke
        // subdirectory installs; absolute form actions caused host 404s.
        if (preg_match('#(?:^|/)guard/activate(?:\.php)?/?$#', $uri)
            || preg_match('#(?:^|/)guard/activate/index\.php$#', $uri)) {
            self::handleActivation();
            return;
        }

        if (!self::authorized()) {
            return; // authorized() halts with a professional error
        }
    }

    /** URL of the activation page under any install prefix (docroot or subdirectory). */
    private static function activateUrl(): string
    {
        $docRoot = rtrim(str_replace('\\', '/', (string) ($_SERVER['DOCUMENT_ROOT'] ?? '')), '/');
        $guardDir = str_replace('\\', '/', dirname(__FILE__));
        if ($docRoot !== '' && str_starts_with($guardDir, $docRoot)) {
            $prefix = substr($guardDir, strlen($docRoot));
            if (str_ends_with($prefix, '/guard')) {
                $prefix = substr($prefix, 0, -strlen('/guard'));
            }
            return $prefix . '/guard/activate.php';
        }
        $script = (string) ($_SERVER['SCRIPT_NAME'] ?? '/index.php');
        $dir = str_replace('\\', '/', dirname($script));
        if ($dir === '/' || $dir === '' || $dir === '.') {
            $dir = '';
        }
        return $dir . '/guard/activate.php';
    }

    // ------------------------------------------------------------------
    // Config / manifest
    // ------------------------------------------------------------------

    /** @return array<string,mixed> */
    private static function cfg(): array
    {
        if (self::$cfg === []) {
            $path = __DIR__ . '/config.json';
            if (!is_file($path)) {
                self::halt('BUILD_INVALID', 'Guard configuration is missing.', 500);
            }
            $cfg = json_decode((string) file_get_contents($path), true);
            if (!is_array($cfg)) {
                self::halt('BUILD_INVALID', 'Guard configuration is corrupted.', 500);
            }
            self::$cfg = $cfg;
        }
        return self::$cfg;
    }

    /** @return array<string,mixed> */
    private static function manifest(): array
    {
        if (self::$manifest === null) {
            $path = __DIR__ . '/manifest.json';
            if (!is_file($path)) {
                self::halt('BUILD_INVALID', 'Build manifest is missing.', 500);
            }
            $m = json_decode((string) file_get_contents($path), true);
            if (!is_array($m)) {
                self::halt('BUILD_INVALID', 'Build manifest is corrupted.', 500);
            }
            self::$manifest = $m;
        }
        return self::$manifest;
    }

    // ------------------------------------------------------------------
    // Environment
    // ------------------------------------------------------------------

    private static function host(): string
    {
        $h = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '';
        $h = strtolower((string) preg_replace('/:\d+$/', '', trim($h)));
        return $h;
    }

    private static function isHttps(): bool
    {
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            return true;
        }
        if (($_SERVER['SERVER_PORT'] ?? null) == 443) {
            return true;
        }
        if (($_SERVER['X_FORWARDED_PROTO'] ?? '') === 'https') {
            return true;
        }
        return false;
    }

    private static function licenseKey(): ?string
    {
        $path = __DIR__ . '/license.key';
        if (!is_file($path)) {
            return null;
        }
        $key = trim((string) file_get_contents($path));
        return $key !== '' ? $key : null;
    }

    // ------------------------------------------------------------------
    // Cryptography helpers
    // ------------------------------------------------------------------

    private static function b64d(string $s): string
    {
        $pad = strlen($s) % 4;
        if ($pad) {
            $s .= str_repeat('=', 4 - $pad);
        }
        return (string) base64_decode(strtr($s, '-_', '+/'), true);
    }

    private static function b64raw(string $s): string
    {
        return self::b64d($s);
    }

    /**
     * Ed25519 verification via libsodium (an established, audited primitive).
     * sig_b64 and pub_b64 accept standard base64 or base64url; msg is the
     * exact signed byte string. Returns false on any problem (never throws).
     */
    private static function edVerify(string $msg, string $sigB64, string $pubB64): bool
    {
        if ($pubB64 === '') {
            return false;
        }
        $sig = self::b64d($sigB64);
        $pub = self::b64d($pubB64);
        if ($sig === false || $pub === false || strlen($sig) !== 64 || strlen($pub) !== 32) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($sig, $msg, $pub);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Verify an authorization token signed by the licensing server. */
    private static function verifyToken(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }
        [$h, $p, $s] = $parts;
        $header = json_decode(self::b64d($h), true);
        if (!is_array($header)
            || ($header['alg'] ?? '') !== 'Ed25519'
            || ($header['typ'] ?? '') !== 'sfg-authz-v1'
        ) {
            return null;
        }
        $payload = json_decode(self::b64d($p), true);
        if (!is_array($payload)) {
            return null;
        }
        $ok = self::edVerify("{$h}.{$p}", $s, (string) (self::cfg()['public_key_raw'] ?? ''));
        return $ok ? $payload : null;
    }

    /**
     * Canonical JSON identical to the server's canonical_json():
     * recursive key sort, compact separators, unescaped slashes, ASCII.
     * (Manifest keys/values are guaranteed ASCII by the build pipeline.)
     */
    private static function canonicalJson($obj): string
    {
        return self::canonical($obj);
    }

    private static function canonical($obj): string
    {
        if (is_array($obj)) {
            if (array_is_list($obj)) {
                $items = [];
                foreach ($obj as $v) {
                    $items[] = self::canonical($v);
                }
                return '[' . implode(',', $items) . ']';
            }
            $keys = array_keys($obj);
            usort($keys, static fn ($a, $b): int => strcmp((string) $a, (string) $b));
            $items = [];
            foreach ($keys as $k) {
                $items[] = self::jsonString((string) $k) . ':' . self::canonical($obj[$k]);
            }
            return '{' . implode(',', $items) . '}';
        }
        if (is_bool($obj)) {
            return $obj ? 'true' : 'false';
        }
        if (is_int($obj)) {
            return (string) $obj;
        }
        if (is_float($obj)) {
            return json_encode($obj, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
        }
        if ($obj === null) {
            return 'null';
        }
        return self::jsonString((string) $obj);
    }

    private static function jsonString(string $s): string
    {
        // ASCII-only manifest data: json_encode with unescaped slashes matches
        // Python json.dumps(separators=(",",":"), ensure_ascii=True) exactly.
        return (string) json_encode($s, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    private static function sha256File(string $path): ?string
    {
        $h = hash_file('sha256', $path);
        return $h === false ? null : $h;
    }

    // ------------------------------------------------------------------
    // 1. Self-integrity
    // ------------------------------------------------------------------

    private static function selfIntegrityCheck(): void
    {
        $m = self::manifest();
        $sigPath = __DIR__ . '/manifest.sig';
        if (!is_file($sigPath)) {
            self::halt('INTEGRITY_FAILED', 'Build manifest signature is missing.', 503);
        }
        $sig = trim((string) file_get_contents($sigPath));
        $canonical = self::canonicalJson($m);
        if (!self::edVerify($canonical, $sig, (string) (self::cfg()['public_key_raw'] ?? ''))) {
            self::report('invalid_signature', 'manifest signature verification failed');
            self::halt('SIGNATURE_INVALID',
                'The build manifest failed cryptographic signature verification.', 503);
        }

        $root = dirname(__DIR__);
        foreach ((array) ($m['runtime'] ?? []) as $rel => $expected) {
            $hash = self::sha256File($root . '/' . $rel);
            if ($hash === null || !hash_equals((string) $expected, $hash)) {
                self::report('integrity_failure', "runtime file mismatch: {$rel}");
                self::halt('INTEGRITY_FAILED',
                    'A protected runtime file was modified or is missing.', 503);
            }
        }
    }

    // ------------------------------------------------------------------
    // 2/3. Authorization
    // ------------------------------------------------------------------

    private static function authorized(): bool
    {
        $cfg = self::cfg();
        $host = self::$lastHost;

        if (($cfg['require_https'] ?? false) === true && !self::isHttps()) {
            if (PHP_SAPI !== 'cli') {
                $scheme = 'https';
                $port = self::port();
                $target = $scheme . '://' . $_SERVER['HTTP_HOST']
                    . (in_array($port, [443, '443'], true) ? '' : ':' . $port)
                    . ($_SERVER['REQUEST_URI'] ?? '/');
                header('Location: ' . $target, true, 301);
            }
            self::halt('HTTP_REQUIRED', 'This deployment must be served over HTTPS.', 503);
        }

        if ($host === '') {
            self::halt('ACTIVATION_FAILED', 'Could not determine the deployment domain.', 503);
        }

        // Local cache of a previously issued signed token.
        $cache = self::readCache();
        if ($cache !== null) {
            $payload = self::verifyToken($cache['token']);
            $now = time();
            if ($payload !== null
                && (int) ($payload['exp'] ?? 0) > $now + 30
                && (int) ($payload['iat'] ?? 0) <= $now + self::TOKEN_TOLERANCE
                && ($now - (int) $cache['ts']) < (int) ($cfg['verify_ttl'] ?? 300)
                && self::domainMatches($payload['dom'] ?? '', $host)
            ) {
                self::$authzPayload = $payload;
                self::noteSuccess();
                return true;
            }
        }

        $key = self::licenseKey();
        if ($key === null) {
            header('Location: ' . self::activateUrl(), true, 302);
            exit;
        }
        // license_server missing/empty → fail with a clear message (never
        // silently 404 on the customer host when POSTing to the wrong base).
        if (trim((string) (self::cfg()['license_server'] ?? '')) === '') {
            self::halt('BUILD_INVALID',
                'License server URL is not set in this build. Set Settings → License server URL, rebuild, and redeploy.', 503);
        }

        // Fresh verification against the licensing server.
        $resp = self::verifyRequest($key, $host);
        if ($resp['ok']) {
            $token = (string) $resp['token'];
            $payload = self::verifyToken($token); // defense in depth
            if ($payload === null
                || (int) ($payload['exp'] ?? 0) <= time()
                || !self::domainMatches($payload['dom'] ?? '', $host)
            ) {
                self::report('invalid_signature', 'issued token failed local re-verification');
                self::halt('SIGNATURE_INVALID', 'Authorization token failed verification.', 503);
            }
            self::writeCache($token);
            self::$authzPayload = $payload;
            self::noteSuccess();
            return true;
        }

        $code = (string) ($resp['code'] ?? 'SERVER_UNAVAILABLE');
        $srvMsg = trim((string) ($resp['message'] ?? ''));

        // Grace period: a previously successful authorization may continue for
        // a bounded window ONLY while the licensing server is unreachable.
        // Explicit denials (revoked, expired, suspended, unauthorized domain,
        // invalid signature) always fail immediately — a grace period must
        // never soften a deliberate license decision.
        if ($code === 'SERVER_UNAVAILABLE') {
            $grace = (int) ($cfg['grace_seconds'] ?? 0);
            if ($grace > 0 && $cache !== null && (time() - (int) $cache['last_success']) < $grace) {
                error_log('SFG: licensing server unreachable; continuing within grace period');
                return true;
            }
        }

        self::noteFailure($code);
        self::halt($code, $srvMsg !== '' ? $srvMsg : self::messageFor($code), 503);
        return false;
    }

    private static function domainMatches(string $tokenDom, string $host): bool
    {
        if ($tokenDom === $host) {
            return true;
        }
        $strip = static fn (string $d): string => preg_replace('/^www\./', '', $d) ?? $d;
        return $strip($tokenDom) === $strip($host);
    }

    private static function port(): int
    {
        return (int) ($_SERVER['SERVER_PORT'] ?? 80);
    }

    private static function verifyRequest(string $key, string $host): array
    {
        $cfg = self::cfg();
        $server = rtrim((string) ($cfg['license_server'] ?? ''), '/');
        if ($server === '') {
            return [
                'ok' => false,
                'code' => 'BUILD_INVALID',
                'message' => 'License server URL is not set in this build. '
                    . 'On the licensing server: Settings → License server URL → save → rebuild → redeploy this package.',
            ];
        }
        $body = [
            'license' => $key,
            'domain' => $host,
            'project' => (string) ($cfg['project'] ?? ''),
            'build' => (string) ($cfg['build'] ?? ''),
            'version' => (string) ($cfg['version'] ?? ''),
            'ts' => time(),
            'nonce' => bin2hex(random_bytes(8)),
        ];
        $url = $server . '/api/v1/public/licenses/verify';
        $resp = self::http('POST', $url, $body, []);
        if ($resp['status'] === 200 && is_array($resp['json'])) {
            $token = (string) ($resp['json']['token'] ?? '');
            if ($token !== '' && !empty($resp['json']['ok'])) {
                return ['ok' => true, 'token' => $token];
            }
        }
        // Structured JSON error from the licensing API (LICENSE_INVALID → 404, etc.)
        if (is_array($resp['json']) && is_array($resp['json']['error'] ?? null)) {
            $err = (array) $resp['json']['error'];
            return [
                'ok' => false,
                'code' => (string) ($err['code'] ?? 'SERVER_UNAVAILABLE'),
                'message' => (string) ($err['message'] ?? 'Verification failed.'),
            ];
        }
        // status 0: timeout / DNS / TLS failure — network problem, not a license decision
        if ($resp['status'] === 0) {
            return [
                'ok' => false,
                'code' => 'SERVER_UNAVAILABLE',
                'message' => 'Could not reach the licensing server (timeout or network error).',
            ];
        }
        // HTML or non-JSON body: reverse-proxy 404, wrong path, SPA catch-all, etc.
        // Never treat this as a license denial — it is a server reachability problem.
        if ($resp['status'] === 404 || $resp['status'] === 405 || $resp['status'] >= 500) {
            return [
                'ok' => false,
                'code' => 'SERVER_UNAVAILABLE',
                'message' => 'Licensing endpoint returned HTTP ' . $resp['status']
                    . ' (check license_server URL points at the FastAPI host, not a PHP path).',
            ];
        }
        return [
            'ok' => false,
            'code' => 'SERVER_UNAVAILABLE',
            'message' => 'Verification failed (HTTP ' . $resp['status'] . ').',
        ];
    }

    private static function readCache(): ?array
    {
        $path = __DIR__ . '/cache/authz.json';
        if (!is_file($path)) {
            return null;
        }
        $c = json_decode((string) @file_get_contents($path), true);
        return is_array($c) && isset($c['token']) ? $c : null;
    }

    private static function writeCache(string $token): void
    {
        $dir = __DIR__ . '/cache';
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        $data = ['token' => $token, 'ts' => time(), 'last_success' => time(), 'domain' => self::$lastHost];
        @file_put_contents($dir . '/authz.json', json_encode($data), LOCK_EX);
        @chmod($dir . '/authz.json', 0600);
    }

    private static function noteSuccess(): void
    {
        self::$failStreak = 0;
        $dir = __DIR__ . '/cache';
        $path = $dir . '/state.json';
        if (is_file($path)) {
            $s = json_decode((string) @file_get_contents($path), true);
            if (is_array($s)) {
                $s['fail_streak'] = 0;
                @file_put_contents($path, json_encode($s), LOCK_EX);
            }
        }
    }

    private static function noteFailure(string $code): void
    {
        $dir = __DIR__ . '/cache';
        $path = $dir . '/state.json';
        $s = is_file($path) ? (array) (json_decode((string) @file_get_contents($path), true) ?: []) : [];
        $s['fail_streak'] = (int) ($s['fail_streak'] ?? 0) + 1;
        $s['last_code'] = $code;
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        @file_put_contents($path, json_encode($s), LOCK_EX);
        @chmod($path, 0600);
        if ((int) $s['fail_streak'] === self::REPEAT_FAIL_LIMIT) {
            self::report('repeated_verification_failures', "consecutive verification failures: {$code}");
        }
    }

    // ------------------------------------------------------------------
    // HTTP (stream contexts — no cURL dependency)
    // ------------------------------------------------------------------

    /** @return array{status:int, json:mixed} */
    private static function http(string $method, string $url, ?array $body, array $headers): array
    {
        $headerLines = ["Accept: application/json"];
        foreach ($headers as $k => $v) {
            $headerLines[] = "$k: $v";
        }
        $opts = [
            'http' => [
                'method' => $method,
                'timeout' => self::HTTP_TIMEOUT,
                'ignore_errors' => true,
                'header' => implode("\r\n", $headerLines),
                'content' => $body === null ? '' : (string) json_encode($body),
            ],
        ];
        if ($body !== null) {
            $opts['http']['header'] .= "\r\nContent-Type: application/json";
        }
        $raw = @file_get_contents($url, false, stream_context_create($opts));
        $status = 0;
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $status = (int) $m[1];
            }
        }
        $json = null;
        if ($raw !== false && $raw !== '') {
            $json = json_decode($raw, true);
        }
        return ['status' => $status, 'json' => $json];
    }

    /** Truncate a detail string; uses mbstring when present, safe fallback otherwise. */
    private static function truncDetail(string $detail, int $max): string
    {
        if (function_exists('mb_substr')) {
            return mb_substr($detail, 0, $max);
        }
        return substr($detail, 0, $max);
    }

    private static function report(string $type, string $detail): void
    {
        try {
            $server = rtrim((string) (self::cfg()['license_server'] ?? ''), '/');
            if ($server === '') {
                return;
            }
            self::http('POST', $server . '/api/v1/public/events', [
                'type' => $type,
                'project' => (string) (self::cfg()['project'] ?? ''),
                'build' => (string) (self::cfg()['build'] ?? ''),
                'domain' => self::$lastHost,
                'detail' => self::truncDetail($detail, 300),
            ], []);
        } catch (\Throwable $e) {
            // best effort only
        }
    }

    // ------------------------------------------------------------------
    // Activation
    // ------------------------------------------------------------------

    private static function handleActivation(): void
    {
        $cfg = self::cfg();
        $error = '';
        $status = 200;

        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            $key = trim((string) ($_POST['license_key'] ?? ''));
            if (!preg_match('/^SFG-[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$/i', $key)) {
                $error = 'ACTIVATION_FAILED: The license key format is not valid.';
            } else {
                $keyPath = __DIR__ . '/license.key';
                $resp = self::verifyRequest($key, self::$lastHost);
                if ($resp['ok']) {
                    $token = (string) $resp['token'];
                    $payload = self::verifyToken($token);
                    if ($payload === null || !self::domainMatches($payload['dom'] ?? '', self::$lastHost)) {
                        $error = 'SIGNATURE_INVALID: Authorization token failed verification.';
                    } else {
                        @file_put_contents($keyPath, $key, LOCK_EX);
                        @chmod($keyPath, 0600);
                        self::writeCache($token);
                        // Relative continue (never Location: /) — ProFreeHost and
                        // subdirectory installs 404 a missing domain-root index.
                        http_response_code(200);
                        header('Content-Type: text/html; charset=utf-8');
                        $okMsg = htmlspecialchars(
                            'License activated for ' . self::$lastHost . '. Opening the application…',
                            ENT_QUOTES);
                        echo <<<HTML
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="1;url=../">
<title>Secure File Guard — Activated</title>
<style>
 body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
   background: radial-gradient(1200px 600px at 70% -10%, #16233d 0%, #0b0f17 55%);
   font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
   color:#e6edf7; padding:24px; }
 .card { width:100%; max-width:460px; background:#101827; border:1px solid rgba(52,211,153,.25);
   border-radius:14px; padding:34px 32px; text-align:center; }
 h1 { font-size:20px; margin:0 0 8px; font-weight:650; }
 p { color:#93a1b8; font-size:13.5px; line-height:1.6; margin:0 0 18px; }
 a { color:#38bdf8; font-weight:600; }
</style></head>
<body><div class="card">
 <h1>License activated</h1>
 <p>{$okMsg}</p>
 <p><a href="../">Continue to the application</a></p>
</div></body></html>
HTML;
                        exit;
                    }
                } else {
                    // Prefer the licensing server's real message (e.g. missing
                    // build, empty license_server URL) over the generic
                    // messageFor() string that used to hide the cause.
                    $srvMsg = trim((string) ($resp['message'] ?? ''));
                    $code = (string) ($resp['code'] ?? 'ACTIVATION_FAILED');
                    $error = $code . ': ' . ($srvMsg !== '' ? $srvMsg : self::messageFor($code));
                }
                // A failed attempt never leaves a key stored (docs contract).
            }
        }

        $keyExists = self::licenseKey() !== null;
        http_response_code($status);
        header('Content-Type: text/html; charset=utf-8');
        echo self::activationPage($error, $keyExists, $cfg);
        exit;
    }

    private static function activationPage(string $error, bool $keyExists, array $cfg): string
    {
        $e = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES);
        $errHtml = $error !== ''
            ? '<div class="err">' . $e($error) . '</div>'
            : '';
        $tpl = file_get_contents(__DIR__ . '/activate.html.tpl');
        if ($tpl === false) {
            $tpl = '<h1>Activation page template missing (BUILD_INVALID)</h1>';
        }
        return strtr($tpl, [
            '__ERROR__' => $errHtml,
            '__PROJECT__' => $e((string) ($cfg['project'] ?? '')),
            '__BUILD__' => $e((string) ($cfg['build'] ?? '')),
            '__VERSION__' => $e((string) ($cfg['version'] ?? '')),
            '__DOMAIN__' => $e(self::$lastHost ?: 'unknown'),
            '__KEY_EXISTS__' => $keyExists ? '1' : '0',
        ]);
    }

    // ------------------------------------------------------------------
    // Protected file gateway
    // ------------------------------------------------------------------

    public static function includeProtected(string $relpath): void
    {
        $plain = self::fetchComponent($relpath);
        // The real file is executed from a temporary location, so path magic
        // constants would resolve to /tmp instead of the project root.
        // Rewrite __DIR__ / __FILE__ (outside strings and comments) to the
        // component's real project-relative location before execution.
        $root = str_replace('\\', '/', dirname(__DIR__));
        $virtual = $root . '/' . str_replace('\\', '/', $relpath);
        $plain = self::rewritePathTokens($plain, $root, $virtual);
        $tmp = tempnam(sys_get_temp_dir(), 'sfg_');
        if ($tmp === false) {
            self::halt('SERVER_UNAVAILABLE', 'Could not prepare a temporary file.', 500);
        }
        file_put_contents($tmp, $plain, LOCK_EX);
        @chmod($tmp, 0600);
        register_shutdown_function(static fn () => @unlink($tmp));
        include $tmp;
    }

    /**
     * Replace __DIR__ and __FILE__ tokens with the project-root path and the
     * component's virtual path, respecting string literals and comments so
     * user strings that merely contain the token text are left untouched.
     */
    private static function rewritePathTokens(string $code, string $root, string $file): string
    {
        $litRoot = "'" . str_replace(['\\', "'"], ['\\\\', "\\'"], $root) . "'";
        $litFile = "'" . str_replace(['\\', "'"], ['\\\\', "\\'"], $file) . "'";
        $out = '';
        $i = 0;
        $n = strlen($code);
        $inS = null;      // active quote char
        $inLine = false;  // // comment
        $inBlock = false; // /* comment */
        $tokens = ['__DIR__' => $litRoot, '__FILE__' => $litFile];
        while ($i < $n) {
            $ch = $code[$i];
            if ($inLine) {
                $out .= $ch;
                if ($ch === "\n") {
                    $inLine = false;
                }
                $i++;
                continue;
            }
            if ($inBlock) {
                if ($ch === '*' && $i + 1 < $n && $code[$i + 1] === '/') {
                    $out .= '*/';
                    $i += 2;
                    $inBlock = false;
                    continue;
                }
                $out .= $ch;
                $i++;
                continue;
            }
            if ($inS !== null) {
                $out .= $ch;
                if ($ch === '\\' && $i + 1 < $n) {
                    $out .= $code[$i + 1];
                    $i += 2;
                    continue;
                }
                if ($ch === $inS) {
                    $inS = null;
                }
                $i++;
                continue;
            }
            if ($ch === "'" || $ch === '"') {
                $inS = $ch;
                $out .= $ch;
                $i++;
                continue;
            }
            if ($ch === '/' && $i + 1 < $n && $code[$i + 1] === '/') {
                $inLine = true;
                $out .= '//';
                $i += 2;
                continue;
            }
            if ($ch === '/' && $i + 1 < $n && $code[$i + 1] === '*') {
                $inBlock = true;
                $out .= '/*';
                $i += 2;
                continue;
            }
            $prev = $i > 0 ? $code[$i - 1] : '';
            $matched = false;
            foreach ($tokens as $tok => $lit) {
                if (substr($code, $i, strlen($tok)) === $tok) {
                    $nextPos = $i + strlen($tok);
                    $next = $nextPos < $n ? $code[$nextPos] : '';
                    if (!preg_match('/[A-Za-z0-9_$]/', (string) $prev) && !preg_match('/[A-Za-z0-9_]/', (string) $next)) {
                        $out .= $lit;
                        $i = $nextPos;
                        $matched = true;
                        break;
                    }
                }
            }
            if ($matched) {
                continue;
            }
            $out .= $ch;
            $i++;
        }
        return $out;
    }

    public static function envFile(): string
    {
        $plain = self::fetchComponent('.env');
        $tmp = tempnam(sys_get_temp_dir(), 'sfgenv_');
        file_put_contents($tmp, $plain, LOCK_EX);
        @chmod($tmp, 0600);
        register_shutdown_function(static fn () => @unlink($tmp));
        return $tmp;
    }

    public static function env(string $name, ?string $default = null): ?string
    {
        static $parsed = null;
        if ($parsed === null) {
            $parsed = self::parseEnvFile(file_get_contents(self::envFile()) ?: '');
        }
        return $parsed[$name] ?? $default;
    }

    public static function fetchFile(string $relpath): string
    {
        return self::fetchComponent($relpath);
    }

    public static function fetchFileToPath(string $relpath): string
    {
        $tmp = tempnam(sys_get_temp_dir(), 'sfgf_');
        file_put_contents($tmp, self::fetchComponent($relpath), LOCK_EX);
        @chmod($tmp, 0600);
        register_shutdown_function(static fn () => @unlink($tmp));
        return $tmp;
    }

    /** @return array<string,string> */
    private static function parseEnvFile(string $text): array
    {
        $out = [];
        foreach (preg_split('/\r?\n/', $text) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (preg_match('/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/', $line, $m)) {
                $v = $m[2];
                if ((strlen($v) >= 2)
                    && (($v[0] === '"' && substr($v, -1) === '"') || ($v[0] === "'" && substr($v, -1) === "'"))
                ) {
                    $v = substr($v, 1, -1);
                }
                $out[$m[1]] = $v;
            }
        }
        return $out;
    }

    private static function componentKey(string $relpath): string
    {
        return rawurlencode(str_replace('\\', '/', $relpath));
    }

    private static function fetchComponent(string $relpath): string
    {
        $cfg = self::cfg();
        $m = self::manifest();
        $key = self::componentKey($relpath);
        $entry = (array) ($m['components'][$key] ?? []);
        if ($entry === []) {
            self::report('integrity_failure', "component not in manifest: {$relpath}");
            self::halt('INTEGRITY_FAILED', 'Requested component is not part of this build.', 503);
        }
        $blobPath = dirname(__DIR__) . '/components/' . $key . '.enc';
        $expectedCt = (string) ($entry['ct_sha256'] ?? '');
        $blobHash = self::sha256File($blobPath);
        if ($blobHash === null || !hash_equals($expectedCt, $blobHash)) {
            self::report('integrity_failure', "component blob mismatch: {$relpath}");
            self::halt('INTEGRITY_FAILED', 'A protected component was modified or is missing.', 503);
        }

        $token = (string) (self::readCache()['token'] ?? '');
        if ($token === '' || self::verifyToken($token) === null) {
            self::halt('ACTIVATION_FAILED', 'Authorization state is invalid.', 503);
        }
        $server = rtrim((string) $cfg['license_server'], '/');
        // Send the RAW project-relative path; the server applies the single
        // canonical URL-encoding to resolve both the on-disk blob and the
        // manifest entry. (Pre-encoding here would be double-encoded on the wire.)
        $url = $server . '/api/v1/public/runtime/file?'
            . http_build_query(['project' => $cfg['project'] ?? '', 'build' => $cfg['build'] ?? '', 'component' => $relpath]);
        $resp = self::http('GET', $url, null, ['Authorization' => 'Bearer ' . $token]);
        if ($resp['status'] !== 200 || !is_array($resp['json'])) {
            $code = is_array($resp['json'])
                ? (string) (($resp['json']['error'] ?? [])['code'] ?? 'SERVER_UNAVAILABLE')
                : 'SERVER_UNAVAILABLE';
            self::halt($code, self::messageFor($code), 503);
        }
        $data = base64_decode((string) ($resp['json']['data'] ?? ''), true);
        if ($data === false) {
            self::halt('SERVER_UNAVAILABLE', 'Received an unreadable component payload.', 503);
        }
        $expectedPlain = (string) ($entry['plain_sha256'] ?? '');
        if ($expectedPlain !== '' && !hash_equals($expectedPlain, hash('sha256', $data))) {
            self::report('integrity_failure', "delivered plaintext hash mismatch: {$relpath}");
            self::halt('INTEGRITY_FAILED', 'Delivered component failed integrity verification.', 503);
        }
        return $data;
    }

    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------

    private static function messageFor(string $code): string
    {
        $map = array(
            'LICENSE_INVALID' => 'The license key is not valid.',
            'LICENSE_EXPIRED' => 'This license has expired.',
            'LICENSE_REVOKED' => 'This license has been revoked.',
            'LICENSE_SUSPENDED' => 'This license is suspended.',
            'DOMAIN_NOT_AUTHORIZED' => 'Domain not authorized for this license.',
            'SIGNATURE_INVALID' => 'Cryptographic signature verification failed.',
            'INTEGRITY_FAILED' => 'Build integrity verification failed.',
            'BUILD_INVALID' => 'This build is invalid or was not found on the license server. '
                . 'Set Settings → License server URL, rebuild the project, and deploy the new package.',
            'VERSION_NOT_ALLOWED' => 'This build version is not allowed by the license.',
            'PROJECT_MISMATCH' => 'License does not match this project.',
            'ACTIVATION_FAILED' => 'Activation failed.',
            'SERVER_UNAVAILABLE' => 'The licensing server is unavailable. If the grace period has elapsed, the protected application cannot start.',
            'HTTP_REQUIRED' => 'HTTPS is required for this deployment.',
        );
        return isset($map[$code]) ? $map[$code] : 'Authorization failed.';
    }

    private static function halt(string $code, string $message, int $httpStatus): void
    {
        self::reportOnce($code);
        if (PHP_SAPI === 'cli') {
            fwrite(STDERR, "SFG: {$code} — {$message}\n");
            exit(75);
        }
        http_response_code($httpStatus);
        header('Content-Type: text/html; charset=utf-8');
        $safeCode = htmlspecialchars($code, ENT_QUOTES);
        $safeMsg = htmlspecialchars($message, ENT_QUOTES);
        $safeDomain = htmlspecialchars(self::$lastHost ?: 'unknown', ENT_QUOTES);
        echo <<<HTML
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure File Guard — {$safeCode}</title>
<style>
 body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
   background: radial-gradient(1200px 600px at 70% -10%, #16233d 0%, #0b0f17 55%);
   font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
   color:#e6edf7; padding:24px; }
 .card { width:100%; max-width:480px; background:#101827; border:1px solid rgba(248,113,113,.22);
   border-radius:14px; padding:34px 32px; box-shadow:0 24px 80px rgba(0,0,0,.5); text-align:center; }
 .code { font-family:ui-monospace,Menlo,monospace; font-size:12.5px; letter-spacing:.12em;
   color:#fca5a5; background:rgba(248,113,113,.08); border:1px solid rgba(248,113,113,.3);
   padding:6px 12px; border-radius:999px; display:inline-block; }
 h1 { font-size:19px; margin:18px 0 8px; font-weight:650; }
 p { color:#93a1b8; font-size:13.5px; line-height:1.6; margin:0; }
 .meta { margin-top:22px; padding-top:16px; border-top:1px solid rgba(255,255,255,.07);
   font-size:11.5px; color:#64748b; font-family:ui-monospace,Menlo,monospace; }
</style></head>
<body>
 <div class="card">
  <span class="code">{$safeCode}</span>
  <h1>Application authorization blocked</h1>
  <p>{$safeMsg}</p>
  <p>Contact the platform owner or the party that issued this license.</p>
  <div class="meta">domain: {$safeDomain}<br>no internal details are disclosed by design</div>
 </div>
</body></html>
HTML;
        exit;
    }

    private static function reportOnce(string $code): void
    {
        static $reported = false;
        if ($reported || in_array($code, ['HTTP_REQUIRED'], true)) {
            return;
        }
        $reported = true;
        self::report('authorization_failed', "code={$code}");
    }
}

function sfg_include(string $path): void
{
    SFG::includeProtected($path);
}

/** Path to a temporary copy of the protected .env (for Dotenv-style loaders). */
function sfg_env_file(): string
{
    return SFG::envFile();
}

/** Read one protected environment variable. */
function sfg_env(string $name, ?string $default = null): ?string
{
    return SFG::env($name, $default);
}

/** Fetch plaintext of any protected component. */
function sfg_fetch_file(string $path): string
{
    return SFG::fetchFile($path);
}

/** Fetch a protected component into a temporary file path. */
function sfg_fetch_file_path(string $path): string
{
    return SFG::fetchFileToPath($path);
}

SFG::start();
