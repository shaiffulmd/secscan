# SecScan

SecScan is a PHP-based web security scanner with a public scan UI, JSON API, SQLite-backed scan logging, and a password-protected usage dashboard.

## Requirements

- PHP 8.1+
- PHP extensions: `curl`, `openssl`, `pdo`, `pdo_sqlite`
- Optional: `dig` for deeper DNSSEC/CAA checks

## Versioning

Update the root `VERSION` file for every release. The value is displayed in the
scanner footer and dashboard; `SECSCAN_APP_VERSION` may override it per deployment.

## Local Run

```sh
php -S 127.0.0.1:8080
```

Then open `http://127.0.0.1:8080/index.php`.

## Production Setup

Set these environment variables before deployment:

- `SECSCAN_DASHBOARD_PASSWORD_HASH`
- `SECSCAN_IP_HASH_SALT`
- `SECSCAN_DATA_DIR`
- `SECSCAN_DB_PATH`

Request JSON dihadkan melalui `SECSCAN_MAX_REQUEST_BYTES` (lalai 64 KiB). UI
dan `api.php` berkongsi kuota scan yang sama (`SECSCAN_SCAN_RATE_LIMIT` /
`SECSCAN_SCAN_RATE_WINDOW`), jadi kuota tidak boleh dipintas dengan menukar endpoint.
Body target yang tidak dipercayai turut dibuffer secara terhad melalui
`SECSCAN_TARGET_MAX_RESPONSE_BYTES` (lalai 2 MiB) dan
`SECSCAN_PROBE_MAX_RESPONSE_BYTES` (lalai 256 KiB) untuk mengelakkan penggunaan
memori tanpa had semasa scan.

## GeoIP country map

The dashboard can download the monthly DB-IP Lite country CSV from its GeoIP
panel, then backfill existing scan records and classify new scan IPs locally.
Country-level data is shown only to dashboard administrators. DB-IP Lite is
published under CC BY 4.0, so the dashboard includes the required attribution.
Set `SECSCAN_GEOIP_UPDATE_URL` only when you need an approved HTTPS mirror.

### Running behind a proxy or CDN

Forwarded client-IP headers (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`)
are spoofable, so SecScan ignores them by default and rate-limits on the direct
connection IP (`REMOTE_ADDR`). If you run behind a reverse proxy, load balancer,
or CDN, you **must** tell SecScan which proxies to trust or per-IP rate limiting
and the dashboard's unique-IP counts will be wrong:

- `SECSCAN_TRUSTED_PROXIES` — comma-separated proxy IPs / CIDR ranges (v4 or v6).
- `SECSCAN_TRUST_CLOUDFLARE=1` — trust Cloudflare's published edge ranges.

Without one of these set, all traffic behind a proxy appears to come from the
proxy's IP and shares a single rate-limit bucket.

### Scanner allowlist identity

Set these so users can allowlist the SecScan server in their WAF/firewall before
starting a scan. The allowlist panel appears only when at least one of these
values is configured:

- `SECSCAN_SCANNER_PUBLIC_DOMAIN` — public scanner hostname shown in the UI.
- `SECSCAN_SCANNER_PUBLIC_IPS` — outbound/NAT IPs used by the scanner server,
  comma-separated.

Generate a dashboard password hash with:

```sh
php -r "echo password_hash('YourNewPassword', PASSWORD_BCRYPT), PHP_EOL;"
```

Store `SECSCAN_DATA_DIR` outside the public web root when possible. Apache deny rules are included as a fallback, but web-server config is safer than relying only on `.htaccess`.

### Contact Us

`about.php` includes a Contact Us form. Set `SECSCAN_CONTACT_ENCRYPTION_KEY` to a
base64-encoded 32-byte value before enabling it; messages are stored with
AES-256-GCM encryption and are readable only from the authenticated dashboard.
Optionally set both `SECSCAN_CONTACT_MAIL_TO` and `SECSCAN_CONTACT_MAIL_FROM` to
send a minimal PHP `mail()` notification after a message is saved. The message
content remains in the dashboard rather than being included in the e-mail.

## Worker VPS (optional)

SecScan can keep the UI and audit database on security.apasaja.my while a VPS
executes outbound scans. Deploy the same project code to the VPS, expose only
worker.php over HTTPS, and configure the same SECSCAN_WORKER_SHARED_SECRET on
both servers. On the web application, set:

    SECSCAN_SCANNER_MODE=remote
    SECSCAN_WORKER_URL=https://scanner-vps.example/worker.php
    SECSCAN_WORKER_SHARED_SECRET=<random secret, at least 32 characters>

On the VPS, keep SECSCAN_SCANNER_MODE=local, set the same shared secret, and
optionally set SECSCAN_WORKER_ALLOWED_CALLERS to the public IP/CIDR of the web
application. The worker accepts only signed POST jobs with a five-minute
timestamp and one-time nonce; it never accepts browser requests directly.
Keep the worker behind a firewall/VPN where possible and do not enable
authenticated scans unless both servers are access-controlled.

## Auto-deploy

Pushing to `main` runs the tests and then updates the VPS through GitHub Actions.
See [docs/auto-deploy.md](docs/auto-deploy.md) for the one-time setup.

## Safety Notes

SecScan performs outbound HTTP, TLS, DNS, and limited port checks. Keep rate limits enabled, avoid exposing the API without access controls on high-traffic deployments, and only scan systems you are allowed to assess.

## Detection coverage

In addition to headers, TLS/SSL, DNS/email-auth, CMS/CVE, exposed files, WAF and
port checks, SecScan now flags:

- **Exposed secrets** — leaked AWS/Google/Stripe/GitHub/Slack/SendGrid/Twilio keys,
  private-key blocks and JWTs in the page source (samples are redacted in the report).
- **CSRF token coverage** — POST forms with no anti-CSRF token field or page-level
  CSRF `<meta>` tag.
- **GraphQL introspection** — probes common GraphQL paths and flags when schema
  introspection is left enabled in production.
- **Email-auth hardening depth** — beyond SPF/DMARC presence: SPF DNS-lookup-limit
  and deprecated-`ptr` warnings, duplicate-SPF permerrors, DMARC enforcement
  coverage (`pct`/`sp`/`rua`), and SMTP TLS reporting (TLS-RPT).
- **Detailed production errors** — detects PHP, database, Python, ASP.NET, and
  Java stack/error disclosures without copying internal paths into the report.
- **Cookie prefix and partitioning rules** — validates exact `Secure`, `HttpOnly`,
  `SameSite`, `__Host-`, `__Secure-`, and `Partitioned` requirements while avoiding
  false positives on non-session cookies that legitimately need JavaScript access.
- **Deployment artefacts** — validates exposed VCS metadata, environment/config
  backups, package lockfiles, registry credentials, Kubernetes config, and
  ASP.NET connection settings using positive content signatures and soft-404 baselines.

- **Version-matched advisories** — WordPress (wp2shell, CVE-2026-87902, 7.1.4),
  Joomla (September 2026 release) and Drupal (SA-CORE-2026-004, -005, -014) core
  ranges, PHP2Shell (CVE-2026-109618/109619) and current nginx/Apache fixes. A
  short version such as the Drupal generator's `11` cannot prove a patch level,
  so it is reported as unconfirmed rather than vulnerable. Distro-tagged banners
  are downgraded because packages may carry backported fixes.
- **CISA KEV awareness** — NVD CVEs are read newest-first and tagged when listed
  in KEV. Recently exploited products (Ivanti, NetScaler, Cisco ASA, PAN-OS,
  GitLab, Atlassian, ScreenConnect, Magento) are fingerprinted passively from the
  landing page as non-scoring prompts, because the version is usually not visible.

The advisory tables live in `scanner.php` (`CMS_CORE_ADVISORIES`,
`KEV_PRODUCT_SIGNATURES`) and need periodic review; each notes its last review date.

Accuracy/scoring improvements: CSP no longer flags `'unsafe-inline'` when a
nonce/hash or `'strict-dynamic'` neutralises it, and advisory `info` findings are
weighted so they no longer unfairly cap an otherwise well-configured site's grade.

### Extended non-destructive detection

A further set of checks sends a small number of crafted but **harmless** requests
(unique markers, quote characters, traversal paths) to catch issues that passive
fingerprinting cannot see. They never exploit a finding, write data, upload
files, or brute-force credentials, and they run in parallel batches under a
per-scan request budget:

- **Active Probes** — open redirect, CRLF/response-header injection, Host-header
  injection, unescaped input reflection (XSS markers), error-based SQL injection
  and path traversal.
- **Sensitive data** — JavaScript source-map exposure, public cloud-storage
  bucket listing (S3/GCS/Azure/R2) and an expanded leaked-secret pattern set
  (OpenAI, Anthropic, Discord, Telegram, DigitalOcean, Datadog, New Relic,
  Shopify, Square, Mailchimp, Azure Storage, Sentry).
- **Deeper CMS coverage** — Drupal/Magento/Ghost/TYPO3 version endpoints plus
  WordPress theme versions, feeding the CVE matcher.
- **API security** — public OpenAPI/Swagger schema exposure and structural JWT
  weaknesses (`alg=none`, missing `exp`, `jku`/`jwk`).
- **DNS/email depth** — MTA-STS policy fetch and validation (mode/mx/max_age).
- **Infra/misconfiguration** — HTTP/2 cleartext (h2c), legacy
  `X-Permitted-Cross-Domain-Policies`, request-smuggling framing indicators and
  framework debug/profiler exposure.

Toggle the whole extended set with `SECSCAN_ALLOW_ACTIVE_PROBES` (default `1`)
and cap its request volume with `SECSCAN_ACTIVE_PROBE_MAX_REQUESTS`. Only enable
active probing on targets you are authorised to test.

## Authenticated scanning

By default SecScan scans as an anonymous visitor. To assess pages that sit
behind a login, enable authenticated scanning and pass credentials with the
scan request:

```sh
SECSCAN_ALLOW_AUTH_SCAN=1
```

It is **off by default on purpose** — a public, unauthenticated endpoint that
forwards arbitrary credentials to arbitrary hosts is an abuse vector. Only
enable it on an access-controlled deployment.

Credentials are sent **only to the original HTTPS origin** (same scheme, host,
and effective port; never across a redirect), and only a safe subset of headers
is honoured:
`Authorization`, `Cookie`, and any `X-*` header. CR/LF is stripped to prevent
header injection. When credentials are supplied, the result JSON includes
`"authenticated": true`.

API request body:

```json
{
  "url": "https://app.example.com/dashboard",
  "auth_cookie": "sessionid=abc123; csrftoken=xyz",
  "auth_headers": ["Authorization: Bearer eyJ...", "X-Api-Key: ..."]
}
```

In the web UI, an "Authenticated scan (advanced)" panel appears under the scan
box when the feature is enabled.

## Checks

Run syntax checks for all PHP files:

```sh
php scripts/check.php
```

Run the offline detection unit tests (no network required):

```sh
php scripts/test_detection.php
```

Or, if Composer is available:

```sh
composer check
composer test:detection
composer test:rate-limit
composer test:storage
```

Run the read-only codebase/deployment audit. It checks PHP syntax, dangerous
source patterns, configuration hygiene, storage permissions, exposed archives,
web-server rules and core verification scripts. It never deletes or rewrites
files, and it does not print secret values:

```sh
php scripts/security_scan.php
php scripts/security_scan.php --json > security-scan.json
php scripts/test_codebase_scanner.php
```

The audit returns exit code `2` for critical findings and `1` for warnings. Use
`--strict` in CI when warnings should fail the build. Findings are review
signals, not proof of exploitability; verify the reported file and apply the
recommendation before deployment.

Run the storage regression test to verify fail-closed rate limiting, private
runtime file modes, and owner-bypass persistence:

```sh
php scripts/test_rate_limiter.php
php scripts/test_storage.php
```
