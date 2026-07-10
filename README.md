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

Accuracy/scoring improvements: CSP no longer flags `'unsafe-inline'` when a
nonce/hash or `'strict-dynamic'` neutralises it, and advisory `info` findings are
weighted so they no longer unfairly cap an otherwise well-configured site's grade.

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
```
