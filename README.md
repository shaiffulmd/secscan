# SecScan

SecScan is a PHP-based web security scanner with a public scan UI, JSON API, SQLite-backed scan logging, and a password-protected usage dashboard.

## Requirements

- PHP 8.1+
- PHP extensions: `curl`, `openssl`, `pdo`, `pdo_sqlite`
- Optional: `dig` for deeper DNSSEC/CAA checks

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

Generate a dashboard password hash with:

```sh
php -r "echo password_hash('YourNewPassword', PASSWORD_BCRYPT), PHP_EOL;"
```

Store `SECSCAN_DATA_DIR` outside the public web root when possible. Apache deny rules are included as a fallback, but web-server config is safer than relying only on `.htaccess`.

## Safety Notes

SecScan performs outbound HTTP, TLS, DNS, and limited port checks. Keep rate limits enabled, avoid exposing the API without access controls on high-traffic deployments, and only scan systems you are allowed to assess.

## Checks

Run syntax checks for all PHP files:

```sh
php scripts/check.php
```

Or, if Composer is available:

```sh
composer check
```
