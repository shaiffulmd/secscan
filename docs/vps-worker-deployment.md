# VPS scanner worker deployment

The web application and the worker run the same codebase. The web application
keeps UI, rate limiting, audit logging, and its SQLite database. The VPS worker
only accepts signed scan jobs through worker.php and performs outbound checks.

## 1. Deploy the worker

Copy this branch to the VPS and configure PHP 8.1 or later with curl, openssl,
mbstring, PDO, and PDO SQLite. Set the worker data directory outside the web
root and make it writable by the PHP user.

Use a long random value for SECSCAN_WORKER_SHARED_SECRET; the exact same value
must be present on both servers.

Worker environment:

    SECSCAN_SCANNER_MODE=local
    SECSCAN_WORKER_SHARED_SECRET=<same long random secret>
    SECSCAN_WORKER_SCAN_TIMEOUT=300
    SECSCAN_WORKER_ALLOWED_CALLERS=<public IP or CIDR of security.apasaja.my>
    SECSCAN_DATA_DIR=/var/lib/secscan-worker

The worker endpoint is the HTTPS URL ending in /worker.php.

## 2. Configure the web application

Keep the current database, dashboard, and rate limits on security.apasaja.my.
After the worker is reachable over HTTPS, add:

    SECSCAN_SCANNER_MODE=remote
    SECSCAN_WORKER_URL=https://scanner-vps.example/worker.php
    SECSCAN_WORKER_SHARED_SECRET=<same long random secret>
    SECSCAN_WORKER_TIMEOUT=240
    SECSCAN_WORKER_MAX_RESPONSE_BYTES=8388608

Restart PHP-FPM or the hosting PHP service after changing environment variables.

## 3. Restrict network access

HMAC signing is mandatory. Also restrict the worker firewall or web server to
the web application's public egress IP where possible. Do not expose the worker
to browsers, and do not use a public CORS policy for it.

For Nginx, a worker location can be restricted conceptually as:

    location = /worker.php {
        allow <security.apasaja.my egress IP>;
        deny all;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root/worker.php;
        fastcgi_pass unix:/run/php/php-fpm.sock;
    }

If a reverse proxy is in front of the worker, configure trusted proxy IP ranges
before using the IP allowlist.

## 4. Verify

Run the local protocol test on both deployments:

    php scripts/test_worker_protocol.php

Keep SECSCAN_SCANNER_MODE=local until a successful signed request has been
verified from the web application. If the worker is unavailable or its response
signature is invalid, the web application fails closed and does not trust the
response.
