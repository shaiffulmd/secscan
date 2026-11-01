#!/usr/bin/env bash
# Deploys the latest commit of the configured branch to the SecScan web root.
#
# Runs on the VPS, normally as a forced SSH command from GitHub Actions. It takes
# no input from the caller: what gets deployed is decided here, by what the branch
# points at on origin. Setup: docs/auto-deploy.md
#
# Output reaches public GitHub Actions logs, so print no paths or hostnames. Full
# output goes to deploy.log in the state directory.
set -euo pipefail
umask 022

CONFIG_FILE="${SECSCAN_DEPLOY_CONFIG:-$HOME/.secscan-deploy.env}"
if [ ! -r "$CONFIG_FILE" ]; then
    echo "Deploy failed: config file is missing on the server." >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$CONFIG_FILE"

WEB_ROOT="${SECSCAN_WEB_ROOT:-}"
REPO_URL="${SECSCAN_REPO_URL:-https://github.com/shaiffulmd/secscan.git}"
BRANCH="${SECSCAN_BRANCH:-main}"
HEALTH_URL="${SECSCAN_HEALTH_URL:-}"
POST_DEPLOY_CMD="${SECSCAN_POST_DEPLOY_CMD:-}"
STATE_DIR="${SECSCAN_DEPLOY_STATE_DIR:-$HOME/.secscan-deploy}"
REPO_DIR="$STATE_DIR/repo"
LOG_FILE="$STATE_DIR/deploy.log"
DEPLOYED_FILE="$STATE_DIR/deployed-commit"
STALE_FILE="$STATE_DIR/stale-files.txt"
LOCK_DIR="$STATE_DIR/lock"

TESTS=(check test_detection test_regression test_baseline test_joomla_fingerprint
       test_codebase_scanner test_rate_limiter test_storage test_worker_protocol)

# Runtime files and anything that should not be served. rsync never deletes or
# overwrites these in the web root.
SYNC_FILTERS=(
    --include=/data/ --include=/data/.htaccess --include=/data/index.html --exclude=/data/*
    --exclude=/.git/ --exclude=/.github/ --exclude=/.env --exclude=/.env.*
    --exclude=/docs/ --exclude=/AGENTS.md --exclude=/cve-report.md
)

fail() {
    echo "Deploy failed: $1" >&2
    exit 1
}

# Refuse a web root that could only be a configuration mistake.
case "$WEB_ROOT" in
    "" | "/" | "$HOME" | "$HOME/") fail "SECSCAN_WEB_ROOT is not set to a usable directory." ;;
    /*) ;;
    *) fail "SECSCAN_WEB_ROOT must be an absolute path." ;;
esac
[ -d "$WEB_ROOT" ] || fail "the web root directory does not exist."

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    fail "another deploy is running. If none is, remove the lock directory in the state directory."
fi
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$LOCK_DIR" "$WORK_DIR"' EXIT
: > "$LOG_FILE"

sync_web_root() {
    # -rlt leaves the owner and modes of files already in the web root untouched.
    rsync -rlt --delay-updates "${SYNC_FILTERS[@]}" "$REPO_DIR/" "$WEB_ROOT/" >> "$LOG_FILE" 2>&1
    if [ -n "$POST_DEPLOY_CMD" ]; then
        bash -c "$POST_DEPLOY_CMD" >> "$LOG_FILE" 2>&1 || echo "Warning: the post-deploy command failed."
    fi
}

check_health() {
    [ -z "$HEALTH_URL" ] && return 0
    local attempt
    for attempt in 1 2 3; do
        if curl --fail --silent --show-error --output /dev/null --max-time 30 "$HEALTH_URL" >> "$LOG_FILE" 2>&1; then
            return 0
        fi
        [ "$attempt" = "3" ] || sleep 5
    done
    return 1
}

if [ ! -d "$REPO_DIR/.git" ]; then
    git clone --quiet "$REPO_URL" "$REPO_DIR" >> "$LOG_FILE" 2>&1 || fail "could not clone the repository."
fi
git -C "$REPO_DIR" fetch --quiet --prune origin "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH" >> "$LOG_FILE" 2>&1 \
    || fail "could not fetch from the repository."
git -C "$REPO_DIR" checkout --quiet --force --detach "origin/$BRANCH"

TARGET="$(git -C "$REPO_DIR" rev-parse HEAD)"
PREVIOUS="$(cat "$DEPLOYED_FILE" 2>/dev/null || true)"
if [ "$TARGET" = "$PREVIOUS" ]; then
    echo "Already on ${TARGET:0:7}; nothing to deploy."
    exit 0
fi
echo "Deploying ${TARGET:0:7}."

# The server's PHP may differ from CI, so test here before touching the web root.
# SECSCAN_ENV_FILE keeps the tests away from the production .env and database.
for test_name in "${TESTS[@]}"; do
    echo "== $test_name" >> "$LOG_FILE"
    if ! (cd "$REPO_DIR" && SECSCAN_ENV_FILE=/dev/null SECSCAN_DATA_DIR="$WORK_DIR" SECSCAN_DB_PATH="$WORK_DIR/test.db" \
        php "scripts/$test_name.php") >> "$LOG_FILE" 2>&1; then
        fail "$test_name did not pass on the server. The live site was not changed."
    fi
done
git -C "$REPO_DIR" clean --quiet -fdx

sync_web_root || fail "could not copy files to the web root. Check deploy.log on the server."

if ! check_health; then
    if [ -n "$PREVIOUS" ] && git -C "$REPO_DIR" checkout --quiet --force --detach "$PREVIOUS"; then
        sync_web_root || fail "the health check failed and rollback could not copy files. Check the site now."
        fail "the health check failed, so the site was rolled back to ${PREVIOUS:0:7}."
    fi
    fail "the health check failed and there is no earlier deploy to roll back to. Check the site now."
fi

echo "$TARGET" > "$DEPLOYED_FILE"

# Files removed from git stay in the web root until someone reviews them, because
# it may also hold files that were never in git. Report the count only.
rsync -rlt --dry-run --delete --itemize-changes "${SYNC_FILTERS[@]}" "$REPO_DIR/" "$WEB_ROOT/" 2>> "$LOG_FILE" \
    | { grep '^\*deleting' || true; } > "$STALE_FILE"
stale_count="$(wc -l < "$STALE_FILE" | tr -d ' ')"
if [ "$stale_count" != "0" ]; then
    echo "Note: $stale_count file(s) in the web root are not in git. Review stale-files.txt on the server."
fi

echo "Deployed ${TARGET:0:7}."
