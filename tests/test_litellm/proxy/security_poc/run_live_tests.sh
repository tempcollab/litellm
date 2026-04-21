#!/usr/bin/env bash
#
# End-to-end security exploit test runner for LiteLLM proxy.
#
# This script:
#   1. Starts a dedicated Postgres container (port 15432)
#   2. Starts a LiteLLM proxy against it (port 14000)
#   3. Runs the live exploit tests
#   4. Tears everything down
#
# Prerequisites: docker, uv (or pip-installed litellm)
#
# Usage:
#   chmod +x tests/test_litellm/proxy/security_poc/run_live_tests.sh
#   ./tests/test_litellm/proxy/security_poc/run_live_tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

DB_CONTAINER="litellm-security-test-db"
DB_PORT=15432
DB_USER=litellm
DB_PASS=testpass123
DB_NAME=litellm_test
DATABASE_URL="postgresql://${DB_USER}:${DB_PASS}@localhost:${DB_PORT}/${DB_NAME}"

PROXY_PORT=14000
MASTER_KEY="sk-test-master-key-1234"

PROXY_PID=""

# ── Cleanup ──────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "Stopping proxy (PID $PROXY_PID)..."
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi
    if docker ps -q -f name="$DB_CONTAINER" | grep -q .; then
        echo "Stopping and removing $DB_CONTAINER..."
        docker rm -f "$DB_CONTAINER" > /dev/null 2>&1 || true
    fi
    echo "Done."
}
trap cleanup EXIT

# ── Step 1: Start Postgres ───────────────────────────────────────────────────

echo "=== Step 1: Start Postgres ($DB_CONTAINER on port $DB_PORT) ==="

# Remove stale container if exists
docker rm -f "$DB_CONTAINER" > /dev/null 2>&1 || true

docker run -d --name "$DB_CONTAINER" \
    -e POSTGRES_PASSWORD="$DB_PASS" \
    -e POSTGRES_DB="$DB_NAME" \
    -e POSTGRES_USER="$DB_USER" \
    -p "${DB_PORT}:5432" \
    postgres:16-alpine > /dev/null

echo -n "Waiting for Postgres..."
for i in $(seq 1 30); do
    if docker exec "$DB_CONTAINER" pg_isready -U "$DB_USER" > /dev/null 2>&1; then
        echo " ready (${i}s)"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo " TIMEOUT"
        exit 1
    fi
    sleep 1
    echo -n "."
done

# ── Step 2: Start LiteLLM proxy ─────────────────────────────────────────────

echo ""
echo "=== Step 2: Start LiteLLM proxy (port $PROXY_PORT) ==="

cd "$REPO_ROOT"

LITELLM_MASTER_KEY="$MASTER_KEY" \
DATABASE_URL="$DATABASE_URL" \
uv run litellm \
    --config "$SCRIPT_DIR/live_test_config.yaml" \
    --port "$PROXY_PORT" \
    > /tmp/litellm_security_test_proxy.log 2>&1 &
PROXY_PID=$!

echo -n "Waiting for proxy (PID $PROXY_PID)..."
for i in $(seq 1 60); do
    if curl -sf "http://localhost:${PROXY_PORT}/health" \
         -H "Authorization: Bearer ${MASTER_KEY}" > /dev/null 2>&1; then
        echo " ready (${i}s)"
        break
    fi
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo " CRASHED"
        echo "Last 30 lines of proxy log:"
        tail -30 /tmp/litellm_security_test_proxy.log
        exit 1
    fi
    if [ "$i" -eq 60 ]; then
        echo " TIMEOUT"
        echo "Last 30 lines of proxy log:"
        tail -30 /tmp/litellm_security_test_proxy.log
        exit 1
    fi
    sleep 1
    echo -n "."
done

# ── Step 3: Run exploit tests ───────────────────────────────────────────────

echo ""
echo "=== Step 3: Run live exploit tests ==="
echo ""

# The test script exits 1 if vulnerabilities found (which is what we expect).
# Capture the exit code but don't let set -e kill us.
TEST_EXIT=0
uv run python "$SCRIPT_DIR/live_exploit_tests.py" || TEST_EXIT=$?

echo ""
if [ "$TEST_EXIT" -eq 1 ]; then
    echo "=== Tests found vulnerabilities (expected) ==="
elif [ "$TEST_EXIT" -eq 0 ]; then
    echo "=== No vulnerabilities found ==="
else
    echo "=== Tests failed with exit code $TEST_EXIT ==="
    echo "Proxy log tail:"
    tail -20 /tmp/litellm_security_test_proxy.log
fi

exit "$TEST_EXIT"
