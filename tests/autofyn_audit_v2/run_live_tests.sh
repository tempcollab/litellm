#!/usr/bin/env bash
#
# End-to-end MCP auth bypass exploit test runner for LiteLLM proxy (v2).
#
# This script:
#   1.   Starts a dedicated Postgres container on the same Docker network
#   1.5. Starts the mock MCP server (port 18100)
#   2.   Starts a LiteLLM proxy against Postgres (port 14000)
#   3.   Runs the live MCP auth bypass exploit tests
#   4.   Tears everything down
#
# Prerequisites: pip-installed litellm[proxy], docker
#
# Usage:
#   chmod +x tests/autofyn_audit_v2/run_live_tests.sh
#   ./tests/autofyn_audit_v2/run_live_tests.sh

set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DB_CONTAINER="litellm-security-test-db-v2"
DB_USER=litellm
DB_PASS=testpass123
DB_NAME=litellm_test
DOCKER_NETWORK="autofyn_default"

MOCK_MCP_PORT=18100
PROXY_PORT=14000
MASTER_KEY="sk-test-master-key-1234"

PROXY_PID=""
MOCK_MCP_PID=""
MALICIOUS_MCP_PID=""
DOCKER_AVAILABLE=false
DB_IP=""

# ── Cleanup ──────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "=== Cleanup ==="

    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "Stopping proxy (PID $PROXY_PID)..."
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi

    if [ -n "$MOCK_MCP_PID" ] && kill -0 "$MOCK_MCP_PID" 2>/dev/null; then
        echo "Stopping mock MCP server (PID $MOCK_MCP_PID)..."
        kill "$MOCK_MCP_PID" 2>/dev/null || true
        wait "$MOCK_MCP_PID" 2>/dev/null || true
    fi

    if [ -n "$MALICIOUS_MCP_PID" ] && kill -0 "$MALICIOUS_MCP_PID" 2>/dev/null; then
        echo "Stopping malicious MCP server (PID $MALICIOUS_MCP_PID)..."
        kill "$MALICIOUS_MCP_PID" 2>/dev/null || true
        wait "$MALICIOUS_MCP_PID" 2>/dev/null || true
    fi

    if [ "$DOCKER_AVAILABLE" = true ]; then
        if docker ps -q -f name="$DB_CONTAINER" | grep -q .; then
            echo "Stopping and removing $DB_CONTAINER..."
            docker rm -f "$DB_CONTAINER" > /dev/null 2>&1 || true
        fi
    fi

    echo "Done."
}
trap cleanup EXIT

# ── Step 1: Start Postgres ──────────────────────────────────────────────────

echo "=== Step 1: Start Postgres ==="

if docker info > /dev/null 2>&1; then
    DOCKER_AVAILABLE=true

    # Remove stale container if exists
    docker rm -f "$DB_CONTAINER" > /dev/null 2>&1 || true

    echo "Starting $DB_CONTAINER on network $DOCKER_NETWORK"
    docker run -d --name "$DB_CONTAINER" \
        --network "$DOCKER_NETWORK" \
        -e POSTGRES_PASSWORD="$DB_PASS" \
        -e POSTGRES_DB="$DB_NAME" \
        -e POSTGRES_USER="$DB_USER" \
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

    # Get the container's IP on the shared network
    DB_IP=$(docker inspect "$DB_CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
    echo "Postgres IP: $DB_IP"
    DATABASE_URL="postgresql://${DB_USER}:${DB_PASS}@${DB_IP}:5432/${DB_NAME}"
else
    echo "WARNING: Docker not available — skipping Postgres."
    DATABASE_URL=""
fi

# ── Step 1.5: Start mock MCP server ──────────────────────────────────────────

echo ""
echo "=== Step 1.5: Start mock MCP server (port $MOCK_MCP_PORT) ==="

cd "$REPO_ROOT"
python3 "$SCRIPT_DIR/mock_mcp_server.py" --port "$MOCK_MCP_PORT" \
    > /tmp/mock_mcp_server.log 2>&1 &
MOCK_MCP_PID=$!

echo -n "Waiting for mock MCP server (PID $MOCK_MCP_PID)..."
for i in $(seq 1 20); do
    if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(1)
try:
    s.connect(('127.0.0.1', $MOCK_MCP_PORT))
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        echo " ready (${i}s)"
        break
    fi
    if ! kill -0 "$MOCK_MCP_PID" 2>/dev/null; then
        echo " CRASHED"
        echo "Mock MCP server log:"
        cat /tmp/mock_mcp_server.log
        exit 1
    fi
    if [ "$i" -eq 20 ]; then
        echo " TIMEOUT"
        echo "Mock MCP server log:"
        cat /tmp/mock_mcp_server.log
        exit 1
    fi
    sleep 1
    echo -n "."
done

# ── Step 1.6: Start malicious MCP server ─────────────────────────────────────

MALICIOUS_MCP_PORT=18101

echo ""
echo "=== Step 1.6: Start malicious MCP server (port $MALICIOUS_MCP_PORT) ==="

cd "$REPO_ROOT"
python3 "$SCRIPT_DIR/malicious_mcp_server.py" --port "$MALICIOUS_MCP_PORT" \
    > /tmp/malicious_mcp_server.log 2>&1 &
MALICIOUS_MCP_PID=$!

echo -n "Waiting for malicious MCP server (PID $MALICIOUS_MCP_PID)..."
for i in $(seq 1 20); do
    if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(1)
try:
    s.connect(('127.0.0.1', $MALICIOUS_MCP_PORT))
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        echo " ready (${i}s)"
        break
    fi
    if ! kill -0 "$MALICIOUS_MCP_PID" 2>/dev/null; then
        echo " CRASHED"
        echo "Malicious MCP server log:"
        cat /tmp/malicious_mcp_server.log
        exit 1
    fi
    if [ "$i" -eq 20 ]; then
        echo " TIMEOUT"
        echo "Malicious MCP server log:"
        cat /tmp/malicious_mcp_server.log
        exit 1
    fi
    sleep 1
    echo -n "."
done

# ── Step 2: Start LiteLLM proxy ──────────────────────────────────────────────

echo ""
echo "=== Step 2: Start LiteLLM proxy (port $PROXY_PORT) ==="

cd "$REPO_ROOT"

LITELLM_MASTER_KEY="$MASTER_KEY" \
DATABASE_URL="${DATABASE_URL:-}" \
python3 -c "
import sys
sys.argv = ['litellm', '--config', '$SCRIPT_DIR/live_test_config.yaml', '--port', '$PROXY_PORT']
from litellm.proxy.proxy_cli import run_server
run_server(standalone_mode=True)
" > /tmp/litellm_security_test_proxy_v2.log 2>&1 &
PROXY_PID=$!

echo -n "Waiting for proxy (PID $PROXY_PID)..."
for i in $(seq 1 120); do
    if curl -sf "http://localhost:${PROXY_PORT}/health" \
         -H "Authorization: Bearer ${MASTER_KEY}" > /dev/null 2>&1; then
        echo " ready (${i}s)"
        break
    fi
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo " CRASHED"
        echo "Last 40 lines of proxy log:"
        tail -40 /tmp/litellm_security_test_proxy_v2.log
        exit 1
    fi
    if [ "$i" -eq 120 ]; then
        echo " TIMEOUT"
        echo "Last 40 lines of proxy log:"
        tail -40 /tmp/litellm_security_test_proxy_v2.log
        exit 1
    fi
    sleep 1
    echo -n "."
done

# ── Step 3a: Run MCP auth bypass exploit tests ────────────────────────────────

echo ""
echo "=== Step 3a: Run MCP auth bypass exploit tests ==="
echo ""

MCP_EXIT=0
python3 "$SCRIPT_DIR/live_exploit_tests.py" || MCP_EXIT=$?

echo ""
if [ "$MCP_EXIT" -eq 1 ]; then
    echo "=== Step 3a: Tests found MCP vulnerabilities (expected — audit confirms live exploit) ==="
elif [ "$MCP_EXIT" -eq 0 ]; then
    echo "=== Step 3a: No MCP vulnerabilities found (bypass may have been patched) ==="
elif [ "$MCP_EXIT" -eq 2 ]; then
    echo "=== Step 3a: Tests could not connect to proxy ==="
    echo "Proxy log tail:"
    tail -20 /tmp/litellm_security_test_proxy_v2.log
else
    echo "=== Step 3a: Tests failed with exit code $MCP_EXIT ==="
    echo "Proxy log tail:"
    tail -20 /tmp/litellm_security_test_proxy_v2.log
    echo ""
    echo "Mock MCP server log:"
    cat /tmp/mock_mcp_server.log
fi

# ── Step 3b: Run IDOR and missing-authorization exploit tests ─────────────────

echo ""
echo "=== Step 3b: Run IDOR and missing-authorization exploit tests ==="
echo ""

IDOR_EXIT=0
python3 "$SCRIPT_DIR/live_idor_exploit_tests.py" || IDOR_EXIT=$?

echo ""
if [ "$IDOR_EXIT" -eq 1 ]; then
    echo "=== Step 3b: Tests found IDOR/auth vulnerabilities (expected — audit confirms live exploit) ==="
elif [ "$IDOR_EXIT" -eq 0 ]; then
    echo "=== Step 3b: No IDOR/auth vulnerabilities found (endpoints may have been patched) ==="
elif [ "$IDOR_EXIT" -eq 2 ]; then
    echo "=== Step 3b: Tests could not connect to proxy or setup failed ==="
    echo "Proxy log tail:"
    tail -20 /tmp/litellm_security_test_proxy_v2.log
else
    echo "=== Step 3b: Tests failed with exit code $IDOR_EXIT ==="
    echo "Proxy log tail:"
    tail -20 /tmp/litellm_security_test_proxy_v2.log
fi

# ── Step 3d: Run Chain-B exploit (zero-auth MCP + recon) ─────────────────────

echo ""
echo "=== Step 3d: Run Chain-B — Zero-Auth MCP Execution + Infrastructure Recon ==="
echo ""

CHAIN_B_EXIT=0
python3 "$SCRIPT_DIR/exploit_chain_b.py" || CHAIN_B_EXIT=$?

echo ""
if [ "$CHAIN_B_EXIT" -eq 1 ]; then
    echo "=== Step 3d: Chain-B confirmed zero-credential MCP exploit (expected — audit confirms live) ==="
elif [ "$CHAIN_B_EXIT" -eq 0 ]; then
    echo "=== Step 3d: Chain-B found no zero-credential vulnerabilities (bypass may have been patched) ==="
elif [ "$CHAIN_B_EXIT" -eq 2 ]; then
    echo "=== Step 3d: Chain-B could not connect to proxy ==="
    echo "Proxy log tail:"
    tail -20 /tmp/litellm_security_test_proxy_v2.log
else
    echo "=== Step 3d: Chain-B failed with exit code $CHAIN_B_EXIT ==="
    echo "Proxy log tail:"
    tail -20 /tmp/litellm_security_test_proxy_v2.log
fi

# ── Step 3e: Run Chain-C exploit (any user → cross-tenant breach + SSRF) ─────

echo ""
echo "=== Step 3e: Run Chain-C — Any User → Cross-Tenant Data Breach + SSRF ==="
echo ""

CHAIN_C_EXIT=0
python3 "$SCRIPT_DIR/exploit_chain_c.py" || CHAIN_C_EXIT=$?

echo ""
if [ "$CHAIN_C_EXIT" -eq 1 ]; then
    echo "=== Step 3e: Chain-C confirmed cross-tenant breach (expected — audit confirms live) ==="
elif [ "$CHAIN_C_EXIT" -eq 0 ]; then
    echo "=== Step 3e: Chain-C found no cross-tenant vulnerabilities (endpoints may have been patched) ==="
elif [ "$CHAIN_C_EXIT" -eq 2 ]; then
    echo "=== Step 3e: Chain-C could not connect to proxy or setup failed ==="
    echo "Proxy log tail:"
    tail -20 /tmp/litellm_security_test_proxy_v2.log
else
    echo "=== Step 3e: Chain-C failed with exit code $CHAIN_C_EXIT ==="
    echo "Proxy log tail:"
    tail -20 /tmp/litellm_security_test_proxy_v2.log
fi

# ── Step 3f: Run Chain-B-RCE exploit (zero-auth MCP → full RCE) ──────────────

echo ""
echo "=== Step 3f: Run Chain-B-RCE — Zero-Auth MCP → Full Remote Code Execution ==="
echo ""

CHAIN_B_RCE_EXIT=0
python3 "$SCRIPT_DIR/exploit_chain_b_rce.py" || CHAIN_B_RCE_EXIT=$?

echo ""
if [ "$CHAIN_B_RCE_EXIT" -eq 1 ]; then
    echo "=== Step 3f: Chain-B-RCE confirmed zero-credential RCE (expected — audit confirms live) ==="
elif [ "$CHAIN_B_RCE_EXIT" -eq 0 ]; then
    echo "=== Step 3f: Chain-B-RCE found no zero-credential vulnerabilities (bypass may have been patched) ==="
elif [ "$CHAIN_B_RCE_EXIT" -eq 2 ]; then
    echo "=== Step 3f: Chain-B-RCE could not connect to proxy ==="
    echo "Proxy log tail:"
    tail -20 /tmp/litellm_security_test_proxy_v2.log
else
    echo "=== Step 3f: Chain-B-RCE failed with exit code $CHAIN_B_RCE_EXIT ==="
    echo "Proxy log tail:"
    tail -20 /tmp/litellm_security_test_proxy_v2.log
    echo ""
    echo "Malicious MCP server log:"
    cat /tmp/malicious_mcp_server.log
fi

# ── Aggregate exit code ───────────────────────────────────────────────────────

# Exit 1 if any test suite confirmed vulnerabilities; preserve exit 2 for
# infrastructure failures when no suite found vulnerabilities.
if [ "$MCP_EXIT" -eq 1 ] || [ "$IDOR_EXIT" -eq 1 ] || [ "$CHAIN_B_EXIT" -eq 1 ] || [ "$CHAIN_C_EXIT" -eq 1 ] || [ "$CHAIN_B_RCE_EXIT" -eq 1 ]; then
    exit 1
elif [ "$MCP_EXIT" -eq 2 ] || [ "$IDOR_EXIT" -eq 2 ] || [ "$CHAIN_B_EXIT" -eq 2 ] || [ "$CHAIN_C_EXIT" -eq 2 ] || [ "$CHAIN_B_RCE_EXIT" -eq 2 ]; then
    exit 2
elif [ "$MCP_EXIT" -ne 0 ] || [ "$IDOR_EXIT" -ne 0 ] || [ "$CHAIN_B_EXIT" -ne 0 ] || [ "$CHAIN_C_EXIT" -ne 0 ] || [ "$CHAIN_B_RCE_EXIT" -ne 0 ]; then
    exit 1
else
    exit 0
fi
