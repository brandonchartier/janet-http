#!/usr/bin/env sh
# Run the test suite. If uvx is available, a real httpbin is started locally so
# the integration tests do not depend on the public httpbin.org; otherwise the
# suite runs against $HTTPBIN_URL (default https://httpbin.org).

if ! command -v uvx >/dev/null 2>&1; then
    echo "uvx not found; running against ${HTTPBIN_URL:-https://httpbin.org}"
    exec jpm test
fi

port="${HTTPBIN_PORT:-8911}"
pidfile="$(mktemp)"

echo "Starting local httpbin on port $port via uvx..."
uvx --with httpbin gunicorn --pid "$pidfile" \
    --bind "127.0.0.1:$port" --workers 8 httpbin:app >/dev/null 2>&1 &

# Wait for it to accept connections.
for _ in $(seq 1 50); do
    curl -sf -o /dev/null "http://127.0.0.1:$port/get" && break
    sleep 0.2
done

HTTPBIN_URL="http://127.0.0.1:$port" jpm test
status=$?

# Killing the gunicorn master (its pid is in $pidfile) makes it reap its workers.
kill "$(cat "$pidfile")" 2>/dev/null
rm -f "$pidfile"
exit "$status"
