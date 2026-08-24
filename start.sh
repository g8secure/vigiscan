#!/bin/bash
# ============================================================
# VigiScan startup script (used as Docker CMD)
# 1. Starts OWASP ZAP in headless daemon mode on 127.0.0.1:8080
# 2. Waits for ZAP to become ready (polling its REST API)
# 3. Starts Gunicorn on 0.0.0.0:$PORT (Render sets $PORT)
# ============================================================

set -u

# ------------------------------------------------------------
# Port configuration
# Render injects $PORT automatically. Default to 5000 for local dev.
# ------------------------------------------------------------
PORT="${PORT:-5000}"

# ------------------------------------------------------------
# ZAP configuration
# ZAP_HOST / ZAP_PORT must match the ZAPv2 proxies in app.py
# (which reads the same env vars and defaults to 127.0.0.1:8080).
# ------------------------------------------------------------
ZAP_HOST="${ZAP_HOST:-127.0.0.1}"
ZAP_PORT="${ZAP_PORT:-8080}"
# JVM heap cap: tunable. Default 300m fits Render Free (512MB RAM).
ZAP_MAX_HEAP="${ZAP_MAX_HEAP:-300m}"

echo "======================================================"
echo " VigiScan container starting"
echo "   Flask/Gunicorn on 0.0.0.0:${PORT}"
echo "   OWASP ZAP on ${ZAP_HOST}:${ZAP_PORT} (headless daemon)"
echo "   ZAP JVM max heap: ${ZAP_MAX_HEAP}"
echo "======================================================"

# ------------------------------------------------------------
# Start OWASP ZAP daemon
# -daemon              : run headless (no GUI), suitable for servers
# -host/-port          : listen only on loopback (not exposed publicly)
# -config api.disablekey=true : app.py uses apikey='' so the API
#                               key check must be disabled
# -dir /tmp/zap_home   : writable home for config and logs
# ------------------------------------------------------------
echo "[start.sh] Starting OWASP ZAP daemon..."
mkdir -p /tmp/zap_home

JAVA_OPTS="-Xmx${ZAP_MAX_HEAP}" /opt/zap/zap.sh \
    -daemon \
    -host "${ZAP_HOST}" \
    -port "${ZAP_PORT}" \
    -config api.disablekey=true \
    -dir /tmp/zap_home \
    > /tmp/zap.log 2>&1 &

ZAP_PID=$!

# ------------------------------------------------------------
# Wait for ZAP to become ready by polling its REST API.
# ZAP can take 30-90s to fully initialize on first boot.
# ------------------------------------------------------------
ZAP_READY_URL="http://${ZAP_HOST}:${ZAP_PORT}/JSON/core/view/version"
ZAP_WAIT_MAX="${ZAP_WAIT_MAX:-120}"   # seconds
ZAP_WAITED=0

echo "[start.sh] Waiting for ZAP API at ${ZAP_READY_URL} (timeout: ${ZAP_WAIT_MAX}s)..."
while [ "${ZAP_WAITED}" -lt "${ZAP_WAIT_MAX}" ]; do
    if curl -sf "${ZAP_READY_URL}" > /dev/null 2>&1; then
        echo "[start.sh] ✅ OWASP ZAP is ready (after ${ZAP_WAITED}s)."
        ZAP_READY=1
        break
    fi

    if ! kill -0 "${ZAP_PID}" 2>/dev/null; then
        echo "[start.sh] ⚠️ ZAP process exited unexpectedly. Log tail:"
        tail -20 /tmp/zap.log
        echo "[start.sh] Continuing without ZAP (app will report 'Scanner Core Unavailable')."
        ZAP_READY=0
        break
    fi

    sleep 2
    ZAP_WAITED=$((ZAP_WAITED + 2))
done

if [ "${ZAP_READY:-0}" -ne 1 ]; then
    echo "[start.sh] ⚠️ ZAP did not become ready within ${ZAP_WAIT_MAX}s. Log tail:"
    tail -20 /tmp/zap.log
    echo "[start.sh] Continuing without ZAP (app will report 'Scanner Core Unavailable')."
fi

# ------------------------------------------------------------
# Start Flask with Gunicorn.
# IMPORTANT: Use a SINGLE worker. The app stores live scan jobs
# (SCAN_JOBS), the background scheduler, and rate limits in
# process memory. Multiple workers would each have their own
# copy, breaking real-time scan status polling.
# ------------------------------------------------------------
echo "[start.sh] Starting Gunicorn on 0.0.0.0:${PORT}..."
exec gunicorn \
    --bind "0.0.0.0:${PORT}" \
    --workers 1 \
    --threads 4 \
    --timeout 300 \
    --graceful-timeout 30 \
    --access-logfile - \
    --error-logfile - \
    app:app