#!/bin/bash

echo "Starting OWASP ZAP in the background..."
# Create a writable directory for ZAP configuration and logs
mkdir -p /tmp/zap_home

# Start ZAP daemon on localhost:8080 with disabled API key requirement.
# Limiting JVM memory to prevent crashing the Render container.
JAVA_OPTS="-Xmx300m" /opt/zap/zap.sh -daemon -port 8080 -host 127.0.0.1 -config api.disablekey=true -dir /tmp/zap_home > /tmp/zap.log 2>&1 &

echo "Waiting for ZAP to initialize..."
sleep 10

echo "Starting Flask Application with Gunicorn..."
# Use a timeout of 120s to allow scans to process if necessary
exec gunicorn --bind 0.0.0.0:5000 --timeout 120 app:app
