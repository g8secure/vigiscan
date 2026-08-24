# ============================================================
# VigiScan - Flask Vulnerability Scanner with OWASP ZAP
# ============================================================
# Multi-stage not required: ZAP is a runtime dependency that
# must live in the same container as Flask (Flask talks to ZAP
# via its local REST API on 127.0.0.1:8080).
# ============================================================

FROM python:3.10-slim

# Build-time configurable ZAP version (default: 2.14.0 stable)
ARG ZAP_VERSION=2.14.0

# Install system dependencies:
#   - nmap          : network scanning (existing functionality preserved)
#   - default-jre-headless : Java runtime required by OWASP ZAP
#   - wget          : download ZAP
#   - curl          : health checks for ZAP readiness
#   - ca-certificates : HTTPS support for downloads and scans
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    default-jre-headless \
    wget \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install OWASP ZAP (headless daemon)
RUN wget -qO zap.tar.gz "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
    && tar -xf zap.tar.gz \
    && rm zap.tar.gz \
    && mv "ZAP_${ZAP_VERSION}" /opt/zap \
    && chmod +x /opt/zap/zap.sh

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Ensure the start script is executable
RUN chmod +x start.sh

# ZAP daemon listens on 127.0.0.1:8080 (internal only, not exposed publicly)
EXPOSE 8080

# Flask/Gunicorn listens on $PORT (Render sets this; default 5000 locally)
EXPOSE 5000

# Health check: verify Flask is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT:-5000}/login || exit 1

# Run the startup script which manages both ZAP and Gunicorn
CMD ["./start.sh"]