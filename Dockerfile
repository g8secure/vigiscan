FROM python:3.10-slim

# Install system dependencies: Nmap, Java (for ZAP), and wget
RUN apt-get update && apt-get install -y \
    nmap \
    default-jre-headless \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Download and install OWASP ZAP 2.14.0
RUN wget -qO zap.tar.gz "https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz" \
    && tar -xf zap.tar.gz \
    && rm zap.tar.gz \
    && mv ZAP_2.14.0 /opt/zap

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Ensure the start script is executable
RUN chmod +x start.sh

# Expose port 5000 for Gunicorn
EXPOSE 5000

# Run the startup script which manages both ZAP and Gunicorn
CMD ["./start.sh"]
