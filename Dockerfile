FROM python:3.11-slim

LABEL maintainer="daecayde@gmail.com"
LABEL description="ShadowTrap - Modular Honeypot Framework"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create log directory
RUN mkdir -p /app/logs

# Generate SSH host key
RUN python -c "from cryptography.hazmat.primitives.asymmetric import rsa; \
    from cryptography.hazmat.primitives import serialization; \
    key = rsa.generate_private_key(65537, 2048); \
    pem = key.private_bytes(serialization.Encoding.PEM, \
    serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()); \
    open('config/ssh_host_rsa_key', 'wb').write(pem)" 2>/dev/null || true

# Expose honeypot ports
EXPOSE 2222 8080 2121 2525 2323

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost', 2222)); s.close()" || exit 1

ENTRYPOINT ["python", "-m", "shadowtrap"]
CMD ["--config", "config/shadowtrap.yml"]
