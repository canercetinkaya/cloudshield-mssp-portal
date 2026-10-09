# ==============================================================================
# CloudShield Security Reporting & Managed Services Visibility Platform
# Hardened Multi-Stage Containerfile for Azure Container Apps & Enterprise Deployments
# ==============================================================================

FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

# OCI Standard Metadata Labels
LABEL org.opencontainers.image.title="CloudShield Security Reporting & Managed Services Visibility Platform"
LABEL org.opencontainers.image.description="Automated Microsoft Security & Compliance Monthly Reporting and Managed Services Visibility Engine"
LABEL org.opencontainers.image.version="3.1.0"
LABEL org.opencontainers.image.vendor="CloudShield Platform Team"
LABEL org.opencontainers.image.source="https://github.com/canercetinkaya/cloudshield-mssp-portal"
LABEL org.opencontainers.image.licenses="Proprietary"

ENV DEBIAN_FRONTEND=noninteractive
ENV PORT=8080
ENV PYTHONUNBUFFERED=1
ENV ENVIRONMENT=production

# Install Python 3.11, Chromium dependencies, and system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    fonts-liberation \
    fonts-dejavu-core \
    fontconfig \
    ca-certificates \
    curl \
    wget \
    xdg-utils \
    && ln -sf /usr/bin/python3.11 /usr/local/bin/python3 \
    && wget -q -O /tmp/google-chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
    && (dpkg -i /tmp/google-chrome.deb || apt-get install -y -f --no-install-recommends) \
    && rm -f /tmp/google-chrome.deb \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user and group
RUN groupadd -g 10001 cloudshield && \
    useradd -u 10001 -g cloudshield -m -s /bin/bash cloudshield

# Set working directory
WORKDIR /app

# Copy application files (protected by .dockerignore)
COPY . /app

# Ensure proper directory ownership and permissions for runtime operations
RUN mkdir -p /app/Engine/Output /app/Engine/Logs /app/Data /app/scratch && \
    sed -i 's/\r$//' /app/Docker/entrypoint.sh && \
    chmod +x /app/Docker/entrypoint.sh && \
    chown -R cloudshield:cloudshield /app

# Build-time verification: validate syntax before pushing
RUN python3 -m py_compile /app/Portal/api/report_generator.py && \
    python3 -m py_compile /app/Portal/api/server.py && \
    python3 -m py_compile /app/Portal/api/rbac_engine.py && \
    python3 -m py_compile /app/Portal/api/rbac_handlers.py && \
    python3 -m py_compile /app/database/db.py && \
    echo "[BUILD] Python syntax verification passed."

# Switch to non-root user
USER cloudshield

# Expose web portal & API port
EXPOSE 8080

# Health check against unauthenticated health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

ENTRYPOINT ["/bin/bash", "/app/Docker/entrypoint.sh"]
