# CloudShield Managed Security Operations & Reporting Platform (MSSP Portal)
# Multi-stage Containerfile for Azure Container Apps & On-Premises Docker

FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

LABEL maintainer="CloudShield MSSP Security Engineering Team <security@cloudshield-mssp.com>"
LABEL description="CloudShield Microsoft Security & Purview Monthly Reporting Engine and MSSP SaaS Portal"
LABEL version="2.5.13"

ENV DEBIAN_FRONTEND=noninteractive
ENV PORT=8080
ENV PYTHONUNBUFFERED=1

# Install Python 3.11 (pinned - ubuntu-22.04 generic python3 installs 3.10 which has
# stricter f-string rules; 3.11 matches our CI/CD environment and supports all syntax used)
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

# Set working directory
WORKDIR /app

# Copy application files
COPY . /app

# Fix Windows CRLF line endings on entrypoint script if cloned on Windows
RUN sed -i 's/\r$//' /app/Docker/entrypoint.sh && chmod +x /app/Docker/entrypoint.sh

# BUILD-TIME syntax check: catch Python syntax errors before the image is pushed
# This ensures what compiles locally also compiles in the container Python version
RUN python3 --version && \
    python3 -m py_compile /app/Portal/api/report_generator.py && \
    python3 -m py_compile /app/Portal/api/server.py && \
    python3 -m py_compile /app/Portal/api/rbac_engine.py && \
    python3 -m py_compile /app/Portal/api/rbac_handlers.py && \
    python3 -m py_compile /app/database/db.py && \
    echo "[BUILD] Python syntax check passed on $(python3 --version)"

# Expose web portal & API port (8080 primary, 80 backup)
EXPOSE 8080 80

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -f http://localhost:8080/api/health || exit 1

ENTRYPOINT ["/bin/bash", "/app/Docker/entrypoint.sh"]

