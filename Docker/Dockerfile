# KoçSistem Managed Security Operations & Reporting Platform (MSSP Portal)
# Multi-stage Containerfile for Azure Container Apps & On-Premises Docker

FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

LABEL maintainer="KoçSistem Managed Security Services Team <siberguvenlik@kocsistem.com.tr>"
LABEL description="KoçSistem Microsoft Security & Purview Monthly Reporting Engine and MSSP SaaS Portal"
LABEL version="2.0.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV PORT=8080
ENV PYTHONUNBUFFERED=1

# Install Python 3, Chromium Headless (for PDF generation), and Turkish-supported TrueType fonts
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    chromium-browser \
    fonts-liberation \
    fonts-dejavu-core \
    fontconfig \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application files
COPY . /app

# Fix Windows CRLF line endings on entrypoint script if cloned on Windows
RUN sed -i 's/\r$//' /app/Docker/entrypoint.sh && chmod +x /app/Docker/entrypoint.sh

# Expose web portal & API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

ENTRYPOINT ["/bin/bash", "/app/Docker/entrypoint.sh"]
