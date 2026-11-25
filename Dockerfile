FROM golang:1.24-bookworm AS go-builder

# Install Go-based security tools
RUN GOBIN=/usr/local/bin go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    GOBIN=/usr/local/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    GOBIN=/usr/local/bin go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    GOBIN=/usr/local/bin go install github.com/ffuf/ffuf/v2@latest && \
    GOBIN=/usr/local/bin go install github.com/owasp-amass/amass/v4/...@master

# ── Runtime Stage ─────────────────────────────────────────────────
FROM python:3.11-slim

# Copy Go binaries from builder
COPY --from=go-builder /usr/local/bin/subfinder /usr/local/bin/
COPY --from=go-builder /usr/local/bin/httpx /usr/local/bin/
COPY --from=go-builder /usr/local/bin/dnsx /usr/local/bin/
COPY --from=go-builder /usr/local/bin/nuclei /usr/local/bin/
COPY --from=go-builder /usr/local/bin/ffuf /usr/local/bin/
COPY --from=go-builder /usr/local/bin/amass /usr/local/bin/

# Install system packages + security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates nmap masscan nikto whatweb wafw00f dnsutils curl git \
    sqlmap hydra theharvester \
    && rm -rf /var/lib/apt/lists/*

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

WORKDIR /opt/nexus
COPY . .
RUN pip install --no-cache-dir -e ".[full]"

ENTRYPOINT ["nexus"]
CMD ["--help"]
