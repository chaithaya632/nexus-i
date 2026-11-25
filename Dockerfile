FROM golang:1.27-trixie AS go-builder

# Install Go-based security tools (pinned/compatible with Go 1.27)
RUN GOBIN=/usr/local/bin go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    GOBIN=/usr/local/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    GOBIN=/usr/local/bin go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    GOBIN=/usr/local/bin go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    GOBIN=/usr/local/bin go install github.com/ffuf/ffuf/v2@latest && \
    GOBIN=/usr/local/bin go install github.com/owasp-amass/amass/v5/cmd/amass@latest

# ── Runtime Stage ─────────────────────────────────────────────────
FROM python:3.12-slim-trixie

# Install system packages + security tools (enable non-free for nikto; Trixie uses bind9-dnsutils)
RUN if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -E -i '/^Components:/ { /non-free/! s/[[:space:]]*$/ non-free/ }' /etc/apt/sources.list.d/debian.sources; \
    fi && \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates nmap masscan nikto whatweb wafw00f \
    bind9-dnsutils netcat-openbsd curl git sqlmap hydra \
    libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binaries compiled against matching Debian Trixie ABI
COPY --from=go-builder /usr/local/bin/subfinder /usr/local/bin/
COPY --from=go-builder /usr/local/bin/httpx /usr/local/bin/
COPY --from=go-builder /usr/local/bin/dnsx /usr/local/bin/
COPY --from=go-builder /usr/local/bin/nuclei /usr/local/bin/
COPY --from=go-builder /usr/local/bin/katana /usr/local/bin/
COPY --from=go-builder /usr/local/bin/ffuf /usr/local/bin/
COPY --from=go-builder /usr/local/bin/amass /usr/local/bin/

# Update nuclei templates when network allows
RUN nuclei -update-templates 2>/dev/null || true

WORKDIR /opt/nexus
COPY . .
RUN pip install --no-cache-dir -e ".[full]"

ENTRYPOINT ["nexus"]
CMD ["--help"]
