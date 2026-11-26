# NEXUS

NEXUS (`nexus-pt`) is a cross-platform penetration testing and security assessment CLI (`nexus`) for Linux, macOS, and Windows. It orchestrates reconnaissance, active and passive vulnerability scanning, finding correlation, attack-chain graphing, confirmation-gated exploitation, and multi-format reporting.

The core pipeline (`init` -> `recon` -> `scan` -> `correlate` -> `exploit` -> `report`) runs standalone offline without an LLM or GPU using a forward-chaining rule engine, bundled CVE and CISA KEV knowledge bases, YAML passive inspection rules, and a Dijkstra attack-chain builder. Local LLM augmentation via Ollama (`[ai]`) is optional.

## Requirements and Installation

Requires Python 3.11 or newer.

```bash
git clone https://github.com/chaithaya632/nexus-i.git
cd nexus-i

# Core CLI and native Python checks
pip install -e .

# Optional extras
pip install -e ".[report]"     # WeasyPrint PDF and python-docx DOCX exports
pip install -e ".[dashboard]"  # FastAPI and Uvicorn web UI / API / repeater
pip install -e ".[ai]"         # Ollama Python client
pip install -e ".[ml]"         # scikit-learn support
pip install -e ".[browser]"    # Playwright SPA crawling
pip install -e ".[proxy]"      # mitmproxy passive HTTP capture (nexus proxy)
pip install -e ".[postgres]"   # PostgreSQL persistence via psycopg
pip install -e ".[full]"       # All optional extras
```

For SPA crawling, NEXUS auto-detects local Chrome, Chromium, or Microsoft Edge binaries and uses native Chrome DevTools Protocol (CDP) when `websockets` is installed, falling back to HTTP/HTML/JS crawling if neither CDP nor `[browser]` (Playwright) is available.

## Quick Start

```bash
# Detect hardware and write ~/.nexus/config.yaml
nexus init

# Full engagement with explicit scope file and SARIF output
nexus engage example.com --scope scope.yaml --profile full
nexus report -e <engagement_id> -f sarif -o results.sarif

# Authenticated API scan with OpenAPI spec, baseline ignore, and regression gate
nexus engage api.example.com -s scope.yaml -p api --openapi openapi.yaml --auth-bearer "$TOKEN" --ignore .nexusignore --no-exploit
nexus diff <baseline_id> <current_id> --fail-on-new critical,high

# Step-by-step execution
nexus recon example.com -s scope.yaml
nexus scan example.com -e <engagement_id> -p web -H "X-Env: staging" --cookie "session=..."
nexus exploit -e <engagement_id>
nexus report -e <engagement_id> -f html

# Passive MITM proxy and local web dashboard
nexus proxy --host 127.0.0.1 --port 8080 -s scope.yaml -e <engagement_id>
NEXUS_DASHBOARD_TOKEN="$DASH_TOKEN" nexus dashboard --host 127.0.0.1 --port 8477
```

## CLI Reference

| Command | Purpose | Key Options |
|---------|---------|-------------|
| `nexus init` | Detect CPU/RAM/GPU and save config | Writes `~/.nexus/config.yaml` |
| `nexus engage TARGET` | Run full engagement pipeline | `-n/--name`, `-s/--scope`, `-p/--profile`, `--stealth`, `--tier`, `--resume`, `-H/--header`, `--cookie`, `--auth-bearer`, `--login-url`, `--login-body`, `--openapi`, `--ignore`, `--ssh-user`, `--ssh-key`, `--local-audit`, `--no-exploit`, `-y/--yes`, `--unrestricted-scope` |
| `nexus recon TARGET` | Run reconnaissance phase only | `-s/--scope`, `-e/--engagement` |
| `nexus scan TARGET` | Run scanning phase on engagement | `-e/--engagement`, `-p/--profile`, `-H/--header`, `--cookie`, `--auth-bearer`, `--openapi`, `--ssh-user`, `--ssh-key`, `--local-audit` |
| `nexus exploit` | Run confirmation-gated exploitation | `-e/--engagement`, `-y/--yes` |
| `nexus report` | Export engagement report | `-e/--engagement`, `-f/--format` (`md`, `html`, `pdf`, `docx`, `json`, `sarif`), `-o/--output` |
| `nexus diff OLD NEW` | Compare two engagements | `-f/--format` (`table`, `json`), `--fail-on-new` |
| `nexus proxy` | Scoped mitmproxy passive capture | `--host`, `-p/--port`, `-s/--scope`, `-e/--engagement` |
| `nexus engagements` | Manage stored engagements | `list`, `show <id>`, `delete <id>` |
| `nexus kb` | Inspect and update knowledge base | `stats`, `search <query>`, `sync [--url]`, `import-kev <file>`, `import-nvd <file>` |
| `nexus ai` | Manage optional Ollama integration | `status`, `setup [--model ...]` |
| `nexus dashboard` | Start FastAPI dashboard and repeater | `--host`, `-p/--port`, `--token` |
| `nexus audit verify` | Verify SHA-256 audit log chain | Checks `~/.nexus/audit.jsonl` |
| `nexus version` | Print version and detected hardware | none |

## Scope and Safety Model

For `engage`, `recon`, `scan`, `exploit`, and the dashboard HTTP repeater, scope enforcement is fail-closed: omitting `--scope` restricts operations to the specified target host, IP, or CIDR. To scan without a target boundary inside an isolated lab, pass `--unrestricted-scope` or set `NEXUS_UNRESTRICTED_SCOPE=true`. For `nexus proxy`, pass `--scope scope.yaml` or `--engagement <id>`; if both are omitted, the proxy records intercepted traffic unfiltered.

Example `scope.yaml`:

```yaml
allowed_domains:
  - example.com
  - "*.example.com"
allowed_ips:
  - 10.0.0.5
allowed_cidrs:
  - 192.168.1.0/24
excluded_targets:
  - production.example.com
allowed_ports: [22, 80, 443, 8080]
notes: "Authorized assessment scope"
```

Active exploitation (`nexus exploit`, or `nexus engage` without `--no-exploit`) requires interactive confirmation unless `-y`/`--yes` or `NEXUS_AUTO_CONFIRM_EXPLOITS=true` is provided. Every action is appended to `~/.nexus/audit.jsonl` as a SHA-256 hash chain; `nexus audit verify` checks chain integrity and `AuditLogger(strict=True)` raises `AuditIntegrityError` if tampering or truncation is detected. Stored credential passwords and hashes are encrypted using `NEXUS_DB_KEY`; when unset, SQLite falls back to the OS keyring or a `0600` keyfile, while PostgreSQL falls back to the OS keyring or a DSN-derived key.

## Capabilities and Integrations

### Native Python Checks

These modules execute directly in Python without requiring external security binaries:

- TLS certificate validation, expiry checks, and negotiated protocol inspection (`nexus/scanner/tls.py` stdlib fallback; full cipher-suite audits use `sslyze` when installed).
- HTTP security headers, cookie flags, CORS, and CSP auditing (`headers.py`), alongside signature-verified exposure checks for `/.git`, `/.env`, Spring Actuator, and `/metrics` (`exposure.py`).
- Passive HTML/JS DAST, client-side secret extraction, GraphQL introspection, and auth-diff enforcement checks (`crawler.py`, `passive_dast.py`), plus OpenAPI/Swagger specification auditing (`openapi.py`).
- Declarative passive HTTP inspection driven by 110 YAML rules in `nexus/brain/knowledge/rules/` (`web_passive_rules.yaml` and `owasp_top100_passive.yaml`, covering 10 checks per OWASP Top 10:2021 category `A01`–`A10`).
- Native socket and HTTP probes for 12 network services: Redis, FTP, MongoDB, PostgreSQL, MySQL, SMTP, etcd, Consul, Kubelet, Elasticsearch, Docker API, and Memcached (`network_services.py`). (`SMB` checks via `nxc`/`netexec`/`nmap`, `SSH` audits via `ssh-audit`/`nmap`, and local/SSH `dpkg-query`/`rpm` package inventory via `host_audit.py` invoke external system tools.)

### Knowledge Base

- 1,841 indexed CVEs across bundled service YAMLs and compressed `cisa_kev_snapshot.json.gz`, updatable online or offline via `nexus kb sync`, `nexus kb import-kev`, and `nexus kb import-nvd`.
- 129 CWE and CVE remediation entries, 7 YAML attack-chain templates (46 graph nodes, 53 edges), 5 WAF profiles (`waf_bypass.py`), and 42 built-in default credential entries.

### Wrapped External Tools and Imports

External binaries are auto-detected on `PATH` and skipped gracefully if absent:

| Stage | Integrations |
|-------|--------------|
| Recon | `nmap`, `subfinder`, `amass`, `httpx` (`httpx-toolkit`), `whatweb`, `dnsx`, `dig`, `wafw00f`, `theHarvester` |
| Web / Network Scan | `nuclei`, `ffuf`, `nikto`, `katana`, `wpscan`, `sslyze`, `ssh-audit`, `nxc`/`netexec`, OWASP ZAP (`zap.sh`/`zaproxy`), `mitmproxy` (`nexus proxy`) |
| Exploit | `sqlmap`, `hydra`, `msfconsole` |
| Host & Import | `dpkg-query`/`rpm` (`host_audit.py`), Nessus XML, Burp Suite XML, CSV (`nexus/scanner/importer.py`) |

### Reporting and Dashboard

`nexus report` writes Markdown, self-contained HTML, PDF (`[report]`), DOCX (`[report]`), secret-redacted JSON, and SARIF 2.1.0. Launching `nexus dashboard` starts a FastAPI server with REST endpoints, WebSocket progress events, proxy history inspection/diffing, and a scope-enforced HTTP repeater; binding outside loopback requires a token via `NEXUS_DASHBOARD_TOKEN` (preferred) or `--token` (auto-generated if unset).

## Configuration and Environment Variables

Defaults are read from `~/.nexus/config.yaml` and overridden by `NEXUS_*` environment variables (note that `nexus engage` also applies CLI defaults `--profile full` and `--stealth medium` when omitted). Scan profiles (`quick`, `web`, `network`, `api`, `full`) select which recon and scanner modules execute; stealth levels (`off`, `low`, `medium`, `high`, `paranoid`) map to concurrency limits, request delays, User-Agent rotation, and target shuffling.

Hardware detection records a resource tier based on free RAM: `minimal` (< 2.5 GB), `light` (>= 2.5 GB), `standard` (>= 6 GB), and `full` (>= 12 GB). Core scanning and correlation behave identically across all tiers; optional Ollama analysis uses `NEXUS_MODEL` (default `dolphin-mistral`, with reference tier profiles documented in `nexus/ai/models.yaml`).

| Variable | Purpose | Default |
|----------|---------|---------|
| `NEXUS_DATA_DIR` | Runtime data and audit directory | `~/.nexus` |
| `NEXUS_DB_PATH` | SQLite database file path | `<NEXUS_DATA_DIR>/nexus.db` |
| `NEXUS_DB_URL` | PostgreSQL DSN for engine and dashboard commands (`postgresql://...`) | SQLite |
| `NEXUS_DB_KEY` | Encryption key for stored credentials | OS keyring / `0600` keyfile (SQLite) |
| `NEXUS_UNRESTRICTED_SCOPE` | Lab-only bypass for default target scope | `false` |
| `NEXUS_PROFILE` | Scan profile (`quick`/`web`/`network`/`api`/`full`) | `full` |
| `NEXUS_STEALTH` | Stealth level (`off`/`low`/`medium`/`high`/`paranoid`) | `medium` |
| `NEXUS_TIER` | Resource tier (`minimal`/`light`/`standard`/`full`) | auto-detected |
| `NEXUS_MAX_THREADS` | Maximum concurrent tasks (`>= 1`) | `5` |
| `NEXUS_OUTPUT_DIR` | Default report output directory | `./nexus_output` |
| `NEXUS_KNOWLEDGE_DIR` | Custom knowledge YAML directory | bundled |
| `NEXUS_IGNORE_FILE` | `.nexusignore` baseline suppression path | none |
| `NEXUS_LOCAL_PKG_AUDIT` | Enable read-only local OS package audit | `false` |
| `NEXUS_AUTO_CONFIRM_EXPLOITS` | Skip interactive exploit confirmation | `false` |
| `NEXUS_AUTH_LOGIN_URL` | Stateful login endpoint URL | none |
| `NEXUS_WPSCAN_API_TOKEN` | WPScan API token (also reads `WPSCAN_API_TOKEN`) | none |
| `NEXUS_DASHBOARD_TOKEN` | Dashboard Bearer / `X-Nexus-Token` secret | none |
| `NEXUS_ZAP_PATH` | OWASP ZAP executable path | `zap.sh` |
| `NEXUS_OLLAMA_HOST` | Optional Ollama API base URL | `http://127.0.0.1:11434` |
| `NEXUS_MODEL` | Optional Ollama model name | `dolphin-mistral` |

## Docker and CI

The `Dockerfile` builds Go/ProjectDiscovery tools (`subfinder`, `httpx`, `dnsx`, `nuclei`, `katana`, `ffuf`, `amass`), installs system security tools (`nmap`, `masscan`, `nikto`, `whatweb`, `wafw00f`, `sqlmap`, `hydra`), and installs `.[full]`. The container runs as the unprivileged `nexus` user with `NEXUS_DATA_DIR=/home/nexus/.nexus` and `ENTRYPOINT ["nexus"]`:

```bash
docker build -t nexus-pt .
docker run --rm -e NEXUS_OUTPUT_DIR=/work/out \
  -v "$PWD/scope.yaml:/work/scope.yaml:ro" -v "$PWD/out:/work/out" \
  nexus-pt engage example.com --scope /work/scope.yaml --no-exploit
```

For CI/CD pipelines, the composite GitHub Action in `action.yml` runs scoped scans (`quick`, `web`, `network`, `api`, or `full`), emits SARIF 2.1.0 for GitHub Code Scanning, and enforces `nexus diff --fail-on-new` regression gates against an optional `baseline_id`. A manual `workflow_dispatch` example is included in `.github/workflows/nexus-reusable-scan.yml`.

## Package Structure

```text
nexus/
├── ai/          # Optional Ollama client, prompt templates, hallucination guard, models.yaml
├── brain/       # Rule engine, CVE/KEV graph, Dijkstra chains, TF-IDF search, YAML rules & KB
├── cli/         # Click CLI commands and Rich terminal output
├── core/        # Config, hardware detection, scope enforcer, hash-chained audit, engine, phases
├── correlator/  # Deduplication, CVSS/CWE/OWASP enrichment, baselines, engagement diff
├── dashboard/   # Optional FastAPI REST API, WebSocket events, proxy history, HTTP repeater
├── db/          # Pydantic models, SQLite store, optional PostgreSQL backend
├── exploit/     # Confirmation-gated executor, sqlmap, hydra/default creds, Metasploit bridge
├── plugins/     # Built-in and community plugin loader
├── recon/       # Subprocess runner and subdomain, DNS, port, tech, WAF, OSINT wrappers
├── reporter/    # Markdown, HTML, PDF, DOCX, JSON, and SARIF 2.1.0 generators
├── scanner/     # Native TLS/SSH/HTTP/exposure/service checks, ZAP, nuclei, proxy, importers
├── stealth/     # Rate limiting, jitter, User-Agent rotation, target shuffling
└── main.py      # CLI entry point (nexus.main:cli)
```

## Development and Tests

```bash
pip install -e ".[dev,dashboard,report]"
pytest tests/ -v
ruff check nexus/ tests/
ruff format --check nexus/ tests/
```

## Authorized Use and License

NEXUS is intended strictly for authorized security testing and defensive verification. Obtain explicit authorization before scanning or testing any target system.

Licensed under the [MIT License](LICENSE).
