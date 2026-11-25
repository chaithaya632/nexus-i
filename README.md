# NEXUS — Network EXploration & Unified Security

> AI-Optional Autonomous Penetration Testing Framework for Linux

```
 ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
 ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
 ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
 ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
 ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

## What is NEXUS?

NEXUS is an **open-source, AI-optional** autonomous penetration testing framework designed for **Kali Linux** and all Linux distributions. It wraps 25+ existing security tools into a unified engine with:

- **500MB Expert System** — Rule engine + CVE knowledge graph + Dijkstra attack chain builder. Zero AI, zero GPU, fully functional on 2GB RAM.
- **100% Free** — No paid tools, no subscriptions, no cloud dependencies.
- **AI is Optional** — Works perfectly without any LLM. When you want AI, it uses uncensored local models (dolphin-mistral, WhiteRabbitNeo) via Ollama that never refuse security tasks.
- **4-Tier Resource System** — Runs on everything from 2GB VMs to 12GB+ workstations.
- **One-Click Reports** — Professional PDF/HTML/DOCX/Markdown pentest reports.
- **Web Dashboard** — Real-time engagement monitoring with live WebSocket updates.

## Quick Start

### Install

```bash
# Clone
git clone https://github.com/nexus-pt/nexus.git
cd nexus

# Install (core only — no heavy dependencies)
pip install -e .

# With all extras
pip install -e ".[full]"

# Or pick what you need
pip install -e ".[dashboard]"    # FastAPI web dashboard
pip install -e ".[report]"       # PDF + DOCX report generation
pip install -e ".[ai]"           # Ollama AI boost
pip install -e ".[dev]"          # pytest, ruff, coverage
```

### First Run

```bash
# Detect hardware and auto-configure
nexus init

# Run a full engagement (Recon → Scan → Correlate → Exploit → Report)
nexus engage example.com --scope scope.yaml --profile full

# Fast DevSecOps / authenticated Web+API check with OpenAPI, baseline ignore & resume
nexus engage api.example.com --scope scope.yaml --profile api --openapi openapi.yaml --auth-bearer "$TOKEN" --ignore .nexusignore
nexus engage --resume <engagement_id>

# Recon only
nexus recon example.com

# Scan an existing engagement (custom headers, cookies, profile)
nexus scan example.com -e <engagement_id> --profile web -H "X-Env: staging" --cookie "session=..."

# Exploit
nexus exploit -e <engagement_id>

# Generate report (md, html, pdf, docx, json, sarif)
nexus report -e <engagement_id> -f html
nexus report -e <engagement_id> -f sarif -o results.sarif

# Diff two runs as a CI/CD regression gate
nexus diff <baseline_eng_id> <current_eng_id> --fail-on-new critical,high

# Check brain stats
nexus kb stats

# Search knowledge base
nexus kb search "log4j"

# List past engagements
nexus engagements list

# Show engagement details
nexus engagements show <engagement_id>

# Launch web dashboard
nexus dashboard

# AI status (optional)
nexus ai status
```

### Scope File (scope.yaml)

```yaml
allowed_domains:
  - example.com
  - "*.example.com"
allowed_ips:
  - 10.0.0.1
  - 10.0.0.5
allowed_cidrs:
  - 192.168.1.0/24
excluded_targets:
  - production.example.com
allowed_ports:
  - 80
  - 443
  - 8080
  - 22
notes: "Authorized pentest — contract #12345"
```

## Features

### 🔍 Reconnaissance (Phase 1)
- **Subdomain Enumeration** — subfinder + amass with dedup merge
- **DNS Resolution** — dnsx + dig zone transfer detection
- **Port Scanning** — nmap with stealth-aware scan profiles
- **Tech Fingerprinting** — httpx + whatweb
- **WAF Detection** — wafw00f with bypass technique library
- **OSINT Gathering** — theHarvester email/host enumeration

### 🔎 Scanning (Phase 2)
- **Vulnerability Scanning** — Nuclei JSONL parser, severity filtering
- **Directory Brute-Force** — ffuf with stealth-aware concurrency
- **Web Server Scanning** — Nikto CSV parser
- **Import External Scans** — Nessus XML, Burp XML, CSV importers

### 🔗 Correlation (Phase 3)
- **Finding Deduplication** — Merge across tools by (host, port, CWE/title)
- **CVSS/CWE Enrichment** — Normalize severities, map OWASP categories
- **Attack Chain Building** — Graph-based Dijkstra pathfinding from findings

### 💥 Exploitation (Phase 4)
- **SQL Injection** — sqlmap wrapper with injection point parsing
- **Default Credentials** — hydra + built-in credential database (42+ services)
- **Metasploit Bridge** — msfconsole integration (optional)
- **Scope-Enforced Execution** — Every action checked against scope + audit-logged

### 🛡️ Stealth (Phase 4)
- **4 Stealth Profiles** — Loud / Normal / Quiet / Ghost
- **Rate Limiting** — Automatic delay injection per stealth level
- **User-Agent Rotation** — Randomized browser fingerprints
- **Target Shuffling** — Randomized scan order in ghost mode
- **Semaphore Concurrency** — Stealth-aware parallel execution limits

### 📊 Reporting (Phase 4)
- **Markdown** — Full report with TOC, severity badges, evidence blocks
- **HTML** — Self-contained dark-themed report with CSS, risk grid, finding cards
- **PDF** — via WeasyPrint (optional dependency)
- **DOCX** — via python-docx (optional dependency)
- **JSON** — Raw data export

### 🤖 AI Boost Layer (Phase 5) — 100% Optional
- **Finding Enhancement** — AI analysis of critical/high findings
- **Attack Chain Analysis** — AI assessment of chain feasibility
- **Executive Summaries** — AI-written professional summaries
- **Exploit Suggestions** — AI-guided exploitation approaches
- **Hallucination Guard** — Cross-checks AI output against expert system KB
- **Recommended Models** — dolphin-mistral, WhiteRabbitNeo, qwen2.5

### 📡 Web Dashboard (Phase 6) — Optional
- **REST API** — FastAPI endpoints for engagements, findings, targets, chains
- **WebSocket** — Live event streaming during engagements
- **Single-Page App** — Dark-themed SPA with severity charts and finding tables
- **Zero Config** — `nexus dashboard` and open http://127.0.0.1:8477

## Resource Tiers

| Tier | RAM | AI | Use Case |
|------|-----|----|----------|
| **Minimal** | 2 GB | None | Expert System only — full functionality |
| **Light** | 4 GB | qwen2.5:0.5b | Small AI boost for report writing |
| **Standard** | 6 GB | dolphin-mistral 7B | Full AI analysis, uncensored |
| **Full** | 12 GB+ | dolphin-llama3 | Maximum AI — best reasoning quality |

## Architecture

```
nexus/
├── core/           # Config, hardware detection, scope enforcement, audit, scheduler
│   ├── config.py       — YAML + env var config with Pydantic
│   ├── hardware.py     — Linux hardware detection, auto tier selection
│   ├── scope.py        — Non-bypassable scope enforcement
│   ├── audit.py        — Hash-chained immutable audit trail
│   ├── scheduler.py    — Async parallel task execution
│   └── engine.py       — Central orchestrator (all phases wired)
├── brain/          # 500MB Expert System (zero AI)
│   ├── expert.py       — Forward-chaining production rule engine
│   ├── knowledge_graph.py — CVE→Exploit YAML mappings
│   ├── chain_builder.py   — Dijkstra attack chain pathfinding
│   ├── vector_search.py   — TF-IDF fuzzy vulnerability matching
│   ├── router.py       — Service-to-tool routing rules
│   ├── credentials.py  — Default credential database (42+ services)
│   ├── waf_bypass.py   — WAF detection and bypass techniques
│   ├── taxonomy.py     — OWASP/CWE mapping
│   ├── payloads.py     — PoC payload templates with encoders
│   ├── remediation.py  — Per-CWE/CVE fix guidance
│   └── knowledge/      — YAML knowledge base files
├── ai/             # Optional AI boost
│   ├── ollama_client.py — Ollama REST client
│   ├── boost.py        — AI enhancement layer with silent fallback
│   ├── prompts.py      — Security analysis prompt templates
│   ├── guard.py        — Hallucination detection + CVE validation
│   └── models.yaml     — Recommended model configs per tier
├── recon/          # Reconnaissance tool wrappers
│   ├── subdomains.py   — subfinder + amass
│   ├── ports.py        — nmap XML parser
│   ├── tech.py         — httpx + whatweb
│   ├── dns.py          — dnsx + dig zone transfer
│   ├── waf.py          — wafw00f WAF detection
│   └── osint.py        — theHarvester
├── scanner/        # Vulnerability scanners
│   ├── nuclei.py       — Nuclei JSONL parser
│   ├── web.py          — ffuf directory brute-force
│   ├── nikto.py        — Nikto CSV parser
│   └── importer.py     — Nessus/Burp/CSV importers
├── correlator/     # Finding correlation engine
│   ├── dedup.py        — Cross-tool deduplication
│   ├── enrichment.py   — CVSS/CWE/OWASP enrichment
│   ├── graph.py        — Attack chain graph builder
│   └── engine.py       — Full correlation pipeline
├── exploit/        # Exploitation modules
│   ├── executor.py     — Scope-enforced exploit runner
│   ├── sqli.py         — sqlmap wrapper
│   ├── credential.py   — hydra + default cred testing
│   └── msf_bridge.py   — Metasploit msfconsole bridge
├── stealth/        # Evasion controller
│   └── controller.py   — Rate limiting, UA rotation, target shuffling
├── reporter/       # Multi-format report generation
│   ├── generator.py    — Report orchestrator
│   ├── markdown.py     — Markdown renderer
│   ├── html.py         — Self-contained HTML renderer
│   ├── pdf.py          — WeasyPrint PDF (optional)
│   └── docx.py         — python-docx DOCX (optional)
├── dashboard/      # Optional FastAPI web dashboard
│   ├── app.py          — REST API + WebSocket + SPA
│   └── static/         — Frontend HTML/JS/CSS
├── cli/            # Click CLI + Rich TUI
│   ├── commands.py     — All CLI commands
│   └── tui.py          — Rich terminal UI
├── db/             # SQLite persistence
│   ├── models.py       — Pydantic data models
│   └── store.py        — CRUD operations
└── plugins/        # Plugin system
```

## Wrapped Tools

NEXUS wraps these Kali tools (all auto-detected, graceful fallback when missing):

| Category | Tools |
|----------|-------|
| **Recon** | nmap, subfinder, amass, httpx, whatweb, dnsx, dig, wafw00f, theHarvester |
| **Scanning** | nuclei, ffuf, nikto |
| **Exploitation** | sqlmap, hydra, msfconsole |
| **Import** | Nessus XML, Burp Suite XML, CSV |

## AI Setup (Optional)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a recommended model
nexus ai setup --model dolphin-mistral    # 7B, uncensored, ~4GB
nexus ai setup --model qwen2.5:0.5b      # Tiny, 500MB, basic
nexus ai setup --model whiterabbitneo     # Security-focused, ~4GB

# Check status
nexus ai status
```

The AI boost layer enhances (never replaces) the expert system:
- Adds AI analysis to critical/high findings
- Generates AI-written executive summaries
- Suggests exploitation approaches
- All AI output is cross-checked against the knowledge base (hallucination guard)

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEXUS_DATA_DIR` | Data directory | `~/.nexus` |
| `NEXUS_DB_PATH` | Database path | `~/.nexus/nexus.db` |
| `NEXUS_STEALTH` | Stealth level (off/low/medium/high/paranoid) | `medium` |
| `NEXUS_TIER` | Resource tier (minimal/light/standard/full) | auto-detected |
| `NEXUS_OLLAMA_HOST` | Ollama API endpoint | `http://127.0.0.1:11434` |
| `NEXUS_MODEL` | AI model name | `dolphin-mistral` |
| `NEXUS_MAX_THREADS` | Max concurrent tasks | `5` |
| `NEXUS_OUTPUT_DIR` | Report output directory | `./nexus_output` |

## Development

```bash
# Install all dev dependencies
pip install -e ".[dev,dashboard,report,ml]"

# Run all tests
pytest tests/ -v

# Run specific test suites
pytest tests/test_core/ -v         # Core engine tests
pytest tests/test_brain/ -v        # Expert system tests
pytest tests/test_recon/ -v        # Recon wrapper tests
pytest tests/test_scanner/ -v      # Scanner tests
pytest tests/test_correlator/ -v   # Correlation tests
pytest tests/test_exploit/ -v      # Exploit tests
pytest tests/test_stealth/ -v      # Stealth tests
pytest tests/test_reporter/ -v     # Reporter tests
pytest tests/test_ai/ -v           # AI boost tests
pytest tests/test_dashboard/ -v    # Dashboard tests

# Lint
ruff check nexus/

# Format
ruff format nexus/
```

## Legal Disclaimer

NEXUS is designed for **authorized security testing only**. Every action is scope-enforced and audit-logged with hash-chained integrity. Unauthorized access to computer systems is illegal. Always obtain proper written authorization before testing.

## License

MIT
