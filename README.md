# CyberLLM

**LLM-powered security analysis platform** for logs, alerts, threat intelligence, and defensive security investigations.

Transform raw security telemetry into structured, analyst-ready intelligence — without standing up a 20-service SOC platform. CyberLLM is lightweight, local-first, and designed for individual analysts and small teams who need to investigate, triage, and report on security events quickly.

## Problem

Security teams drown in alerts. Raw logs from firewalls, endpoints, and SIEMs are unstructured and noisy. Existing options force a choice between heavy monolithic SOC platforms (hard to deploy, hard to maintain) and one-off CLI scripts (no reporting, no enrichment, no persistence). There's no lightweight, open-source middle ground that lets an analyst ingest a log file, get an LLM-powered analysis with MITRE ATT&CK mapping and remediation guidance, enrich indicators with threat intel, and export a shareable report — all with a single command.

## Features

| Category | Capability |
|----------|------------|
| **Log ingestion** | Parse JSON, syslog, Apache/Nginx access logs, and Windows Event logs into a common schema |
| **LLM analysis** | Structured threat analysis (summary, severity, confidence, MITRE mapping, remediation) via local Ollama or OpenAI-compatible APIs |
| **Threat intel** | Enrich IP addresses and domains with reputation data (VirusTotal, AbuseIPDB, or local allow/block lists) |
| **Human-in-the-loop** | Analysts can override LLM findings; corrections are saved as few-shot examples for continuous improvement |
| **Reporting** | Export Markdown, JSON, or SIEM-ready incident reports |
| **CLI-first** | `cyberllm analyze <logfile>` — works in terminals, CI/CD, and automation |
| **Local-first** | Runs fully offline with Ollama; no cloud API keys required |
| **Config-driven** | Environment-based configuration via `.env` + `config.yaml` |

## Quick Start

```bash
# Clone
git clone https://github.com/danishkumar26/cyberllm.git
cd cyberllm

# Install
pip install -e .

# Configure
cp .env.example .env
# Edit .env with your LLM provider (OLLAMA_BASE_URL, OPENAI_API_KEY, etc.)

# Analyze a log file
cyberllm analyze samples/auth.log --provider ollama --model llama3.2

# Export a report
cyberllm analyze samples/auth.log --format markdown --out report.md
```

## Installation

### From source (recommended)

```bash
git clone https://github.com/danishkumar26/cyberllm.git
cd cyberllm
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
# Edit .env to set your LLM provider
```

### With Docker

```bash
docker compose up -d
docker exec -it cyberllm cyberllm analyze /logs/auth.log
```

## Usage

```bash
# Analyze a single log file with Ollama (local, no API key)
cyberllm analyze /var/log/auth.log --provider ollama --model llama3.2

# Analyze with OpenAI
CYBERLLM_PROVIDER=openai CYBERLLM_MODEL=gpt-4o cyberllm analyze alerts.json

# Batch-analyze a directory of logs
cyberllm analyze ./logs/ --recursive --format json --out results.json

# Enrich with threat intelligence
cyberllm analyze auth.log --enable-ti --ti-provider virustotal

# Generate a SIEM-ready incident report
cyberllm analyze auth.log --format siem --out incident.json
```

See `config.yaml.example` for all available options.

## Project Structure

```
cyberllm/
├── src/cyberllm/          # Core package
│   ├── cli.py              # Typer CLI entrypoint
│   ├── config.py           # Settings (env + yaml)
│   ├── analyzer.py         # LLM analysis engine
│   ├── parsers.py          # Log parsers (syslog, JSON, Apache, Windows)
│   ├── enrichment.py       # Threat intel enrichment
│   ├── mitre.py            # MITRE ATT&CK technique mapping
│   ├── reporter.py         # Markdown/JSON/SIEM report generation
│   └── providers/          # LLM provider abstractions
│       ├── base.py
│       ├── ollama.py
│       └── openai.py
├── tests/                  # pytest suite
├── samples/                # Example log files
├── config.yaml.example     # Configuration template
├── .env.example            # Environment variable template
├── Dockerfile              # Container build
├── docker-compose.yml      # Multi-container deploy
├── pyproject.toml          # Package metadata & dependencies
└── .github/workflows/ci.yml# Test + lint on every push
```

## Configuration

Copy `.env.example` to `.env` and set at minimum:

| Variable | Purpose | Default |
|----------|---------|---------|
| `CYBERLLM_PROVIDER` | LLM provider: `ollama` or `openai` | `ollama` |
| `CYBERLLM_MODEL` | Model name | `llama3.2` |
| `OLLAMA_BASE_URL` | Ollama endpoint | `http://localhost:11434` |
| `OPENAI_API_KEY` | OpenAI API key (if provider=openai) | — |
| `CYBERLLM_ENABLE_TI` | Enable threat intel enrichment | `false` |
| `VT_API_KEY` | VirusTotal API key (optional) | — |

See `config.yaml.example` for parser, enrichment, and reporting settings.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Log files │────▶│  Parsers (syslog │────▶│   Analyzer      │
│  (auth.log, │     │   JSON, Apache)  │     │   (LLM)         │
│   JSON)     │     └──────────────────┘     │  - Summary      │
└─────────────┘                              │  - Severity     │
                                             │  - MITRE ATT&CK │
                                             │  - Remediation  │
                                             └────────┬────────┘
                                                      │
                          ┌───────────────────────────┴───────────────────────────┐
                                                      ▼
                                              ┌─────────────────┐
                                              │   Enrichment    │◀── Threat Intel APIs
                                              │   (IP/domain)   │    (VirusTotal, etc.)
                                              └────────┬────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │   Reporter      │◀── Analyst override (human-in-loop)
                                              │  MD / JSON /    │
                                              │   SIEM          │
                                              └─────────────────┘
```

## Testing

```bash
pytest
```

CI runs `pytest` + `ruff` on every push via GitHub Actions.

## Roadmap

- [x] v0.1.0 — CLI scaffold: log parsing, Ollama/OpenAI providers, Markdown/JSON reports
- [ ] v0.2.0 — Threat intel enrichment (VirusTotal, AbuseIPDB, local lists)
- [ ] v0.3.0 — MITRE ATT&CK technique mapping with confidence scoring
- [ ] v0.4.0 — Human-in-the-loop: analyst corrections saved as few-shot examples
- [ ] v0.5.0 — FastAPI web UI for interactive investigation
- [ ] v1.0.0 — Stable release, Docker image, SIEM webhook output

## License

MIT License. See [LICENSE](LICENSE).

## Author

Built by [danishkumar26](https://github.com/danishkumar26) — Cybersecurity | AI Engineering | Intelligent Automation | Backend Systems.

---

*Operate only within explicitly authorized environments, owned systems, or designated security labs. Never perform unauthorized access, credential theft, or destructive activity.*