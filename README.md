# Auto-pen

LLM-powered automated penetration testing tool.

## Overview

Auto-pen is an autonomous pentest agent that uses a ReAct (Reason + Act) loop to drive industry-standard security tools via an LLM backend. It supports multiple LLM providers (Ollama, OpenAI, Anthropic) and wraps tools such as nmap, gobuster, nikto, sqlmap, hydra, metasploit, and more.

## Features

- **ReAct agent loop** — LLM reasons about findings and selects the next tool automatically
- **Scope enforcement** — hard IP/CIDR/domain scope checks with wildcard support
- **Human confirmation gate** — configurable risk thresholds require operator approval
- **Multiple LLM backends** — Ollama (local), OpenAI, Anthropic
- **CVE enrichment** — automatic CVE lookup and CVSS scoring
- **Passive recon tools** — whois, dig, whatweb, DuckDuckGo search
- **Web GUI** — Next.js dashboard with real-time WebSocket updates
- **REST API** — FastAPI server for programmatic control
- **Offline mode** — enforce local-only Ollama provider for air-gapped environments

## Installation

```bash
pip install -e ".[dev]"
```

## Quick Start

```bash
# Start a web scan using a local Ollama model
auto-pen scan --target https://example.com \
              --profile web \
              --auth-token "I have written authorization to test example.com" \
              --llm ollama/llama3.1

# List sessions
auto-pen sessions list

# Generate a report
auto-pen report <session-id> --format markdown
```

## Scan Profiles

| Profile   | Description                          |
|-----------|--------------------------------------|
| `web`     | HTTP/HTTPS application testing       |
| `network` | Infrastructure / port scanning       |
| `cloud`   | Cloud service enumeration            |
| `ctf`     | CTF / lab environment (permissive)   |

## Tools

| Tool        | Risk    | Description                          |
|-------------|---------|--------------------------------------|
| nmap        | MEDIUM  | Port scanning & service detection    |
| gobuster    | MEDIUM  | Directory/file brute-forcing         |
| ffuf        | MEDIUM  | Fast web fuzzer                      |
| nikto       | MEDIUM  | Web server vulnerability scanner     |
| sqlmap      | HIGH    | SQL injection exploitation           |
| hydra       | HIGH    | Network login brute-forcer           |
| nuclei      | MEDIUM  | Template-based vulnerability scanner |
| metasploit  | CRITICAL| Exploitation framework               |
| whois       | LOW     | Domain registration lookup           |
| dig         | LOW     | DNS lookup                           |
| whatweb     | LOW     | Web technology fingerprinting        |

## Development

```bash
# Run tests
pytest

# Lint
ruff check src/

# Type check
mypy src/
```

## Legal

Auto-pen must only be used against systems you own or have explicit written authorization to test. Unauthorized penetration testing is illegal and unethical.
