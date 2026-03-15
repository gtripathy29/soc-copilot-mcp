# SOC Copilot MCP

> An AI-native security investigation assistant that correlates multi-source threat intelligence, maps to MITRE ATT&CK, and generates incident reports — replacing 2 hours of analyst work with a single prompt.

---

## What Makes This Different

Most threat intel MCPs on GitHub are single-API wrappers (just VirusTotal or just Shodan). SOC Copilot is different:

| Feature | Basic Threat Intel MCP | SOC Copilot |
|---------|----------------------|-------------|
| VirusTotal lookup | ✅ | ✅ |
| AbuseIPDB check | ✅ | ✅ |
| Shodan search | ✅ | ✅ |
| **Cross-source correlation** | ❌ | ✅ |
| **Conflict detection** | ❌ | ✅ |
| **MITRE ATT&CK mapping** | ❌ | ✅ |
| **YARA rule generation** | ❌ | ✅ |
| **IR report drafting** | ❌ | ✅ |
| **Lookalike domain hunting** | ❌ | ✅ |
| **CVE exploitability (NVD + Shodan)** | ❌ | ✅ |
| **Full investigation orchestration** | ❌ | ✅ |

---

## Tools (15 total)

### VirusTotal
- `vt_check_ip` — IP threat lookup
- `vt_check_domain` — Domain threat lookup  
- `vt_check_file_hash` — File hash lookup (MD5/SHA1/SHA256)

### AbuseIPDB
- `abuseipdb_check_ip` — Abuse score + report history
- `abuseipdb_report_ip` — Submit abuse reports

### Shodan
- `shodan_lookup_ip` — Full host intelligence
- `shodan_search` — Internet-wide device search
- `shodan_get_exploits` — Public exploit database

### Correlation & Intelligence ⭐ New
- `correlate_ioc` — Fans out to ALL sources, reconciles conflicts, returns unified threat score
- `map_to_mitre` — Maps any threat description to MITRE ATT&CK techniques

### Analyst Workflow ⭐ New
- `generate_yara_rule` — Hash → deployable YARA detection rule
- `draft_ir_report` — IOC list → professional IR report for management
- `hunt_lookalike_domains` — Detects typosquatting / phishing domains
- `check_cve_exploitability` — CVE CVSS score + live internet exposure count
- `full_investigation` — One call → complete analyst brief across all tools

---

## Quick Start

### 1. Clone and install

```bash
git clone <your-repo-url>
cd soc-copilot
pip install -r requirements.txt
```

### 2. Configure API keys

```bash
cp .env.example .env
# Edit .env and add your API keys:
# - VIRUSTOTAL_API_KEY  (https://www.virustotal.com)
# - ABUSEIPDB_API_KEY   (https://www.abuseipdb.com)
# - SHODAN_API_KEY      (https://shodan.io)
```

### 3. Run the web server

```bash
python http_server.py
```

Open **http://localhost:8000** in your browser.

### 4. Use the web client

1. Enter your **Anthropic API key** (starts with `sk-ant-`)
2. Click **Connect**
3. Start investigating:
   - *"Investigate IP 1.2.3.4"*
   - *"Is this hash malicious: abc123..."*
   - *"Check CVE-2021-44228 exploitability"*
   - *"Hunt lookalike domains for company.com"*
   - *"Draft an IR report for these IOCs: ..."*

---

## Running the MCP Server (stdio mode)

For use with Claude Desktop or other MCP clients:

```bash
python server.py
```

Claude Desktop config (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "soc-copilot": {
      "command": "python",
      "args": ["/path/to/soc-copilot/server.py"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_key",
        "ABUSEIPDB_API_KEY": "your_key",
        "SHODAN_API_KEY": "your_key"
      }
    }
  }
}
```

---

## Project Structure

```
soc-copilot/
├── server.py           # MCP server (FastMCP, stdio transport)
├── http_server.py      # HTTP server (web UI + REST tool proxy)
├── requirements.txt
├── .env.example
├── tools/
│   ├── virustotal.py   # VirusTotal API client
│   ├── abuseipdb.py    # AbuseIPDB API client
│   ├── shodan.py       # Shodan API client
│   ├── correlation.py  # Cross-source correlation + MITRE mapping ⭐
│   ├── analyst_tools.py # YARA + IR report generation ⭐
│   ├── hunting.py      # Lookalike domains + CVE exploitability ⭐
│   └── orchestrator.py # Full investigation orchestration ⭐
├── utils/
│   └── formatter.py    # Shared output formatting
└── static/
    └── index.html      # Web client (single-file, no build step)
```

---

## Example Prompts

```
Investigate these IOCs: 1.2.3.4, evil-domain.com, CVE-2021-44228

Is 8.8.8.8 malicious? Check all sources.

Generate a YARA rule for hash: 44d88612fea8a8f36de82e1278abb02f

Hunt for typosquatting domains targeting paypal.com

Check if Log4Shell (CVE-2021-44228) is still widely exploitable

Map this attack to MITRE ATT&CK: SSH brute force followed by data exfiltration

Draft an incident response report for a phishing campaign using domain fake-login.company.com
```

---

## Architecture

```
Browser (Web Client)
    │  Anthropic API key (user-provided)
    │  Natural language query
    ▼
Claude API (claude-sonnet-4)
    │  Tool-use / function calling
    ▼
HTTP Server (http_server.py, port 8000)
    │  REST: POST /tools/{tool_name}
    ▼
MCP Tools (15 tools across 5 categories)
    │
    ├── VirusTotal API
    ├── AbuseIPDB API
    ├── Shodan API
    ├── NVD (CVE data, no key required)
    └── DNS Google (lookalike domain resolution)
```

---

## Market Analysis

See the attached PDF for the full one-page market analysis covering:
- Target market: Enterprise SOC teams, MSSPs, threat intelligence analysts
- Value proposition: Replaces 2 hours of analyst investigation with a single prompt
- Revenue model: SaaS subscription per analyst seat ($200-500/month)
- Disruption potential: Tier-1 SOC analyst automation ($50B+ market)
