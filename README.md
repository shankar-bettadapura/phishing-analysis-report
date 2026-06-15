# Phishing Analysis Report

**Automated Email Header Parsing, IOC Extraction, Threat Intelligence Enrichment, and Dual-Format Report Generation**

A Python command-line tool that ingests a raw `.eml` file, parses headers and body content across a five-module pipeline, extracts indicators of compromise across four types, cross-references them against open-source threat intelligence feeds, and produces two professional deliverables simultaneously: a dark-themed HTML triage report and a four-sheet Excel workbook.

---

## What It Does

Most phishing triage workflows treat detection as a visual exercise — check the sender address, hover over links, exercise caution with attachments. The forensic evidence that exposes a phishing campaign reliably is not in the visible layer of the email but in the technical layer beneath it: the authentication results written by the receiving mail server, the originating IP embedded in the headers, the domains embedded in both the visible body and the raw HTML source, and the cryptographic fingerprints of any attached files. This tool automates the systematic extraction and enrichment of that technical layer.

---

## Features

- **Full email parsing** — headers, SPF/DKIM/DMARC authentication results, Received chain hop analysis, plain text and HTML body, and attachment metadata with SHA256 hashing
- **IOC extraction** — URLs, IP addresses, domains, and file hashes extracted from headers and body; all IOCs defanged for safe display (`hxxp://`, `[.]`)
- **Threat intelligence enrichment** — queries AlienVault OTX (IPs and domains), AbuseIPDB (IPs), and URLhaus (URLs and SHA256 hashes)
- **Verdict scoring** — CLEAN / SUSPICIOUS / MALICIOUS per IOC based on how many sources flagged it; UNKNOWN when no enrichment data is available
- **HTML report** — dark-themed single-file output with overall verdict banner, IOC summary tiles, header analysis table with colour-coded authentication badges, per-IOC enrichment results table, and attachment register
- **Excel workbook** — four worksheets: Executive Summary, Header Analysis, IOC Verdicts, and Raw IOC Register; colour-coded by verdict and authentication result
- **Offline mode** — `--no-enrichment` flag skips all API calls for fast air-gapped parsing

---

## Architecture

```
phishing-analysis-report/
├── main.py                     CLI entry point and pipeline orchestrator
├── parsers/
│   └── email_parser.py         .eml ingestion, MIME tree traversal, header and attachment extraction
├── ioc/
│   └── extractor.py            Regex-based IOC extraction with defanging and deduplication
├── enrichment/
│   └── engine.py               OTX, AbuseIPDB, and URLhaus API clients with verdict scoring
├── reports/
│   ├── html_report.py          Dark-themed HTML report generator
│   └── excel_report.py         Four-sheet openpyxl workbook generator
├── sample_emails/
│   └── phishing_sample.eml     Synthetic PayPal impersonation email for testing
├── requirements.txt
└── README.md
```

---

## Pipeline

```
.eml file
    ↓
email_parser.py    Structures the raw email into headers, auth results, body, attachments
    ↓
extractor.py       Mines the parsed dict for URLs, IPs, domains, and hashes; defangs all IOCs
    ↓
engine.py          Queries each IOC against OTX, AbuseIPDB, and URLhaus; assigns verdicts
    ↓
html_report.py     Generates dark-themed HTML triage report
excel_report.py    Generates four-sheet Excel workbook
```

---

## Data Sources

| Source | IOC Types | Authentication |
|---|---|---|
| AlienVault OTX | IP, Domain | API key (free) |
| AbuseIPDB | IP | API key (free) |
| URLhaus | URL, SHA256 Hash | None required |

---

## Verdict Logic

| Verdict | Condition |
|---|---|
| CLEAN | Zero sources flagged the IOC |
| SUSPICIOUS | Exactly one source flagged the IOC |
| MALICIOUS | Two or more sources flagged the IOC |
| UNKNOWN | No enrichment data available (missing API key or no sources configured for this IOC type) |

AbuseIPDB confidence threshold: 25/100. OTX flags any IOC with at least one threat pulse. URLhaus flags any URL with online or unknown status, and any hash present in the payload database.

---

## Setup

**1. Clone the repository**
```bash
git clone https://github.com/shankar-bettadapura/phishing-analysis-report.git
cd phishing-analysis-report
```

**2. Create and activate a virtual environment**
```bash
# Mac/Linux
python -m venv venv && source venv/bin/activate

# Windows
python -m venv venv && venv\Scripts\activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Add API keys to a `.env` file in the project root**
```
OTX_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

Free API keys:
- AlienVault OTX: https://otx.alienvault.com — Settings → API Integration
- AbuseIPDB: https://www.abuseipdb.com — Account → API

---

## Usage

```bash
# Full analysis with live TI enrichment
python main.py sample_emails/phishing_sample.eml --org "Your Organisation"

# Offline mode — parsing and IOC extraction only, no API calls
python main.py sample_emails/phishing_sample.eml --no-enrichment

# Custom output directory
python main.py /path/to/email.eml --output /path/to/reports/ --org "Your Organisation"
```

| Argument | Description |
|---|---|
| `email` | Path to `.eml` file (required) |
| `--output` | Output directory for reports (default: `reports/`) |
| `--org` | Organisation name used in report headers |
| `--no-enrichment` | Skip TI enrichment — faster, works offline |

---

## Sample Output

```
[*] Phishing Analysis Report
    File    : sample_emails/phishing_sample.eml
    Time    : 2026-06-15 03:24 UTC
    Org     : Portfolio Demo

[1/4] Parsing email headers and body...
      From        : PayPal Security <security@paypal.com>
      Subject     : Urgent: Your PayPal account has been limited
      Auth        : SPF=fail  DKIM=fail  DMARC=fail

[2/4] Extracting IOCs...
      URLs    : 5
      IPs     : 2
      Domains : 7
      Hashes  : 2
      Total   : 16 IOCs extracted

[3/4] Enriching IOCs against threat intelligence feeds...
      MALICIOUS  : 0
      SUSPICIOUS : 2
      CLEAN      : 14

[4/4] Generating reports...
      HTML  -> reports/Phishing_Report_Urgent__Your_PayPal_account_ha_20260615.html
      Excel -> reports/Phishing_Report_Urgent__Your_PayPal_account_ha_20260615.xlsx

[+] Analysis complete.
```

---

## IOC Defanging Reference

| Type | Raw | Defanged |
|---|---|---|
| URL | `http://evil.ru/payload` | `hxxp://evil[.]ru/payload` |
| IP | `185.220.101.45` | `185[.]220[.]101[.]45` |
| Domain | `paypa1-verify.ru` | `paypa1-verify[.]ru` |
| Hash | `a3f4b2c1...` | `a3f4b2c1...` (unchanged) |

---

## Architecture Lineage

This tool is the third in a connected pipeline of Python security tools:

- **IOC enrichment and verdict scoring** → [Threat Intelligence Aggregator](https://github.com/shankar-bettadapura/threat-intel-aggregator) (Project 5)
- **Excel workbook generation via openpyxl** → [GRC Control Gap Analyzer](https://github.com/shankar-bettadapura/grc-control-gap-analyzer) (Project 10)
- **Indicator extraction patterns** → [APT TTP Mapper v1.1](https://github.com/shankar-bettadapura/apt-ttp-mapper-v1.1) (Project 7)

---

## Known Limitations

- URLs, domains, and hashes are queried against one source each, capping their maximum verdict at SUSPICIOUS under the current threshold model. Adding VirusTotal as a secondary source would enable MALICIOUS verdicts for those IOC types.
- Legitimate domains that appear frequently in threat intelligence reports as impersonation targets (e.g. `paypal.com`) may produce false positive SUSPICIOUS verdicts due to OTX pulse accumulation. Raw source data is exposed alongside verdict labels so analysts can make this determination without re-querying.
- Attachment analysis is limited to SHA256 hashing and URLhaus payload lookup. A production version would integrate a sandboxing API for behavioural analysis of novel payloads.

---

## Author

**Shankar Bettadapura** — Cybersecurity and IT GRC professional, M.S. Cybersecurity Studies (AMU), CompTIA Security+, CISA/CRISC/ISO 42001 in progress, Former U.S. Army All-Source Intelligence Analyst.

🔗 [LinkedIn](https://www.linkedin.com/in/shankar-bettadapura) | 🔗 [Substack](https://shankarbettadapura.substack.com) | 🔗 [GitHub](https://github.com/shankar-bettadapura)
