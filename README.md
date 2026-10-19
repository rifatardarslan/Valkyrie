<div align="center">

# 🛡️ VALKYRIE 
**Professional-Grade Automated Malware Analysis & Proactive Defense Grid**

*Valkyrie isn't just a scanner; it's a comprehensive threat intelligence pipeline designed for security researchers and SOC analysts. It tears apart suspect binaries statically, detonates them in isolated Docker sandboxes, extracts actionable Intelligence (MITRE/Capa), and generates proactive "Vaccine" defense scripts to protect your endpoints.*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/release/python-390/)
[![Docker](https://img.shields.io/badge/docker-Ready-blue.svg)](https://www.docker.com/)

</div>

---

## 🔥 Key Features

| Feature | Description |
| :--- | :--- |
| **🔍 Deep Static Extraction** | YARA hunting, Entropy visualization, PE header anomaly detection, and automated UPX unpacking. |
| **💥 Docker Sandboxing** | Ephemeral, isolated execution environments capturing `strace` system calls, File I/O, and `PCAP` network traffic. |
| **🧠 Intelligence Layer** | Auto-maps behaviors to **MITRE ATT&CK**, detects Base64/XOR obfuscation, and generates OpenAI-powered Executive Summaries. |
| **💉 Vaccine Mode** | **Exclusive Feature:** Extracts Mutexes and Registry keys used by malware and generates a standalone `.py` script to preemptively lock them on hosts, tricking the malware into shutting down. |
| **📊 STIX & Enterprise Reports** | Outputs data into beautifully rendered JSON, HTML dashboards, native PDFs, and instantly streams `STIX 2.1` objects to your SIEM/Webhooks. |

---

## 🚀 Installation

Valkyrie is built for Python 3.9+ and requires Docker Desktop (or Engine) to perform dynamic detonation.

### 1. Clone & Setup
```bash
git clone https://github.com/yourusername/valkyrie.git
cd valkyrie

# Create a virtual environment (Recommended)
python -m venv venv

# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate
```

### 2. Install Valkyrie
```bash
# Install the package globally
pip install -e .
```

### 3. API Keys (Optional but Recommended)
Copy the environment template and add your API keys (VirusTotal, OpenAI, etc.) for maximum intelligence yield.
```bash
copy config\.env.example config\.env
```

---

## 🛠️ Windows Installation & Troubleshooting

If you are running Valkyrie on Windows, you may encounter strict execution policies or missing build tools.

**1. PowerShell Execution Policy**
If your terminal refuses to run the `Activate` command for your virtual environment, run this once:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**2. Microsoft C++ Build Tools (YARA Requirement)**
Valkyrie depends on `yara-python`. If `pip install` fails while compiling YARA, you need the **Microsoft C++ Build Tools**.
- Download from: [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- During installation, ensure "**Desktop development with C++**" is checked.

---

## 🛠️ Usage Examples

Valkyrie is completely CLI-driven, utilizing rich terminal tables to present data instantly.

### Quick Static Triage
Run a rapid, non-executing static analysis on a suspect file.
```bash
valkyrie analyze -f target_malware.exe -m static
```

### Full Detonation & Enterprise Export
Execute the sample in the Docker sandbox, run the AI intelligence layer, and export STIX, PDF, and HTML reports.
```bash
valkyrie analyze -f target_malware.exe -m full --outdir reports/
```

### Proactive Vaccine Generation
Generate a prophylactic defense script based on the last discovered Mutexes for instant endpoint protection.
```bash
valkyrie vaccine -r reports/valkyrie_report.json -o protect_host.py
```

---

## ⚖️ Legal & Educational Disclaimer
> [!WARNING]
> **Educational Purposes Only.**
> Valkyrie is designed for authorized malware analysis, reverse engineering, and defensive research. Do **NOT** use this software to analyze materials you do not own or have explicit permission to inspect. The creators are not responsible for any misuse, damage, or data loss incurred through the operation of this tool. Always detonate suspect binaries in isolated, non-production environments.

---

### Project Structure (For Contributors)

```text
valkyrie/
├── src/
│   └── valkyrie/
│       ├── cli/         # Click Top-Level Commands
│       ├── core/        # Exporters & Base Classes
│       ├── modules/
│           ├── static/  # YARA, Entropy, Unpackers
│           ├── dynamic/ # Docker Orchestrator, Strace Parsers
│           └── intel/   # MITRE, Capa, Vaccine Generator
├── data/
│   └── rules/           # Custom YARA Signatures
├── docker/              # Base OS Sandbox Images
└── tests/               # PyTest Suite
```
