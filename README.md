# 🛡️ Automated Authentication & Log Anomaly Analyzer

An enterprise-grade, modular Security Information and Event Management (SIEM) and network telemetry tool developed as an M.Sc. Cyber Security practical project at Kristu Jayanti University.

## 🚀 Key Features
- **Phase 1: Ingestion & Sanitization (`parser.py`)**: Normalizes messy MAC addresses, maps hardware vendor OUIs, and extracts log fields via regular expressions.
- **Phase 2: Threat Detection Engine (`processor.py`)**: Enforces command injection guards, IPv4 subnet scoping, and detects **ARP Cache Poisoning** & **Gateway MitM Hijacking**.
- **Phase 3: Persistence Layer (`database.py`)**: SQLite-backed storage with thread-safe reentrant locks (`threading.RLock()`) and real-time metric tracking.
- **Phase 4: OS Watcher Daemon & UI (`daemon.py` & `app.py`)**: Autonomous background worker polling native OS ARP tables (`arp -a` / `arp -n`), paired with a Datadog/Splunk-style Flask SOC dashboard.

---

## 🛠️ Modular Architecture
```text
src/
├── __init__.py      # Package identifier
├── database.py      # SQLite storage & multi-threaded state locks
├── parser.py        # Regex tokenization, normalization & OUI lookup
├── processor.py     # Core threat analysis & anomaly detection rules
├── daemon.py        # Autonomous OS background reconnaissance worker
└── app.py           # Flask REST API server & SOC web dashboard