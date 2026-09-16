<p align="center">
  <img src="assets/icon.jpg" alt="Project Guard - Open-Source Windows Antivirus, EDR & Threat Hunting Agent in Rust" width="160" style="border-radius: 24px; box-shadow: 0 10px 30px rgba(6, 182, 212, 0.4);" />
</p>

<h1 align="center">Project Guard (English Documentation)</h1>

<p align="center">
  <strong>Next-Generation Open-Source Windows Antivirus, EDR & Threat Hunting Platform</strong><br>
  <em>Engineered in Pure Rust (2024 Edition) with Windows Defender Dual-Layer Coexistence & 21 Autonomous Engines</em>
</p>

<p align="center">
  <a href="README.md">🌐 <strong>Main README</strong></a> &nbsp;|&nbsp;
  <a href="README_EN.md">🇬🇧 <strong>English Docs</strong></a> &nbsp;|&nbsp;
  <a href="README_TR.md">🇹🇷 <strong>Türkçe Dokümantasyon</strong></a> &nbsp;|&nbsp;
  <a href="QUICKSTART.md">⚡ <strong>Quickstart Guide</strong></a> &nbsp;|&nbsp;
  <a href="ARCHITECTURE.md">🏛️ <strong>Architecture</strong></a>
</p>

<p align="center">
  <a href="https://github.com/kilic/project-guard/actions"><img src="https://img.shields.io/badge/CI-Build%20%26%20Test-brightgreen.svg?style=for-the-badge&logo=githubactions&logoColor=white" alt="CI Build and Test" /></a>
  <img src="https://img.shields.io/badge/Language-Rust%202024-orange.svg?style=for-the-badge&logo=rust" alt="Rust 2024 Edition" />
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20%2F%20Server-0078D6.svg?style=for-the-badge&logo=windows" alt="Supported on Windows 10, 11, and Server" />
  <img src="https://img.shields.io/badge/Detection%20Engines-21%20Active-06B6D4.svg?style=for-the-badge" alt="21 Detection Engines" />
  <img src="https://img.shields.io/badge/Defender%20Coexistence-Dual--Layer%20OK-10B981.svg?style=for-the-badge&logo=windows-defender" alt="Windows Defender Dual-Layer Coexistence" />
  <img src="https://img.shields.io/badge/Tests-28%20Passing-brightgreen.svg?style=for-the-badge" alt="28 Unit Tests Passing" />
  <img src="https://img.shields.io/badge/License-Apache%202.0%20%2F%20MIT-blue.svg?style=for-the-badge" alt="Apache-2.0 or MIT License" />
</p>

---

## 📑 Table of Contents
- [Overview & Vision](#-overview--vision)
- [Why Project Guard? (Comparison Matrix)](#-why-project-guard-comparison-matrix)
- [Architecture & 21 Autonomous Engines](#-architecture--21-autonomous-engines)
- [1-Click Windows Setup (Zero-Config)](#-1-click-windows-setup-zero-config)
- [Windows Defender Dual-Layer Coexistence](#-windows-defender-dual-layer-coexistence)
- [Desktop GUI & Web SOC Control Center](#-desktop-gui--web-soc-control-center)
- [24/7 Windows Service Daemon](#-247-windows-service-daemon)
- [CLI Reference & Usage](#-cli-reference--usage)
- [Security & Vault Architecture](#-security--vault-architecture)
- [From the Developer: FatRab Budget Tracker](#-from-the-developer-fatrab-budget-tracker-on-google-play)
- [Contributing & Development](#-contributing--development)
- [Citation](#-citation)
- [License](#-license)

---

## 🛡️ Overview & Vision

**Project Guard** is an enterprise-grade, memory-safe **Endpoint Detection & Response (EDR), Antivirus, and Threat Hunting Agent** built entirely in **pure Rust**. 

Traditional antiviruses often rely solely on outdated static signatures, introduce unmanageable memory overhead, or conflict aggressively with Microsoft Windows Defender. Project Guard bridges this gap by acting as a **force multiplier**:

1. **21 Coordinated Detection Engines**: Combines real-time threat intelligence feeds (*Abuse.ch MalwareBazaar, ThreatFox, Feodo C2, ClamAV CVD, YARA-Forge*), deep PE static triage, in-memory RWX code injection hunting, AMSI/script deobfuscation, and live Windows Event Log telemetry (Event ID 4104).
2. **Zero-Friction Windows Defender Coexistence**: Gracefully detects and handles `WdFilter.sys` locking (`os error 225`), encapsulates quarantined threats in XOR `0x5A` vault envelopes, and aggregates `Get-MpComputerStatus` telemetry directly onto its unified SOC console.
3. **100% Memory Safety**: Zero buffer overflows, zero use-after-free vulnerabilities, and sub-millisecond scan throughput powered by modern Rust concurrency.
4. **Autonomous Windows Service**: Ships with native Service Control Manager (SCM) integration for uninterrupted 24/7 endpoint protection with automatic failure recovery.

---

## 📊 Why Project Guard? (Comparison Matrix)

| Feature / Capability | ClamAV | Windows Defender (Alone) | Commercial EDR | **Project Guard (Rust)** |
|:---|:---:|:---:|:---:|:---:|
| **Memory-Safe Architecture (Rust)** | ❌ C/C++ | ❌ C++ / COM | ⚠️ Mixed | **✅ Pure Rust 2024** |
| **Defender Coexistence (Dual-Layer)** | ❌ Conflicts | N/A | ❌ Disables Defender | **✅ Seamless Coexistence** |
| **YARA-X Pure Rust Compilation** | ❌ | ❌ | ⚠️ Cloud Only | **✅ Native YARA-X Engine** |
| **In-Memory RWX / Unbacked Hunter** | ❌ | ⚠️ Cloud Depend | ✅ Enterprise $ | **✅ Built-in RWX Scanner** |
| **Live EventLog 4104 Script Telemetry** | ❌ | ⚠️ Logs Only | ✅ Enterprise $ | **✅ Real-time Ingestion** |
| **BYOVD / LOLDrivers Ring0 Hunter** | ❌ | ⚠️ Recent Windows 11 | ✅ Enterprise $ | **✅ 100+ Blacklist Hashes** |
| **PE Shannon Entropy & Capa ATT&CK** | ❌ | ⚠️ Cloud | ✅ | **✅ Instant Offline Triage** |
| **Ransomware Canary Honeypot Traps** | ❌ | ❌ | ⚠️ Partial | **✅ Autonomous Canary Watch** |
| **1-Click Windows Setup (Setup.cmd)** | ❌ | Built-in | ❌ MDM / MSI Heavy | **✅ 1-Click Zero Config** |
| **Open Source & Extensible** | ✅ GPL | ❌ Closed | ❌ Closed | **✅ Apache 2.0 / MIT** |

---

## ⚡ Architecture & 21 Autonomous Engines

```
                                 ┌────────────────────────────────────────────────────────┐
                                 │              PROJECT GUARD CORE AGENT                  │
                                 └──────────────────────────┬─────────────────────────────┘
                                                            │
         ┌──────────────────────────────────────────────────┼──────────────────────────────────────────────────┐
         │                                                  │                                                  │
┌────────▼────────┐                                ┌────────▼────────┐                                ┌────────▼────────┐
│ Threat Intel &  │                                │ Heuristic & PE  │                                │ In-Memory &     │
│ Rule Signatures │                                │ Capabilities    │                                │ Script Hunter   │
├─────────────────┤                                ├─────────────────┤                                ├─────────────────┤
│ • YARA-X Engine │                                │ • PE Shannon    │                                │ • In-Memory RWX │
│ • MalwareBazaar │                                │   Entropy Heat  │                                │   Injection     │
│ • ThreatFox IOC │                                │ • W^X Violation │                                │ • AMSI Bypass   │
│ • Feodo C2 IP   │                                │ • Capa ATT&CK   │                                │ • Script Cradle │
│ • ClamAV CVD    │                                │ • UPX / Crypter │                                │ • LOLBAS Hunter │
│ • YARA-Forge    │                                │ • BYOVD Drivers │                                │ • Base64 Deob   │
└─────────────────┘                                └─────────────────┘                                └─────────────────┘
         │                                                  │                                                  │
         └──────────────────────────────────────────────────┼──────────────────────────────────────────────────┘
                                                            │
         ┌──────────────────────────────────────────────────┼──────────────────────────────────────────────────┐
         │                                                  │                                                  │
┌────────▼────────┐                                ┌────────▼────────┐                                ┌────────▼────────┐
│ Host Defense &  │                                │ 7/24 Background │                                │ Native Desktop  │
│ Anti-Tampering  │                                │ Windows Service │                                │ & Web SOC Panel │
├─────────────────┤                                ├─────────────────┤                                ├─────────────────┤
│ • EventLog 4104 │                                │ • SCM Service   │                                │ • Standalone GUI│
│ • Canary Traps  │                                │ • Auto Restart  │                                │ • 18-Tab Live   │
│ • FIM Integrity │                                │ • 24/7 RTP Loop │                                │   SOC Console   │
│ • USB Worm Guard│                                │ • Event Logging │                                │ • RESTful JSON  │
│ • Defender Dual │                                │ • System SYSTEM │                                │ • Dark Obsidian │
└─────────────────┘                                └─────────────────┘                                └─────────────────┘
```

### 1. Threat Intelligence & Signature Engines
* **YARA-X Pure Rust Engine:** Compiles and evaluates modern YARA rules utilizing VirusTotal's memory-safe `yara-x` compiler.
* **MalwareBazaar & ThreatFox Feeds:** Ingests daily updated malicious SHA-256 hashes and IOCs from Abuse.ch into an embedded SQLite index (`.project_guard/guard.db`).
* **Feodo Tracker C2 Botnet Hunter:** Cross-references outbound TCP sockets against known botnet command & control nodes in real-time.
* **ClamAV CVD & clamd Integration:** Ingests open-source ClamAV hash databases (`.hdb`) and communicates over local `clamd` sockets.
* **YARA-Forge Community Rules:** Synchronizes vetted rules targeting Cobalt Strike, Mimikatz, Ransomware, and Infostealers.

### 2. Heuristics & Deep PE Static Triage
* **Per-Section Shannon Entropy (0.00 - 8.00):** Visualizes entropy across `.text`, `.rdata`, `.data`, `.rsrc` to pinpoint crypters and encrypted payloads.
* **W^X Security Violation Detection:** Flags binaries exhibiting simultaneously writable (`IMAGE_SCN_MEM_WRITE`) and executable (`IMAGE_SCN_MEM_EXECUTE`) sections.
* **Capa & MITRE ATT&CK Mapping:** Extracts capability vectors (Process Injection, Credential Theft, Anti-Analysis) to generate a 0-100 Threat Risk Score.
* **BYOVD / LOLDrivers Hunter:** Scans system and staging paths against 100+ vulnerable kernel drivers (`gdrv.sys`, `mhyprot2.sys`, `procexp.sys`).

### 3. In-Memory & Script Hunting
* **In-Memory RWX Hunter:** Employs `VirtualQueryEx` and `ReadProcessMemory` to inspect unbacked, private executable memory pages for Cobalt Strike beacons.
* **LOLBAS & Parent-Child Process Anomalies:** Identifies exploitation of legitimate Windows binaries (`certutil`, `mshta`, `regsvr32`, `rundll32`).
* **AMSI & Script Hunter:** Uncovers in-memory AMSI patching (`amsiInitFailed`), Base64 obfuscated payloads, and VBScript/Batch download cradles.

### 4. Host Defense & DFIR Telemetry
* **Windows Event Log Hunter:** Queries `Microsoft-Windows-PowerShell/Operational` (Event ID 4104), Defender detections (1116/1117), and Security Log clearing attempts (1102).
* **Ransomware Canary Traps (Honeypot):** Deploys decoy files in strategic user directories to detect and abort mass-encryption routines immediately.
* **File Integrity Monitoring (FIM):** Establishes cryptographic SHA-256 baselines over critical binaries (`hosts`, `cmd.exe`, `dnsapi.dll`).
* **USB & Removable Media Sentry:** Automatically neutralizes `autorun.inf` and hidden `.lnk` shortcut worms upon device insertion.
* **XOR 0x5A Quarantine Vault:** Encapsulates quarantined files with reversible byte-masking to prevent Windows Defender execution lockouts.

---

## 🚀 1-Click Windows Setup (Zero-Config)

Project Guard is designed for both security engineers and non-technical users:

### 🌟 1-Click Installation (`Setup.cmd`)
1. Download or clone this repository.
2. Double-click **`Setup.cmd`** in the project root.
3. When the Windows UAC (User Account Control) prompt appears, click **"Yes"**.
4. The automated installer will immediately:
   * Deploy the optimized executable to `C:\Program Files\ProjectGuard`.
   * Create **Desktop** and **Start Menu** shortcuts with embedded custom icons.
   * Append the installation folder to the system `PATH`.
   * Register and start the 24/7 **Windows Background Service (`ProjectGuard`)**.
   * Launch the Windows Desktop Control Center!

### 🗑️ 1-Click Clean Uninstall (`Uninstall.cmd`)
* Double-click **`Uninstall.cmd`** or choose **"Uninstall Project Guard"** from the Start Menu / Windows Settings (Apps & Features) to completely stop the service and remove all installed shortcuts and files.

### 📦 Standalone Installer Builder (`installer/project-guard.iss`)
* Compile `installer/project-guard.iss` with [Inno Setup 6](https://jrsoftware.org/isinfo.php) to build a distributable `ProjectGuard-Setup-v1.1.0.exe` setup wizard.

---

## 🛡️ Windows Defender Dual-Layer Coexistence

Running third-party antiviruses on Windows often triggers stability issues or Defender conflict errors:

```
[Threat Detected] ──> Project Guard Scans ──> If Defender WdFilter.sys locks (Error 225)
                                                      │
                                                      ├──> Handled gracefully without crash
                                                      ├──> Safe XOR 0x5A vaulting
                                                      └──> Aggregated on Web SOC Console
```

* **Error 225 Tolerance:** Traps Windows error code 225 (`ERROR_VIRUS_INFECTED`) generated by Defender's `WdFilter.sys` minifilter driver and informs the analyst without crashing.
* **XOR 0x5A Masking:** Neutralizes malicious file contents so Defender does not repeatedly lock the quarantine directory.
* **Unified Defender Telemetry:** Collects signature version, engine health, and active status via PowerShell/WMI APIs.

---

## 🌐 Desktop GUI & Web SOC Control Center

Project Guard includes a state-of-the-art Dark Obsidian cybersecurity dashboard:

```powershell
# Launch as an independent Windows Desktop App:
project-guard gui

# Or launch as a background Web SOC server:
project-guard ui --port 7890
```

Access the dashboard at **`http://127.0.0.1:7890`**:
* **Bilingual Switcher:** Instant, persistent English 🇬🇧 and Turkish 🇹🇷 localization.
* **Real-Time SOC Telemetry:** Live memory graphs, engine counters, and service control buttons.
* **Interactive Threat Vault:** Search, inspect, restore, or permanently purge quarantined threats.
* **One-Click Intelligence Sync:** Instantly refresh YARA-Forge, MalwareBazaar, and Feodo C2 threat feeds.

---

## ⚙️ 24/7 Windows Service Daemon

Install Project Guard into the Windows Service Control Manager (SCM) for continuous protection:

```powershell
# Open PowerShell as Administrator:
project-guard service install   # Registers service with SCM (Auto-Start)
project-guard service start     # Starts the background engine
project-guard service status    # Displays live service telemetry
project-guard service stop      # Safely stops the daemon
project-guard service uninstall # Removes service from SCM
```

---

## 📖 CLI Reference & Usage

| Command | Purpose | Example Syntax |
|:---|:---|:---|
| `scan <target>` | Multi-engine scan on a file or folder | `project-guard scan C:\Downloads -q --recursive` |
| `scan-eventlog` | Audits PowerShell 4104 and Defender event logs | `project-guard scan-eventlog --limit 50` |
| `triage <file>` | PE section Shannon entropy & ATT&CK matrix | `project-guard triage C:\Windows\System32\cmd.exe` |
| `sync-yara` | Downloads & compiles YARA-Forge threat rules | `project-guard sync-yara` |
| `scan-script <path>` | Scans for AMSI bypass, Base64 & download cradles | `project-guard scan-script payload.ps1` |
| `extract-iocs <path>` | Extracts embedded C2 IPs, URLs, BTC wallets | `project-guard extract-iocs sample.exe` |
| `scan-drivers` | Hunts for vulnerable BYOVD / LOLDrivers | `project-guard scan-drivers` |
| `fim-init` | Generates cryptographic SHA-256 baselines | `project-guard fim-init` |
| `fim-check` | Detects unauthorized system binary tampering | `project-guard fim-check` |
| `canary-deploy` | Deploys anti-ransomware honeypot trap files | `project-guard canary-deploy C:\Users\Documents` |
| `canary-watch` | Real-time monitoring of canary decoy traps | `project-guard canary-watch C:\Users\Documents` |
| `scan-lolbas` | Detects malicious abuse of signed Windows binaries | `project-guard scan-lolbas --kill` |
| `scan-memory` | Hunts for unbacked executable RWX process memory | `project-guard scan-memory` |
| `scan-network` | Inspects active sockets against C2 botnet lists | `project-guard scan-network` |
| `scan-persistence` | Scans Run keys, Startup folders & SchTasks | `project-guard scan-persistence` |
| `scan-usb` | Scans plugged USB drives for LNK and autorun worms | `project-guard scan-usb -q` |
| `defender-status` | Audits Windows Defender health and telemetry | `project-guard defender-status` |
| `quarantine list` | Lists all quarantined files in vault | `project-guard quarantine list` |
| `quarantine restore` | Safely restores a file from quarantine | `project-guard quarantine restore <ID>` |
| `service <action>` | Windows Service management (install/start/stop) | `project-guard service status` |
| `gui` | Launches the Windows Desktop Application window | `project-guard gui` |
| `ui` | Launches the Web SOC dashboard server | `project-guard ui --port 7890` |

---

## 🔒 Security & Vault Architecture

* **XOR 0x5A Reversible Encryption:** Ensures zero accidental execution by the operating system while maintaining forensic integrity.
* **Rust Concurrency & Memory Safety:** Protects against use-after-free, double-free, and buffer overrun exploits.
* **Defensive Error Handling:** Standardized error logging without exposing sensitive internal system pointers.

---

## 📱 From the Developer: FatRab Budget Tracker on Google Play

<p align="center">
  <a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank">
    <img src="assets/feature-graphic-1024x500.png" alt="FatRab Personal Budget Tracker Android App Google Play Feature Graphic" width="760" style="border-radius: 14px; box-shadow: 0 10px 30px rgba(0,0,0,0.35);" />
  </a>
</p>

<p align="center">
  <a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank">
    <img src="https://img.shields.io/badge/Google_Play-FatRab_Budget_Tracker-34A853?style=for-the-badge&logo=google-play&logoColor=white" alt="FatRab Budget Tracker on Google Play" />
  </a>
  <img src="https://img.shields.io/badge/Platform-Android-green.svg?style=for-the-badge&logo=android" alt="Android Platform" />
  <img src="https://img.shields.io/badge/Category-Finance%20%26%20Budgeting-blue.svg?style=for-the-badge" alt="Finance and Budgeting Category" />
</p>

<div align="center">

| <a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank"><img src="assets/play-icon-512.png" width="96" alt="FatRab Budget Tracker App Icon" style="border-radius: 20px;" /></a> | ### 💰 [FatRab Budget Tracker - Available on Google Play](https://play.google.com/store/apps/details?id=com.fatrab.budget)<br>Take control of your personal finances and savings goals with effortless expense tracking, customizable categories, and comprehensive graphical reports. Designed with simplicity and privacy in mind.<br><br><a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank"><img src="https://play.google.com/intl/en_us/badges/static/images/badges/en_badge_web_generic.png" alt="Get it on Google Play" height="52"></a> |
|:---:|---|

</div>

---

## 🤝 Contributing & Development

We welcome contributions from security analysts, malware researchers, and Rust engineers!
* Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** for coding standards, engine guidelines, and PR procedures.
* To report security vulnerabilities, review our **[SECURITY.md](SECURITY.md)** policy.

---

## 📜 Citation

If you reference Project Guard in academic research, threat intelligence reports, or security conferences, please cite using:

```bibtex
@software{project_guard_2026,
  author = {Project Guard Team},
  title = {Project Guard: Next-Generation Open-Source Antivirus, EDR & Threat Hunting Platform in Rust},
  url = {https://github.com/kilic/project-guard},
  version = {1.1.0},
  year = {2026}
}
```

---

## 📄 License

This project is dual-licensed under **Apache License 2.0** and the **MIT License**. See [LICENSE](LICENSE) for details.
