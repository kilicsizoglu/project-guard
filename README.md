<p align="center">
  <img src="assets/icon.jpg" alt="Project Guard - Open-Source Windows Antivirus, EDR & Threat Hunting Agent in Rust" width="160" style="border-radius: 24px; box-shadow: 0 10px 30px rgba(6, 182, 212, 0.4);" />
</p>

<h1 align="center">Project Guard</h1>

<div align="center">
  <a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank">
    <img src="assets/feature-graphic-1024x500.png" alt="FatRab Bütçe Takipçisi" width="600" style="border-radius: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); margin-bottom: 10px;" />
  </a>
  <p>
    <em>🌟 Sponsored by <strong><a href="https://play.google.com/store/apps/details?id=com.fatrab.budget">FatRab Budget Tracker</a></strong> - Manage your personal finances effortlessly! Available on Google Play. 🌟</em>
  </p>
</div>

<p align="center">
  <strong>Next-Generation Open-Source Windows Antivirus, EDR & Threat Hunting Platform</strong><br>
  <em>Engineered in Pure Rust (2024 Edition) with Windows Defender Dual-Layer Coexistence & 21 Autonomous Engines</em>
</p>

<p align="center">
  <a href="#-english-documentation">🇬🇧 <strong>English Documentation</strong></a> &nbsp;|&nbsp;
  <a href="#-türkçe-dokümantasyon">🇹🇷 <strong>Türkçe Dokümantasyon</strong></a> &nbsp;|&nbsp;
  <a href="QUICKSTART.md">⚡ <strong>Quickstart Guide</strong></a> &nbsp;|&nbsp;
  <a href="ARCHITECTURE.md">🏛️ <strong>Architecture</strong></a> &nbsp;|&nbsp;
  <a href="#-citation">📜 <strong>Cite This Repo</strong></a>
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

# 🇬🇧 English Documentation

## 📑 Table of Contents (English)
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

# 🇹🇷 Türkçe Dokümantasyon

## 📑 İçindekiler (Türkçe)
- [Vizyon ve Genel Bakış](#-vizyon-ve-genel-bakış)
- [Temel Güvenlik Motorları (21 Aktif Motor)](#-temel-güvenlik-motorları-21-aktif-motor)
- [Kolay Kurulum (1-Click Windows Setup)](#-kolay-kurulum-1-click-windows-setup)
- [Kurulum ve Derleme (Geliştiriciler İçin)](#-kurulum-ve-derleme-geliştiriciler-için)
- [Windows Hizmeti (Service) Olarak Çalıştırma](#-windows-hizmeti-service-olarak-çalıştırma)
- [Web Tabanlı SOC Kontrol Paneli](#-web-tabanlı-soc-kontrol-paneli-ve-yerel-masaüstü-arayüzü)
- [CLI Komut Referansı](#-cli-komut-referansı)
- [Güvenlik ve İzolasyon Mimarisi](#-güvenlik-ve-izolasyon-mimarisi)
- [Geliştiriciden: FatRab Bütçe Takipçisi](#-geliştiriciden-fatrab-bütçe-takipçisi-google-play)
- [Katkıda Bulunma ve Lisans](#-katkıda-bulunma-contributing)

---

## 🛡️ Vizyon ve Genel Bakış

**Project Guard**, modern kurumsal uç nokta tehditlerine (dosyasız saldırılar, fidye yazılımları, bellek enjeksiyonu, BYOVD savunmasız çekirdek sürücüleri ve sıfır-gün komut dosyası suistimalleri) karşı geliştirilmiş, **saf Rust** mimarili, açık kaynak istihbaratından beslenen bir **Antivirus ve EDR (Endpoint Detection & Response)** platformudur.

Geleneksel imza tabanlı antivirüslerin ötesine geçerek; **canlı Windows Olay Günlüğü telemetrisi (Event ID 4104)**, **bölüm bazlı Shannon entropisi triyajı**, **Capa/ATT&CK statik yetenek eşleştirme**, **in-memory RWX bellek avcılığı** ve **XOR `0x5A` maskeli karantina kasası** ile işletim sistemini 7/24 kesintisiz korur.

> [!IMPORTANT]
> **Windows Defender Eşzamanlı Koruma (Dual-Layer Shield):**
> Project Guard, Microsoft Defender Antivirus ile tam uyumlu çalışacak şekilde tasarlanmıştır. Defender'ın çekirdek sürücüsü `WdFilter.sys` tarafından üretilen `os error 225` hatalarını yakalar, karantinaya alınan dosyaları tersine çevrilebilir XOR maskelemesiyle Defender'dan izole eder ve `Get-MpComputerStatus` telemetrisini tek bir merkezi SOC panelinde birleştirir.

---

## ⚡ Temel Güvenlik Motorları (21 Aktif Motor)

```
                                 ┌────────────────────────────────────────────────────────┐
                                 │                PROJECT GUARD EDR AGENT                 │
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
│ Host Defense &  │                                │ 7/24 Background │                                │ Glassmorphic    │
│ Anti-Tampering  │                                │ Windows Service │                                │ Web Dashboard   │
├─────────────────┤                                ├─────────────────┤                                ├─────────────────┤
│ • EventLog 4104 │                                │ • SCM Service   │                                │ • 18-Tab Live   │
│ • Canary Traps  │                                │ • Auto Restart  │                                │   SOC Console   │
│ • FIM Integrity │                                │ • 24/7 RTP Loop │                                │ • RESTful JSON  │
│ • USB Worm Guard│                                │ • Event Logging │                                │ • Dark Obsidian │
│ • Defender Dual │                                │ • System SYSTEM │                                │ • Interactive   │
└─────────────────┘                                └─────────────────┘                                └─────────────────┘
```

### 1. Tehdit İstihbaratı ve İmza Motorları
* **YARA-X Saf Rust Motoru:** VirusTotal'ın modern, bellek güvenli YARA-X kütüphanesiyle kuralları anında derler ve çalıştırır.
* **MalwareBazaar & ThreatFox Canlı Akışları:** Abuse.ch tarafından sağlanan günlük zararlı dosya hash'leri ve C2 IOC'leri yerel SQLite veritabanına (`.project_guard/guard.db`) senkronize edilir.
* **Feodo Tracker C2 Botnet Avcısı:** Aktif botnet komuta kontrol IP'leri ağ soketleriyle eş zamanlı karşılaştırılır.
* **ClamAV CVD & clamd Soket Adaptörü:** Açık kaynak ClamAV virüs hash imzaları (`.hdb`) ve yerel clamd arka plan daemon soket entegrasyonu.
* **YARA-Forge Topluluk Kuralları Senkronizasyonu:** Cobalt Strike, Fidye Yazılımları, Mimikatz ve Bilgi Çalıcılar için vetted topluluk imzaları.

### 2. Sezgisel (Heuristic) ve Derin PE Triyajı
* **Bölüm Bazlı Shannon Entropisi (0.00 - 8.00):** `.text`, `.rdata`, `.data`, `.rsrc` bölümlerinin entropisini hesaplayarak şifreli veya Crypter ile paketlenmiş zararlı yükleri saptar.
* **W^X Güvenlik İhlali Tespiti:** Aynı anda hem yazılabilir (`IMAGE_SCN_MEM_WRITE`) hem çalıştırılabilir (`IMAGE_SCN_MEM_EXECUTE`) şüpheli bellek/PE bölümlerini yakalar.
* **Capa & MITRE ATT&CK Yetenek Matrisi:** Süreç Enjeksiyonu, Kimlik Bilgisi Hırsızlığı, Anti-Debugging ve Fidye Yazılımı API kümelerini tespit ederek 0-100 Tehdit Riski Skoru üretir.
* **BYOVD / LOLDrivers Avcısı:** Zafiyetli veya iptal edilmiş ring0 çekirdek sürücülerini (`gdrv.sys`, `mhyprot2.sys`, `procexp.sys` vb.) ve hazırlık alanlarını denetler.

### 3. Bellek İçi ve Komut Dosyası Avcılığı
* **Canlı Bellek Enjeksiyon Avcısı (In-Memory Hunter):** `VirtualQueryEx` ve `ReadProcessMemory` ile diske yazılmamış (unbacked) özel yürütülebilir bölgeleri ve Cobalt Strike stager'larını yakalar.
* **LOLBAS & Ebeveyn-Çocuk Süreç Anomalisi:** Microsoft imzalı meşru ikililerin (`certutil`, `mshta`, `regsvr32`, `rundll32`) suistimalini ve Office makro/PowerShell türetmelerini engeller.
* **Komut & AMSI Avcısı:** PowerShell bellek yamalarını (`amsiInitFailed`), Base64 şifreli komut yüklerini ve VBScript/Batch indirme beşiklerini yakalar.

### 4. Uç Nokta Savunması ve DFIR
* **Windows Olay Günlüğü Avcısı:** `Microsoft-Windows-PowerShell/Operational` (Event ID 4104) günlüklerini tarayarak bellek içi yürütmeleri yakalar; Windows Defender tespitlerini (1116/1117) ve Olay Günlüğü silme girişimlerini (1102) raporlar.
* **Stratejik Fidye Kapanı (Canary / Honeypot):** Kritik dizinlere yerleştirilen alfanumerik yem dosyaları izler; sıfır-gün fidye yazılımı şifreleme girişimlerinde alarm üretir.
* **Dosya Bütünlüğü İzleme (FIM):** `hosts`, `cmd.exe`, `powershell.exe`, `dnsapi.dll` gibi kritik sistem ikililerini SHA-256 referansı ile kriptografik olarak korur.
* **USB & Çıkarılabilir Sürücü Koruması:** `autorun.inf` ve gizli `.lnk` kısayol solucanlarını takıldığı anda nötralize eder.
* **XOR 0x5A İzolasyonlu Karantina Kasası:** Dosyalar şifrelenerek ikili çalıştırılamaz hale getirilir ve Windows Defender ile kilitlenme yaşanması önlenir.

---

## 🚀 Kolay Kurulum (1-Click Windows Setup)

Project Guard'ı sisteminize kurmak, masaüstü simgesi oluşturmak ve 7/24 arka plan korumasını aktif etmek için hiçbir teknik komut girmenize gerek yoktur:

### 🌟 Tek Tıkla Kurulum (`Setup.cmd`)
1. Proje kök dizinindeki **`Setup.cmd`** dosyasına çift tıklayın.
2. Açılan Windows UAC (Kullanıcı Hesabı Denetimi) onay penceresinde **"Evet"** butonuna basın.
3. Otomatik Kurulum Sihirbazı anında şu adımları tamamlar:
   * **C:\Program Files\ProjectGuard** kurumsal dizinini hazırlar.
   * En güncel ve optimize ikili dosyayı (`project-guard.exe`) ve görsel varlıkları kopyalar.
   * **Masaüstü** ve **Başlat Menüsü**'ne özel logonun yer aldığı kısayolları ekler.
   * Komut satırından her yerden erişim için sistem `PATH` ortam değişkenine ekler.
   * 7/24 arka plan **Windows Hizmetini (ProjectGuard)** kaydeder ve otomatik başlatır.
   * Windows Masaüstü Kontrol Merkezini (GUI) doğrudan açar.

### 🗑️ Tek Tıkla Kaldırma (`Uninstall.cmd`)
* İster Başlat Menüsündeki **"Uninstall Project Guard"** kısayoluna, ister kök dizindeki **`Uninstall.cmd`** dosyasına çift tıklayarak hizmeti durdurup tüm dosyaları ve kısayolları sisteminizden temizleyebilirsiniz.
* Ayrıca Windows **Ayarlar > Uygulamalar (Program Ekle/Kaldır)** listesinden de standart bir Windows uygulaması gibi kaldırılabilir.

### 📦 Bağımsız Kurulum Paketi (.exe Installer)
* Dilerseniz `installer/project-guard.iss` dosyasını [Inno Setup 6](https://jrsoftware.org/isinfo.php) ile derleyerek tek bir bağımsız **`ProjectGuard-Setup-v1.1.0.exe`** dağıtım dosyası elde edebilirsiniz.

---

## 🛠️ Kurulum ve Derleme (Geliştiriciler İçin)

### Ön Koşullar
* **Windows 10 / 11 / Server 2019+** (x64 veya ARM64)
* **Rust 1.85+ (Rust 2024 Edition)**
* **Git**

```powershell
# 1. Depoyu klonlayın
git clone https://github.com/kilic/project-guard.git
cd project-guard

# 2. Birim testlerini çalıştırın (28 test)
cargo test

# 3. İkili dosyayı Windows kaynakları ve simgesiyle derleyin
cargo build --release
```

Derlenen çalıştırılabilir dosya: `target/release/project-guard.exe`

---

## ⚙️ Windows Hizmeti (Service) Olarak Çalıştırma

Project Guard, kurumsal ortamlarda sistem başlangıcında otomatik çalışan 7/24 bir **Windows Hizmeti** olarak kurulabilir:

```powershell
# Yönetici yetkileriyle PowerShell açın:

# 1. Windows Hizmetini sisteme kaydedin (Otomatik Başlangıç)
project-guard service install

# 2. Hizmeti başlatın
project-guard service start

# 3. Hizmetin çalışma durumunu sorgulayın
project-guard service status

# 4. Hizmeti durdurun veya sistemden kaldırın
project-guard service stop
project-guard service uninstall
```

Hizmet günlükleri `.project_guard/service.log` dosyasına kaydedilir ve sistem sağlığını doğrulamak için periyodik can damarı (heartbeat) sinyalleri üretir.

---

## 🌐 Web Tabanlı SOC Kontrol Paneli ve Yerel Masaüstü Arayüzü

Project Guard, güvenlik analistleri ve sistem yöneticileri için hem komut satırı hem de şık bir grafiksel kullanıcı arayüzü sunar:

```powershell
# Masaüstü penceresi modunda başlat (Bağımsız Native Pencere):
project-guard gui

# Veya yerel Web SOC sunucusu olarak çalıştır:
project-guard ui --port 7890
```

Tarayıcınızdan **`http://127.0.0.1:7890`** adresine giderek Dark Obsidian temalı modern kontrol paneline erişebilirsiniz.

* **Genel Bakış (Overview):** 21 motorun anlık durumu, Windows Defender eşzamanlı çalışma telemetrisi ve Windows Hizmet kontrol kartı.
* **Olay Günlükleri (EventLog Hunter):** Canlı PowerShell ScriptBlock olayları (4104), Defender tespit geçmişi ve Güvenlik Denetimi temizleme uyarıları.
* **Derin PE Triyajı:** Bölüm bazlı Shannon entropi renkli ilerleme çubukları ve MITRE ATT&CK yetenek matrisi.
* **Süreç ve Bellek Avcısı:** Canlı çalışan işlemler, RWX bellek bölgeleri ve tek tıkla süreç sonlandırma (Kill Switch).
* **Tehdit İstihbaratı:** Abuse.ch MalwareBazaar, ThreatFox, Feodo C2 ve YARA-Forge tek tıkla senkronizasyon.

---

## 📖 CLI Komut Referansı

| Komut | Açıklama | Örnek |
|---|---|---|
| `scan <hedef>` | Dosya veya dizini çoklu motorlarla tarar | `guard scan C:\Users\Downloads -q` |
| `scan-eventlog` | Windows Olay Günlüklerini (4104/1116/1102) denetler | `guard scan-eventlog --limit 25` |
| `triage <dosya>` | PE bölüm entropisi ve ATT&CK yetenek matrisi çıkarır | `guard triage C:\Windows\System32\cmd.exe` |
| `sync-yara` | Topluluk YARA-Forge ve Cobalt Strike kurallarını derler | `guard sync-yara` |
| `scan-script <yol>` | PowerShell / AMSI atlatma ve indirme beşiklerini tarar | `guard scan-script payload.ps1` |
| `extract-iocs <yol>` | Gizli dize, public IP, URL ve C2 botnet eşleşmelerini ayıklar | `guard extract-iocs sample.exe` |
| `scan-drivers` | BYOVD zafiyetli çekirdek sürücülerini (LOLDrivers) tarar | `guard scan-drivers` |
| `fim-init` | Kritik sistem dosyaları için SHA-256 referansı oluşturur | `guard fim-init` |
| `fim-check` | Sistem dosyalarında yetkisiz değişiklik kontrolü yapar | `guard fim-check` |
| `canary-deploy` | Stratejik yem (Canary) tuzak dosyaları yerleştirir | `guard canary-deploy C:\Users\Documents` |
| `canary-watch` | Fidye yazılımlarına karşı yem tuzakları canlı izler | `guard canary-watch C:\Users\Documents` |
| `scan-lolbas` | Microsoft imzalı ikililerin suistimalini tarar | `guard scan-lolbas --kill` |
| `scan-memory` | Canlı süreçlerde enjekte edilmiş RWX bellek bölgelerini arar | `guard scan-memory` |
| `scan-network` | Aktif TCP soketlerini ve C2 portlarını denetler | `guard scan-network` |
| `scan-persistence` | Windows Run, Startup ve SchTasks kalıcılıklarını tarar | `guard scan-persistence` |
| `scan-usb` | Çıkarılabilir USB sürücüleri ve LNK solucanlarını tarar | `guard scan-usb -q` |
| `defender-status` | Windows Defender sağlık ve uyumluluk durumunu sorgular | `guard defender-status` |
| `quarantine list` | Karantinadaki dosyaları listeler | `guard quarantine list` |
| `quarantine restore` | Karantinadaki dosyayı orijinal konumuna geri yükler | `guard quarantine restore <ID>` |
| `service <action>` | Windows Hizmeti yönetimi (install, start, stop, status) | `guard service install` |
| `ui` | Web Kontrol Merkezini başlatır | `guard ui --port 7890` |

---

## 🔒 Güvenlik ve İzolasyon Mimarisi

* **XOR 0x5A Kasa Koruması:** Karantinaya alınan her dosya `0x5A` maskesi ile tersyüz edilir. Bu sayede dosya diskte bulunsa dahi Windows işletim sistemi veya Defender tarafından çalıştırılamaz ya da kilitlenemez.
* **Bellek Güvenliği:** Rust'ın mülkiyet ve yaşam döngüsü (ownership/borrowing) modeli sayesinde bellek sızıntıları (memory leak) ve kullanım sonrası serbest bırakma (use-after-free) açıkları imkansızdır.
* **WdFilter Error 225 Toleransı:** Windows Defender RTP devredeyken oluşan erişim engelleri yakalanarak kullanıcıya net ve aksiyon alınabilir çözümler sunulur.

---

## 📱 Geliştiriciden: FatRab Bütçe Takipçisi (Google Play)

<p align="center">
  <a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank">
    <img src="assets/feature-graphic-1024x500.png" alt="FatRab Bütçe Takipçisi Android Uygulaması Google Play Banner" width="760" style="border-radius: 14px; box-shadow: 0 10px 30px rgba(0,0,0,0.35);" />
  </a>
</p>

<p align="center">
  <a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank">
    <img src="https://img.shields.io/badge/Google_Play-FatRab_Bütçe_Takipçisi-34A853?style=for-the-badge&logo=google-play&logoColor=white" alt="Google Play FatRab Bütçe Takipçisi" />
  </a>
  <img src="https://img.shields.io/badge/Platform-Android-green.svg?style=for-the-badge&logo=android" alt="Android Platform" />
  <img src="https://img.shields.io/badge/Kategori-Finans%20%26%20Bütçe-blue.svg?style=for-the-badge" alt="Kategori Finans ve Bütçe" />
</p>

<div align="center">

| <a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank"><img src="assets/play-icon-512.png" width="96" alt="FatRab Bütçe Takipçisi Uygulama Simgesi" style="border-radius: 20px;" /></a> | ### 💰 [FatRab Bütçe Takipçisi - Google Play'de Keşfedin](https://play.google.com/store/apps/details?id=com.fatrab.budget)<br>Kişisel bütçenizi, harcamalarınızı ve birikim hedeflerinizi zahmetsizce yönetin. Gelişmiş harcama kategorizasyonu, grafiksel finansal raporlar ve sade arayüzüyle bütçenizi kontrol altında tutun!<br><br><a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank"><img src="https://play.google.com/intl/en_us/badges/static/images/badges/tr_badge_web_generic.png" alt="Google Play'den İndirin" height="52"></a> |
|:---:|---|

</div>

---

## 🤝 Katkıda Bulunma (Contributing)

Geliştirici yönergeleri, yeni tespit motoru ekleme rehberi ve çekme isteği (PR) kuralları için **[CONTRIBUTING.md](CONTRIBUTING.md)** dosyasını inceleyebilirsiniz.

---

## 📄 Lisans

Bu proje **Apache 2.0** ve **MIT** çift lisansı altında sunulmaktadır.
Daha fazla bilgi için [LICENSE](LICENSE) dosyasına bakabilirsiniz.
