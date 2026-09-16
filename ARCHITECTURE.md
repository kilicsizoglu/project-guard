# Project Guard Architecture Specification

This document details the engineering architecture, internal subsystems, concurrency models, and security guarantees of **Project Guard** — a pure Rust Next-Gen Antivirus, EDR (Endpoint Detection & Response), and Threat Hunting platform designed specifically for Windows environments with native Windows Defender coexistence.

---

## 1. High-Level Architectural Overview

Project Guard operates across three main operational planes:
1. **Host Defense & Telemetry Plane**: Low-level kernel driver checks (BYOVD), Windows Event Log telemetry (ETW / Event ID 4104), active memory scanning (`VirtualQueryEx`), and ransomware honeypots.
2. **Analysis & Triage Plane**: Multi-engine orchestrator executing YARA-X compiled rules, section-based Shannon entropy analysis, MITRE ATT&CK capability matching, and IOC extraction.
3. **Control & Response Plane**: Windows Service Control Manager (SCM) background daemon, XOR `0x5A` quarantine vault, RESTful JSON API server, and a Glassmorphic Web SOC console.

```mermaid
graph TD
    subgraph Host Defense & Telemetry
        ETW[Windows EventLog 4104/1116] --> ES[EventLog Hunter]
        FIM[File Integrity Monitor] --> CRIT[System Binaries & Hosts]
        MEM[Process Memory Scanner] --> RWX[RWX / Unbacked Injection]
        CANARY[Ransomware Canary Traps] --> WATCH[Canary Watcher Thread]
        BYOVD[Vulnerable Driver Scanner] --> DRV[LOLDrivers DB & Hash Triad]
    end

    subgraph Analysis & Triage Engine
        ORCH[Scan Orchestrator]
        YARA[YARA-X Safely Compiled Rules]
        ENTROPY[Shannon Section Entropy Triage]
        CAPA[MITRE ATT&CK Capability Matcher]
        HASH[SQLite Hash DB MalwareBazaar / ClamAV]
        SCRIPT[Script & AMSI Deobfuscator]
    end

    subgraph Storage & Quarantine
        VAULT[XOR 0x5A Quarantine Vault]
        SQLITE[SQLite Embedded DB - guard.db]
        CANARY_STATE[canaries.json State]
    end

    subgraph Service & Control Layer
        SCM[Windows Service Manager - ProjectGuard]
        API[Axum REST JSON API - Port 7890]
        UI[Glassmorphic Web SOC Console]
    end

    ES --> ORCH
    MEM --> ORCH
    CANARY --> ORCH
    BYOVD --> ORCH

    ORCH --> YARA
    ORCH --> ENTROPY
    ORCH --> CAPA
    ORCH --> HASH
    ORCH --> SCRIPT

    ORCH -->|Quarantine Action| VAULT
    ORCH -->|Threat Logging| SQLITE
    CANARY -->|Tamper Event| CANARY_STATE

    SCM -->|Daemon 24/7| ORCH
    API --> SQLITE
    API --> SCM
    UI --> API
```

---

## 2. Windows Defender Coexistence Architecture (Dual-Layer Shield)

### The Coexistence Problem in Windows
Traditional third-party antivirus software registers with Windows Security Center (`WSC`), which instructs Windows Defender Antivirus to enter passive or disabled mode. Furthermore, naive quarantine engines and file watchers trigger collision loops:
1. When third-party AV writes or moves a malware sample, Windows Defender's kernel filter (`WdFilter.sys`) intercepts the I/O request.
2. If Defender detects the file first, the OS returns error `0x800700E1` or `std::io::ErrorKind::PermissionDenied` / `os error 225` ("Operation did not complete successfully because the file contains a virus or potentially unwanted software").
3. Third-party software crashes or enters an unhandled loop.

### Project Guard's Dual-Layer Solution
1. **Active Intercept & Graceful Degradation**:
   When scanning files or moving infected artifacts, Project Guard explicitly detects raw OS error 225:
   ```rust
   match fs::copy(&infected_path, &vault_temp) {
       Ok(_) => { /* Proceed to isolate */ },
       Err(ref e) if e.raw_os_error() == Some(225) => {
           // Intercepted by Defender WdFilter.sys:
           // Treat as successful active mitigation by primary layer!
       }
       Err(e) => return Err(e.into()),
   }
   ```
2. **Reversible XOR `0x5A` Vault Masking**:
   Quarantined files are not stored as plain bytes. Every byte is XOR-transformed with key `0x5A`:
   $$B_{vault}[i] = B_{original}[i] \oplus \text{0x5A}$$
   - Any PE executable headers (`MZ\x90\x00` $\rightarrow$ `\x17\x00\x6A\x5A`) are rendered completely un-executable by the Windows kernel.
   - Defender does not quarantine the vault repository, preventing false-positive loops.
   - Restoration is instantaneous and lossless: $(B \oplus K) \oplus K = B$.

3. **Unified Telemetry Fusion**:
   Project Guard continuously queries Defender's status via PowerShell CIM bindings (`Get-MpComputerStatus`) and merges Defender's detection events (Event ID 1116 / 1117) into its unified Web SOC Dashboard.

---

## 3. The 21 Security Engines Breakdown

| Category | Engine Name | Detection Methodology | ATT&CK Reference |
|---|---|---|---|
| **Signature & Intel** | `YaraEngine` | Memory-safe YARA-X compiled pattern matching | All Techniques |
| | `HashEngine` | SHA-256 / MD-5 lookups against SQLite local cache | T1204 (User Execution) |
| | `MalwareBazaarFeed` | Daily automated sync of known ransomware & trojans | T1566 (Phishing) |
| | `ThreatFoxFeed` | Live ingestion of malicious C2 IPs & payload URLs | T1071 (Application Layer) |
| | `FeodoTrackerFeed` | Real-time Dridex/Emotet/Qakbot C2 IP verification | T1573 (Encrypted Channel) |
| | `ClamAvEngine` | Native ClamAV `.hdb` hash database & clamd socket | T1027 (Obfuscation) |
| | `YaraForgeSync` | Curated YARA rulesets for Cobalt Strike, APTs & Mimikatz | T1003 (Credential Dumping) |
| **Heuristic & PE** | `PeTriager` | Shannon Entropy calculation per section (0.0 - 8.0) | T1027.002 (Software Packing) |
| | `WXViolationEngine` | Identification of dual `WRITE` + `EXECUTE` sections | T1055 (Process Injection) |
| | `CapaCapabilityEngine`| Behavioral API pattern scoring for ransomware & evasion | T1486 (Data Encrypted) |
| | `DriverHunter` | LOLDrivers hash list & vulnerable kernel drivers | T1068, T1543 (BYOVD) |
| | `UpxCrypterEngine` | Detection of packed executables and modified headers | T1027.002 (Packing) |
| **Memory & Script** | `ProcessMemoryScanner`| Live `VirtualQueryEx` unbacked `PAGE_EXECUTE_READWRITE` | T1055.001 (DLL Injection) |
| | `ScriptHunter` | AST & regex parsing of PowerShell / VBScript / Batch | T1059 (Command & Script) |
| | `AmsiBypassDetector` | Detection of `amsiInitFailed` and memory patch patterns | T1562.001 (Disable Tools) |
| | `LolbasHunter` | Parent-child anomalies (`mshta`, `rundll32`, `certutil`) | T1218 (System Binary Proxy) |
| | `IocExtractor` | In-flight decoding of Base64, Bitcoin wallets, and IPs | T1027 (Deobfuscation) |
| **Host Defense** | `EventLogHunter` | Real-time monitoring of Windows Event Log ID 4104/1102 | T1059.001, T1070 (Logs) |
| | `CanaryManager` | Strategic honeypot files monitoring ransomware trips | T1486 (Ransomware Defense) |
| | `FimEngine` | Cryptographic SHA-256 integrity checks on hosts/system | T1565 (Data Manipulation) |
| | `UsbMonitor` | Plug-and-play removable drive scanning for LNK worms | T1091 (Replication Media) |

---

## 4. Windows Service Architecture & Lifecycle

The background service integrates with the Windows **Service Control Manager (SCM)** using standard system APIs (`sc.exe` and native Windows threading).

```
   ┌────────────────────────────────────────────────────────┐
   │             Windows Service Control Manager            │
   └───────────────────────────┬────────────────────────────┘
                               │ sc.exe start ProjectGuard
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │     project-guard.exe service run (SYSTEM Context)     │
   └─────────────┬────────────────────────────┬─────────────┘
                 │                            │
                 ▼                            ▼
   ┌───────────────────────────┐┌───────────────────────────┐
   │ Canary Monitor Thread     ││ Main Watchdog Loop        │
   │ Checks honeypot canaries  ││ Heartbeat logging         │
   │ Every 3 seconds           ││ EventLog / FIM checks     │
   │ Triggers emergency alerts ││ Every 10 seconds          │
   └───────────────────────────┘└───────────────────────────┘
```

### Auto-Recovery Configuration
When registered via `project-guard service install`, Project Guard configures the SCM failure policy:
- **First Failure**: Restart service after 5,000 ms.
- **Second Failure**: Restart service after 10,000 ms.
- **Subsequent Failures**: Restart service after 20,000 ms.
- **Fail Count Reset**: 86,400 seconds (24 hours).

---

## 5. Concurrency & Memory Safety Guarantees

1. **Zero-Cost Abstractions & No Garbage Collector**:
   Written in **Rust 2024 Edition**, memory safety is mathematically enforced by the compiler's affine type system. No data races, no memory leaks, and no use-after-free conditions are possible in safe blocks.
2. **Thread Isolation**:
   - The Web UI runs asynchronously on **Tokio** multi-threaded runtime.
   - The Windows Service daemon and Canary monitoring run on dedicated OS threads with atomic synchronizations (`std::sync::atomic::AtomicBool`).
   - The Database layer utilizes connection pools with thread-safe Mutex wrappers.
3. **PE Parser Safety**:
   PE parsing is executed via the `object` crate, completely sandboxed from unchecked pointer arithmetic, eliminating parser vulnerability exploits common in legacy C++ AV products.

---

## 6. Directory Layout & Data Storage

All operational data is maintained in `.project_guard/`:

```
.project_guard/
├── guard.db            # SQLite 3 WAL database storing IOCs, threat rules, and detection history
├── canaries.json       # Metadata and state of active ransomware canary traps
├── fim_baseline.json   # Cryptographic SHA-256 baselines of protected system binaries
├── service.log         # 24/7 Windows Service heartbeat and event log
├── quarantine/         # XOR 0x5A encrypted quarantine vault
└── rules/              # Compiled YARA rules and community threat signatures
```
