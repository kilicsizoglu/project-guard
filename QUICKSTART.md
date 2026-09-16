# 🚀 Project Guard Quickstart Guide (5-Minute Onboarding)

Welcome to **Project Guard**. This guide provides an accelerated walkthrough for security analysts, incident responders, and system administrators to build, test, and deploy Project Guard on Windows.

---

## 📋 Prerequisites

Ensure your system has:
* **Windows 10 / 11 / Server 2019+** (64-bit x64 or ARM64)
* **Rust 1.85+ (Rust 2024 Edition)**: [Install Rust via rustup](https://rustup.rs/)
* **Administrator Privileges** (Required for Windows Service and Event Log access)

---

## ⚡ Fast-Track: 1-Click Windows Setup (Zero Config)

If you just want to install and use Project Guard immediately on Windows:

1. Double-click **`Setup.cmd`** in the repository root.
2. Accept the Windows UAC Administrator prompt (**Yes**).
3. Project Guard will automatically build (if needed), install to `C:\Program Files\ProjectGuard`, add Desktop & Start Menu shortcuts, register system PATH, configure 7/24 Windows Service, and launch the Desktop Control Center!

To uninstall cleanly at any time, double-click **`Uninstall.cmd`** or remove from Windows Settings > Installed Apps.

---

## ⚡ Step 1: Build the Executable with Embedded Windows Icon (Manual)

Clone the repository and build the release binary:

```powershell
# Open PowerShell as Administrator:
cd C:\path\to\project-guard

# Run unit tests to verify all 21 engines
cargo test

# Compile optimized release binary with embedded Windows icon & version resources
cargo build --release
```

The output binary will be generated at:
`target\release\project-guard.exe`

Right-click the executable in Windows File Explorer -> **Properties** -> **Details** to see the embedded version metadata (`Project Guard Autonomous Security Agent & EDR`).

---

## 🔍 Step 2: Instant CLI Health & Defender Coexistence Check

Verify that Project Guard recognizes your environment and Windows Defender status:

```powershell
# Check Windows Defender coexistence status
.\target\release\project-guard.exe defender-status
```

*Example Output:*
```
[+] Windows Defender Entegrasyon Raporu:
    Antivirus Durumu     : CALISIYOR (Active)
    Gercek Zamanli Koruma: ETKIN (Real-time Protection Enabled)
    Protokol             : Dual-Layer Coexistence [OK]
```

Test a quick directory scan:
```powershell
.\target\release\project-guard.exe scan . --recursive
```

---

## ⚙️ Step 3: Install as a 24/7 Windows Service

To enable persistent background protection that starts automatically on boot:

```powershell
# 1. Install the service into Windows Service Control Manager (SCM)
.\target\release\project-guard.exe service install

# 2. Start the background service
.\target\release\project-guard.exe service start

# 3. Query the live status
.\target\release\project-guard.exe service status
```

You will see:
```
  Hizmet Adi    : ProjectGuard
  Gorunen Isim  : Project Guard Autonomous EDR & Threat Hunter
  Yuklu mu?     : EVET [OK]
  Calisma Durumu: CALISIYOR (RUNNING) [OK]
```

Honeypot canary monitoring and service heartbeats will be logged to:
`.project_guard\service.log`

---

## 🖥️ Step 4: Launch the Glassmorphic Web SOC Dashboard

Launch the embedded web server:

```powershell
.\target\release\project-guard.exe ui --port 7890
```

Open your browser to: **[http://127.0.0.1:7890](http://127.0.0.1:7890)**

### Available Tabs:
1. **Overview**: Real-time engine health, Defender telemetry, and Windows Service Start/Stop card.
2. **EventLog Hunter**: Live PowerShell Event ID 4104 script execution logs.
3. **PE Triager**: Shannon entropy heatmap per section and MITRE ATT&CK capability matrix.
4. **Threat Intel**: 1-click sync for MalwareBazaar, ThreatFox, Feodo C2, and YARA-Forge.
5. **Memory & Process Scanner**: Live unbacked RWX memory detection and process killswitch.
6. **Canary Traps**: Deploy and monitor ransomware tripwires.

---

## 🪤 Step 5: Test Strategic Ransomware Canary Traps

Deploy canary traps in your documents folder:

```powershell
.\target\release\project-guard.exe canary-deploy $HOME\Documents
```

Project Guard places disguised decoy files with cryptographic SHA-256 signatures. The background service monitors these decoys every 3 seconds. If any ransomware attempts to encrypt them, an instant emergency alert is generated in the dashboard and logs.

---

## 🛑 Step 6: Uninstalling or Stopping the Service

When maintenance is needed:

```powershell
# Stop the service
.\target\release\project-guard.exe service stop

# Completely remove the service from Windows SCM
.\target\release\project-guard.exe service uninstall
```

---

## ❓ Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| `Access is denied (os error 5)` during build | An existing instance of `project-guard.exe` is running | Run `taskkill /F /IM project-guard.exe` and rebuild |
| `sc.exe create` fails | PowerShell is not running as Administrator | Re-open PowerShell with **Run as Administrator** |
| `os error 225` on quarantine | Windows Defender intercepted the malware first | Normal behavior: Project Guard safely handles this as a dual-layer mitigation |
| Port 7890 in use | Another application or previous UI instance is on port 7890 | Use `project-guard ui --port 8080` |
