use super::trait_engine::{FileHashes, ScanEngine, Severity, ThreatDetection};
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct WindowsDefenderEngine {
    mpcmdrun_path: Option<PathBuf>,
}

impl WindowsDefenderEngine {
    pub fn new() -> Self {
        let possible_paths = [
            PathBuf::from(r"C:\Program Files\Windows Defender\MpCmdRun.exe"),
            PathBuf::from(r"C:\ProgramData\Microsoft\Windows Defender\Platform"),
        ];

        let mut found_path = None;
        if possible_paths[0].exists() {
            found_path = Some(possible_paths[0].clone());
        } else if possible_paths[1].exists() {
            // Platform klasörü altındaki en güncel sürüm dizinine bak
            if let Ok(entries) = std::fs::read_dir(&possible_paths[1]) {
                for entry in entries.flatten() {
                    let exe = entry.path().join("MpCmdRun.exe");
                    if exe.exists() {
                        found_path = Some(exe);
                        break;
                    }
                }
            }
        }

        Self {
            mpcmdrun_path: found_path,
        }
    }

    pub fn is_available(&self) -> bool {
        self.mpcmdrun_path.is_some()
    }
}

impl Default for WindowsDefenderEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanEngine for WindowsDefenderEngine {
    fn name(&self) -> &'static str {
        "Windows-Defender-Engine"
    }

    fn description(&self) -> &'static str {
        "Yerlesik Microsoft Windows Defender (MpCmdRun CLI) motor adaptoru"
    }

    fn scan(
        &self,
        path: &Path,
        _content: &[u8],
        _hashes: &FileHashes,
    ) -> Result<Option<ThreatDetection>> {
        let exe = match &self.mpcmdrun_path {
            Some(p) => p,
            None => return Ok(None),
        };

        // MpCmdRun.exe -Scan -ScanType 3 -File <path> -DisableRemediation
        // -DisableRemediation: Dosyayı silmeden veya karantinaya almadan sadece sonucu döner.
        // Return code:
        // 0: Temiz
        // 2: Tehdit bulundu veya hata
        let mut cmd = Command::new(exe);
        cmd.arg("-Scan")
            .arg("-ScanType")
            .arg("3")
            .arg("-File")
            .arg(path)
            .arg("-DisableRemediation");
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        let output = cmd.output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{}\n{}", stdout, stderr);

            // Windows Defender tespit kontrolü
            if out.status.code() == Some(2) || combined.contains("Threat ") || combined.contains("found:") {
                let mut threat_name = "WinDefender.DetectedThreat".to_string();
                for line in combined.lines() {
                    if line.contains("Threat ") || line.contains("ThreatName") {
                        threat_name = format!("WinDefender.{}", line.trim());
                        break;
                    }
                }

                return Ok(Some(ThreatDetection {
                    threat_name,
                    engine_name: self.name().to_string(),
                    severity: Severity::Critical,
                    details: "Microsoft Windows Defender motoru tarafindan dogrulanmis tehdit tespiti".to_string(),
                    rule_name: Some("windows_defender_mpcmdrun".to_string()),
                }));
            }
        }

        Ok(None)
    }
}
