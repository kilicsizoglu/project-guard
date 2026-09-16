use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

use crate::core::ScanOrchestrator;
use crate::db::DbStore;
use crate::engines::behavior_engine::BehaviorEngine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub location: String,
    pub name: String,
    pub command: String,
    pub target_path: Option<String>,
    pub is_suspicious: bool,
    pub severity: String,
    pub threat_details: Option<String>,
}

pub struct PersistenceScanner {
    _db: Arc<std::sync::Mutex<DbStore>>,
    orchestrator: Arc<ScanOrchestrator>,
}

impl PersistenceScanner {
    pub fn new(db: Arc<std::sync::Mutex<DbStore>>, orchestrator: Arc<ScanOrchestrator>) -> Self {
        Self {
            _db: db,
            orchestrator,
        }
    }

    /// Tüm Windows kalıcılık ve başlangıç noktalarını (Kayıt Defteri, Başlangıç Klasörü, Zamanlanmış Görevler) tarar.
    pub fn scan_all(&self) -> Result<Vec<PersistenceEntry>> {
        let mut entries = Vec::new();

        // 1. Kayıt Defteri Run ve RunOnce anahtarları
        self.scan_registry_keys(&mut entries);

        // 2. Başlangıç klasörleri (Startup Folders)
        self.scan_startup_folders(&mut entries);

        // 3. Zamanlanmış Görevler (Scheduled Tasks)
        self.scan_scheduled_tasks(&mut entries);

        Ok(entries)
    }

    fn scan_registry_keys(&self, entries: &mut Vec<PersistenceEntry>) {
        let reg_targets = [
            ("HKCU\\Run", "HKCU\\Software\\Microsoft\x5cWindows\\CurrentVersion\\Run"),
            ("HKCU\\RunOnce", "HKCU\\Software\\Microsoft\x5cWindows\\CurrentVersion\\RunOnce"),
            ("HKLM\\Run", "HKLM\\Software\\Microsoft\x5cWindows\\CurrentVersion\\Run"),
            ("HKLM\\RunOnce", "HKLM\\Software\\Microsoft\x5cWindows\\CurrentVersion\\RunOnce"),
        ];

        for (loc_name, key_path) in reg_targets {
            let mut cmd = Command::new("reg");
            cmd.args(["query", key_path]);
            #[cfg(windows)]
            cmd.creation_flags(CREATE_NO_WINDOW);
            let output = cmd.output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with("HKEY_") {
                        continue;
                    }

                    // Format: Name REG_SZ Value VEYA Name REG_EXPAND_SZ Value
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let name = parts[0].to_string();
                        // Değer, türden sonraki tüm kısımdır
                        let cmd_start_idx = if trimmed.contains("REG_SZ") {
                            trimmed.find("REG_SZ").map(|idx| idx + 6)
                        } else if trimmed.contains("REG_EXPAND_SZ") {
                            trimmed.find("REG_EXPAND_SZ").map(|idx| idx + 13)
                        } else {
                            None
                        };

                        let full_command = cmd_start_idx
                            .map(|idx| trimmed[idx..].trim().to_string())
                            .unwrap_or_else(|| parts[2..].join(" "));

                        let entry = self.analyze_entry(loc_name, &name, &full_command);
                        entries.push(entry);
                    }
                }
            }
        }
    }

    fn scan_startup_folders(&self, entries: &mut Vec<PersistenceEntry>) {
        let mut dirs = Vec::new();

        if let Ok(appdata) = std::env::var("APPDATA") {
            dirs.push(("Kullanıcı Başlangıç Klasörü", PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup")));
        }
        if let Ok(progdata) = std::env::var("ProgramData") {
            dirs.push(("Sistem Başlangıç Klasörü", PathBuf::from(progdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup")));
        }

        for (loc_name, dir_path) in dirs {
            if dir_path.exists() {
                if let Ok(read_dir) = fs::read_dir(&dir_path) {
                    for entry_res in read_dir.flatten() {
                        let path = entry_res.path();
                        if path.is_file() {
                            let filename = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                            let cmd = path.display().to_string();
                            let mut item = self.analyze_entry(loc_name, &filename, &cmd);
                            item.target_path = Some(cmd.clone());
                            entries.push(item);
                        }
                    }
                }
            }
        }
    }

    fn scan_scheduled_tasks(&self, entries: &mut Vec<PersistenceEntry>) {
        let mut cmd = Command::new("schtasks");
        cmd.args(["/query", "/fo", "CSV", "/v"]);
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        let output = cmd.output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut lines = stdout.lines();

            // İlk satır başlıklar (HostName, TaskName, ..., Task To Run)
            if let Some(header_line) = lines.next() {
                let headers: Vec<&str> = header_line.split(',').map(|s| s.trim_matches('"').trim()).collect();
                let task_to_run_idx = headers.iter().position(|&h| h == "Task To Run");
                let task_name_idx = headers.iter().position(|&h| h == "TaskName");
                let author_idx = headers.iter().position(|&h| h == "Author");

                for line in lines {
                    if line.starts_with('"') {
                        // Basit CSV ayıklama
                        let cols: Vec<String> = line
                            .split("\",\"")
                            .map(|s| s.trim_matches('"').trim().to_string())
                            .collect();

                        if let (Some(name_idx), Some(run_idx)) = (task_name_idx, task_to_run_idx) {
                            if cols.len() > run_idx && cols.len() > name_idx {
                                let task_name = &cols[name_idx];
                                let task_run = &cols[run_idx];
                                let author = author_idx.and_then(|i| cols.get(i)).map(|s| s.as_str()).unwrap_or("");

                                // Windows dahili veya boş görevleri filtrele (isteğe bağlı, şüpheli olanları önceliklendir)
                                if task_run.is_empty() || task_run == "COM handler" || task_run == "N/A" || task_name == "TaskName" || task_run == "Task To Run" {
                                    continue;
                                }

                                // Microsoft dışındaki veya şüpheli komutları tara
                                let is_ms = author.contains("Microsoft") || task_name.starts_with("\\Microsoft\\");
                                let has_behaviors = !BehaviorEngine::analyze_command_line(task_run).is_empty();

                                if !is_ms || has_behaviors {
                                    let mut entry = self.analyze_entry("Zamanlanmış Görev", task_name, task_run);
                                    if is_ms {
                                        entry.severity = "Medium".to_string();
                                    }
                                    entries.push(entry);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_entry(&self, location: &str, name: &str, command: &str) -> PersistenceEntry {
        let mut is_suspicious = false;
        let mut severity = "Clean".to_string();
        let mut details = Vec::new();

        // 1. Komut satırı davranış analizi (Sigma kuralları)
        let behaviors = BehaviorEngine::analyze_command_line(command);
        if !behaviors.is_empty() {
            is_suspicious = true;
            severity = "Critical".to_string();
            for b in behaviors {
                details.push(format!("[{}] {} (MITRE: {})", b.severity, b.rule_name, b.mitre_attack_id));
            }
        }

        // 2. Hedef dosya yolunu ayıkla
        let target_path = extract_executable_path(command);

        // 3. Dosya yolu şüpheli konumlarda mı?
        if let Some(ref path_str) = target_path {
            let path_lower = path_str.to_lowercase();
            let is_in_temp = path_lower.contains("\\temp\\") || path_lower.contains("\\tmp\\");
            let is_in_appdata = path_lower.contains("\\appdata\\local\\") || path_lower.contains("\\appdata\\roaming\\");
            let is_in_public = path_lower.contains("c:\\users\\public");

            if is_in_temp || (is_in_appdata && !path_lower.contains("microsoft") && !path_lower.contains("programs")) || is_in_public {
                is_suspicious = true;
                if severity == "Clean" {
                    severity = "High".to_string();
                }
                details.push("Hedef ikili supheli/yazilabilir dizinden (AppData/Temp/Public) calisiyor.".to_string());
            }

            // 4. Hedef dosya mevcutsa çoklu motorla doğrula
            let file_path = Path::new(path_str);
            if file_path.exists() && file_path.is_file() {
                if let Ok(report) = self.orchestrator.scan_single_file(file_path, false) {
                    let real_threats: Vec<_> = report.detections.into_iter()
                        .filter(|d| d.severity == crate::engines::Severity::Critical || d.severity == crate::engines::Severity::High)
                        .collect();

                    if !real_threats.is_empty() {
                        is_suspicious = true;
                        severity = "Critical".to_string();
                        for det in real_threats {
                            details.push(format!("Motor Tespiti: [{}] {}", det.engine_name, det.threat_name));
                        }
                    }
                }
            }
        }

        let threat_details = if details.is_empty() {
            None
        } else {
            Some(details.join(" | "))
        };

        PersistenceEntry {
            location: location.to_string(),
            name: name.to_string(),
            command: command.to_string(),
            target_path,
            is_suspicious,
            severity,
            threat_details,
        }
    }
}

/// Komut satırı dizesinden yürütülebilir dosyanın tam yolunu ayıklar.
fn extract_executable_path(cmd: &str) -> Option<String> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with('"') {
        if let Some(end_quote) = trimmed[1..].find('"') {
            let candidate = &trimmed[1..=end_quote];
            return Some(candidate.to_string());
        }
    }

    // .exe iceren tirnaksiz (unquoted) bosluklu yollari ayikla
    let lower = trimmed.to_lowercase();
    if let Some(exe_idx) = lower.find(".exe") {
        let candidate = &trimmed[..exe_idx + 4];
        return Some(candidate.to_string());
    }

    let first_part = trimmed.split_whitespace().next().unwrap_or(trimmed);
    let path = Path::new(first_part);
    if path.extension().is_some() || first_part.contains('\\') || first_part.contains('/') {
        Some(first_part.to_string())
    } else {
        None
    }
}
