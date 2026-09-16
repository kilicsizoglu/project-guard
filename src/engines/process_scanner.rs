use crate::core::ScanOrchestrator;
use crate::engines::{Severity, ThreatDetection};
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use sysinfo::{Pid, System};

#[derive(Debug, Clone)]
pub struct ProcessThreatReport {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
    pub cmd: Vec<String>,
    pub detections: Vec<ThreatDetection>,
    pub killed: bool,
}

pub struct ProcessScanner {
    orchestrator: Arc<ScanOrchestrator>,
}

impl ProcessScanner {
    pub fn new(orchestrator: Arc<ScanOrchestrator>) -> Self {
        Self { orchestrator }
    }

    /// Sistemde aktif calisan tum surecleri tarar (Tekrarlayan binary'ler onbelleginir)
    pub fn scan_all_processes(&self, kill_malicious: bool) -> Result<Vec<ProcessThreatReport>> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let processes: Vec<(Pid, String, Option<PathBuf>, Vec<String>)> = sys
            .processes()
            .iter()
            .map(|(pid, proc_info)| {
                let name = proc_info.name().to_string_lossy().to_string();
                let exe = proc_info.exe().map(|p| p.to_path_buf());
                let cmd = proc_info
                    .cmd()
                    .iter()
                    .map(|c| c.to_string_lossy().to_string())
                    .collect();
                (*pid, name, exe, cmd)
            })
            .collect();

        let pb = ProgressBar::new(processes.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} Surec Taraniyor: {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        let mut reports = Vec::new();
        // Aynı dosya yolunu tekrar tekrar taramamak için önbellek (Örn: 80 adet svchost.exe)
        let mut exe_cache: HashMap<PathBuf, Vec<ThreatDetection>> = HashMap::new();

        for (pid, name, exe_path, cmd) in processes {
            pb.set_message(name.clone());
            let mut detections = Vec::new();

            // 1. Komut satiri (Command-line) Davranissal Analiz (Sigma Kurallari)
            let full_cmd_line = cmd.join(" ");
            if !full_cmd_line.is_empty() {
                let behaviors = crate::engines::behavior_engine::BehaviorEngine::analyze_command_line(&full_cmd_line);
                for b in behaviors {
                    let sev = match b.severity.as_str() {
                        "Critical" => Severity::Critical,
                        "High" => Severity::High,
                        "Medium" => Severity::Medium,
                        _ => Severity::Low,
                    };
                    detections.push(ThreatDetection {
                        threat_name: format!("Proc.Behavior.{}", b.mitre_attack_id),
                        engine_name: "Behavior-Sigma-Engine".to_string(),
                        severity: sev,
                        details: format!("[{}] {} -> {}", b.rule_id, b.rule_name, b.description),
                        rule_name: Some(b.rule_id),
                    });
                }
            }

            // 2. Surecin diskteki EXE dosyasini coklu motorla tarama (Onbellekli)
            if let Some(ref exe) = exe_path {
                if exe.exists() {
                    if let Some(cached_detections) = exe_cache.get(exe) {
                        for det in cached_detections {
                            detections.push(det.clone());
                        }
                    } else {
                        let mut file_detections = Vec::new();
                        if let Ok(file_report) = self.orchestrator.scan_single_file(exe, false) {
                            file_detections = file_report.detections;
                        }
                        for det in &file_detections {
                            detections.push(det.clone());
                        }
                        exe_cache.insert(exe.clone(), file_detections);
                    }
                }
            }

            if !detections.is_empty() {
                let mut killed = false;
                if kill_malicious {
                    if let Some(proc_to_kill) = sys.process(pid) {
                        killed = proc_to_kill.kill();
                    }
                }

                reports.push(ProcessThreatReport {
                    pid: pid.as_u32(),
                    name,
                    exe_path,
                    cmd,
                    detections,
                    killed,
                });
            }

            pb.inc(1);
        }

        pb.finish_with_message("Tum surecler tarandi.");
        Ok(reports)
    }

    /// Belirtilen PID'ye sahip zararlı süreci anında sonlandırır (Kill Switch)
    pub fn kill_process_by_pid(pid: u32) -> Result<bool> {
        // 1. Native Windows TerminateProcess çağrısı
        if let Some(handle) = crate::engines::win_api::ProcessHandle::open(pid, crate::engines::win_api::PROCESS_TERMINATE) {
            if handle.terminate(1) {
                return Ok(true);
            }
        }

        // 2. Sysinfo ile deneme
        let mut sys = System::new_all();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let pid_val = Pid::from_u32(pid);
        if let Some(p) = sys.process(pid_val) {
            return Ok(p.kill());
        }

        Ok(false)
    }
}
