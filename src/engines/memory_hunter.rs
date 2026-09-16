use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::sync::Arc;
use sysinfo::System;

use super::win_api::*;
use crate::engines::yara_engine::YaraEngine;
use crate::engines::ScanEngine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryThreatReport {
    pub pid: u32,
    pub process_name: String,
    pub region_address: String,
    pub region_size: usize,
    pub protection: String,
    pub memory_type: String,
    pub threat_type: String,
    pub severity: String,
    pub details: String,
    pub yara_matches: Vec<String>,
}

pub struct MemoryHunter {
    yara_engine: Option<Arc<YaraEngine>>,
}

impl MemoryHunter {
    pub fn new(yara_engine: Option<Arc<YaraEngine>>) -> Self {
        Self { yara_engine }
    }

    /// Sistemdeki tüm kullanıcı süreçlerinin bellek bölgelerini tarar ve enjeksiyonları avlar
    pub fn scan_all_processes(&self) -> Result<Vec<MemoryThreatReport>> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let mut reports = Vec::new();

        for (pid, proc_info) in sys.processes() {
            let pid_u32 = pid.as_u32();
            // Sistem boşta ve temel kernel süreçlerini atla
            if pid_u32 <= 4 {
                continue;
            }

            let proc_name = proc_info.name().to_string_lossy().to_string();
            let mut proc_reports = self.scan_process_memory(pid_u32, &proc_name);
            reports.append(&mut proc_reports);
        }

        Ok(reports)
    }

    /// Belirli bir sürecin bellek sayfalarını tarar
    pub fn scan_process_memory(&self, pid: u32, proc_name: &str) -> Vec<MemoryThreatReport> {
        let mut detections = Vec::new();

        let handle = match ProcessHandle::open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) {
            Some(h) => h,
            None => return detections, // Yetersiz ayrıcalık veya erişim reddedildi
        };

        let mut current_addr = 0usize;
        let max_user_addr = 0x7FFFFFFF0000usize; // 64-bit kullanıcı alanı sınırı

        // Maksimum 500 sayfa tara (aşırı bellek harcamasını ve takılmaları önler)
        let mut scanned_regions = 0;
        while current_addr < max_user_addr && scanned_regions < 500 {
            scanned_regions += 1;
            let ptr = current_addr as *const c_void;
            let mbi = match handle.query_memory_region(ptr) {
                Some(m) => m,
                None => break,
            };

            let region_size = mbi.region_size;
            if region_size == 0 {
                break;
            }

            // Yalnızca ayrılmış (MEM_COMMIT) sayfaları incele
            if mbi.state == MEM_COMMIT {
                let is_exec = (mbi.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                let is_rwx = (mbi.protect & PAGE_EXECUTE_READWRITE) != 0;
                let is_private = mbi.memory_type == MEM_PRIVATE;

                // 1. Durum: Unbacked Private Executable Memory (Reflective DLL / Shellcode / Cobalt Strike Beacon)
                // Diskteki bir dosyaya (MEM_IMAGE) dayanmayan, özel tahsis edilmiş çalıştırılabilir bellek
                if is_exec && is_private {
                    let mut yara_hits = Vec::new();

                    // Bellek içeriğini güvenle oku (en fazla 1 MB)
                    let read_limit = region_size.min(1024 * 1024);
                    if let Some(bytes) = handle.read_memory(mbi.base_address, read_limit) {
                        // YARA-X motoruyla tara
                        if let Some(ref yara) = self.yara_engine {
                            let dummy_hashes = crate::engines::FileHashes {
                                sha256: "memory_buffer".to_string(),
                                md5: "memory_buffer".to_string(),
                            };
                            let dummy_path = std::path::Path::new("in_memory_injection.bin");
                            if let Ok(Some(threat)) = yara.scan(dummy_path, &bytes, &dummy_hashes) {
                                yara_hits.push(format!("{}: {}", threat.threat_name, threat.details));
                            }
                        }

                        // Shellcode NOP sled ve MZ header tespiti
                        let has_mz = bytes.starts_with(b"MZ");
                        let is_suspicious_payload = has_mz || !yara_hits.is_empty() || is_rwx;

                        if is_suspicious_payload {
                            let threat_type = if has_mz {
                                "ReflectiveDLL.Injection (In-Memory PE)"
                            } else if is_rwx {
                                "Shellcode.RWX.UnbackedMemory"
                            } else {
                                "ProcessHollowing.UnbackedExecutable"
                            };

                            let details = format!(
                                "Diskte karsiligi olmayan (Unbacked) ozel calistirilabilir bellek bolgesi. {} (Boyut: {} KB)",
                                if has_mz { "Gizlenmis MZ basligi tespit edildi." } else { "Supheli bellek enjeksiyonu." },
                                region_size / 1024
                            );

                            detections.push(MemoryThreatReport {
                                pid,
                                process_name: proc_name.to_string(),
                                region_address: format!("0x{:X}", mbi.base_address as usize),
                                region_size,
                                protection: if is_rwx { "PAGE_EXECUTE_READWRITE (RWX)".to_string() } else { "PAGE_EXECUTE_READ".to_string() },
                                memory_type: "MEM_PRIVATE (Dosyasiz Bellek)".to_string(),
                                threat_type: threat_type.to_string(),
                                severity: "Critical".to_string(),
                                details,
                                yara_matches: yara_hits,
                            });
                        }
                    }
                }
            }

            // Bir sonraki bellek sayfasına geç
            match current_addr.checked_add(region_size) {
                Some(next_addr) => current_addr = next_addr,
                None => break,
            }
        }

        detections
    }
}
