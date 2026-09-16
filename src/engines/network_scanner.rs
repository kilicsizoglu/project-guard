use super::trait_engine::{Severity, ThreatDetection};
use crate::db::DbStore;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::{Arc, Mutex};
use sysinfo::{Pid, System};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionInfo {
    pub proto: String,
    pub local_addr: String,
    pub foreign_addr: String,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
    pub is_suspicious: bool,
    pub threat_details: Option<String>,
}

pub struct NetworkThreatHunter {
    db: Arc<Mutex<DbStore>>,
}

impl NetworkThreatHunter {
    pub fn new(db: Arc<Mutex<DbStore>>) -> Self {
        Self { db }
    }

    /// Sistemdeki aktif TCP baglantilarini netstat ile listeler ve C2 IOC analizi yapar
    pub fn scan_connections(&self) -> Result<Vec<NetworkConnectionInfo>> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let output = Command::new("netstat")
            .args(["-ano", "-p", "tcp"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut connections = Vec::new();

        // Bilinen şüpheli/zararlı C2 portları
        let suspicious_c2_ports = [4444, 1337, 6667, 8888, 31337, 7777, 9999];

        // SQLite C2 IOC haritasını çek
        let c2_map = {
            if let Ok(db_guard) = self.db.lock() {
                db_guard.get_all_c2_ips().unwrap_or_default()
            } else {
                std::collections::HashMap::new()
            }
        };

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format: TCP    192.168.1.15:52345     52.178.1.2:443       ESTABLISHED     1234
            if parts.len() >= 5 && parts[0].to_uppercase() == "TCP" {
                let local_addr = parts[1].to_string();
                let foreign_addr = parts[2].to_string();
                let state = parts[3].to_string();
                let pid: u32 = parts[4].parse().unwrap_or(0);

                // Yalnızca dış dünyaya bağlı olanları veya dinleyenleri değerlendir
                if foreign_addr.contains("0.0.0.0") || foreign_addr.contains("*") || foreign_addr.contains("127.0.0.1") {
                    continue;
                }

                let proc_name = if pid > 0 {
                    sys.process(Pid::from(pid as usize))
                        .map(|p| p.name().to_string_lossy().to_string())
                        .unwrap_or_else(|| "Bilinmiyor".to_string())
                } else {
                    "System".to_string()
                };

                let mut is_suspicious = false;
                let mut threat_details = None;

                // 1. Dış IP Adresi C2 Tehdit İstihbaratı Kontrolü
                let foreign_ip = foreign_addr.split(':').next().unwrap_or("");
                if let Some(malware_name) = c2_map.get(foreign_ip) {
                    is_suspicious = true;
                    threat_details = Some(format!(
                        "[KRİTİK C2] Doğrulanmış Botnet C2 Sunucusu ile İletişim! Tehdit: {} (IP: {})",
                        malware_name, foreign_ip
                    ));
                }

                // 2. Şüpheli C2 Port Kontrolü
                if let Some(port_str) = foreign_addr.split(':').last() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        if suspicious_c2_ports.contains(&port) {
                            is_suspicious = true;
                            let msg = format!("Şüpheli C2 / Arka Kapı (Backdoor) Portu tespit edildi: {}", port);
                            threat_details = match threat_details {
                                Some(existing) => Some(format!("{} | {}", existing, msg)),
                                None => Some(msg),
                            };
                        }
                    }
                }

                connections.push(NetworkConnectionInfo {
                    proto: "TCP".to_string(),
                    local_addr,
                    foreign_addr,
                    state,
                    pid,
                    process_name: proc_name,
                    is_suspicious,
                    threat_details,
                });
            }
        }

        Ok(connections)
    }
}
