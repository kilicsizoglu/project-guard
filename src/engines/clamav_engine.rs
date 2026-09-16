use super::trait_engine::{FileHashes, ScanEngine, Severity, ThreatDetection};
use crate::db::DbStore;
use anyhow::Result;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct ClamAvEngine {
    clamd_addr: Option<SocketAddr>,
    db: Arc<Mutex<DbStore>>,
}

impl ClamAvEngine {
    pub fn new(clamd_port: Option<u16>, db: Arc<Mutex<DbStore>>) -> Self {
        let addr = clamd_port.and_then(|port| format!("127.0.0.1:{}", port).parse::<SocketAddr>().ok());
        Self {
            clamd_addr: addr,
            db,
        }
    }

    /// clamd TCP servisine INSTREAM komutu ile dosya akisi gonderip tarama yaptirir
    fn scan_via_clamd(&self, addr: SocketAddr, content: &[u8]) -> Result<Option<String>> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        // ClamAV INSTREAM protokolü
        stream.write_all(b"zINSTREAM\0")?;

        let chunk_size = 4096;
        for chunk in content.chunks(chunk_size) {
            let len = (chunk.len() as u32).to_be_bytes();
            stream.write_all(&len)?;
            stream.write_all(chunk)?;
        }
        // Sifir uzunluklu paket ile stream sonlandirilir
        stream.write_all(&[0, 0, 0, 0])?;
        stream.flush()?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        // ClamAV yanit formati: "stream: <virus_adi> FOUND" veya "stream: OK"
        if response.contains("FOUND") {
            let parts: Vec<&str> = response.split_whitespace().collect();
            if parts.len() >= 2 {
                return Ok(Some(parts[1].to_string()));
            }
            return Ok(Some("ClamAV.DetectedThreat".to_string()));
        }

        Ok(None)
    }
}

impl ScanEngine for ClamAvEngine {
    fn name(&self) -> &'static str {
        "ClamAV-Adapter-Engine"
    }

    fn description(&self) -> &'static str {
        "ClamAV yerel daemon (clamd) ve resmi CVD/NDB acik kaynak imza adaptoru"
    }

    fn scan(
        &self,
        _path: &Path,
        content: &[u8],
        hashes: &FileHashes,
    ) -> Result<Option<ThreatDetection>> {
        // 1. Canli clamd servisi varsa once ona danis
        if let Some(addr) = self.clamd_addr {
            if let Ok(Some(threat)) = self.scan_via_clamd(addr, content) {
                return Ok(Some(ThreatDetection {
                    threat_name: format!("ClamAV.{}", threat),
                    engine_name: self.name().to_string(),
                    severity: Severity::Critical,
                    details: format!("Yerel ClamAV motoru tespiti: {}", threat),
                    rule_name: Some(threat),
                }));
            }
        }

        // 2. ClamAV CVD/HDB acik kaynak imza veritabanindan cekilmis hash kontrolu
        let db_guard = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        if let Some((threat, source)) = db_guard.find_signature(&hashes.md5)? {
            if source.to_lowercase().contains("clamav") {
                return Ok(Some(ThreatDetection {
                    threat_name: format!("ClamAV.{}", threat),
                    engine_name: self.name().to_string(),
                    severity: Severity::Critical,
                    details: format!("ClamAV Acik Kaynak CVD Imzasi: {}", threat),
                    rule_name: Some(format!("clamav:{}", hashes.md5)),
                }));
            }
        }

        Ok(None)
    }
}
