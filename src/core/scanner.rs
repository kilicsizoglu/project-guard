use super::report::{FileReport, ScanSummary};
use crate::engines::{FileHashes, ScanEngine, ThreatDetection};
use crate::quarantine::QuarantineManager;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use md5::Md5;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use walkdir::WalkDir;

pub struct ScanOrchestrator {
    engines: Vec<Arc<dyn ScanEngine>>,
    quarantine_manager: Option<Arc<QuarantineManager>>,
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

impl ScanOrchestrator {
    pub fn new(
        engines: Vec<Arc<dyn ScanEngine>>,
        quarantine_manager: Option<Arc<QuarantineManager>>,
    ) -> Self {
        Self {
            engines,
            quarantine_manager,
        }
    }

    /// Dosyayi tek geciste okuyup hem icerigi hem de SHA256/MD5 hashlerini hesaplar
    pub fn read_and_hash_file(path: &Path, max_bytes: usize) -> Result<(Vec<u8>, FileHashes, u64)> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        let mut sha256_hasher = Sha256::new();
        let mut md5_hasher = Md5::new();

        let mut buffer = [0u8; 16384];
        let mut content = Vec::new();
        let mut total_read = 0;

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            sha256_hasher.update(&buffer[..bytes_read]);
            md5_hasher.update(&buffer[..bytes_read]);

            if total_read < max_bytes {
                let to_take = (max_bytes - total_read).min(bytes_read);
                content.extend_from_slice(&buffer[..to_take]);
                total_read += to_take;
            }
        }

        let sha256_res = sha256_hasher.finalize();
        let md5_res = md5_hasher.finalize();

        let sha256_hex = bytes_to_hex(&sha256_res);
        let md5_hex = bytes_to_hex(&md5_res);

        Ok((
            content,
            FileHashes {
                sha256: sha256_hex,
                md5: md5_hex,
            },
            file_size,
        ))
    }

    /// Tek bir dosyayi tum kayitli motorlarla tarar
    pub fn scan_single_file(
        &self,
        path: &Path,
        auto_quarantine: bool,
    ) -> Result<FileReport> {
        let (content, hashes, file_size) = match Self::read_and_hash_file(path, 64 * 1024 * 1024) {
            Ok(data) => data,
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("225")
                    || err_str.contains("contains a virus")
                    || err_str.contains("potentially unwanted software")
                {
                    let detection = ThreatDetection {
                        threat_name: "WinDefender.KernelFilter.BlockedMalware".to_string(),
                        engine_name: "Windows-Defender-Native".to_string(),
                        severity: crate::engines::Severity::Critical,
                        details: "Windows Defender (WdFilter.sys) isletim sistemi seviyesinde dosya erisimini engelledi (OS Error 225).".to_string(),
                        rule_name: Some("defender_kernel_block".to_string()),
                    };
                    return Ok(FileReport {
                        file_path: path.to_path_buf(),
                        file_size: 0,
                        sha256: "BLOCKED_BY_DEFENDER_DRIVER".to_string(),
                        md5: "BLOCKED_BY_DEFENDER_DRIVER".to_string(),
                        detections: vec![detection],
                        is_infected: true,
                        quarantined: false,
                    });
                }
                return Err(e);
            }
        };

        let mut detections = Vec::new();
        for engine in &self.engines {
            match engine.scan(path, &content, &hashes) {
                Ok(Some(detection)) => {
                    detections.push(detection);
                }
                Ok(None) => {}
                Err(err) => {
                    eprintln!("Motor [{}] hata bildirdi ({}): {:?}", engine.name(), path.display(), err);
                }
            }
        }

        let is_infected = !detections.is_empty();
        let mut quarantined = false;

        if is_infected && auto_quarantine {
            if let Some(ref q_mgr) = self.quarantine_manager {
                let first_threat = &detections[0];
                match q_mgr.quarantine_file(
                    path,
                    &first_threat.threat_name,
                    &first_threat.engine_name,
                    &hashes.sha256,
                ) {
                    Ok(_) => {
                        quarantined = true;
                    }
                    Err(err) => {
                        eprintln!("Karantinaya alma basarisiz ({}): {:?}", path.display(), err);
                    }
                }
            }
        }

        Ok(FileReport {
            file_path: path.to_path_buf(),
            file_size,
            sha256: hashes.sha256,
            md5: hashes.md5,
            detections,
            is_infected,
            quarantined,
        })
    }

    /// Bir hedefi (dosya veya dizin) tarar ve ozet uretir
    pub fn scan_target(
        &self,
        target: &Path,
        recursive: bool,
        auto_quarantine: bool,
        show_progress: bool,
    ) -> Result<ScanSummary> {
        let start_time = Instant::now();
        let mut summary = ScanSummary::new(target.to_string_lossy().to_string());

        let mut files_to_scan: Vec<PathBuf> = Vec::new();

        if target.is_file() {
            files_to_scan.push(target.to_path_buf());
        } else if target.is_dir() {
            let max_depth = if recursive { usize::MAX } else { 1 };
            for entry in WalkDir::new(target)
                .max_depth(max_depth)
                .into_iter()
                .filter_entry(|e| {
                    let name = e.file_name().to_string_lossy();
                    !name.starts_with(".project_guard") && !name.starts_with(".git")
                })
                .flatten()
            {
                if entry.file_type().is_file() {
                    files_to_scan.push(entry.into_path());
                }
            }
        }

        let pb = if show_progress && files_to_scan.len() > 1 {
            let bar = ProgressBar::new(files_to_scan.len() as u64);
            bar.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            Some(bar)
        } else {
            None
        };

        for path in &files_to_scan {
            if let Some(ref bar) = pb {
                bar.set_message(
                    path.file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_string(),
                );
            }

            match self.scan_single_file(path, auto_quarantine) {
                Ok(report) => {
                    summary.total_bytes += report.file_size;
                    summary.scanned_files += 1;
                    if report.is_infected {
                        summary.infected_files += 1;
                    }
                    summary.reports.push(report);
                }
                Err(e) => {
                    eprintln!("Dosya atlandi ({}): {}", path.display(), e);
                }
            }

            if let Some(ref bar) = pb {
                bar.inc(1);
            }
        }

        if let Some(bar) = pb {
            bar.finish_with_message("Tarama tamamlandi");
        }

        summary.elapsed_ms = start_time.elapsed().as_millis();
        Ok(summary)
    }
}
