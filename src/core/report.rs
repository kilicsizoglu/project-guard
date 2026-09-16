use crate::engines::ThreatDetection;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReport {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub sha256: String,
    pub md5: String,
    pub detections: Vec<ThreatDetection>,
    pub is_infected: bool,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub target_path: String,
    pub scanned_files: usize,
    pub infected_files: usize,
    pub total_bytes: u64,
    pub elapsed_ms: u128,
    pub reports: Vec<FileReport>,
}

impl ScanSummary {
    pub fn new(target_path: String) -> Self {
        Self {
            target_path,
            scanned_files: 0,
            infected_files: 0,
            total_bytes: 0,
            elapsed_ms: 0,
            reports: Vec::new(),
        }
    }
}
