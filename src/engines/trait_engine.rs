use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Suspicious,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Suspicious => write!(f, "SUSPICIOUS"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub threat_name: String,
    pub engine_name: String,
    pub severity: Severity,
    pub details: String,
    pub rule_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FileHashes {
    pub sha256: String,
    pub md5: String,
}

pub trait ScanEngine: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn scan(
        &self,
        path: &Path,
        content: &[u8],
        hashes: &FileHashes,
    ) -> Result<Option<ThreatDetection>>;
}
