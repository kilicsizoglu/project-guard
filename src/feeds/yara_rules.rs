use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use yara_x::Compiler;

pub struct YaraRuleFeed {
    rules_dir: PathBuf,
}

impl YaraRuleFeed {
    pub fn new(rules_dir: PathBuf) -> Self {
        Self { rules_dir }
    }

    /// Topluluk kural setlerini hazırlar ve yerel kural dizinine kaydeder
    pub fn sync_community_rules(&self) -> Result<usize> {
        if !self.rules_dir.exists() {
            fs::create_dir_all(&self.rules_dir)?;
        }

        let mut synced_count = 0;

        // 1. Standart Açık Kaynak Kural Seti: Mimikatz & Credential Dumping
        let mimikatz_rules = r#"
rule HackTool_Mimikatz_Strings {
    meta:
        description = "Mimikatz parola ve bilet ele gecirme araci imzasi"
        threat_level = "Critical"
        author = "Community / Project Guard"
    strings:
        $m1 = "sekurlsa::logonpasswords" ascii nocase wide
        $m2 = "lsadump::sam" ascii nocase wide
        $m3 = "kerberos::golden" ascii nocase wide
        $m4 = "privilege::debug" ascii nocase wide
        $m5 = "gentilkiwi" ascii nocase
        $m6 = "crypto::certificates" ascii nocase wide
    condition:
        2 of them
}
"#;
        if self.validate_and_save("mimikatz.yar", mimikatz_rules).is_ok() {
            synced_count += 1;
        }

        // 2. Kripto Madenci (CoinMiner) Kuralları
        let coinminer_rules = r#"
rule CoinMiner_Generic_Indicators {
    meta:
        description = "XMRig ve yetkisiz kripto para madenciligi (Cryptojacking)"
        threat_level = "High"
        author = "Community / Project Guard"
    strings:
        $c1 = "stratum+tcp://" ascii nocase
        $c2 = "stratum+ssl://" ascii nocase
        $c3 = "xmrig" ascii nocase
        $c4 = "cryptonight" ascii nocase
        $c5 = "rx/0" ascii
        $c6 = "--donate-level=" ascii
    condition:
        2 of them
}
"#;
        if self.validate_and_save("coinminer.yar", coinminer_rules).is_ok() {
            synced_count += 1;
        }

        // 3. Tersine Kabuk (Reverse Shell) & Ağ Aracılığı Kuralları
        let netcat_shell_rules = r#"
rule Reverse_Shell_Payloads {
    meta:
        description = "Powershell / Bash / Python Tersine Baglanti (Reverse Shell)"
        threat_level = "Critical"
        author = "Community / Project Guard"
    strings:
        $s1 = "/bin/sh -i >& /dev/tcp/" ascii
        $s2 = "/bin/bash -i >& /dev/tcp/" ascii
        $s3 = "New-Object System.Net.Sockets.TCPClient" ascii nocase
        $s4 = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)" ascii
        $s5 = "subprocess.call([\"/bin/sh\",\"-i\"])" ascii
    condition:
        any of them
}
"#;
        if self.validate_and_save("reverseshell.yar", netcat_shell_rules).is_ok() {
            synced_count += 1;
        }

        // 4. Uzak GitHub açık kaynak kural depolarından kural indirmeyi dene
        let remote_rules = [
            (
                "webshells_collection.yar",
                "https://raw.githubusercontent.com/Yara-Rules/rules/master/Webshells/Wshell_PHP.yar",
            ),
            (
                "cve_exploits.yar",
                "https://raw.githubusercontent.com/Yara-Rules/rules/master/Exploit-Kits/EK_Blackhole.yar",
            ),
        ];

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("ProjectGuard-OpenAV/1.0")
            .build();

        if let Ok(client) = client {
            for (filename, url) in remote_rules {
                if let Ok(resp) = client.get(url).send() {
                    if resp.status().is_success() {
                        if let Ok(content) = resp.text() {
                            if self.validate_and_save(filename, &content).is_ok() {
                                println!("Uzak YARA kurali basariyla indirildi ve derlendi: {}", filename);
                                synced_count += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(synced_count)
    }

    /// Kuralı diske kaydetmeden önce YARA-X ile sözdizimini doğrular
    fn validate_and_save(&self, filename: &str, content: &str) -> Result<()> {
        let mut compiler = Compiler::new();
        compiler
            .add_source(content)
            .with_context(|| format!("Kural soz dizimi hatasi: {}", filename))?;

        let path = self.rules_dir.join(filename);
        fs::write(&path, content)?;
        Ok(())
    }
}
