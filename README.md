<p align="center">
  <img src="assets/icon.jpg" alt="Project Guard Logo" width="160" style="border-radius: 24px; box-shadow: 0 10px 30px rgba(6, 182, 212, 0.4);" />
</p>

<h1 align="center">Project Guard</h1>

<p align="center">
  <strong>Next-Generation Open-Source Antivirus, EDR & Threat Hunting Platform</strong><br>
  <em>Engineered in Pure Rust (2024 Edition) with Windows Defender Dual-Layer Coexistence</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust%202024-orange.svg?style=for-the-badge&logo=rust" alt="Rust 2024" />
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20%2F%20Server-0078D6.svg?style=for-the-badge&logo=windows" alt="Windows" />
  <img src="https://img.shields.io/badge/Detection%20Engines-21%20Active-06B6D4.svg?style=for-the-badge" alt="21 Engines" />
  <img src="https://img.shields.io/badge/Defender%20Coexistence-Dual--Layer%20OK-10B981.svg?style=for-the-badge&logo=windows-defender" alt="Defender Coexistence" />
  <img src="https://img.shields.io/badge/Tests-28%20Passing-brightgreen.svg?style=for-the-badge" alt="28 Tests Passing" />
  <img src="https://img.shields.io/badge/License-Apache%202.0%20%2F%20MIT-blue.svg?style=for-the-badge" alt="License" />
</p>

---

## 🛡️ Vizyon ve Genel Bakış

**Project Guard**, modern kurumsal uç nokta tehditlerine (dosyasız saldırılar, fidye yazılımları, bellek enjeksiyonu, BYOVD savunmasız çekirdek sürücüleri ve sıfır-gün komut dosyası suistimalleri) karşı geliştirilmiş, **saf Rust** mimarili, açık kaynak istihbaratından beslenen bir **Antivirus ve EDR (Endpoint Detection & Response)** platformudur.

Geleneksel imza tabanlı antivirüslerin ötesine geçerek; **canlı Windows Olay Günlüğü telemetrisi (Event ID 4104)**, **bölüm bazlı Shannon entropisi triyajı**, **Capa/ATT&CK statik yetenek eşleştirme**, **in-memory RWX bellek avcılığı** ve **XOR `0x5A` maskeli karantina kasası** ile işletim sistemini 7/24 kesintisiz korur.

> [!IMPORTANT]
> **Windows Defender Eşzamanlı Koruma (Dual-Layer Shield):**
> Project Guard, Microsoft Defender Antivirus ile tam uyumlu çalışacak şekilde tasarlanmıştır. Defender'ın çekirdek sürücüsü `WdFilter.sys` tarafından üretilen `os error 225` hatalarını yakalar, karantinaya alınan dosyaları tersine çevrilebilir XOR maskelemesiyle Defender'dan izole eder ve `Get-MpComputerStatus` telemetrisini tek bir merkezi SOC panelinde birleştirir.

---

## ⚡ Temel Güvenlik Motorları (21 Aktif Motor)

```
                                 ┌────────────────────────────────────────────────────────┐
                                 │                PROJECT GUARD EDR AGENT                 │
                                 └──────────────────────────┬─────────────────────────────┘
                                                            │
         ┌──────────────────────────────────────────────────┼──────────────────────────────────────────────────┐
         │                                                  │                                                  │
┌────────▼────────┐                                ┌────────▼────────┐                                ┌────────▼────────┐
│ Threat Intel &  │                                │ Heuristic & PE  │                                │ In-Memory &     │
│ Rule Signatures │                                │ Capabilities    │                                │ Script Hunter   │
├─────────────────┤                                ├─────────────────┤                                ├─────────────────┤
│ • YARA-X Engine │                                │ • PE Shannon    │                                │ • In-Memory RWX │
│ • MalwareBazaar │                                │   Entropy Heat  │                                │   Injection     │
│ • ThreatFox IOC │                                │ • W^X Violation │                                │ • AMSI Bypass   │
│ • Feodo C2 IP   │                                │ • Capa ATT&CK   │                                │ • Script Cradle │
│ • ClamAV CVD    │                                │ • UPX / Crypter │                                │ • LOLBAS Hunter │
│ • YARA-Forge    │                                │ • BYOVD Drivers │                                │ • Base64 Deob   │
└─────────────────┘                                └─────────────────┘                                └─────────────────┘
         │                                                  │                                                  │
         └──────────────────────────────────────────────────┼──────────────────────────────────────────────────┘
                                                            │
         ┌──────────────────────────────────────────────────┼──────────────────────────────────────────────────┐
         │                                                  │                                                  │
┌────────▼────────┐                                ┌────────▼────────┐                                ┌────────▼────────┐
│ Host Defense &  │                                │ 7/24 Background │                                │ Glassmorphic    │
│ Anti-Tampering  │                                │ Windows Service │                                │ Web Dashboard   │
├─────────────────┤                                ├─────────────────┤                                ├─────────────────┤
│ • EventLog 4104 │                                │ • SCM Service   │                                │ • 18-Tab Live   │
│ • Canary Traps  │                                │ • Auto Restart  │                                │   SOC Console   │
│ • FIM Integrity │                                │ • 24/7 RTP Loop │                                │ • RESTful JSON  │
│ • USB Worm Guard│                                │ • Event Logging │                                │ • Dark Obsidian │
│ • Defender Dual │                                │ • System SYSTEM │                                │ • Interactive   │
└─────────────────┘                                └─────────────────┘                                └─────────────────┘
```

### 1. Tehdit İstihbaratı ve İmza Motorları
* **YARA-X Saf Rust Motoru:** VirusTotal'ın modern, bellek güvenli YARA-X kütüphanesiyle kuralları anında derler ve çalıştırır.
* **MalwareBazaar & ThreatFox Canlı Akışları:** Abuse.ch tarafından sağlanan günlük zararlı dosya hash'leri ve C2 IOC'leri yerel SQLite veritabanına (`.project_guard/guard.db`) senkronize edilir.
* **Feodo Tracker C2 Botnet Avcısı:** Aktif botnet komuta kontrol IP'leri ağ soketleriyle eş zamanlı karşılaştırılır.
* **ClamAV CVD & clamd Soket Adaptörü:** Açık kaynak ClamAV virüs hash imzaları (`.hdb`) ve yerel clamd arka plan daemon soket entegrasyonu.
* **YARA-Forge Topluluk Kuralları Senkronizasyonu:** Cobalt Strike, Fidye Yazılımları, Mimikatz ve Bilgi Çalıcılar için vetted topluluk imzaları.

### 2. Sezgisel (Heuristic) ve Derin PE Triyajı
* **Bölüm Bazlı Shannon Entropisi (0.00 - 8.00):** `.text`, `.rdata`, `.data`, `.rsrc` bölümlerinin entropisini hesaplayarak şifreli veya Crypter ile paketlenmiş zararlı yükleri saptar.
* **W^X Güvenlik İhlali Tespiti:** Aynı anda hem yazılabilir (`IMAGE_SCN_MEM_WRITE`) hem çalıştırılabilir (`IMAGE_SCN_MEM_EXECUTE`) şüpheli bellek/PE bölümlerini yakalar.
* **Capa & MITRE ATT&CK Yetenek Matrisi:** Süreç Enjeksiyonu, Kimlik Bilgisi Hırsızlığı, Anti-Debugging ve Fidye Yazılımı API kümelerini tespit ederek 0-100 Tehdit Riski Skoru üretir.
* **BYOVD / LOLDrivers Avcısı:** Zafiyetli veya iptal edilmiş ring0 çekirdek sürücülerini (`gdrv.sys`, `mhyprot2.sys`, `procexp.sys` vb.) ve hazırlık alanlarını denetler.

### 3. Bellek İçi ve Komut Dosyası Avcılığı
* **Canlı Bellek Enjeksiyon Avcısı (In-Memory Hunter):** `VirtualQueryEx` ve `ReadProcessMemory` ile diske yazılmamış (unbacked) özel yürütülebilir bölgeleri ve Cobalt Strike stager'larını yakalar.
* **LOLBAS & Ebeveyn-Çocuk Süreç Anomalisi:** Microsoft imzalı meşru ikililerin (`certutil`, `mshta`, `regsvr32`, `rundll32`) suistimalini ve Office makro/PowerShell türetmelerini engeller.
* **Komut & AMSI Avcısı:** PowerShell bellek yamalarını (`amsiInitFailed`), Base64 şifreli komut yüklerini ve VBScript/Batch indirme beşiklerini yakalar.

### 4. Uç Nokta Savunması ve DFIR
* **Windows Olay Günlüğü Avcısı:** `Microsoft-Windows-PowerShell/Operational` (Event ID 4104) günlüklerini tarayarak bellek içi yürütmeleri yakalar; Windows Defender tespitlerini (1116/1117) ve Olay Günlüğü silme girişimlerini (1102) raporlar.
* **Stratejik Fidye Kapanı (Canary / Honeypot):** Kritik dizinlere yerleştirilen alfanumerik yem dosyaları izler; sıfır-gün fidye yazılımı şifreleme girişimlerinde alarm üretir.
* **Dosya Bütünlüğü İzleme (FIM):** `hosts`, `cmd.exe`, `powershell.exe`, `dnsapi.dll` gibi kritik sistem ikililerini SHA-256 referansı ile kriptografik olarak korur.
* **USB & Çıkarılabilir Sürücü Koruması:** `autorun.inf` ve gizli `.lnk` kısayol solucanlarını takıldığı anda nötralize eder.
* **XOR 0x5A İzolasyonlu Karantina Kasası:** Dosyalar şifrelenerek ikili çalıştırılamaz hale getirilir ve Windows Defender ile kilitlenme yaşanması önlenir.

---

## 🛠️ Kurulum ve Derleme

### Ön Koşullar
* **Windows 10 / 11 / Server 2019+** (x64 veya ARM64)
* **Rust 1.85+ (Rust 2024 Edition)**
* **Git**

```powershell
# 1. Depoyu klonlayın
git clone https://github.com/your-org/project-guard.git
cd project-guard

# 2. Birim testlerini çalıştırın (28 test)
cargo test

# 3. İkili dosyayı Windows kaynakları ve simgesiyle derleyin
cargo build --release
```

Derlenen çalıştırılabilir dosya: `target/release/project-guard.exe`

---

## ⚙️ Windows Hizmeti (Service) Olarak Çalıştırma

Project Guard, kurumsal ortamlarda sistem başlangıcında otomatik çalışan 7/24 bir **Windows Hizmeti** olarak kurulabilir:

```powershell
# Yönetici yetkileriyle PowerShell açın:

# 1. Windows Hizmetini sisteme kaydedin (Otomatik Başlangıç)
project-guard service install

# 2. Hizmeti başlatın
project-guard service start

# 3. Hizmetin çalışma durumunu sorgulayın
project-guard service status

# 4. Hizmeti durdurun veya sistemden kaldırın
project-guard service stop
project-guard service uninstall
```

Hizmet günlükleri `.project_guard/service.log` dosyasına kaydedilir ve sistem sağlığını doğrulamak için periyodik can damarı (heartbeat) sinyalleri üretir.

### 💡 Tek Tıkla Otomatik Kurulum (PowerShell Script)
Yönetici olarak açılan PowerShell penceresinde tek komutla kurulum ve yapılandırma:
```powershell
# Hizmeti otomatik kurar, başlatır ve durumunu doğrular:
.\scripts\install-service.ps1

# Hizmeti durdurup sistemden temiz bir şekilde kaldırmak için:
.\scripts\uninstall-service.ps1
```

> [!TIP]
> Ayrıntılı kurulum adımları ve test yönergeleri için **[QUICKSTART.md](QUICKSTART.md)** kılavuzuna, derinlemesine teknik mimari için **[ARCHITECTURE.md](ARCHITECTURE.md)** belgesine göz atabilirsiniz.

---

## 🖥️ Web Kontrol Merkezi (Dashboard)

Görsel kontrol merkezini başlatmak için:

```powershell
project-guard ui --port 7890
```

Tarayıcınızda otomatik olarak açılır: **`http://127.0.0.1:7890`**

### Kontrol Paneli Özellikleri
* **Genel Bakış (Overview):** 21 motorun anlık durumu, Windows Defender eşzamanlı çalışma telemetrisi ve Windows Hizmet kontrol kartı.
* **Olay Günlükleri (EventLog Hunter):** Canlı PowerShell ScriptBlock olayları (4104), Defender tespit geçmişi ve Güvenlik Denetimi temizleme uyarıları.
* **Derin PE Triyajı:** Bölüm bazlı Shannon entropi renkli ilerleme çubukları ve MITRE ATT&CK yetenek matrisi.
* **Süreç ve Bellek Avcısı:** Canlı çalışan işlemler, RWX bellek bölgeleri ve tek tıkla süreç sonlandırma (Kill Switch).
* **Tehdit İstihbaratı:** Abuse.ch MalwareBazaar, ThreatFox, Feodo C2 ve YARA-Forge tek tıkla senkronizasyon.

---

## 📖 CLI Komut Referansı

| Komut | Açıklama | Örnek |
|---|---|---|
| `scan <hedef>` | Dosya veya dizini çoklu motorlarla tarar | `guard scan C:\Users\Downloads -q` |
| `scan-eventlog` | Windows Olay Günlüklerini (4104/1116/1102) denetler | `guard scan-eventlog --limit 25` |
| `triage <dosya>` | PE bölüm entropisi ve ATT&CK yetenek matrisi çıkarır | `guard triage C:\Windows\System32\cmd.exe` |
| `sync-yara` | Topluluk YARA-Forge ve Cobalt Strike kurallarını derler | `guard sync-yara` |
| `scan-script <yol>` | PowerShell / AMSI atlatma ve indirme beşiklerini tarar | `guard scan-script payload.ps1` |
| `extract-iocs <yol>` | Gizli dize, public IP, URL ve C2 botnet eşleşmelerini ayıklar | `guard extract-iocs sample.exe` |
| `scan-drivers` | BYOVD zafiyetli çekirdek sürücülerini (LOLDrivers) tarar | `guard scan-drivers` |
| `fim-init` | Kritik sistem dosyaları için SHA-256 referansı oluşturur | `guard fim-init` |
| `fim-check` | Sistem dosyalarında yetkisiz değişiklik kontrolü yapar | `guard fim-check` |
| `canary-deploy` | Stratejik yem (Canary) tuzak dosyaları yerleştirir | `guard canary-deploy C:\Users\Documents` |
| `canary-watch` | Fidye yazılımlarına karşı yem tuzakları canlı izler | `guard canary-watch C:\Users\Documents` |
| `scan-lolbas` | Microsoft imzalı ikililerin suistimalini tarar | `guard scan-lolbas --kill` |
| `scan-memory` | Canlı süreçlerde enjekte edilmiş RWX bellek bölgelerini arar | `guard scan-memory` |
| `scan-network` | Aktif TCP soketlerini ve C2 portlarını denetler | `guard scan-network` |
| `scan-persistence` | Windows Run, Startup ve SchTasks kalıcılıklarını tarar | `guard scan-persistence` |
| `scan-usb` | Çıkarılabilir USB sürücüleri ve LNK solucanlarını tarar | `guard scan-usb -q` |
| `defender-status` | Windows Defender sağlık ve uyumluluk durumunu sorgular | `guard defender-status` |
| `quarantine list` | Karantinadaki dosyaları listeler | `guard quarantine list` |
| `quarantine restore` | Karantinadaki dosyayı orijinal konumuna geri yükler | `guard quarantine restore <ID>` |
| `service <action>` | Windows Hizmeti yönetimi (install, start, stop, status) | `guard service install` |
| `ui` | Web Kontrol Merkezini başlatır | `guard ui --port 7890` |

---

## 🔒 Güvenlik ve İzolasyon Mimarisi

* **XOR 0x5A Kasa Koruması:** Karantinaya alınan her dosya `0x5A` maskesi ile tersyüz edilir. Bu sayede dosya diskte bulunsa dahi Windows işletim sistemi veya Defender tarafından çalıştırılamaz ya da kilitlenemez.
* **Bellek Güvenliği:** Rust'ın mülkiyet ve yaşam döngüsü (ownership/borrowing) modeli sayesinde bellek sızıntıları (memory leak) ve kullanım sonrası serbest bırakma (use-after-free) açıkları imkansızdır.
* **WdFilter Error 225 Toleransı:** Windows Defender RTP devredeyken oluşan erişim engelleri yakalanarak kullanıcıya net ve aksiyon alınabilir çözümler sunulur.

---

## 📱 Geliştiriciden: FatRab Bütçe Takipçisi (Google Play)

<p align="center">
  <a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank">
    <img src="assets/feature-graphic-1024x500.png" alt="FatRab Bütçe Takipçisi Banner" width="760" style="border-radius: 14px; box-shadow: 0 10px 30px rgba(0,0,0,0.35);" />
  </a>
</p>

<p align="center">
  <a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank">
    <img src="https://img.shields.io/badge/Google_Play-FatRab_Bütçe_Takipçisi-34A853?style=for-the-badge&logo=google-play&logoColor=white" alt="Google Play" />
  </a>
  <img src="https://img.shields.io/badge/Platform-Android-green.svg?style=for-the-badge&logo=android" alt="Android" />
  <img src="https://img.shields.io/badge/Kategori-Finans%20%26%20Bütçe-blue.svg?style=for-the-badge" alt="Kategori Finans" />
</p>

<div align="center">

| <a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank"><img src="assets/play-icon-512.png" width="96" alt="FatRab Logo" style="border-radius: 20px;" /></a> | ### 💰 [FatRab Bütçe Takipçisi - Google Play'de Keşfedin](https://play.google.com/store/apps/details?id=com.fatrab.budget)<br>Kişisel bütçenizi, harcamalarınızı ve birikim hedeflerinizi zahmetsizce yönetin. Gelişmiş harcama kategorizasyonu, grafiksel finansal raporlar ve sade arayüzüyle bütçenizi kontrol altında tutun!<br><br><a href="https://play.google.com/store/apps/details?id=com.fatrab.budget" target="_blank"><img src="https://play.google.com/intl/en_us/badges/static/images/badges/tr_badge_web_generic.png" alt="Google Play'den İndirin" height="52"></a> |
|:---:|---|

</div>

---

## 🤝 Katkıda Bulunma (Contributing)

Geliştirici yönergeleri, yeni tespit motoru ekleme rehberi ve çekme isteği (PR) kuralları için **[CONTRIBUTING.md](CONTRIBUTING.md)** dosyasını inceleyebilirsiniz.

---

## 📄 Lisans

Bu proje **Apache 2.0** ve **MIT** çift lisansı altında sunulmaktadır.
Daha fazla bilgi için [LICENSE](LICENSE) dosyasına bakabilirsiniz.

