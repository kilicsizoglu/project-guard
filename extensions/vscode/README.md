# Project Guard - VS Code Güvenlik ve EDR Eklentisi

**Project Guard VS Code Extension**, geliştiricilerin kaynak kod yazarken veya projeleri incelerken zararlı kod kalıplarını, fidye yazılımı komutlarını (T1490/T1562), EDR-Kill tekniklerini, yetkisiz kimlik bilgisi döküm komutlarını ve CISA Honeytoken sızıntılarını gerçek zamanlı olarak tespit etmesini sağlar.

---

## Yetenekler ve Koruma Katmanları

1. **Satır İçi Tehdit Teşhisi (Inline Diagnostic Linting)**:
   - **CISA Honeytoken & Gizli Anahtar Sızıntıları**: Açıkta bırakılmış AWS anahtarları (`AKIA...`), gömülü SSH/RSA Private Key'ler.
   - **Fidye Yazılımı Kurtarma Sabotajı (T1490)**: `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit safeboot minimal`.
   - **EDR-Kill ve Minifilter Boşaltma (T1562.001)**: `fltmc unload`, `sc config ... start=disabled`, `net stop`.
   - **Kimlik Bilgisi Hırsızlığı (T1003.001)**: `comsvcs.dll, MiniDump` LSASS bellek dökümü komutları.
   - **Zararlı Betik Gizleme (T1059.001)**: Base64 kodlu gizli PowerShell komut blokları.
   - **İz Silme (T1070.001)**: `wevtutil cl Security/System/Application` olay günlüğü temizleme komutları.

2. **CISA KEV Zafiyet Denetleyicisi (Webview)**:
   - CISA Known Exploited Vulnerabilities kataloğundaki en güncel Windows uç nokta zafiyetlerini (CVE-2024-21338, CVE-2024-38063 vb.) doğrudan editör içinden görsel panelde inceleme.

3. **Masaüstü SOC Konsolu Entegrasyonu**:
   - Durum çubuğundan tek tıkla Project Guard'ın yerel REST API'sine ve Web SOC arayüzüne (`http://localhost:7890`) bağlanma.

4. **Kenar Çubuğu (Activity Bar) Gezgini**:
   - "Project Guard EDR" sekmesinde motor durumu, aktif CISA zafiyetleri ve hızlı tarama eylemleri.

---

## Kurulum ve Çalıştırma

### Geliştirici Modunda Çalıştırma (F5):
1. VS Code içinde `extensions/vscode` klasörünü açın.
2. `F5` tuşuna basarak **Extension Development Host** penceresini başlatın.
3. Açılan yeni pencerede herhangi bir dosya açtığınızda veya kaydettiğinizde Project Guard otomatik güvenlik analizini yürütecektir.

### Manuel VSIX Paketi Olarak Yükleme:
```bash
# @vscode/vsce aracı yüklüyse:
cd extensions/vscode
npx @vscode/vsce package
code --install-extension project-guard-vscode-1.0.0.vsix
```
