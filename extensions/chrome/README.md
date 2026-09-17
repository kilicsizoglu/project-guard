# Project Guard Web Shield - Chrome Eklentisi (Manifest V3)

Project Guard Antivirus ve EDR sisteminin masaüstü motoruyla entegre çalışan, tarayıcı seviyesinde kimlik avı (phishing), zararlı C2 (Komuta Kontrol) sunucu erişimi ve şüpheli indirme engelleyicisidir.

---

## Özellikler
1. **Gerçek Zamanlı C2 & Phishing Engelleme**: Doğrudan IP erişimleri, riskli TLD uzantıları (`.top`, `.xyz`, `.zip`, `.mov`) ve kimlik avı anahtar kelimelerini otomatik analiz eder.
2. **Kötü Amaçlı Çift Uzantı Tespiti**: Web sayfalarındaki `.docx.exe`, `.pdf.vbs` gibi yem dosyalarını ve güvensiz HTTP şifre formlarını işaretler.
3. **Masaüstü EDR Senkronizasyonu**: Yerel REST API (`http://localhost:7890`) ile anlık iletişim kurarak EDR durumunu bildirir.
4. **Glassmorphic SOC Kullanıcı Arayüzü**: Tek tıkla koruma açma/kapatma, engellenen tehdit istatistikleri ve SOC paneline hızlı erişim.

---

## Kurulum (Geliştirici Modu)
1. Google Chrome tarayıcısını açın ve adres çubuğuna şunu yazın:  
   `chrome://extensions/`
2. Sağ üst köşedeki **"Geliştirici modu" (Developer mode)** anahtarını açın.
3. Sol üstteki **"Paketlenmemiş öğe yükle" (Load unpacked)** butonuna tıklayın.
4. Bu klasörü seçin:  
   `c:\Users\kilic\OneDrive\Belgeler\GitHub\project-guard-windows-antivirus-edr\extensions\chrome`
5. Project Guard Web Shield simgesi Chrome uzantı çubuğunuzda belirecektir!
