# Project Guard - Docker Desktop Extension

**Project Guard Docker Extension**, Docker Desktop kullanıcılarına yerel konteyner ortamları ve imajları için gerçek zamanlı güvenlik denetimi, imtiyaz risk analizi (`--privileged`, `hostPID`), CISA KEV zafiyet eşleştirmesi ve ana makinedeki (host) Project Guard EDR servisi ile doğrudan telemetri senkronizasyonu sağlar.

---

## Temel Özellikler

1. **Konteyner Çalışma Zamanı ve İmtiyaz Denetimi**:
   - `window.ddClient.docker.listContainers()` API'si ile çalışan ve durdurulmuş konteynerlerin taranması.
   - Ana makine çekirdeğini tehlikeye atan aşırı imtiyaz (`HostConfig.Privileged: true`) ve süreç izolasyon ihlallerinin (`PidMode: host`) anında tespiti ve uyarılması.
   - Bilinen C2 / arka kapı portları (4444, 1337 vb.) ile çalışan konteynerlerin işaretlenmesi.

2. **İmaj ve Paket Zafiyet Taraması**:
   - Yerel Docker imajlarının taranması, riskli/eski temel imajların ve crypto-mining kalıplarının tespiti.

3. **Docker CIS Benchmark Sertleştirme (Hardening)**:
   - Konteyner orkestrasyonu için CIS güvenlik kriterleri ve en iyi uygulama kontrol listesi.

4. **Host Project Guard EDR Köprüsü**:
   - Konteyner ortamından ana makinedeki `http://host.docker.internal:7890` EDR servisine otomatik bağlanarak ortak tehdit istihbaratını paylaşır.

---

## Derleme ve Kurulum (Docker Desktop)

### 1. Eklentiyi Derleme:
```bash
cd extensions/docker
docker build -t projectguard/docker-extension:1.0.0 .
```

### 2. Docker Desktop'a Yükleme:
```bash
docker extension install projectguard/docker-extension:1.0.0
```

### 3. Geliştirici Modunda İnceleme ve Test:
```bash
# Eklentiyi Docker Desktop arayüzünde canlı önizleyin
docker extension dev ui-source projectguard/docker-extension:1.0.0 http://localhost:3000
```
Yükleme tamamlandığında Docker Desktop sol gezinme menüsünde **Project Guard EDR** sekmesi görünecektir!
