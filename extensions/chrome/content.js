// Project Guard Web Shield - Content Script
// Inspects active page for credential harvesting on insecure protocols and dual-extension malware lures.

(function () {
  "use strict";

  // Check 1: Insecure password submission check
  if (window.location.protocol === "http:" && window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1") {
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    if (passwordInputs.length > 0) {
      console.warn("[Project Guard] GÜVENSİZ ŞİFRE FORMU: Bu sayfa şifrelenmemiş (HTTP) bağlantı kullanıyor!");
      injectWarningBanner("DİKKAT: Bu web sayfası güvenli değildir (HTTP). Şifre veya kimlik bilgilerinizi girmeyiniz!");
    }
  }

  // Check 2: Dual extension inspection on download links (e.g., .docx.exe, .pdf.js)
  const links = document.querySelectorAll("a[href]");
  const dangerousPatterns = [/\.(pdf|docx|xlsx|jpg|png)\.(exe|vbs|bat|cmd|scr|ps1)$/i, /\.iso$/i, /\.vhd$/i];

  let suspiciousLinksFound = 0;
  for (const link of links) {
    const href = link.getAttribute("href") || "";
    if (dangerousPatterns.some(pattern => pattern.test(href))) {
      suspiciousLinksFound++;
      link.style.border = "2px dashed #EF4444";
      link.style.backgroundColor = "rgba(239, 68, 68, 0.15)";
      link.title = "Project Guard Uyarısı: Bu dosya çift uzantılı gizli çalıştırılabilir zararlı olabilir!";
    }
  }

  if (suspiciousLinksFound > 0) {
    console.warn(`[Project Guard] Sayfada ${suspiciousLinksFound} adet şüpheli/çift uzantılı indirme bağlantısı tespit edildi.`);
  }

  // Check 3: Shadowserver SocGholish / FakeUpdates inspection (WordPress compromised lures)
  const pageText = (document.body ? document.body.innerText : "").toLowerCase();
  const isBrowserVendorDomain = /^(.*\.)?(google\.com|chrome\.com|microsoft\.com|mozilla\.org)$/i.test(window.location.hostname);

  if (!isBrowserVendorDomain && (
    (pageText.includes("update your browser") || pageText.includes("tarayıcınızı güncelleyin") || pageText.includes("chrome update") || pageText.includes("browser update required") || pageText.includes("outdated browser"))
    && (pageText.includes("download") || pageText.includes("indir") || pageText.includes("install") || pageText.includes("yükle") || pageText.includes("update"))
  )) {
    console.warn("[Project Guard] SHADOWSERVER SOCGHOLISH UYARISI: Sahte tarayıcı güncellemesi ekranı tespit edildi!");
    injectWarningBanner("KRİTİK UYARI (SocGholish FakeUpdate Tuzağı): Bu web sitesi resmi olmayan sahte bir tarayıcı güncellemesi sunuyor. İndirilen dosyaları ASLA açmayınız!");
    try {
      chrome.runtime.sendMessage({
        type: "THREAT_DETECTED",
        reason: "SocGholish Sahte Tarayıcı Güncellemesi Tuzağı",
        url: window.location.href
      });
    } catch (_e) {}
  }

  function injectWarningBanner(message) {
    if (document.getElementById("project-guard-alert-banner")) return;

    const banner = document.createElement("div");
    banner.id = "project-guard-alert-banner";
    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.width = "100%";
    banner.style.backgroundColor = "#EF4444";
    banner.style.color = "#FFFFFF";
    banner.style.fontWeight = "bold";
    banner.style.fontSize = "13px";
    banner.style.textAlign = "center";
    banner.style.padding = "8px 16px";
    banner.style.zIndex = "2147483647";
    banner.style.boxShadow = "0 4px 6px -1px rgba(0, 0, 0, 0.3)";
    banner.style.fontFamily = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
    banner.innerHTML = `🛡️ <strong>PROJECT GUARD GÜVENLİK UYARISI:</strong> ${message} <button id="pg-banner-close" style="margin-left:15px; background:rgba(255,255,255,0.25); border:none; color:white; border-radius:4px; padding:2px 8px; cursor:pointer;">Kapat</button>`;

    document.body.prepend(banner);

    const closeBtn = document.getElementById("pg-banner-close");
    if (closeBtn) {
      closeBtn.addEventListener("click", () => banner.remove());
    }
  }
})();
