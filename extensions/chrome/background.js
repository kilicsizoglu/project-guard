// Project Guard - Chrome Extension Background Service Worker (Manifest V3)
// Strictly follows async/await, ephemeral storage, and MV3 lifecycle standards.

const DAEMON_URL = "http://localhost:7890";
const SUSPICIOUS_TLDS = [".top", ".xyz", ".work", ".click", ".buzz", ".zip", ".mov"];
const PHISHING_KEYWORDS = ["verify-account", "secure-login", "bank-login", "crypto-wallet", "metamask-auth", "paypal-security"];

// Initialize default storage on install
chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(["protectionEnabled", "blockedCount", "scannedCount", "daemonOnline"]);
  await chrome.storage.local.set({
    protectionEnabled: existing.protectionEnabled !== undefined ? existing.protectionEnabled : true,
    blockedCount: existing.blockedCount || 0,
    scannedCount: existing.scannedCount || 0,
    daemonOnline: false,
    lastThreat: null
  });

  await chrome.action.setBadgeText({ text: "ON" });
  await chrome.action.setBadgeBackgroundColor({ color: "#10B981" }); // Emerald

  // Setup periodic health-check alarm every 1 minute
  chrome.alarms.create("daemonHealthCheck", { periodInMinutes: 1 });
  await checkDaemonStatus();
});

// Periodic alarm handler for daemon connection sync
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "daemonHealthCheck") {
    await checkDaemonStatus();
  }
});

// Query Project Guard local REST API
async function checkDaemonStatus() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);
    const res = await fetch(`${DAEMON_URL}/api/status`, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (res.ok) {
      await chrome.storage.local.set({ daemonOnline: true });
      const { protectionEnabled } = await chrome.storage.local.get("protectionEnabled");
      if (protectionEnabled) {
        await chrome.action.setBadgeText({ text: "ON" });
        await chrome.action.setBadgeBackgroundColor({ color: "#10B981" });
      }
      return true;
    }
  } catch (_e) {
    // Daemon is not running
  }

  await chrome.storage.local.set({ daemonOnline: false });
  return false;
}

// Intercept and evaluate tabs when updated or navigated
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab.url) return;

  const { protectionEnabled } = await chrome.storage.local.get("protectionEnabled");
  if (!protectionEnabled) return;

  // Increment scan counter
  const { scannedCount = 0 } = await chrome.storage.local.get("scannedCount");
  await chrome.storage.local.set({ scannedCount: scannedCount + 1 });

  const urlObj = new URL(tab.url);
  const hostname = urlObj.hostname.toLowerCase();

  // 1. IP format check (Direct IP access in browser often correlates with C2 servers)
  const isDirectIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const hasSuspiciousTld = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
  const hasPhishingKw = PHISHING_KEYWORDS.some(kw => tab.url.toLowerCase().includes(kw));

  if ((isDirectIp && urlObj.port && urlObj.port !== "80" && urlObj.port !== "443") || (hasSuspiciousTld && hasPhishingKw)) {
    const { blockedCount = 0 } = await chrome.storage.local.get("blockedCount");
    const newCount = blockedCount + 1;
    await chrome.storage.local.set({
      blockedCount: newCount,
      lastThreat: {
        url: tab.url,
        hostname,
        time: new Date().toLocaleTimeString(),
        reason: isDirectIp ? "Doğrudan IP / Şüpheli C2 Port Erişimi" : "Zararlı TLD ve Kimlik Avı (Phishing) Kalıbı"
      }
    });

    await chrome.action.setBadgeText({ text: "ALERT" });
    await chrome.action.setBadgeBackgroundColor({ color: "#EF4444" }); // Red

    // Push system notification
    try {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon-128.png",
        title: "Project Guard Web Shield - Tehdit Engellendi!",
        message: `Şüpheli zararlı adres veya C2 bağlantısı tespit edildi: ${hostname}`,
        priority: 2
      });
    } catch (_e) {}
  }
});

// Handle messages from popup or content script
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    if (message.type === "CHECK_DAEMON") {
      const isOnline = await checkDaemonStatus();
      sendResponse({ online: isOnline });
    } else if (message.type === "TOGGLE_PROTECTION") {
      const { protectionEnabled } = await chrome.storage.local.get("protectionEnabled");
      const newState = !protectionEnabled;
      await chrome.storage.local.set({ protectionEnabled: newState });

      if (newState) {
        await chrome.action.setBadgeText({ text: "ON" });
        await chrome.action.setBadgeBackgroundColor({ color: "#10B981" });
      } else {
        await chrome.action.setBadgeText({ text: "OFF" });
        await chrome.action.setBadgeBackgroundColor({ color: "#6B7280" });
      }
      sendResponse({ protectionEnabled: newState });
    } else if (message.type === "GET_STATS") {
      const data = await chrome.storage.local.get([
        "protectionEnabled",
        "blockedCount",
        "scannedCount",
        "daemonOnline",
        "lastThreat"
      ]);
      sendResponse(data);
    } else if (message.type === "THREAT_DETECTED") {
      const { blockedCount = 0 } = await chrome.storage.local.get("blockedCount");
      const urlStr = message.url || "";
      let hostStr = "";
      try {
        hostStr = new URL(urlStr).hostname;
      } catch (_e) {
        hostStr = urlStr;
      }
      await chrome.storage.local.set({
        blockedCount: blockedCount + 1,
        lastThreat: {
          url: urlStr,
          hostname: hostStr,
          time: new Date().toLocaleTimeString(),
          reason: message.reason || "Web Kalkanı Tehdit Tespiti"
        }
      });
      await chrome.action.setBadgeText({ text: "ALERT" });
      await chrome.action.setBadgeBackgroundColor({ color: "#EF4444" });
      try {
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon-128.png",
          title: "Project Guard Web Shield - Tehdit Tespit Edildi!",
          message: `${message.reason || "Şüpheli web tehdidi"}: ${hostStr}`,
          priority: 2
        });
      } catch (_e) {}
      sendResponse({ status: "recorded" });
    }
  })();
  return true; // Keep message channel open for async response
});
