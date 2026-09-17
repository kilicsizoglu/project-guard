// Project Guard Web Shield - Popup Logic
// Synchronizes UI with Chrome Storage and background Service Worker.

document.addEventListener("DOMContentLoaded", async () => {
  const toggleShield = document.getElementById("toggle-shield");
  const shieldState = document.getElementById("shield-state");
  const shieldDesc = document.getElementById("shield-desc");
  const statusCard = document.getElementById("status-card");
  const daemonBadge = document.getElementById("daemon-badge");
  const daemonText = document.getElementById("daemon-text");
  const blockedCountEl = document.getElementById("blocked-count");
  const scannedCountEl = document.getElementById("scanned-count");
  const threatCard = document.getElementById("threat-card");
  const threatTime = document.getElementById("threat-time");
  const threatTarget = document.getElementById("threat-target");
  const threatReason = document.getElementById("threat-reason");
  const openSocBtn = document.getElementById("open-soc-btn");
  const syncBtn = document.getElementById("sync-btn");

  // Load and render initial state
  await renderStats();

  // Handle Shield Toggle
  toggleShield.addEventListener("change", async () => {
    const response = await chrome.runtime.sendMessage({ type: "TOGGLE_PROTECTION" });
    updateShieldUi(response.protectionEnabled);
  });

  // Open SOC Dashboard button
  openSocBtn.addEventListener("click", async () => {
    await chrome.tabs.create({ url: "http://localhost:7890" });
  });

  // Sync / Refresh button
  syncBtn.addEventListener("click", async () => {
    daemonText.textContent = "DENETLENİYOR...";
    await chrome.runtime.sendMessage({ type: "CHECK_DAEMON" });
    await renderStats();
  });

  async function renderStats() {
    const stats = await chrome.runtime.sendMessage({ type: "GET_STATS" });
    if (!stats) return;

    // Protection state
    toggleShield.checked = !!stats.protectionEnabled;
    updateShieldUi(stats.protectionEnabled);

    // Counts
    blockedCountEl.textContent = (stats.blockedCount || 0).toLocaleString();
    scannedCountEl.textContent = (stats.scannedCount || 0).toLocaleString();

    // Daemon online badge
    if (stats.daemonOnline) {
      daemonBadge.className = "daemon-badge online";
      daemonText.textContent = "EDR BAĞLI (7890)";
    } else {
      daemonBadge.className = "daemon-badge offline";
      daemonText.textContent = "EDR ÇEVRİMDIŞI";
    }

    // Last threat
    if (stats.lastThreat) {
      threatCard.classList.remove("hidden");
      threatTime.textContent = stats.lastThreat.time || "";
      threatTarget.textContent = stats.lastThreat.hostname || stats.lastThreat.url;
      threatReason.textContent = stats.lastThreat.reason || "Kötü Amaçlı Ağ Bağlantısı";
    } else {
      threatCard.classList.add("hidden");
    }
  }

  function updateShieldUi(isEnabled) {
    if (isEnabled) {
      shieldState.textContent = "KALKAN AKTİF";
      shieldDesc.textContent = "Web trafiği ve C2 bağlantıları izleniyor";
      statusCard.className = "status-card active";
    } else {
      shieldState.textContent = "KORUMA DURAKLATILDI";
      shieldDesc.textContent = "Web kalkanı devre dışı bırakıldı";
      statusCard.className = "status-card inactive";
    }
  }
});
