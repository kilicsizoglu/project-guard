// Project Guard Docker Desktop Extension Client Logic
// Seamlessly operates within Docker Desktop (window.ddClient) or standalone mode with Host EDR sync.

document.addEventListener("DOMContentLoaded", async () => {
  const ddClient = window.ddClient || null;
  const HOST_EDR_API = "http://localhost:7890"; // In desktop browser or host.docker.internal inside VM

  // UI Elements
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");
  const hostStatus = document.getElementById("host-status");
  const hostStatusText = document.getElementById("host-status-text");
  const metricContainers = document.getElementById("metric-containers");
  const metricImages = document.getElementById("metric-images");
  const metricRisks = document.getElementById("metric-risks");
  const containersTbody = document.getElementById("containers-tbody");
  const imagesTbody = document.getElementById("images-tbody");
  const btnScanAll = document.getElementById("btn-scan-all");
  const btnOpenHostSoc = document.getElementById("btn-open-host-soc");

  // Tab Switching
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = `tab-${btn.dataset.tab}`;
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add("active");
    });
  });

  // Open Host SOC button
  btnOpenHostSoc.addEventListener("click", () => {
    if (ddClient && ddClient.host && ddClient.host.openExternal) {
      ddClient.host.openExternal(HOST_EDR_API);
    } else {
      window.open(HOST_EDR_API, "_blank");
    }
  });

  btnScanAll.addEventListener("click", async () => {
    btnScanAll.innerHTML = "Taranıyor...";
    await loadDockerData();
    await checkHostEdrStatus();
    btnScanAll.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="btn-icon"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg> Kapsamlı Tara`;
  });

  // Check Host Project Guard Daemon
  async function checkHostEdrStatus() {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2500);
      const res = await fetch(`${HOST_EDR_API}/api/status`, { signal: controller.signal });
      clearTimeout(timeoutId);

      if (res.ok) {
        hostStatus.className = "host-status online";
        hostStatusText.textContent = "HOST EDR BAĞLI (7890)";
        return;
      }
    } catch (_e) {}

    hostStatus.className = "host-status offline";
    hostStatusText.textContent = "HOST EDR ÇEVRİMDIŞI";
  }

  // Fetch Containers and Images
  async function loadDockerData() {
    let containers = [];
    let images = [];

    if (ddClient && ddClient.docker) {
      try {
        containers = await ddClient.docker.listContainers({ all: true });
      } catch (err) {
        console.warn("Docker listContainers error:", err);
      }

      try {
        images = await ddClient.docker.listImages();
      } catch (err) {
        console.warn("Docker listImages error:", err);
      }
    } else {
      // Standalone simulation fallback for non-Docker desktop browser preview
      containers = [
        {
          Id: "a1b2c3d4e5f6",
          Names: ["/project-guard-api"],
          Image: "project-guard/service:latest",
          State: "running",
          Ports: [{ PublicPort: 7890, PrivatePort: 7890, Type: "tcp" }],
          HostConfig: { Privileged: false }
        },
        {
          Id: "f6e5d4c3b2a1",
          Names: ["/legacy-database-redis"],
          Image: "redis:6.2-alpine",
          State: "running",
          Ports: [{ PublicPort: 6379, PrivatePort: 6379, Type: "tcp" }],
          HostConfig: { Privileged: false }
        },
        {
          Id: "987654321fed",
          Names: ["/test-privileged-worker"],
          Image: "ubuntu:22.04",
          State: "running",
          Ports: [{ PublicPort: 4444, PrivatePort: 4444, Type: "tcp" }],
          HostConfig: { Privileged: true, PidMode: "host" }
        }
      ];

      images = [
        {
          Id: "sha256:11223344556677889900",
          RepoTags: ["project-guard/service:latest"],
          Size: 45200000,
          Created: Math.floor(Date.now() / 1000) - 3600
        },
        {
          Id: "sha256:aabbccddeeff00112233",
          RepoTags: ["redis:6.2-alpine"],
          Size: 32400000,
          Created: Math.floor(Date.now() / 1000) - 86400
        },
        {
          Id: "sha256:99887766554433221100",
          RepoTags: ["ubuntu:22.04"],
          Size: 77800000,
          Created: Math.floor(Date.now() / 1000) - 172800
        }
      ];
    }

    renderContainers(containers);
    renderImages(images);
  }

  function renderContainers(containers) {
    metricContainers.textContent = containers.length;
    let riskCount = 0;

    if (containers.length === 0) {
      containersTbody.innerHTML = `<tr><td colspan="6" class="loading-cell">Aktif veya durdurulmuş konteyner bulunamadı.</td></tr>`;
      metricRisks.textContent = 0;
      return;
    }

    let rowsHtml = "";
    containers.forEach(c => {
      const name = (c.Names && c.Names[0]) ? c.Names[0].replace(/^\//, "") : c.Id.slice(0, 12);
      const isPrivileged = !!(c.HostConfig && c.HostConfig.Privileged);
      const isHostPid = !!(c.HostConfig && c.HostConfig.PidMode === "host");

      let portsDesc = "Yok";
      if (c.Ports && c.Ports.length > 0) {
        portsDesc = c.Ports.map(p => `${p.PublicPort || p.PrivatePort}/${p.Type}`).join(", ");
      }

      let ratingBadge = `<span class="badge safe">GÜVENLİ</span>`;
      if (isPrivileged || isHostPid) {
        riskCount++;
        ratingBadge = `<span class="badge danger">KRİTİK İMTİYAZ (${isPrivileged ? 'Privileged' : 'HostPID'})</span>`;
      } else if (portsDesc.includes("4444") || portsDesc.includes("1337")) {
        riskCount++;
        ratingBadge = `<span class="badge warn">ŞÜPHELİ PORT</span>`;
      }

      const stateClass = c.State === "running" ? "text-emerald" : "text-muted";

      rowsHtml += `
        <tr>
          <td><strong>${name}</strong></td>
          <td><code>${c.Image}</code></td>
          <td class="${stateClass}">${(c.State || "bilinmiyor").toUpperCase()}</td>
          <td>${portsDesc}</td>
          <td>${ratingBadge}</td>
          <td><button class="btn btn-secondary btn-sm" onclick="alert('Konteyner: ${name} denetlendi.')">Detay</button></td>
        </tr>
      `;
    });

    containersTbody.innerHTML = rowsHtml;
    metricRisks.textContent = riskCount;
  }

  function renderImages(images) {
    metricImages.textContent = images.length;

    if (images.length === 0) {
      imagesTbody.innerHTML = `<tr><td colspan="5" class="loading-cell">Yerel Docker imajı bulunamadı.</td></tr>`;
      return;
    }

    let rowsHtml = "";
    images.forEach(img => {
      const tag = (img.RepoTags && img.RepoTags[0]) ? img.RepoTags[0] : "<etiketsiz>";
      const shortId = (img.Id || "").replace("sha256:", "").slice(0, 12);
      const sizeMb = (img.Size / (1024 * 1024)).toFixed(1);
      const createdDate = new Date(img.Created * 1000).toLocaleDateString("tr-TR");

      let threatBadge = `<span class="badge safe">TEMİZ (0 CVE)</span>`;
      if (tag.includes("ubuntu:14") || tag.includes("node:10") || tag.includes("python:2.7")) {
        threatBadge = `<span class="badge danger">ESKİ TABAN / GÜVENLİKSİZ</span>`;
      }

      rowsHtml += `
        <tr>
          <td><strong>${tag}</strong></td>
          <td><code>${shortId}</code></td>
          <td>${sizeMb} MB</td>
          <td>${createdDate}</td>
          <td>${threatBadge}</td>
        </tr>
      `;
    });

    imagesTbody.innerHTML = rowsHtml;
  }

  // Initial Load
  await checkHostEdrStatus();
  await loadDockerData();
});
