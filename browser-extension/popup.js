const DAEMON_STATUS_URL = "http://127.0.0.1:7840/api/v1/status";
const DAEMON_DOMAINS_URL = "http://127.0.0.1:7840/api/v1/domains";

function openViewer(domain, path = "/") {
  const viewerUrl = new URL(chrome.runtime.getURL("viewer.html"));
  viewerUrl.searchParams.set("domain", domain);
  viewerUrl.searchParams.set("path", path);
  chrome.tabs.create({ url: viewerUrl.toString() });
}

function shortenOwner(owner) {
  if (!owner || typeof owner !== "string") {
    return "Owner unknown";
  }
  if (owner.length <= 28) {
    return owner;
  }
  return `${owner.slice(0, 14)}…${owner.slice(-10)}`;
}

async function refreshStatus() {
  const statusEl = document.getElementById("status");
  try {
    const status = await fetchCompatibleDaemonStatus(DAEMON_STATUS_URL);

    statusEl.textContent =
      `Daemon ${status.daemon_version}. API ${status.api_version}. ` +
      `DID ${status.daemon_did}. Active backend ${status.active_backend || "not connected yet"}.`;
  } catch (error) {
    statusEl.textContent = `Daemon unavailable: ${error.message}`;
  }
}

async function refreshDomains() {
  const listEl = document.getElementById("domains");
  try {
    await fetchCompatibleDaemonStatus(DAEMON_STATUS_URL);

    const response = await fetch(DAEMON_DOMAINS_URL);

    if (!response.ok) {
      throw new Error(`daemon returned ${response.status}`);
    }

    const payload = await response.json();
    const domains = Array.isArray(payload.domains) ? payload.domains : [];

    if (domains.length === 0) {
      listEl.textContent = "No domains reported by the backend node.";
      return;
    }

    listEl.replaceChildren(
      ...domains.map((record) => {
        const row = document.createElement("div");
        row.className = "domain-item";

        const meta = document.createElement("div");
        meta.className = "domain-meta";

        const name = document.createElement("span");
        name.className = "domain-name";
        name.textContent = record.domain || "unknown";

        const owner = document.createElement("span");
        owner.className = "domain-owner";
        owner.textContent = shortenOwner(record.owner);

        meta.append(name, owner);

        const openButton = document.createElement("button");
        openButton.type = "button";
        openButton.className = "domain-open";
        openButton.textContent = "Open";
        openButton.disabled = !record.domain;
        openButton.addEventListener("click", () => openViewer(record.domain, "/"));

        row.append(meta, openButton);
        return row;
      })
    );
  } catch (error) {
    listEl.textContent = `Failed to load domains: ${error.message}`;
  }
}

document.getElementById("open-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const domain = document.getElementById("domain").value.trim();
  const path = document.getElementById("path").value.trim() || "/";
  if (!domain) {
    return;
  }
  openViewer(domain, path);
});

refreshStatus();
refreshDomains();
