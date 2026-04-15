const STATUS_URL = "http://127.0.0.1:7840/api/v1/status";
const RESOLVE_URL = "http://127.0.0.1:7840/api/v1/resolve";
const RAW_CONTENT_BASE = "http://127.0.0.1:7840/web4/content";

function query() {
  return new URLSearchParams(window.location.search);
}

function normalizePath(rawPath) {
  if (!rawPath || rawPath === "") {
    return "/";
  }
  return rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
}

function buildRawContentUrl(domain, path) {
  const normalized = normalizePath(path);
  const encodedDomain = encodeURIComponent(domain);
  const trimmed = normalized === "/" ? "" : normalized;
  return `${RAW_CONTENT_BASE}/${encodedDomain}${trimmed}`;
}

async function loadViewer() {
  const params = query();
  const domain = params.get("domain");
  const path = normalizePath(params.get("path") || "/");
  const source = params.get("source");

  const domainLabel = document.getElementById("domain-label");
  const sourceLabel = document.getElementById("source-label");
  const daemonStatus = document.getElementById("daemon-status");
  const inspector = document.getElementById("inspector");
  const frame = document.getElementById("content-frame");

  if (!domain) {
    domainLabel.textContent = "Missing domain";
    inspector.textContent = "No .zhtp or .sov domain was provided to the viewer.";
    return;
  }

  domainLabel.textContent = `${domain}${path}`;
  sourceLabel.textContent = source || `zhtp://${domain}${path}`;

  try {
    const status = await fetchCompatibleDaemonStatus(STATUS_URL);

    const resolveResponse = await fetch(`${RESOLVE_URL}/${encodeURIComponent(domain)}`);
    if (!resolveResponse.ok) {
      throw new Error(`resolve returned ${resolveResponse.status}`);
    }
    const resolved = await resolveResponse.json();

    frame.src = buildRawContentUrl(domain, path);
    daemonStatus.textContent =
      `Daemon ${status.daemon_version}. Backend ${status.active_backend || "pending"}.`;
    inspector.textContent = `Owner ${resolved.owner || "unknown"} · Registered ${resolved.registered_at || "unknown"} · Expires ${resolved.expires_at || "unknown"}.`;
  } catch (error) {
    daemonStatus.textContent =
      error.code === "DAEMON_INCOMPATIBLE" ? "Daemon incompatible" : "Daemon unavailable";
    inspector.textContent = `Resolution failed: ${error.message}`;
    frame.removeAttribute("src");
  }
}

loadViewer();
