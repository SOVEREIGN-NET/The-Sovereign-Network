const EXTENSION_VERSION = chrome.runtime.getManifest().version;
const REQUIRED_DAEMON_API_VERSION = "1";

function daemonCompatibilityError(status) {
  if (!status || typeof status !== "object") {
    return "daemon returned an invalid status payload";
  }

  if (status.api_version !== REQUIRED_DAEMON_API_VERSION) {
    return `daemon API ${status.api_version || "unknown"} is incompatible with extension ${EXTENSION_VERSION}`;
  }

  return null;
}

async function fetchCompatibleDaemonStatus(statusUrl) {
  const response = await fetch(statusUrl);
  if (!response.ok) {
    throw new Error(`daemon returned ${response.status}`);
  }

  const status = await response.json();
  const compatibilityError = daemonCompatibilityError(status);
  if (compatibilityError) {
    const error = new Error(compatibilityError);
    error.code = "DAEMON_INCOMPATIBLE";
    throw error;
  }

  return status;
}
