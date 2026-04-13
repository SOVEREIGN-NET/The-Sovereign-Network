const SUPPORTED_TLDS = new Set(["zhtp", "sov"]);

function isExtensionUrl(url) {
  return url.startsWith(chrome.runtime.getURL(""));
}

function parseHandledUrl(urlString) {
  try {
    const url = new URL(urlString);
    if (!["http:", "https:"].includes(url.protocol)) {
      return null;
    }

    const hostParts = url.hostname.split(".");
    const tld = hostParts[hostParts.length - 1];
    if (!SUPPORTED_TLDS.has(tld)) {
      return null;
    }

    return {
      domain: url.hostname,
      path: `${url.pathname || "/"}${url.search || ""}${url.hash || ""}`
    };
  } catch (_error) {
    return null;
  }
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0 || isExtensionUrl(details.url)) {
    return;
  }

  const handled = parseHandledUrl(details.url);
  if (!handled) {
    return;
  }

  const viewerUrl = chrome.runtime.getURL("viewer.html");
  const redirect = new URL(viewerUrl);
  redirect.searchParams.set("domain", handled.domain);
  redirect.searchParams.set("path", handled.path);
  redirect.searchParams.set("source", details.url);

  chrome.tabs.update(details.tabId, { url: redirect.toString() });
});
