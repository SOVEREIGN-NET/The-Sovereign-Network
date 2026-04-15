# browser-extension

This extension is the browser-side half of the QUIC-native ZHTP browser flow.

It does not speak QUIC itself. Instead it:

- watches for `.zhtp` and `.sov` top-level navigations
- redirects those navigations into `viewer.html`
- loads verified content from the local `zhtp-daemon` over `http://127.0.0.1:7840`

## Current behavior

- Popup allows manual domain/path entry.
- Background worker redirects `.zhtp` and `.sov` navigations into the viewer.
- Viewer embeds the daemon-served content route in an iframe.
- Relative assets work because the daemon exposes a raw localhost content origin.

## Local development

1. Start `zhtp-daemon`.
2. Load `browser-extension/` as an unpacked extension.
3. Visit `https://example.zhtp/` or open a domain from the popup.

The canonical network path remains QUIC. The extension only bridges the browser to the local daemon.

## Chrome developer release

The developer release target is Chrome with an unpacked extension install.

### Requirements

- Google Chrome
- local `zhtp-daemon` running on `127.0.0.1:7840`
- daemon API version `1`

The popup and viewer both check daemon compatibility through `GET /api/v1/status`. If the daemon API version does not match, the extension will show an incompatibility error instead of trying to browse.

### Install in Chrome

1. Open `chrome://extensions`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select the `browser-extension/` directory
5. Pin `ZHTP Browser Bridge` if you want one-click access

### Package a Chrome artifact

```bash
bash scripts/package-browser-extension-chrome.sh
```

This produces:

- `target/browser-extension/zhtp-browser-bridge-chrome.zip`
- `target/browser-extension/zhtp-browser-bridge-chrome.sha256`

The zip is the developer distribution artifact for Chrome. It is intended for unpacking/install review, not store upload yet.
