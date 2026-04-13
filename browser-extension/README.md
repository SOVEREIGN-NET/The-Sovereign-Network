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
