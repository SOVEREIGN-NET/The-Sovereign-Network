# T4 Plan: Extend setup.html with Observer Admission Panel

**Epic**: #2523 — Observer Onboarding
**Issue**: #2527 — [Observer Onboarding] Extend setup.html with observer admission panel
**File touched**: `zhtp-cli/src/ui/setup.html` (single-file; all HTML/CSS/JS is inline)

---

## Scope Boundary

T4 handles ONLY the frontend — HTML structure, CSS styles, and JavaScript logic inside `setup.html`. It assumes that T5 (`setup_ui.rs`) will provide four new `proxy_control` actions:

| Action | What it does (T5 provides) |
|--------|---------------------------|
| `generate_observer_identity` | Creates Dilithium5+Kyber1024 keypair in `~/.zhtp/keystore/observer/`, returns `{did, dilithium_pk_hex, kyber_pk_hex}` |
| `admission_qr_payload` | POSTs to `/api/v1/observer/admission/prepare` over QUIC, returns the JSON payload for the QR |
| `admission_status` | GETs `/api/v1/observer/admission/status?did=...` over QUIC, returns status record |
| `start_observer_node` | Spawns `zhtp` in observer mode using the observer keystore (only if admitted) |

T4 also assumes T5 will serve `qrcode.min.js` at a route like `/js/qrcode.min.js`.

---

## 1. Vendor QR Code Library

- Download a minimal `qrcode.min.js` (e.g., from [davidshimjs/qrcodejs](https://github.com/davidshimjs/qrcodejs) or [kazuhikoarase/qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator))
- Place at `zhtp-cli/src/ui/qrcode.min.js`
- **Does NOT modify setup.html to embed it** — T4 adds only the `<script>` reference; T5 adds the axum route

---

## 2. Observer Mode Detection

The UI needs to know whether it's running in observer mode (zhtp-observer daemon) or normal mode (zhtp-cli node setup-ui).

**Mechanism**: T5/T6 will inject a mode indicator. Two options:
- **Option A (simpler)**: The `proxy_status` response includes `"mode": "observer"` when running under zhtp-observer. The JS reads this on bootstrap.
- **Option B**: The HTML includes a meta tag or JS variable set by T5/T6 at serve time (requires T6 to use a different HTML or query param).

**Recommended for T4**: The JS checks `status.mode === "observer"` on the initial `/api/status` response. If true, it enters observer flow. T5 controls what `proxy_status` returns.

If not in observer mode: existing behavior is unchanged. No regression.

---

## 3. Hide Existing Identity Panels in Observer Mode

When `mode === "observer"`:
- Hide `#view-setup` entirely (the Restore Identity / Create New Node panels)
- Hide the `#view-dashboard` too initially (observer has its own dashboard)
- Show the new `#view-observer` section
- The hero panel remains visible
- The topbar nav remains visible

---

## 4. Observer Admission Panel — 5 States

Add a new `<section id="view-observer">` (hidden by default) with sub-panels for each state:

### State 1: Generate
```
┌────────────────────────────────────────┐
│  Observer Node Setup                   │
│                                        │
│  This machine will run as an observer  │
│  node on the Sovereign Network. Your   │
│  phone acts as the sole signer.        │
│                                        │
│  [Create Observer Identity]            │
│                                        │
│  Operational notes (reuse note-list):  │
│   - No private key leaves this machine │
│   - Phone scans QR to approve          │
│   - Keystore: ~/.zhtp/keystore/observer│
└────────────────────────────────────────┘
```

**DOM**: `#observer-generate` panel with a single primary button `#obs-gen-btn`.
**JS**: On click → calls `postControl("generate_observer_identity")`. On success → stores `{did, dilithium_pk_hex, kyber_pk_hex}` in a JS variable, transitions to State 2.

Error handling: shows error-box if keystore already exists, network unreachable, etc.

### State 2: Pending Phone Signature (QR)
```
┌────────────────────────────────────────┐
│  Scan with Sovereign Mobile App        │
│                                        │
│  ┌──────────────────────────────┐      │
│  │                              │      │
│  │    [QR code rendered here]   │      │
│  │                              │      │
│  └──────────────────────────────┘      │
│                                        │
│  Waiting for phone approval...  ◌      │
│  (polling every 2s)                    │
│                                        │
│  Observer DID: did:zhtp:abc123...      │
│  [Copy DID]  [Show ASCII QR]  [Cancel] │
└────────────────────────────────────────┘
```

**DOM**: `#observer-qr` panel.
- QR canvas/div: `#obs-qr-container`
- Spinner + status text: `#obs-qr-status`
- DID display: `#obs-qr-did`
- Buttons: `#obs-copy-did-btn`, `#obs-ascii-qr-btn`, `#obs-cancel-btn`

**JS Flow**:
1. On entry → call `postControl("admission_qr_payload", {did})` to get the JSON payload
2. Render QR using `qrcode.min.js` into `#obs-qr-container`
3. Start polling `postControl("admission_status", {did})` every 2s
4. When status returns `record.status === "Active"` → transition to State 3
5. On Cancel → call a reset action (T5: `reset_observer_identity` or similar), return to State 1

**QR rendering** (using qrcodejs or similar):
```js
// Assuming qrcodejs API (standard)
new QRCode(document.getElementById("obs-qr-container"), {
  text: JSON.stringify(payloadJson),
  width: 256,
  height: 256,
  correctLevel: QRCode.CorrectLevel.M
});
```

The "Show ASCII QR" button reveals a pre-formatted `<pre>` block with the ASCII QR (which T5 can generate server-side and return, or T4 can compute with a JS ASCII QR library — but given the existing `qrcode` crate usage in `observer.rs`, T5 could return the ASCII QR as part of the payload response).

### State 3: Admitted
```
┌────────────────────────────────────────┐
│  ✓ Observer Admitted                   │
│                                        │
│  DID: did:zhtp:abc123...               │
│  Status: Active                        │
│  Sponsor: did:zhtp:sponsor...          │
│                                        │
│  Starting observer node...             │
│                                        │
│  [Start Node]                          │
└────────────────────────────────────────┘
```

**DOM**: `#observer-admitted` panel.
- Green checkmark / success icon
- Admission record details (DID, status, sponsor)
- Auto-trigger or manual button to start the node

**JS**: On entry → auto-call `postControl("start_observer_node", {did})`. On success → transition to State 4. On error → show error with retry.

### State 4: Running
```
┌────────────────────────────────────────┐
│  ● Observer Running                    │
│  ─────────────────────────────────     │
│  Chain Height    42,817                │
│  Connected Peers 3                     │
│  Sync Progress   ████████░░ 82%        │
│  Network         testnet               │
│                                        │
│  Uptime: 4m 32s                        │
│  [Refresh]  [Stop Node]                │
└────────────────────────────────────────┘
```

**DOM**: `#observer-running` panel.
- Reuses existing metric cards styling
- Live telemetry via existing `/api/status` polling
- Progress bar for sync
- Stop button → calls disconnect action

This state essentially becomes the "dashboard" for observer mode.

### State 5: Error
```
┌────────────────────────────────────────┐
│  ⚠ Admission Error                     │
│                                        │
│  Chain unreachable                     │
│  The bootstrap node did not respond.   │
│  Check your network connection.        │
│                                        │
│  [Retry]   [Reset]                     │
└────────────────────────────────────────┘
```

**DOM**: `#observer-error` panel.
- Error icon
- Descriptive message (chain unreachable, tx rejected, network mismatch)
- Retry button → re-enters State 2
- Reset button → returns to State 1 (calls reset action in T5)

---

## 5. CSS Styles to Add

New CSS classes needed:

```css
/* Observer panel base — reuses .panel */
#view-observer { display: grid; gap: 24px; }
#view-observer .obs-panel { /* same as .panel but for observer states */ }

/* QR container */
.obs-qr-wrap {
  display: flex; flex-direction: column; align-items: center;
  padding: 24px; background: #fff; border-radius: 18px;
  border: 1px solid var(--line);
}
.obs-qr-wrap canvas, .obs-qr-wrap img { border-radius: 8px; }

/* Status spinner */
.obs-spinner {
  display: inline-block; width: 20px; height: 20px;
  border: 2px solid var(--line); border-top-color: var(--gold);
  border-radius: 50%; animation: obs-spin 0.8s linear infinite;
}
@keyframes obs-spin { to { transform: rotate(360deg); } }

/* Success checkmark */
.obs-check {
  width: 48px; height: 48px; border-radius: 50%;
  background: var(--signal-soft); color: var(--signal);
  display: flex; align-items: center; justify-content: center;
  font-size: 24px;
}

/* Error icon */
.obs-error-icon {
  width: 48px; height: 48px; border-radius: 50%;
  background: var(--err-soft); color: var(--err);
  display: flex; align-items: center; justify-content: center;
  font-size: 24px;
}

/* ASCII QR display */
.obs-ascii-qr {
  font-family: var(--mono); font-size: 8px; line-height: 1;
  padding: 16px; background: #fff; border-radius: 12px;
  border: 1px solid var(--line); overflow-x: auto;
  white-space: pre;
}

/* Observer status card */
.obs-status-grid {
  display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
```

All new styles go inside the existing `<style>` block (no new files).

---

## 6. JavaScript Logic

### State Machine

```
                  ┌──────────┐
      bootstrap → │ GENERATE │
                  └────┬─────┘
                       │ generate_observer_identity success
                       ▼
                  ┌──────────┐
          ┌────── │ PENDING  │ ←──── retry on error
          │       └────┬─────┘
          │ cancel     │ admission_status → Active
          ▼            ▼
     (back to     ┌──────────┐
      GENERATE)   │ ADMITTED │
                  └────┬─────┘
                       │ start_observer_node success
                       ▼
                  ┌──────────┐
                  │ RUNNING  │
                  └──────────┘
                  
                  ┌──────────┐
          ┌────── │  ERROR   │
          │       └──────────┘
          │ retry → PENDING
          │ reset → GENERATE
```

### New JS functions to add:

```js
// Observer state
let obsMode = false;
let obsState = "generate"; // generate|pending|admitted|running|error
let obsDid = null;
let obsPayload = null;
let obsPollTimer = null;

// Entry: called from bootstrap() when mode === "observer"
function enterObserverMode() {
  obsMode = true;
  els["view-setup"].classList.add("hidden");
  els["view-dashboard"].classList.add("hidden");
  els["view-observer"].classList.remove("hidden");
  showObserverState("generate");
}

// State switcher
function showObserverState(state) {
  obsState = state;
  // Hide all observer panels
  ["obs-generate","obs-qr","obs-admitted","obs-running","obs-error"]
    .forEach(id => els[id].classList.add("hidden"));
  // Show current
  els["obs-" + state].classList.remove("hidden");

  if (state === "pending") startObserverPolling();
  else stopObserverPolling();
}

// Generate observer identity
async function doObserverGenerate() {
  // setBusy, clear errors, call postControl("generate_observer_identity")
  // on success: obsDid = data.did; showObserverState("pending")
  // on error: show error in obs-generate-error
}

// QR payload + render
async function loadQrPayload() {
  // call postControl("admission_qr_payload", {did: obsDid})
  // render QR via qrcodejs
  // set up 2s polling for admission_status
}

// Poll admission status
function startObserverPolling() {
  obsPollTimer = setInterval(async () => {
    const data = await postControl("admission_status", {did: obsDid});
    if (data.record && data.record.status === "Active") {
      showObserverState("admitted");
      doStartObserverNode();
    }
  }, 2000);
}

function stopObserverPolling() {
  if (obsPollTimer) { clearInterval(obsPollTimer); obsPollTimer = null; }
}

// Start observer node
async function doStartObserverNode() {
  // call postControl("start_observer_node", {did: obsDid})
  // on success: showObserverState("running")
  // on error: showObserverState("error") with message
}

// Copy observer DID
function copyObserverDid() { /* copy obsDid to clipboard */ }

// Cancel admission flow
async function cancelObserverAdmission() {
  stopObserverPolling();
  showObserverState("generate");
  // optionally call postControl("reset_observer_identity") in T5
}
```

### Bootstrap Changes

In the existing `bootstrap()` function:
1. After the initial `/api/status` call, check `data.mode === "observer"`
2. If true → call `enterObserverMode()` and return
3. If false → existing behavior unchanged

### Element Caching

Add new element IDs to `cacheElements()`:
- `view-observer`, `obs-generate`, `obs-qr`, `obs-admitted`, `obs-running`, `obs-error`
- `obs-gen-btn`, `obs-qr-container`, `obs-qr-status`, `obs-qr-did`
- `obs-copy-did-btn`, `obs-ascii-qr-btn`, `obs-cancel-btn`
- `obs-start-btn`, `obs-retry-btn`, `obs-reset-btn`
- `obs-generate-error`, `obs-admitted-error`, `obs-running-error`, `obs-error-message`

---

## 7. QR Library Script Reference

At the bottom of `<body>`, alongside the existing inline `<script>` block, add before the main script:

```html
<script src="/js/qrcode.min.js"></script>
```

T5 serves this file from `zhtp-cli/src/ui/qrcode.min.js` via a new axum route. The `<script>` tag fails gracefully — if T5 hasn't added the route yet, the QR rendering function checks `typeof QRCode !== "undefined"` and shows a fallback message.

---

## 8. Integration Points with T5

T4's JS calls these `proxy_control` actions that T5 must implement:

| Action | Body params | Expected response |
|--------|------------|-------------------|
| `generate_observer_identity` | `{}` | `{success: true, did, dilithium_pk_hex, kyber_pk_hex}` |
| `admission_qr_payload` | `{did}` | JSON payload object (the v1 QR payload) |
| `admission_status` | `{did}` | `{record: {...} \| null, status: "ok"}` |
| `start_observer_node` | `{did}` | `{success: true, message, pid}` |

T5 must also:
- Serve `qrcode.min.js` at `/js/qrcode.min.js`
- Have `proxy_status` return `"mode": "observer"` when running in observer mode
- Potentially add `reset_observer_identity` action (Cancel button)

---

## 9. Error States

| Error | Trigger | UI Behavior |
|-------|---------|------------|
| Keystore exists | generate_observer_identity returns error | Show in obs-generate-error: "Observer identity already exists. Delete ~/.zhtp/keystore/observer/ to regenerate." |
| Chain unreachable | admission_qr_payload fails to connect | Transition to error state: "The bootstrap node did not respond. Check network." |
| Tx rejected | admission_status returns rejected status | Transition to error state: "Transaction rejected: {reason}" |
| Network mismatch | QR payload network ≠ expected | Transition to error state: "Network mismatch. Expected testnet, got {actual}" |
| Start failed | start_observer_node fails | Show in obs-admitted-error: "Failed to start observer node: {reason}" |
| QR library missing | typeof QRCode === "undefined" | Show text fallback: "QR library not loaded. Use ASCII QR instead." |

---

## Files Changed (T4 Scope)

| File | Change |
|------|--------|
| `zhtp-cli/src/ui/qrcode.min.js` | **NEW** — vendored QR code library |
| `zhtp-cli/src/ui/setup.html` | Observer panel HTML + CSS + JS |

---

## Out of Scope (T4)

- **T5**: Adding `proxy_control` actions in `setup_ui.rs` (generate_observer_identity, admission_qr_payload, admission_status, start_observer_node)
- **T5**: Adding `/js/qrcode.min.js` route to the axum router
- **T5**: Modifying `proxy_status` to return `mode: "observer"`
- **T6**: `zhtp-observer` binary target — T4 only reads the mode flag
- **T6**: `--observer-flow` CLI flag
- Any Rust code changes whatsoever
- Starting actual observer node processes
- TLS/QUIC connection logic
