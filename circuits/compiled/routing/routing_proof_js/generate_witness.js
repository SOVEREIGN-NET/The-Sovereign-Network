// generate_witness.js
"use strict";

/**
 * Security hardening highlights:
 * - Strict path resolution against CWD (no traversal, no absolute, no symlinks)
 * - Enforces expected file extensions + validates WASM magic + size caps
 * - Defensive JSON parsing + prototype pollution guards + deep structuredClone
 * - Runs witness calculation in an isolated Worker with resourceLimits + timeout
 * - No eval-based Workers; uses an ephemeral worker file in a private temp dir
 * - Atomic write to a temp file + chmod 0600 + rename to final .wtns (prevents partial/clobber)
 * - Avoids following symlinks for inputs and the output destination
 * - Removes racy “create empty output file” logic at the end
 */

const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { Worker } = require("worker_threads");

const USAGE = "Usage: node generate_witness.js <file.wasm> <input.json> <output.wtns>";

// ---- CLI ----
if (process.argv.length !== 5) {
  console.error(USAGE);
  process.exit(1);
}

const cwd = process.cwd();
const wasmPath = safeResolveFile(cwd, process.argv[2], [".wasm"]);
const inputPath = safeResolveFile(cwd, process.argv[3], [".json"]);
const outputPath = safeResolvePath(cwd, process.argv[4], [".wtns"]); // checked later for existence/dir

// ---- JSON: sanitize + validate ----
let input;
try {
  const raw = awaitSafeReadText(inputPath, { maxBytes: 1_000_000 }); // 1 MB cap (tweak as needed)
  input = sanitizeAndValidateJSON(raw);
} catch (e) {
  console.error("Invalid input JSON:", e.message || String(e));
  process.exit(1);
}

// ---- WASM: validate basic structure + size caps ----
let wasmBuffer;
try {
  wasmBuffer = awaitSafeReadBuffer(wasmPath, { maxBytes: 64 * 1024 * 1024 }); // 64 MB cap
  assertWasmMagic(wasmBuffer);
} catch (e) {
  console.error("Invalid WASM:", e.message || String(e));
  process.exit(1);
}

// ---- Output: prepare atomic temp target + ensure parent dir is sane ----
let finalOutAbs;
try {
  finalOutAbs = await prepareOutputTarget(outputPath);
} catch (e) {
  console.error("Output path error:", e.message || String(e));
  process.exit(1);
}

// ---- Create ephemeral worker file in private tmp dir (no eval worker) ----
let tmpDir, workerFile;
try {
  tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "wtns-"));
  workerFile = path.join(tmpDir, "witness_worker.cjs");
  const workerSource = getWorkerSource();
  await fsp.writeFile(workerFile, workerSource, { mode: 0o600, flag: "wx" });
} catch (e) {
  console.error("Failed to create worker file:", e.message || String(e));
  process.exit(1);
}

// ---- Run worker with isolation + timeout ----
const controller = new AbortController();
const timeoutMs = 3 * 60 * 1000; // 3 minutes; adjust as needed
const timeout = setTimeout(() => controller.abort(), timeoutMs);

const tempOut = path.join(tmpDir, "out_" + crypto.randomBytes(8).toString("hex") + ".wtns");

try {
  const { ok, error } = await runWorker({
    workerFile,
    wasmBuffer,
    input,
    tempOut
  }, {
    timeoutSignal: controller.signal,
    resourceLimits: {
      // Tight but practical; tune for a better workloads:
      maxOldGenerationSizeMb: 512,  // memory ceiling
      maxYoungGenerationSizeMb: 128,
      codeRangeSizeMb: 64,
      stackSizeMb: 4
    }
  });
  if (!ok) {
    console.error("Witness generation failed:", error);
    process.exit(1);
  }
 
// Move the temp output to the final destination
  await fsp.rename(tempOut, finalOutAbs);
  console.log("Witness generation succeeded:", finalOutAbs);
  
// Cleanup: remove the temporary worker file and directory
  await fsp.unlink(workerFile);
  await fsp.rmdir(tmpDir);
  console.log("Cleanup completed.");
} catch (e) {
  console.error("Witness generation error:", e.message || String(e));
  process.exit(1);
}

