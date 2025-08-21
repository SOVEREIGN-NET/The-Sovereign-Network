// generate_witness.js
"use strict";

const { readFileSync, writeFile } = require("fs");
const path = require("path");
const { Worker } = require("worker_threads");

if (process.argv.length !== 5) {
  console.log("Usage: node generate_witness.js <file.wasm> <input.json> <output.wtns>");
  process.exit(1);
}

function safeResolve(baseDir, userPath) {
  const abs = path.resolve(baseDir, userPath);
  if (!abs.startsWith(baseDir + path.sep)) {
    throw new Error("Path traversal or absolute path detected: " + userPath);
  }
  return abs;
}

function assertExt(p, allowed) {
  const ext = path.extname(p).toLowerCase();
  if (!allowed.includes(ext)) {
    throw new Error(`Invalid file extension for ${p}; expected ${allowed.join(", ")}`);
  }
}

function sanitizeAndValidateJSON(text, { maxBytes = 1_000_000 } = {}) {
  if (text.length > maxBytes) throw new Error("Input JSON file is too large.");

  // Strict parse
  let obj = JSON.parse(text);
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("Input JSON must be a non-null object.");
  }

  // Prevent prototype pollution
  const stack = [obj];
  while (stack.length) {
    const cur = stack.pop();
    if (Object.prototype.hasOwnProperty.call(cur, "__proto__") || Object.prototype.hasOwnProperty.call(cur, "constructor")) {
      throw new Error("Disallowed key detected (__proto__/constructor).");
    }
    for (const [k, v] of Object.entries(cur)) {
      if (typeof k !== "string" || k.length > 200) {
        throw new Error("Invalid key.");
      }
      if (typeof v === "function") throw new Error("Functions not allowed in input.");
      if (typeof v === "string" && v.length > 100_000) {
        throw new Error("Overlong string value.");
      }
      if (typeof v === "object" && v !== null) stack.push(v);
    }
  }

  // Deep clone to strip prototypes
  return structuredClone(obj);
}

const cwd = process.cwd();
const wasmPath = safeResolve(cwd, process.argv[2]);
const inputPath = safeResolve(cwd, process.argv[3]);
const outputPath = safeResolve(cwd, process.argv[4]);

assertExt(wasmPath, [".wasm"]);
assertExt(inputPath, [".json"]);
assertExt(outputPath, [".wtns"]);

let input;
try {
  const raw = readFileSync(inputPath, "utf8");
  input = sanitizeAndValidateJSON(raw);
} catch (e) {
  console.error("Invalid input JSON:", e.message);
  process.exit(1);
}

// Run the risky work in an isolated worker with string-based codegen disabled.
const worker = new Worker(
  `
  const { parentPort, workerData } = require("worker_threads");
  const { readFileSync, writeFile } = require("fs");

  // Optional: freeze some intrinsics (lightweight)
  Object.freeze(global.Object);
  Object.freeze(global.Array);
  Object.freeze(global.Function);

  (async () => {
    try {
      const wc = require(workerData.wcPath);   // local, controlled
      const wasmBuffer = readFileSync(workerData.wasmPath);
      const witnessCalculator = await wc(wasmBuffer);

      const w = await witnessCalculator.calculateWitness(workerData.input, 0);
      if (w == null) throw new Error("Witness calculation returned null.");

      const buff = await witnessCalculator.calculateWTNSBin(workerData.input, 0);
      writeFile(workerData.outputPath, buff, (err) => {
        if (err) throw err;
        parentPort.postMessage({ ok: true });
      });
    } catch (err) {
      parentPort.postMessage({ ok: false, error: err.message || String(err) });
    }
  })();
`,
  {
    eval: true,
    execArgv: ["--disallow-code-generation-from-strings"], // 🚫 blocks eval/Function("...")
    workerData: {
      wcPath: path.resolve(__dirname, "witness_calculator.js"),
      wasmPath,
      outputPath,
      input
    }
  }
);

worker.once("message", (m) => {
  if (!m.ok) {
    console.error("Witness generation failed:", m.error);
    process.exit(1);
  }
  process.exit(0);
});

worker.once("error", (err) => {
  console.error("Worker error:", err.message || err);
  process.exit(1);
});

worker.once("exit", (code) => {
  if (code !== 0) {
    console.error("Worker exited with code", code);
    process.exit(code);
  }
});
if (input) {
  writeFile(outputPath, "", (err) => {
	if (err) throw err;
	console.log("Output file created:", outputPath);
  });
}