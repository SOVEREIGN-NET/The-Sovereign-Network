# Final Security Audit Summary

* **Rust Dependencies:** 7
* **TypeScript Dependencies:** 8
* **Hardcoded Secrets:** 12
* **Unsafe Blocks:** 294
* **Unwrap/Expect Calls:** 16210
* **System Command Executions:** 202
* **Raw File System Access:** 84
* **Insecure Random:** 1
* **Unbounded Loops:** 3
* **Blocking Operations:** 20
* **Unbounded Reads:** 12
* **Weak Crypto:** 3
* **Hardcoded Keys/Seeds:** 5
* **Usage of 'any' type:** 21

**Total Identified Vulnerabilities/Risks:** 16882
**Overall Security Grade:** F

### Unrealized Access Discoveries
Identified 597 vectors that could potentially lead to unauthorized access or Remote Code Execution (RCE).
These include Unsafe Blocks, System Command Executions, Raw File System Access, and Hardcoded Secrets/Keys.
