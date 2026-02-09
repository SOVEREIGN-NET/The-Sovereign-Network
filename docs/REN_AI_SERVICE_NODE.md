# Ren AI Service Node -- Architecture & Design

**Branch:** `feature/ren-ai-service-node`
**Target:** `development`
**Status:** Scaffold (Phase 0)

---

## 1. Overview

A **Ren AI Service Node** is a new ZHTP node type that hosts the Ren LLM and
exposes inference endpoints to the Sovereign Network mesh. Clients submit
DID-signed prompts, pay SOV micro-transactions, and receive completions.
The node operator earns SOV rewards proportional to tokens generated, quality
scores, and uptime.

This document covers the architecture, data flow, reward economics, API
surface, and security model.

---

## 2. Node Type Comparison

| Property | Full Node | Validator | Storage | **Ren AI** |
|---|---|---|---|---|
| Primary role | API / explorer | Consensus | Distributed storage | LLM inference |
| GPU required | No | No | No | **Yes** |
| Min RAM | 4 GB | 8 GB | 2 GB | **32 GB** |
| Min VRAM | -- | -- | -- | **24 GB** |
| Min stake | 1,000 SOV | 10,000 SOV | 1,000 SOV | **5,000 SOV** |
| Validates blocks | No | Yes | No | **No** |
| Reward multiplier | -- | -- | storage 3x | **inference 2x, embedding 1.5x** |
| Smart contracts | Yes | Yes | No | **Yes** (payment escrow) |
| Max connections | 2,000 | 2,000 | 1,000 | **500** |
| Request timeout | 30 s | 30 s | 45 s | **120 s** |

---

## 3. Architecture Diagram

```
                        Sovereign Network Mesh
                               |
                     +---------+---------+
                     |   ZHTP Protocol   |
                     |  (QUIC + TLS 1.3) |
                     +---------+---------+
                               |
                     +---------+---------+
                     |  Ren AI Node      |
                     |  (zhtp binary)    |
                     +---------+---------+
                               |
          +--------------------+--------------------+
          |                    |                    |
   +------+------+    +-------+-------+    +-------+-------+
   | Rate Limiter |    | Prompt       |    | Model         |
   | (per-DID)    |    | Validator    |    | Registry      |
   +--------------+    | (sig verify) |    | (on-chain ad) |
                       +------+-------+    +---------------+
                              |
                     +--------+--------+
                     | Content         |
                     | Guardrails      |
                     +--------+--------+
                              |
                     +--------+--------+
                     | Inference       |
                     | Engine          |
                     | (Ren LLM)      |
                     +--------+--------+
                              |
               +--------------+--------------+
               |              |              |
        +------+------+ +----+----+ +-------+-------+
        | Token       | | Receipt | | Reward        |
        | Streaming   | | Builder | | Tracker       |
        | (SSE/WS)    | | (sign)  | | (epoch agg)   |
        +-------------+ +---------+ +---------------+
```

---

## 4. Data Flow

### 4.1 Inference Request Lifecycle

```
1. Client creates InferenceRequest {
       request_id:  UUID v7
       client_did:  "did:zhtp:person:abc..."
       task:        Completion { prompt, max_tokens }
       sampling:    { temperature: 0.7 }
       signature:   Ed25519(request_bytes)
       payment_tx:  "0xabc..."  (optional escrow tx hash)
   }

2. Client sends POST /ren/v1/completions over ZHTP/QUIC

3. Ren AI Node pipeline:
   a. Rate limiter: check per-DID quota (60 req/min default)
   b. Signature verification: verify Ed25519/Dilithium sig
   c. Payment check: verify escrow or debit balance
   d. Content guardrails: prompt injection scan
   e. Inference engine: load into GPU, generate tokens
   f. Token streaming: SSE events back to client
   g. Receipt builder: create InferenceReceipt, sign with node key
   h. Reward tracker: accumulate into epoch stats

4. Response: InferenceResponse {
       request_id, node_did, model_id,
       output: Completion { text, finish_reason },
       usage: { input_tokens, output_tokens, latency_ms, tps },
       receipt: InferenceReceipt { signed by node }
   }
```

### 4.2 Reward Cycle

```
Epoch N (1 week)
    |
    +-- Node serves inference requests all week
    |   Accumulates EpochInferenceStats:
    |     total_input_tokens, total_output_tokens,
    |     requests_by_task, quality_score, uptime_fraction
    |
    +-- Epoch boundary reached
    |
    +-- InferenceRewardCalculator.calculate(stats, epoch)
    |     input_token_reward  = (total_input / 1K) * 1 SOV
    |     output_token_reward = (total_output / 1K) * 2 SOV
    |     task_complexity_bonus (chat 1.2x, summarization 1.5x)
    |     quality_bonus  = +25% if quality_score >= 0.85
    |     uptime_bonus   = +15% if uptime >= 99%
    |     total_reward   = sum of above (min 1 SOV)
    |
    +-- Reward submitted to Treasury Kernel
```

---

## 5. API Surface

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/ren/v1/completions` | Text completion |
| `POST` | `/ren/v1/chat` | Multi-turn chat |
| `POST` | `/ren/v1/embeddings` | Embedding generation |
| `POST` | `/ren/v1/summarize` | Text summarization |
| `GET`  | `/ren/v1/models` | List available models |
| `GET`  | `/ren/v1/health` | Engine health + GPU status |
| `GET`  | `/ren/v1/metrics` | Prometheus exposition metrics |

---

## 6. Pricing Model

| Parameter | Default | Description |
|-----------|---------|-------------|
| Input cost | 1 SOV / 1K tokens | Charged to client |
| Output cost | 3 SOV / 1K tokens | Charged to client |
| Min charge | 1 SOV | Floor per request |

Node operators set prices in `ren-ai-node.toml` and advertise them on-chain
via the Model Registry. Clients can compare prices across nodes.

---

## 7. Security Model

### 7.1 Authentication
- All prompts must carry a valid DID signature (Ed25519 or Dilithium)
- Node verifies signature before queuing for inference
- Payment escrow verified on-chain or via pre-funded balance

### 7.2 Rate Limiting
- Per-DID: 60 prompts/minute (configurable)
- Per-IP: standard ZHTP rate limiting
- Batch queue: max 8 concurrent requests (configurable)

### 7.3 Content Safety
- Prompt injection detection (keyword + pattern heuristic, upgradeable to ML classifier)
- Output content filter (scaffold for Llama Guard / custom classifier)
- Audit log of all requests (hashed prompt, no plaintext storage)

### 7.4 Privacy
- Prompts are NOT stored on-chain
- Only Blake3 hashes of prompt/output appear in InferenceReceipt
- Receipts are used for reward calculation and dispute resolution
- Audit logs can be disabled by operator

---

## 8. File Structure

```
zhtp/
  configs/
    ren-ai-node.toml            # Node configuration template
  src/
    ren_ai/
      mod.rs                    # Module root, public exports
      config.rs                 # RenAiConfig struct + validation
      types.rs                  # Request/Response/Receipt/Error types
      engine.rs                 # Model loading, inference, streaming
      routes.rs                 # HTTP route handlers
      rewards.rs                # SOV reward calculation
      metrics.rs                # Prometheus metrics
      guardrails.rs             # Content filtering, abuse prevention
```

---

## 9. Configuration Reference

See `zhtp/configs/ren-ai-node.toml` for the full annotated configuration.

Key `[ren_ai_config]` fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | false | Enable the Ren AI engine |
| `model_id` | string | "ren-v1" | Model identifier |
| `model_path` | string | "./models/ren-v1" | Path to weights |
| `model_format` | enum | safetensors | gguf, safetensors, onnx |
| `quantization` | enum | Q4_K_M | Q4_K_M, Q8_0, F16, F32 |
| `context_window` | u32 | 8192 | Max context tokens |
| `max_batch_size` | u32 | 8 | Concurrent requests |
| `gpu_layers` | i32 | 99 | Layers on GPU |
| `gpu_memory_fraction` | f32 | 0.90 | VRAM fraction |
| `content_filter_enabled` | bool | true | Safety filter |
| `require_signed_prompts` | bool | true | DID signatures |
| `pricing_sov_per_1k_input_tokens` | u64 | 1 | Input pricing |
| `pricing_sov_per_1k_output_tokens` | u64 | 3 | Output pricing |

---

## 10. Implementation Phases

| Phase | Description | Status |
|-------|-------------|--------|
| **0 - Scaffold** | Module structure, types, config, route stubs | **Done** |
| 1 - Engine wiring | Integrate llama.cpp / candle for actual inference | Not started |
| 2 - Payment pipeline | Escrow verification, SOV debit/credit | Not started |
| 3 - Streaming | SSE / WebSocket token streaming | Not started |
| 4 - On-chain registry | Model advertisement, discovery | Not started |
| 5 - Production hardening | ML content filter, load testing, GPU monitoring | Not started |

---

## 11. Starting a Ren AI Node

```bash
# Download / place model weights
mkdir -p ./models/ren-v1
# ... copy safetensors files ...

# Start the node
zhtp --node-type ren-ai
# or
zhtp node start --config ./configs/ren-ai-node.toml
```

---

## 12. Running the Scaffold Tests

```bash
cargo test --package zhtp --lib ren_ai
```
