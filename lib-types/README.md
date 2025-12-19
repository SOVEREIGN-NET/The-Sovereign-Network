# lib-types

Sovereign Network primitives and protocol-neutral data shapes. Behavior-free and runtime-free.

## Non-goals
- No async, no tokio
- No networking, no storage, no logging
- No feature flags
- No dependency on any internal crate
- No behavior or policy; if a type needs logic, it lives elsewhere

## Dependency policy
- Only `serde` (derive), `blake3`, and `hex`
- Nothing else; adding dependencies requires explicit approval

## Stability contract (v0.1.0)
- Binary layout of `NodeId` and `ChunkId` must not change
- Serialized field names and enum variants are stable
- Allowed: adding new enums/structs/modules
- Breaking changes (require v1.0): changing existing struct fields, enum variants, or serialization behavior

## Crate layout (target)
```
lib-types/
└── src/
    ├── lib.rs
    ├── node_id.rs
    ├── dht/
    │   ├── mod.rs
    │   ├── types.rs
    │   ├── message.rs
    │   └── transport.rs
    ├── chunk.rs
    └── errors.rs
```
