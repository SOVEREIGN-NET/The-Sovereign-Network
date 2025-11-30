# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records (ADRs) for lib-identity.

## What is an ADR?

An Architecture Decision Record captures an important architectural decision made along with its context and consequences.

## ADR Format

Each ADR follows this structure:
- **Title**: Clear, descriptive name
- **Date**: When the decision was made
- **Status**: Proposed, Accepted, Deprecated, Superseded
- **Context**: What is the issue we're addressing?
- **Decision**: What is the change we're making?
- **Consequences**: What becomes easier or harder?

## Index

- [ADR-0001](./0001-seed-anchored-identity.md) - Seed-Anchored Identity Architecture (2025-11-29)
  - **Status**: Accepted
  - **Summary**: Anchor identity on cryptographic seed rather than PQC keypairs, enabling deterministic recovery while maintaining PQC security as attached capabilities.

## Adding New ADRs

When making significant architectural decisions:

1. Create a new file: `docs/adr/NNNN-short-title.md`
2. Use the next sequential number (NNNN)
3. Follow the format of existing ADRs
4. Update this README index
5. Link from relevant code/docs

## References

- [ADR GitHub Repo](https://github.com/joelparkerhenderson/architecture-decision-record)
- [Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
