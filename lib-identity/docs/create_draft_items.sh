#!/bin/bash

# Get the project ID for SOVEREIGN-NET project #5
PROJECT_ID=$(gh api graphql -f query='
  query {
    organization(login: "SOVEREIGN-NET") {
      projectV2(number: 5) {
        id
      }
    }
  }
' --jq '.data.organization.projectV2.id')

echo "Project ID: $PROJECT_ID"

# PR-1: Create ProofEnvelope V0 wrapper
gh api graphql -f query='
  mutation($projectId: ID!, $title: String!, $body: String!) {
    addProjectV2DraftIssue(input: {
      projectId: $projectId
      title: $title
      body: $body
    }) {
      projectItem {
        id
      }
    }
  }
' -f projectId="$PROJECT_ID" \
  -f title="PR-1: Create ProofEnvelope V0 wrapper for legacy proofs" \
  -f body="## Description

Create a minimal ProofEnvelope V0 wrapper that wraps existing ZeroKnowledgeProof without breaking changes.

## Acceptance Criteria

- [ ] ProofEnvelope struct created with version field
- [ ] Automatic wrapping of legacy ZeroKnowledgeProof
- [ ] No breaking changes to existing code
- [ ] All existing tests pass

## Technical Notes

This is a compatibility shim allowing gradual migration to V1.

## Dependencies

None (can start immediately)

## Estimate

4-6 hours"

# PR-2: Update serialization
gh api graphql -f query='
  mutation($projectId: ID!, $title: String!, $body: String!) {
    addProjectV2DraftIssue(input: {
      projectId: $projectId
      title: $title
      body: $body
    }) {
      projectItem {
        id
      }
    }
  }
' -f projectId="$PROJECT_ID" \
  -f title="PR-2: Update serialization with V0 version markers" \
  -f body="## Description

Wrap all existing ZeroKnowledgeProof serialization points with V0 version markers to enable future migration tracking.

## Acceptance Criteria

- [ ] All serialization points include version=\"v0\" field
- [ ] Deserialization handles version field
- [ ] Version mismatch warnings logged
- [ ] No breaking changes to existing code

## Technical Notes

Update serde serialization to include version field in all ZeroKnowledgeProof instances.

## Dependencies

Requires PR-1 to be completed first.

## Estimate

1-2 hours"

# PR-3: Migration documentation
gh api graphql -f query='
  mutation($projectId: ID!, $title: String!, $body: String!) {
    addProjectV2DraftIssue(input: {
      projectId: $projectId
      title: $title
      body: $body
    }) {
      projectItem {
        id
      }
    }
  }
' -f projectId="$PROJECT_ID" \
  -f title="PR-3: Create V0 to V1 migration documentation" \
  -f body="## Description

Document the migration path from V0 (legacy ZeroKnowledgeProof) to V1 (ProofEnvelope with typed system).

## Acceptance Criteria

- [ ] Migration guide created in docs/migration/
- [ ] Code examples for each proof type conversion
- [ ] Timeline and deprecation schedule documented
- [ ] Breaking changes clearly identified

## Technical Notes

Include examples of converting existing proofs to new ProofEnvelope format.

## Dependencies

None

## Estimate

2-3 hours"

# PR-4: Update ADR-0003
gh api graphql -f query='
  mutation($projectId: ID!, $title: String!, $body: String!) {
    addProjectV2DraftIssue(input: {
      projectId: $projectId
      title: $title
      body: $body
    }) {
      projectItem {
        id
      }
    }
  }
' -f projectId="$PROJECT_ID" \
  -f title="PR-4: Update ADR-0003 status to 'Phased Implementation'" \
  -f body="## Description

Update ADR-0003 status field to reflect phased rollout strategy and add implementation timeline.

## Acceptance Criteria

- [ ] Status changed from 'Proposed' to 'Phased Implementation'
- [ ] Phase 1 (V0 wrapper) timeline documented
- [ ] Phase 2 (V1 implementation) timeline documented
- [ ] Deprecation schedule added

## Technical Notes

Simple documentation update to reflect Option 3 phased rollout decision.

## Dependencies

None

## Estimate

30 minutes"

# PG-1: ProofType enum
gh api graphql -f query='
  mutation($projectId: ID!, $title: String!, $body: String!) {
    addProjectV2DraftIssue(input: {
      projectId: $projectId
      title: $title
      body: $body
    }) {
      projectItem {
        id
      }
    }
  }
' -f projectId="$PROJECT_ID" \
  -f title="PG-1: Implement ProofType enum with 13 proof variants" \
  -f body="## Description

Create the canonical ProofType enum with all 13 proof types defined in ADR-0003.

## Acceptance Criteria

- [ ] ProofType enum implemented in lib-proofs
- [ ] All 13 variants defined (SignaturePopV1, IdentityAttributeZkV1, etc.)
- [ ] Display and serialization traits implemented
- [ ] Unit tests for enum conversion

## Technical Notes

Replace string-based proof type dispatch with type-safe enum.

## Dependencies

None (can start immediately)

## Estimate

3-4 hours"

# PG-2: ProofRegistry
gh api graphql -f query='
  mutation($projectId: ID!, $title: String!, $body: String!) {
    addProjectV2DraftIssue(input: {
      projectId: $projectId
      title: $title
      body: $body
    }) {
      projectItem {
        id
      }
    }
  }
' -f projectId="$PROJECT_ID" \
  -f title="PG-2: Implement ProofRegistry for validation and versioning" \
  -f body="## Description

Build the ProofRegistry module to manage proof specs, validation rules, and version compatibility.

## Acceptance Criteria

- [ ] ProofRegistry struct with HashMap<(ProofType, Version), ProofSpec>
- [ ] Registration functions for each proof type
- [ ] Validation logic per proof type
- [ ] Deprecation tracking
- [ ] Unit tests for registry operations

## Technical Notes

Central registry provides schema validation, version negotiation, and upgrade paths.

## Dependencies

Requires PG-1 (ProofType enum)

## Estimate

1-2 days"

# PG-3: SignaturePopV1
gh api graphql -f query='
  mutation($projectId: ID!, $title: String!, $body: String!) {
    addProjectV2DraftIssue(input: {
      projectId: $projectId
      title: $title
      body: $body
    }) {
      projectItem {
        id
      }
    }
  }
' -f projectId="$PROJECT_ID" \
  -f title="PG-3: Implement SignaturePopV1 proof type" \
  -f body="## Description

Implement SignaturePopV1 for binding operational keys to the root-key-anchored DID via the Root Signing Key.

## Acceptance Criteria

- [ ] SignaturePopV1 struct with ProofEnvelope
- [ ] Dilithium signature generation
- [ ] Canonical binding message: b\"IDENTITY_BIND_V1:\" + did
- [ ] Verification function
- [ ] Integration with ZhtpIdentity constructor
- [ ] Unit tests

## Technical Notes

This is the ownership proof that binds deterministic identity to PQC keypair.

## Dependencies

Requires PG-1 (ProofType enum) and PG-2 (ProofRegistry)

## Estimate

2-3 days"

# PG-4: CredentialProofV1
gh api graphql -f query='
  mutation($projectId: ID!, $title: String!, $body: String!) {
    addProjectV2DraftIssue(input: {
      projectId: $projectId
      title: $title
      body: $body
    }) {
      projectItem {
        id
      }
    }
  }
' -f projectId="$PROJECT_ID" \
  -f title="PG-4: Implement CredentialProofV1 proof type" \
  -f body="## Description

Implement CredentialProofV1 for external issuer credential verification.

## Acceptance Criteria

- [ ] CredentialProofV1 struct with ProofEnvelope
- [ ] Issuer signature verification
- [ ] Credential claim encoding
- [ ] Revocation checking hooks
- [ ] Unit tests

## Technical Notes

Used for verifiable credentials, DAO attestations, reputation proofs.

## Dependencies

Requires PG-1 (ProofType enum) and PG-2 (ProofRegistry)

## Estimate

2-3 days"

# PG-5: CBOR serialization
gh api graphql -f query='
  mutation($projectId: ID!, $title: String!, $body: String!) {
    addProjectV2DraftIssue(input: {
      projectId: $projectId
      title: $title
      body: $body
    }) {
      projectItem {
        id
      }
    }
  }
' -f projectId="$PROJECT_ID" \
  -f title="PG-5: Implement canonical CBOR serialization" \
  -f body="## Description

Replace JSON serialization with canonical CBOR for all proof types.

## Acceptance Criteria

- [ ] CBOR serialization for ProofEnvelope
- [ ] CBOR serialization for all proof types
- [ ] Deterministic encoding tests
- [ ] Cross-device equality verification
- [ ] Migration from JSON documented

## Technical Notes

CBOR ensures canonical encoding for cryptographic proofs (JSON is not canonical).

## Dependencies

Requires PG-1, PG-2, PG-3, PG-4

## Estimate

3-5 days"

# PG-6: Migrate references
gh api graphql -f query='
  mutation($projectId: ID!, $title: String!, $body: String!) {
    addProjectV2DraftIssue(input: {
      projectId: $projectId
      title: $title
      body: $body
    }) {
      projectItem {
        id
      }
    }
  }
' -f projectId="$PROJECT_ID" \
  -f title="PG-6: Migrate 81 ZeroKnowledgeProof references to V1 system" \
  -f body="## Description

Update all 81 references to ZeroKnowledgeProof across 15 files to use new ProofEnvelope and typed system.

## Acceptance Criteria

- [ ] All lib-identity references updated
- [ ] All lib-proofs references updated
- [ ] All test files updated
- [ ] String-based dispatch replaced with enum dispatch
- [ ] All tests passing
- [ ] No regressions

## Technical Notes

Systematic migration of entire codebase to governed proof system.

## Dependencies

Requires ALL previous PG tasks (PG-1 through PG-5)

## Estimate

1-2 weeks"

# PG-7: V0 deprecation
gh api graphql -f query='
  mutation($projectId: ID!, $title: String!, $body: String!) {
    addProjectV2DraftIssue(input: {
      projectId: $projectId
      title: $title
      body: $body
    }) {
      projectItem {
        id
      }
    }
  }
' -f projectId="$PROJECT_ID" \
  -f title="PG-7: V0 deprecation and cleanup" \
  -f body="## Description

Remove V0 wrapper code and complete transition to V1 proof system after 6-month deprecation period.

## Acceptance Criteria

- [ ] V0 compatibility layer removed
- [ ] Legacy ZeroKnowledgeProof struct removed
- [ ] All migration warnings removed
- [ ] Documentation updated
- [ ] ADR-0003 status updated to 'Completed'

## Technical Notes

Final cleanup after successful migration period.

## Dependencies

Requires PG-6 completion + 6 months in production

## Estimate

2-3 days"

echo "All draft items created successfully!"
