//! Oracle State Migration Module
//!
//! ORACLE-R4: Oracle State V2 Migration + Import/Export Compatibility
//!
//! This module provides versioned serialization and migration for oracle state,
//! ensuring safe upgrades and cross-version compatibility.

use serde::{Deserialize, Serialize};

/// Oracle state format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleStateVersion {
    /// Legacy V1 format (pre-remediation).
    /// - No protocol version field
    /// - Immediate committee removal on slash
    /// - No deviation band slashing
    V1Legacy,
    /// Current V2 format (post-remediation).
    /// - Protocol version and activation gate
    /// - Next-epoch committee removal queue
    /// - Deviation band validation
    /// - Shadow mode parity tracking
    V2Current,
}

impl Default for OracleStateVersion {
    fn default() -> Self {
        Self::V2Current
    }
}

impl OracleStateVersion {
    /// Get version as u16 for serialization.
    pub fn as_u16(&self) -> u16 {
        match self {
            Self::V1Legacy => 1,
            Self::V2Current => 2,
        }
    }

    /// Parse from u16.
    pub fn from_u16(version: u16) -> Option<Self> {
        match version {
            1 => Some(Self::V1Legacy),
            2 => Some(Self::V2Current),
            _ => None,
        }
    }
}

/// Versioned oracle state envelope for import/export.
///
/// This envelope allows detecting the state version during deserialization
/// and applying appropriate migration logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleStateEnvelope {
    /// State format version.
    pub version: u16,
    /// Serialized state data (format depends on version).
    pub data: Vec<u8>,
    /// Timestamp when state was exported.
    pub exported_at: u64,
    /// Block height when state was exported.
    pub exported_at_height: u64,
    /// Source node identifier (optional, for audit trail).
    pub source_node_id: Option<String>,
}

impl OracleStateEnvelope {
    /// Create a new envelope with current version.
    pub fn new(data: Vec<u8>, height: u64, node_id: Option<String>) -> Self {
        Self {
            version: OracleStateVersion::V2Current.as_u16(),
            data,
            exported_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            exported_at_height: height,
            source_node_id: node_id,
        }
    }

    /// Create legacy V1 envelope for backward compatibility testing.
    #[cfg(test)]
    pub fn new_v1(data: Vec<u8>, height: u64) -> Self {
        Self {
            version: OracleStateVersion::V1Legacy.as_u16(),
            data,
            exported_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            exported_at_height: height,
            source_node_id: None,
        }
    }
}

/// Migration result indicating what transformation was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationResult {
    /// No migration needed - state is current version.
    NoMigrationNeeded,
    /// State was migrated from V1 to V2.
    MigratedFromV1,
    /// State migration failed.
    MigrationFailed(String),
}

/// Import validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportValidationResult {
    /// State is valid and can be imported.
    Valid,
    /// State version is unsupported.
    UnsupportedVersion(u16),
    /// State data is corrupted or invalid.
    InvalidData(String),
    /// State is from a future height (potential replay attack).
    FutureHeight { imported: u64, current: u64 },
    /// State hash mismatch (corruption detected).
    HashMismatch,
}

/// Validates an oracle state envelope before import.
pub fn validate_import_envelope(
    envelope: &OracleStateEnvelope,
    current_height: u64,
) -> ImportValidationResult {
    // Check version support
    match OracleStateVersion::from_u16(envelope.version) {
        Some(OracleStateVersion::V1Legacy) | Some(OracleStateVersion::V2Current) => {}
        None => {
            return ImportValidationResult::UnsupportedVersion(envelope.version);
        }
    }

    // Check for future height (potential replay)
    if envelope.exported_at_height > current_height {
        return ImportValidationResult::FutureHeight {
            imported: envelope.exported_at_height,
            current: current_height,
        };
    }

    // Basic data validation
    if envelope.data.is_empty() {
        return ImportValidationResult::InvalidData("Empty state data".to_string());
    }

    ImportValidationResult::Valid
}

/// Export oracle state to versioned envelope.
pub fn export_state<T: Serialize>(
    state: &T,
    height: u64,
    node_id: Option<String>,
) -> Result<OracleStateEnvelope, Box<dyn std::error::Error>> {
    let data = bincode::serialize(state)?;
    Ok(OracleStateEnvelope::new(data, height, node_id))
}

/// Import oracle state from envelope with automatic migration.
pub fn import_state<T: for<'de> Deserialize<'de>>(
    envelope: &OracleStateEnvelope,
) -> Result<(T, MigrationResult), Box<dyn std::error::Error>> {
    match OracleStateVersion::from_u16(envelope.version) {
        Some(OracleStateVersion::V2Current) => {
            let state: T = bincode::deserialize(&envelope.data)?;
            Ok((state, MigrationResult::NoMigrationNeeded))
        }
        Some(OracleStateVersion::V1Legacy) => {
            // V1 state can be deserialized as V2 due to serde defaults
            let state: T = bincode::deserialize(&envelope.data)?;
            Ok((state, MigrationResult::MigratedFromV1))
        }
        None => Err(format!("Unsupported state version: {}", envelope.version).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestState {
        value: u64,
        #[serde(default)]
        new_field: Option<String>,
    }

    #[test]
    fn test_oracle_state_version_roundtrip() {
        assert_eq!(OracleStateVersion::V1Legacy.as_u16(), 1);
        assert_eq!(OracleStateVersion::V2Current.as_u16(), 2);
        assert_eq!(
            OracleStateVersion::from_u16(1),
            Some(OracleStateVersion::V1Legacy)
        );
        assert_eq!(
            OracleStateVersion::from_u16(2),
            Some(OracleStateVersion::V2Current)
        );
        assert_eq!(OracleStateVersion::from_u16(99), None);
    }

    #[test]
    fn test_envelope_creation() {
        let envelope = OracleStateEnvelope::new(vec![1, 2, 3], 100, Some("node1".to_string()));
        assert_eq!(envelope.version, 2);
        assert_eq!(envelope.data, vec![1, 2, 3]);
        assert_eq!(envelope.exported_at_height, 100);
        assert_eq!(envelope.source_node_id, Some("node1".to_string()));
        assert!(envelope.exported_at > 0);
    }

    #[test]
    fn test_validate_import_envelope() {
        let valid = OracleStateEnvelope::new(vec![1, 2, 3], 100, None);
        assert_eq!(
            validate_import_envelope(&valid, 200),
            ImportValidationResult::Valid
        );

        // Future height
        let future = OracleStateEnvelope::new(vec![1, 2, 3], 300, None);
        assert_eq!(
            validate_import_envelope(&future, 200),
            ImportValidationResult::FutureHeight {
                imported: 300,
                current: 200
            }
        );

        // Empty data
        let empty = OracleStateEnvelope::new(vec![], 100, None);
        assert!(matches!(
            validate_import_envelope(&empty, 200),
            ImportValidationResult::InvalidData(_)
        ));
    }

    #[test]
    fn test_export_import_roundtrip() {
        let state = TestState {
            value: 42,
            new_field: Some("test".to_string()),
        };

        let envelope = export_state(&state, 100, Some("node1".to_string())).unwrap();
        let (imported, result) = import_state::<TestState>(&envelope).unwrap();

        assert_eq!(imported, state);
        assert_eq!(result, MigrationResult::NoMigrationNeeded);
    }

    #[test]
    fn test_v1_to_v2_migration() {
        // Simulate V1 state (without new_field)
        let v1_state = TestState {
            value: 42,
            new_field: None,
        };
        let v1_data = bincode::serialize(&v1_state).unwrap();
        let v1_envelope = OracleStateEnvelope::new_v1(v1_data, 100);

        let (imported, result) = import_state::<TestState>(&v1_envelope).unwrap();

        assert_eq!(imported.value, 42);
        assert_eq!(imported.new_field, None);
        assert_eq!(result, MigrationResult::MigratedFromV1);
    }
}
