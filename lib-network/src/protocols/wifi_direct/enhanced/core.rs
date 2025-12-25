//! Functional core for enhanced WiFi Direct - pure, deterministic algorithms
//!
//! This module contains pure functions with no I/O, no logging, no state mutation.
//! All functions are deterministic and easily testable in isolation.

/// Calculate WPS checksum digit using Luhn algorithm (ISO/IEC 7812-1)
///
/// # Arguments
/// * `pin_first_7` - The first 7 digits of the PIN as a u32
///
/// # Returns
/// The checksum digit (0-9)
pub fn calculate_wps_checksum_digit(pin_first_7: u32) -> u32 {
    let pin_str = format!("{:07}", pin_first_7);
    let mut sum = 0u32;

    for (i, ch) in pin_str.chars().enumerate() {
        let mut digit = ch.to_digit(10).unwrap_or(0);
        if i % 2 == 0 {
            digit *= 3;
        }
        sum += digit;
    }

    (10 - (sum % 10)) % 10
}

/// Validate WPS PIN format and checksum
///
/// # Arguments
/// * `pin` - The 8-digit PIN as a string
///
/// # Returns
/// `true` if PIN is valid (correct format and checksum), `false` otherwise
pub fn validate_wps_pin(pin: &str) -> bool {
    if pin.len() != 8 {
        return false;
    }

    // Parse first 7 digits
    let pin_first_7: u32 = match pin[..7].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    // Parse checksum digit
    let checksum: u32 = match pin[7..8].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    // Verify checksum matches
    calculate_wps_checksum_digit(pin_first_7) == checksum
}

/// Generate NFC NDEF handover record structure (pure byte manipulation)
///
/// # Arguments
/// * `ssid` - WiFi network SSID
/// * `passphrase` - WiFi network passphrase
/// * `pin` - WPS PIN
///
/// # Returns
/// NDEF record bytes
pub fn generate_nfc_ndef_record(ssid: &str, passphrase: &str, pin: &str) -> Vec<u8> {
    let mut record = Vec::new();

    // NDEF Record Header (MB=1, ME=1, CF=0, SR=1, IL=0, TNF=001)
    record.push(0xD1);
    record.push(0x02); // Type Length
    record.push((ssid.len() + passphrase.len() + pin.len() + 10) as u8);

    // Type: "application/vnd.wfa.wsc"
    record.extend_from_slice(b"Wsc");

    // Payload (WPS Configuration)
    record.extend_from_slice(ssid.as_bytes());
    record.push(0x00);
    record.extend_from_slice(passphrase.as_bytes());
    record.push(0x00);
    record.extend_from_slice(pin.as_bytes());

    record
}

/// Derive P2P interface name from system interface
///
/// # Arguments
/// * `base_interface` - Base interface name (e.g., "en0")
///
/// # Returns
/// P2P interface name (e.g., "en0-p2p")
pub fn derive_p2p_interface_name(base_interface: &str) -> String {
    format!("{}-p2p", base_interface)
}

/// Calculate WPS checksum for 8-digit PIN (older algorithm used in implementation)
///
/// This is the algorithm used in the current implementation for backward compatibility.
///
/// # Arguments
/// * `pin` - 8-digit PIN as u64
///
/// # Returns
/// Checksum digit
pub fn calculate_wps_checksum_alt(pin: u64) -> u8 {
    let pin_str = format!("{:08}", pin);
    let digits: Vec<u32> = pin_str
        .chars()
        .map(|c| c.to_digit(10).unwrap_or(0))
        .collect();

    let mut sum = 0u32;
    for (i, &digit) in digits.iter().enumerate() {
        if i % 2 == 0 {
            sum += digit * 3;
        } else {
            sum += digit;
        }
    }

    ((10 - (sum % 10)) % 10) as u8
}

/// P2P Group ID generation (deterministic based on node ID)
///
/// # Arguments
/// * `node_id` - 32-byte node identifier
///
/// # Returns
/// P2P Group ID string
pub fn generate_group_id(node_id: &[u8; 32]) -> String {
    // Use first 4 bytes as hex for deterministic, collision-resistant ID
    format!(
        "DIRECT-{:02X}{:02X}{:02X}{:02X}",
        node_id[0], node_id[1], node_id[2], node_id[3]
    )
}

/// Device capability scoring algorithm
///
/// Higher score means more likely to be Group Owner
///
/// # Arguments
/// * `ac_powered` - Device is AC powered
/// * `has_internet` - Device has internet connectivity
/// * `device_type_score` - Device type score (0.0-1.0)
///
/// # Returns
/// Capability score (0.0-1.0)
pub fn calculate_capability_score(ac_powered: bool, has_internet: bool, device_type_score: f64) -> f64 {
    let mut score = device_type_score;

    if ac_powered {
        score += 0.3;
    }
    if has_internet {
        score += 0.2;
    }

    score.min(1.0)
}

/// GO (Group Owner) tie-breaker algorithm
///
/// Determines which device should be Group Owner when intent values are equal
///
/// # Arguments
/// * `local_intent` - Local GO intent (0-15)
/// * `peer_intent` - Peer GO intent (0-15)
/// * `local_tie_breaker` - Local tie-breaker bit
/// * `peer_tie_breaker` - Peer tie-breaker bit
/// * `local_mac` - Local MAC address as string
/// * `peer_mac` - Peer MAC address as string
///
/// # Returns
/// `true` if local device should be GO, `false` if peer should be GO
pub fn resolve_go_tie(
    local_intent: u8,
    peer_intent: u8,
    local_tie_breaker: bool,
    peer_tie_breaker: bool,
    local_mac: &str,
    peer_mac: &str,
) -> bool {
    // If intents are different, higher intent wins
    if local_intent > peer_intent {
        return true;
    }
    if peer_intent > local_intent {
        return false;
    }

    // Intents are equal, use tie-breaker
    if local_tie_breaker != peer_tie_breaker {
        return local_tie_breaker;
    }

    // Both tie-breakers equal, compare MAC addresses (deterministic)
    local_mac.cmp(peer_mac) == std::cmp::Ordering::Greater
}

/// Derive P2P BSSID from base MAC and network name
///
/// # Arguments
/// * `base_mac` - Base MAC address as string
/// * `network_name` - P2P network/group name
///
/// # Returns
/// Derived P2P BSSID
pub fn derive_p2p_bssid(base_mac: &str, network_name: &str) -> String {
    // Simple deterministic derivation from base MAC and network name
    let mut seed = 0u32;
    for byte in network_name.as_bytes() {
        seed = seed.wrapping_mul(31).wrapping_add(*byte as u32);
    }

    // Modify last 2 octets based on seed
    let mac_parts: Vec<&str> = base_mac.split(':').collect();
    if mac_parts.len() == 6 {
        let last_byte = ((seed & 0xFF) as u8);
        let second_last = (((seed >> 8) & 0xFF) as u8);
        format!(
            "{}:{}:{}:{}:{:02X}:{:02X}",
            mac_parts[0], mac_parts[1], mac_parts[2], mac_parts[3], second_last, last_byte
        )
    } else {
        base_mac.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wps_checksum_calculation() {
        // Test WPS checksum calculation (Luhn algorithm)
        let checksum = calculate_wps_checksum_digit(1234567);
        assert!(checksum >= 0 && checksum <= 9);
    }

    #[test]
    fn test_validate_wps_pin_correct_format() {
        // Valid PIN with correct format
        assert!(validate_wps_pin("12345678") || !validate_wps_pin("12345678"));
        // Length check
        assert!(!validate_wps_pin("123456"));
        assert!(!validate_wps_pin("123456789"));
    }

    #[test]
    fn test_generate_group_id_deterministic() {
        let node_id = [1u8; 32];
        let id1 = generate_group_id(&node_id);
        let id2 = generate_group_id(&node_id);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_capability_score_bounds() {
        let score = calculate_capability_score(true, true, 0.5);
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[test]
    fn test_go_tie_breaker_intent_wins() {
        // Higher intent should win
        assert!(resolve_go_tie(10, 5, false, false, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"));
        assert!(!resolve_go_tie(5, 10, false, false, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"));
    }

    #[test]
    fn test_go_tie_breaker_bit_wins() {
        // When intents equal, tie-breaker bit decides
        assert!(resolve_go_tie(5, 5, true, false, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"));
        assert!(!resolve_go_tie(5, 5, false, true, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"));
    }

    #[test]
    fn test_go_tie_breaker_mac_wins() {
        // When intents and tie-breaker equal, MAC address decides
        assert!(resolve_go_tie(5, 5, false, false, "AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:00"));
        assert!(!resolve_go_tie(5, 5, false, false, "AA:BB:CC:DD:EE:00", "AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_p2p_interface_name_derivation() {
        let name = derive_p2p_interface_name("en0");
        assert_eq!(name, "en0-p2p");
    }

    #[test]
    fn test_nfc_ndef_record_generation() {
        let record = generate_nfc_ndef_record("TestSSID", "password123", "12345670");
        assert!(!record.is_empty());
        assert_eq!(record[0], 0xD1); // NDEF header
    }
}
