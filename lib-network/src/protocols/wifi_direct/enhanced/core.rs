//! Pure functional algorithms for WiFi Direct enhanced operations
//!
//! These are deterministic, side-effect-free functions suitable for testing

use anyhow::Result;

/// Generate 8-digit WPS PIN with Luhn checksum (deterministic)
pub fn generate_wps_pin_deterministic(base: u32) -> String {
    let pin_7 = format!("{:07}", base % 10_000_000);
    let check_digit = calculate_wps_checksum_digit(&pin_7);
    format!("{}{}", pin_7, check_digit)
}

/// Calculate WPS checksum digit using Luhn algorithm (ISO/IEC 7812-1)
fn calculate_wps_checksum_digit(pin_7digits: &str) -> u32 {
    let mut sum = 0u32;
    for (i, ch) in pin_7digits.chars().enumerate() {
        let mut digit = ch.to_digit(10).unwrap_or(0);
        if i % 2 == 0 {
            digit *= 3;
        }
        sum += digit;
    }
    (10 - (sum % 10)) % 10
}

/// Validate WPS PIN format and checksum
pub fn validate_wps_pin_format(pin: &str) -> bool {
    if pin.len() != 8 {
        return false;
    }

    let pin_7 = &pin[..7];
    let check_digit: u32 = match pin[7..].parse() {
        Ok(d) => d,
        Err(_) => return false,
    };

    if !pin.chars().all(|c| c.is_numeric()) {
        return false;
    }

    calculate_wps_checksum_digit(pin_7) == check_digit
}

/// Parse airport command output
pub fn parse_airport_output(output: &str) -> Option<AirportInfo> {
    let mut info = AirportInfo {
        ssid: None,
        bssid: None,
        channel: None,
        signal_strength: None,
    };

    for line in output.lines() {
        if let Some(ssid_val) = line.strip_prefix("     SSID:") {
            info.ssid = Some(ssid_val.trim().to_string());
        } else if let Some(bssid_val) = line.strip_prefix("     BSSID:") {
            info.bssid = Some(bssid_val.trim().to_string());
        } else if let Some(channel_val) = line.strip_prefix("     channel:") {
            if let Ok(ch) = channel_val.trim().parse::<u16>() {
                info.channel = Some(ch);
            }
        } else if let Some(signal_val) = line.strip_prefix("agrCtlRSSI:") {
            if let Ok(sig) = signal_val.trim().parse::<i16>() {
                info.signal_strength = Some(sig);
            }
        }
    }

    if info.ssid.is_some() || info.bssid.is_some() {
        Some(info)
    } else {
        None
    }
}

/// Derive P2P interface name
pub fn derive_p2p_interface_name(base: &str) -> String {
    format!("{}-p2p", base)
}

/// Frequency to WiFi channel conversion
pub fn frequency_to_channel(frequency: u16) -> Option<u8> {
    match frequency {
        2412 => Some(1),
        2417 => Some(2),
        2422 => Some(3),
        2427 => Some(4),
        2432 => Some(5),
        2437 => Some(6),
        2442 => Some(7),
        2447 => Some(8),
        2452 => Some(9),
        2457 => Some(10),
        2462 => Some(11),
        2467 => Some(12),
        2472 => Some(13),
        2484 => Some(14),
        5180 => Some(36),
        5200 => Some(40),
        5220 => Some(44),
        5240 => Some(48),
        5260 => Some(52),
        5280 => Some(56),
        5300 => Some(60),
        5320 => Some(64),
        5500 => Some(100),
        5520 => Some(104),
        5540 => Some(108),
        5560 => Some(112),
        5580 => Some(116),
        5600 => Some(120),
        5620 => Some(124),
        5640 => Some(128),
        5660 => Some(132),
        5680 => Some(136),
        5700 => Some(140),
        5720 => Some(144),
        5745 => Some(149),
        5765 => Some(153),
        5785 => Some(157),
        5805 => Some(161),
        5825 => Some(165),
        _ => None,
    }
}

/// WiFi Airport info extracted from command output
#[derive(Debug, Clone)]
pub struct AirportInfo {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub channel: Option<u16>,
    pub signal_strength: Option<i16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wps_checksum_valid() {
        let pin = generate_wps_pin_deterministic(12345678);
        assert!(validate_wps_pin_format(&pin));
        assert_eq!(pin.len(), 8);
    }

    #[test]
    fn test_wps_checksum_deterministic() {
        let pin1 = generate_wps_pin_deterministic(87654321);
        let pin2 = generate_wps_pin_deterministic(87654321);
        assert_eq!(pin1, pin2);
    }

    #[test]
    fn test_wps_pin_validation_fails_invalid() {
        assert!(!validate_wps_pin_format("1234567"));
        assert!(!validate_wps_pin_format("123456789"));
        assert!(!validate_wps_pin_format("abcdefgh"));
    }

    #[test]
    fn test_frequency_to_channel_2ghz() {
        assert_eq!(frequency_to_channel(2412), Some(1));
        assert_eq!(frequency_to_channel(2437), Some(6));
        assert_eq!(frequency_to_channel(2462), Some(11));
    }

    #[test]
    fn test_p2p_interface_naming() {
        assert_eq!(derive_p2p_interface_name("en0"), "en0-p2p");
        assert_eq!(derive_p2p_interface_name("wlan0"), "wlan0-p2p");
    }
}
