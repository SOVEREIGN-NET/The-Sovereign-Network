//! Parsing helpers for Bluetooth mesh (logs, CLI outputs, JSON-ish payloads).

#[cfg(target_os = "windows")]
use anyhow::anyhow;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use anyhow::Result;

use super::BluetoothMeshProtocol;

impl BluetoothMeshProtocol {
    /// Extract device name from bluetoothctl output
    #[allow(dead_code)]
    pub(crate) fn extract_device_name(output: &str) -> Option<String> {
        for line in output.lines() {
            if line.trim().starts_with("Name:") {
                return Some(line.split("Name:").nth(1)?.trim().to_string());
            }
        }
        None
    }

    /// Extract device name from Windows PowerShell output
    #[allow(dead_code)]
    pub(crate) fn extract_device_name_windows(output: &str) -> Option<String> {
        for line in output.lines() {
            if line.contains("FriendlyName") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    return Some(parts[1..].join(" "));
                }
            }
        }
        None
    }

    /// Extract device name from macOS system_profiler output
    #[allow(dead_code)]
    pub(crate) fn extract_device_name_macos(output: &str, _address: &str) -> Option<String> {
        if let Some(name_start) = output.find("\"_name\"") {
            if let Some(colon_pos) = output[name_start..].find(':') {
                let after_colon = &output[name_start + colon_pos + 1..];
                if let Some(quote_start) = after_colon.find('"') {
                    if let Some(quote_end) = after_colon[quote_start + 1..].find('"') {
                        let name = &after_colon[quote_start + 1..quote_start + 1 + quote_end];
                        return Some(name.to_string());
                    }
                }
            }
        }
        None
    }

    /// Extract services from bluetoothctl output
    #[allow(dead_code)]
    pub(crate) fn extract_services(output: &str) -> Vec<String> {
        let mut services = Vec::new();

        for line in output.lines() {
            if line.trim().starts_with("UUID:") {
                if let Some(uuid_part) = line.split("UUID:").nth(1) {
                    let uuid = uuid_part.trim().split_whitespace().next().unwrap_or("").to_string();
                    if !uuid.is_empty() {
                        services.push(uuid);
                    }
                }
            }
        }

        services
    }

    /// Parse Windows Bluetooth address from string.
    #[cfg(target_os = "windows")]
    pub(crate) fn parse_windows_bluetooth_address(&self, address: &str) -> Result<u64> {
        let clean_address = address.replace(":", "");
        let address_bytes = (0..clean_address.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean_address[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()?;

        if address_bytes.len() != 6 {
            return Err(anyhow!("Invalid Bluetooth address length"));
        }

        let mut address_u64 = 0u64;
        for (i, &byte) in address_bytes.iter().enumerate() {
            address_u64 |= (byte as u64) << (8 * (5 - i));
        }

        Ok(address_u64)
    }

    /// Extract byte array from D-Bus response
    #[cfg(target_os = "linux")]
    pub(crate) fn extract_dbus_byte_array(&self, dbus_response: &str) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();

        if let Some(start) = dbus_response.find('[') {
            if let Some(end) = dbus_response.find(']') {
                let array_content = &dbus_response[start + 1..end];

                for part in array_content.split(',') {
                    if let Some(byte_val) = part.trim().strip_prefix("byte:") {
                        if let Ok(byte) = byte_val.parse::<u8>() {
                            bytes.push(byte);
                        }
                    }
                }
            }
        }

        if bytes.is_empty() {
            None
        } else {
            Some(bytes)
        }
    }

    /// Extract service UUIDs from D-Bus response
    #[cfg(target_os = "linux")]
    pub(crate) fn extract_services_from_dbus(&self, dbus_response: &str) -> Vec<String> {
        let mut services = Vec::new();

        for line in dbus_response.lines() {
            if line.contains("UUID") {
                if let Some(start) = line.find('"') {
                    if let Some(end) = line[start + 1..].find('"') {
                        let uuid = &line[start + 1..start + 1 + end];
                        if uuid.len() >= 8 && uuid.contains('-') {
                            services.push(uuid.to_string());
                        }
                    }
                }
            }
        }

        services
    }

    /// Extract byte array from D-Bus response (regex-based)
    #[cfg(target_os = "linux")]
    pub(crate) fn parse_dbus_byte_array(&self, dbus_output: &str) -> Result<Option<Vec<u8>>> {
        use regex::Regex;

        let array_regex = Regex::new(r"array \\[(.*?)\\]")?;
        let byte_regex = Regex::new(r"byte:(\\d+)")?;

        if let Some(array_match) = array_regex.captures(dbus_output) {
            let array_content = &array_match[1];
            let mut bytes = Vec::new();

            for byte_match in byte_regex.captures_iter(array_content) {
                if let Ok(byte_val) = byte_match[1].parse::<u8>() {
                    bytes.push(byte_val);
                }
            }

            if !bytes.is_empty() {
                return Ok(Some(bytes));
            }
        }

        let variant_regex = Regex::new(r"variant\\s+array\\s+\\[([^\\]]+)\\]")?;
        if let Some(variant_match) = variant_regex.captures(dbus_output) {
            let variant_content = &variant_match[1];
            let mut bytes = Vec::new();

            for byte_str in variant_content.split(',') {
                if let Ok(byte_val) = byte_str.trim().parse::<u8>() {
                    bytes.push(byte_val);
                }
            }

            if !bytes.is_empty() {
                return Ok(Some(bytes));
            }
        }

        Ok(None)
    }

    /// Parse macOS GATT read output for a specific characteristic.
    #[cfg(target_os = "macos")]
    pub(crate) fn parse_macos_gatt_data(
        &self,
        json_output: &str,
        device_address: &str,
        char_uuid: &str,
    ) -> Result<Option<Vec<u8>>> {
        // Naive JSON parsing for now (kept as-is for parity with legacy behavior).
        if !json_output.contains(device_address) || !json_output.contains(char_uuid) {
            return Ok(None);
        }

        if let Some(value_pos) = json_output.find("\"value\"") {
            let after_value = &json_output[value_pos..];
            if let Some(start) = after_value.find('[') {
                if let Some(end) = after_value[start + 1..].find(']') {
                    let list = &after_value[start + 1..start + 1 + end];
                    let bytes = list
                        .split(',')
                        .filter_map(|b| b.trim().parse::<u8>().ok())
                        .collect::<Vec<u8>>();
                    if !bytes.is_empty() {
                        return Ok(Some(bytes));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Extract macOS services from system_profiler output
    pub(crate) fn extract_macos_services(
        &self,
        json_output: &str,
        device_address: &str,
    ) -> Vec<String> {
        if !json_output.contains(device_address) {
            return Vec::new();
        }

        let mut services = Vec::new();
        for line in json_output.lines() {
            if line.contains("UUID") {
                if let Some(start) = line.find('"') {
                    if let Some(end) = line[start + 1..].find('"') {
                        let uuid = &line[start + 1..start + 1 + end];
                        if uuid.len() >= 8 && uuid.contains('-') {
                            services.push(uuid.to_string());
                        }
                    }
                }
            }
        }
        services
    }
}

#[cfg(test)]
mod tests {
    use super::BluetoothMeshProtocol;
    use lib_crypto::KeyPair;

    fn protocol() -> BluetoothMeshProtocol {
        let node_id = [4u8; 32];
        let keypair = KeyPair::generate().unwrap();
        BluetoothMeshProtocol::new(node_id, keypair.public_key).unwrap()
    }

    #[test]
    fn test_extract_device_name() {
        let output = "Name: ZHTP-Node";
        assert_eq!(
            BluetoothMeshProtocol::extract_device_name(output).unwrap(),
            "ZHTP-Node"
        );
    }

    #[test]
    fn test_extract_device_name_windows() {
        let output = "FriendlyName ZHTP Laptop";
        assert_eq!(
            BluetoothMeshProtocol::extract_device_name_windows(output).unwrap(),
            "ZHTP Laptop"
        );
    }

    #[test]
    fn test_extract_services() {
        let output = "UUID: 6ba7b810-9dad-11d1-80b4-00c04fd430ca";
        let services = BluetoothMeshProtocol::extract_services(output);
        assert_eq!(services.len(), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_macos_gatt_data() {
        let proto = protocol();
        let json = r#"{"device":"AA","char":"BB","value":[1,2,3]}"#;
        let data = proto.parse_macos_gatt_data(json, "AA", "BB").unwrap();
        assert_eq!(data.unwrap(), vec![1, 2, 3]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_extract_macos_services() {
        let proto = protocol();
        let json = "Device AA\nUUID \"1234-5678\"\nUUID \"9abc-def0\"";
        let services = proto.extract_macos_services(json, "AA");
        assert_eq!(services.len(), 2);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_windows_bluetooth_address() {
        let proto = protocol();
        let parsed = proto.parse_windows_bluetooth_address("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(parsed, 0xAABBCCDDEEFF);
    }
}
