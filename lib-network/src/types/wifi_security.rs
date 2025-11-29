/// WiFi security types
#[derive(Debug, Clone)]
pub enum WiFiSecurity {
    Open,
    WEP,
    WPA,
    WPA2,
    WPA3,
    Enterprise,
}
