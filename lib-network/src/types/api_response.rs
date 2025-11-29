use std::collections::HashMap;

/// ZHTP API response structure for native protocol requests
#[derive(Debug, Clone)]
pub struct ZhtpApiResponse {
    pub status: u16,
    pub status_message: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}
