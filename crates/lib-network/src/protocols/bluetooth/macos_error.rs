// macOS Core Bluetooth Error Handling
// Comprehensive NSError parsing and Core Bluetooth error code mapping

#[cfg(target_os = "macos")]
use objc2::runtime::AnyObject;
#[cfg(target_os = "macos")]
use objc2::{msg_send, sel};
#[cfg(target_os = "macos")]
use anyhow::{anyhow, Result};
#[cfg(target_os = "macos")]
use std::fmt;

/// Core Bluetooth error domain
#[cfg(target_os = "macos")]
pub const CB_ERROR_DOMAIN: &str = "CBErrorDomain";

/// Core Bluetooth ATT error domain
#[cfg(target_os = "macos")]
pub const CB_ATT_ERROR_DOMAIN: &str = "CBATTErrorDomain";

/// Core Bluetooth error codes from CBError enum
/// Reference: https://developer.apple.com/documentation/corebluetooth/cberror/code
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum CBErrorCode {
    /// The connection failed.
    Unknown = 0,
    
    /// The specified parameters are invalid.
    InvalidParameters = 1,
    
    /// The specified attribute handle is invalid.
    InvalidHandle = 2,
    
    /// The device isn't currently connected.
    NotConnected = 3,
    
    /// The device has run out of space to complete the intended operation.
    OutOfSpace = 4,
    
    /// The operation isn't supported.
    OperationCancelled = 5,
    
    /// The connection timed out.
    ConnectionTimeout = 6,
    
    /// The peripheral disconnected.
    PeripheralDisconnected = 7,
    
    /// The specified UUID isn't permitted.
    UUIDNotAllowed = 8,
    
    /// The peripheral is already advertising.
    AlreadyAdvertising = 9,
    
    /// The connection failed because the system rejected it.
    ConnectionFailed = 10,
    
    /// The connection failed due to an internal system limit.
    ConnectionLimitReached = 11,
    
    /// The operation failed.
    OperationNotSupported = 12,
    
    /// The Core Bluetooth manager is still being initialized.
    UnknownDevice = 13,
    
    /// The device has run out of space to complete the intended operation.
    InvalidData = 14,
    
    /// The peer rejected the request.
    PeerRemovedPairingInformation = 15,
    
    /// The connection attempt or operation is already in progress.
    EncryptionTimedOut = 16,
    
    /// The peripheral disconnected.
    TooManyLEPairedDevices = 17,
}

impl CBErrorCode {
    /// Convert from i64 error code
    pub fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(CBErrorCode::Unknown),
            1 => Some(CBErrorCode::InvalidParameters),
            2 => Some(CBErrorCode::InvalidHandle),
            3 => Some(CBErrorCode::NotConnected),
            4 => Some(CBErrorCode::OutOfSpace),
            5 => Some(CBErrorCode::OperationCancelled),
            6 => Some(CBErrorCode::ConnectionTimeout),
            7 => Some(CBErrorCode::PeripheralDisconnected),
            8 => Some(CBErrorCode::UUIDNotAllowed),
            9 => Some(CBErrorCode::AlreadyAdvertising),
            10 => Some(CBErrorCode::ConnectionFailed),
            11 => Some(CBErrorCode::ConnectionLimitReached),
            12 => Some(CBErrorCode::OperationNotSupported),
            13 => Some(CBErrorCode::UnknownDevice),
            14 => Some(CBErrorCode::InvalidData),
            15 => Some(CBErrorCode::PeerRemovedPairingInformation),
            16 => Some(CBErrorCode::EncryptionTimedOut),
            17 => Some(CBErrorCode::TooManyLEPairedDevices),
            _ => None,
        }
    }
    
    /// Get human-readable error message
    pub fn message(&self) -> &'static str {
        match self {
            CBErrorCode::Unknown => "Connection failed due to unknown error",
            CBErrorCode::InvalidParameters => "Invalid parameters provided",
            CBErrorCode::InvalidHandle => "Invalid attribute handle",
            CBErrorCode::NotConnected => "Device is not currently connected",
            CBErrorCode::OutOfSpace => "Out of space to complete operation",
            CBErrorCode::OperationCancelled => "Operation was cancelled",
            CBErrorCode::ConnectionTimeout => "Connection timed out",
            CBErrorCode::PeripheralDisconnected => "Peripheral disconnected",
            CBErrorCode::UUIDNotAllowed => "UUID is not permitted",
            CBErrorCode::AlreadyAdvertising => "Peripheral is already advertising",
            CBErrorCode::ConnectionFailed => "Connection failed",
            CBErrorCode::ConnectionLimitReached => "Connection limit reached",
            CBErrorCode::OperationNotSupported => "Operation is not supported",
            CBErrorCode::UnknownDevice => "Unknown device or system still initializing",
            CBErrorCode::InvalidData => "Invalid data provided",
            CBErrorCode::PeerRemovedPairingInformation => "Peer removed pairing information",
            CBErrorCode::EncryptionTimedOut => "Encryption timed out",
            CBErrorCode::TooManyLEPairedDevices => "Too many BLE paired devices",
        }
    }
}

impl fmt::Display for CBErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

/// Core Bluetooth ATT error codes
/// Reference: https://developer.apple.com/documentation/corebluetooth/cbatterror/code
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum CBATTErrorCode {
    /// The ATT command or request successfully completed.
    Success = 0x00,
    
    /// The attribute handle is invalid on this peripheral.
    InvalidHandle = 0x01,
    
    /// The permissions prohibit reading the attribute's value.
    ReadNotPermitted = 0x02,
    
    /// The permissions prohibit writing the attribute's value.
    WriteNotPermitted = 0x03,
    
    /// The attribute Protocol Data Unit (PDU) is invalid.
    InvalidPdu = 0x04,
    
    /// Reading or writing the attribute's value failed for lack of authentication.
    InsufficientAuthentication = 0x05,
    
    /// The attribute server doesn't support the request received from the client.
    RequestNotSupported = 0x06,
    
    /// The specified offset value was past the end of the attribute's value.
    InvalidOffset = 0x07,
    
    /// Reading or writing the attribute's value failed for lack of authorization.
    InsufficientAuthorization = 0x08,
    
    /// The prepare queue is full, as a result of there being too many write requests in the queue.
    PrepareQueueFull = 0x09,
    
    /// The attribute wasn't found within the specified attribute handle range.
    AttributeNotFound = 0x0A,
    
    /// The ATT read blob request can't read or write the attribute.
    AttributeNotLong = 0x0B,
    
    /// The encryption key size used for encrypting this link is insufficient.
    InsufficientEncryptionKeySize = 0x0C,
    
    /// The length of the attribute's value is invalid for the intended operation.
    InvalidAttributeValueLength = 0x0D,
    
    /// The ATT request encountered an unlikely error and wasn't completed.
    UnlikelyError = 0x0E,
    
    /// Reading or writing the attribute's value failed for lack of encryption.
    InsufficientEncryption = 0x0F,
    
    /// The attribute type isn't a supported grouping attribute as defined by a higher-layer specification.
    UnsupportedGroupType = 0x10,
    
    /// Resources are insufficient to complete the ATT request.
    InsufficientResources = 0x11,
}

impl CBATTErrorCode {
    /// Convert from i64 error code
    pub fn from_code(code: i64) -> Option<Self> {
        match code {
            0x00 => Some(CBATTErrorCode::Success),
            0x01 => Some(CBATTErrorCode::InvalidHandle),
            0x02 => Some(CBATTErrorCode::ReadNotPermitted),
            0x03 => Some(CBATTErrorCode::WriteNotPermitted),
            0x04 => Some(CBATTErrorCode::InvalidPdu),
            0x05 => Some(CBATTErrorCode::InsufficientAuthentication),
            0x06 => Some(CBATTErrorCode::RequestNotSupported),
            0x07 => Some(CBATTErrorCode::InvalidOffset),
            0x08 => Some(CBATTErrorCode::InsufficientAuthorization),
            0x09 => Some(CBATTErrorCode::PrepareQueueFull),
            0x0A => Some(CBATTErrorCode::AttributeNotFound),
            0x0B => Some(CBATTErrorCode::AttributeNotLong),
            0x0C => Some(CBATTErrorCode::InsufficientEncryptionKeySize),
            0x0D => Some(CBATTErrorCode::InvalidAttributeValueLength),
            0x0E => Some(CBATTErrorCode::UnlikelyError),
            0x0F => Some(CBATTErrorCode::InsufficientEncryption),
            0x10 => Some(CBATTErrorCode::UnsupportedGroupType),
            0x11 => Some(CBATTErrorCode::InsufficientResources),
            _ => None,
        }
    }
    
    /// Get human-readable error message
    pub fn message(&self) -> &'static str {
        match self {
            CBATTErrorCode::Success => "Success",
            CBATTErrorCode::InvalidHandle => "Invalid attribute handle",
            CBATTErrorCode::ReadNotPermitted => "Read not permitted",
            CBATTErrorCode::WriteNotPermitted => "Write not permitted",
            CBATTErrorCode::InvalidPdu => "Invalid PDU",
            CBATTErrorCode::InsufficientAuthentication => "Insufficient authentication",
            CBATTErrorCode::RequestNotSupported => "Request not supported",
            CBATTErrorCode::InvalidOffset => "Invalid offset",
            CBATTErrorCode::InsufficientAuthorization => "Insufficient authorization",
            CBATTErrorCode::PrepareQueueFull => "Prepare queue full",
            CBATTErrorCode::AttributeNotFound => "Attribute not found",
            CBATTErrorCode::AttributeNotLong => "Attribute not long",
            CBATTErrorCode::InsufficientEncryptionKeySize => "Insufficient encryption key size",
            CBATTErrorCode::InvalidAttributeValueLength => "Invalid attribute value length",
            CBATTErrorCode::UnlikelyError => "Unlikely error occurred",
            CBATTErrorCode::InsufficientEncryption => "Insufficient encryption",
            CBATTErrorCode::UnsupportedGroupType => "Unsupported group type",
            CBATTErrorCode::InsufficientResources => "Insufficient resources",
        }
    }
}

impl fmt::Display for CBATTErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

/// Parsed NSError information
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct NSErrorInfo {
    /// Error domain (e.g., "CBErrorDomain", "CBATTErrorDomain")
    pub domain: String,
    
    /// Error code as integer
    pub code: i64,
    
    /// Localized description from NSError
    pub localized_description: String,
    
    /// Parsed CB error code (if from CBErrorDomain)
    pub cb_error: Option<CBErrorCode>,
    
    /// Parsed ATT error code (if from CBATTErrorDomain)
    pub att_error: Option<CBATTErrorCode>,
}

impl NSErrorInfo {
    /// Create a user-friendly error message
    pub fn to_error_message(&self) -> String {
        if let Some(cb_error) = &self.cb_error {
            format!("Core Bluetooth Error: {} (code: {}, domain: {})", 
                    cb_error.message(), self.code, self.domain)
        } else if let Some(att_error) = &self.att_error {
            format!("ATT Error: {} (code: 0x{:02X}, domain: {})", 
                    att_error.message(), self.code, self.domain)
        } else {
            format!("Error: {} (code: {}, domain: {})", 
                    self.localized_description, self.code, self.domain)
        }
    }
    
    /// Convert to anyhow Result error
    pub fn into_result<T>(self) -> Result<T> {
        Err(anyhow!(self.to_error_message()))
    }
}

impl fmt::Display for NSErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_error_message())
    }
}

impl std::error::Error for NSErrorInfo {}

/// Parse NSError object into structured error information
/// 
/// # Safety
/// The error pointer must be a valid NSError object or null
#[cfg(target_os = "macos")]
pub unsafe fn parse_nserror(error: *mut AnyObject) -> Option<NSErrorInfo> {
    if error.is_null() {
        return None;
    }
    
    // Extract error code
    let code: i64 = msg_send![error, code];
    
    // Extract error domain
    let domain_obj: *mut AnyObject = msg_send![error, domain];
    let domain = if !domain_obj.is_null() {
        let domain_cstr: *const i8 = msg_send![domain_obj, UTF8String];
        std::ffi::CStr::from_ptr(domain_cstr).to_string_lossy().to_string()
    } else {
        "Unknown".to_string()
    };
    
    // Extract localized description
    let desc_obj: *mut AnyObject = msg_send![error, localizedDescription];
    let localized_description = if !desc_obj.is_null() {
        let desc_cstr: *const i8 = msg_send![desc_obj, UTF8String];
        std::ffi::CStr::from_ptr(desc_cstr).to_string_lossy().to_string()
    } else {
        "No description available".to_string()
    };
    
    // Parse specific error codes based on domain
    let cb_error = if domain == CB_ERROR_DOMAIN {
        CBErrorCode::from_code(code)
    } else {
        None
    };
    
    let att_error = if domain == CB_ATT_ERROR_DOMAIN {
        CBATTErrorCode::from_code(code)
    } else {
        None
    };
    
    Some(NSErrorInfo {
        domain,
        code,
        localized_description,
        cb_error,
        att_error,
    })
}

/// Parse NSError and convert to anyhow Result
/// Returns Ok(()) if error is null, Err with parsed error info otherwise
/// 
/// # Safety
/// The error pointer must be a valid NSError object or null
#[cfg(target_os = "macos")]
pub unsafe fn check_nserror(error: *mut AnyObject) -> Result<()> {
    if let Some(error_info) = parse_nserror(error) {
        error_info.into_result()
    } else {
        Ok(())
    }
}

/// Parse NSError and log it with appropriate level
/// Returns true if error was present, false if null
/// 
/// # Safety
/// The error pointer must be a valid NSError object or null
#[cfg(target_os = "macos")]
pub unsafe fn log_nserror(error: *mut AnyObject, context: &str) -> bool {
    if let Some(error_info) = parse_nserror(error) {
        use tracing::error;
        error!(" {} - {}", context, error_info.to_error_message());
        true
    } else {
        false
    }
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;
    
    #[test]
    fn test_cb_error_code_mapping() {
        assert_eq!(CBErrorCode::from_code(0), Some(CBErrorCode::Unknown));
        assert_eq!(CBErrorCode::from_code(3), Some(CBErrorCode::NotConnected));
        assert_eq!(CBErrorCode::from_code(6), Some(CBErrorCode::ConnectionTimeout));
        assert_eq!(CBErrorCode::from_code(999), None);
    }
    
    #[test]
    fn test_att_error_code_mapping() {
        assert_eq!(CBATTErrorCode::from_code(0x01), Some(CBATTErrorCode::InvalidHandle));
        assert_eq!(CBATTErrorCode::from_code(0x02), Some(CBATTErrorCode::ReadNotPermitted));
        assert_eq!(CBATTErrorCode::from_code(0x0F), Some(CBATTErrorCode::InsufficientEncryption));
        assert_eq!(CBATTErrorCode::from_code(0xFF), None);
    }
    
    #[test]
    fn test_error_messages() {
        let cb_error = CBErrorCode::NotConnected;
        assert_eq!(cb_error.message(), "Device is not currently connected");
        
        let att_error = CBATTErrorCode::ReadNotPermitted;
        assert_eq!(att_error.message(), "Read not permitted");
    }
    
    #[test]
    fn test_error_info_display() {
        let error_info = NSErrorInfo {
            domain: CB_ERROR_DOMAIN.to_string(),
            code: 3,
            localized_description: "Not connected".to_string(),
            cb_error: Some(CBErrorCode::NotConnected),
            att_error: None,
        };
        
        let message = error_info.to_error_message();
        assert!(message.contains("Device is not currently connected"));
        assert!(message.contains("CBErrorDomain"));
    }
}
