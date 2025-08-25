use anyhow::{Result, anyhow};
use std::net::IpAddr;

use crate::errors::{ZhtpError, ZhtpResult};

/// Validation context for enhanced security checks
#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub user_agent: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
}

/// Comprehensive input validation utilities for ZHTP
#[derive(Debug)]
pub struct InputValidator;

impl InputValidator {
    /// Create new input validator
    pub fn new() -> Self {
        Self
    }

    /// Maximum lengths for various input types
    const MAX_NODE_ID_LENGTH: usize = 64;
    const MAX_CONTENT_LENGTH: usize = 10_000_000; // 10MB
    const MAX_TAG_LENGTH: usize = 100;
    const MAX_TAGS_COUNT: usize = 20;
    const MAX_DOMAIN_LENGTH: usize = 253;
    const MAX_CONTENT_TYPE_LENGTH: usize = 100;
    const _MAX_SEARCH_RESULTS: usize = 1000;
    const MAX_SEARCH_QUERY_LENGTH: usize = 200;

    /// Validate node identifier
    pub fn validate_node_id(id: &str) -> Result<()> {
        if id.is_empty() {
            return Err(anyhow!("Node ID cannot be empty"));
        }
        
        if id.len() > Self::MAX_NODE_ID_LENGTH {
            return Err(anyhow!("Node ID too long (max {} characters)", Self::MAX_NODE_ID_LENGTH));
        }
        
        // Only allow alphanumeric, hyphens, and underscores
        if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow!("Node ID contains invalid characters (only alphanumeric, -, _ allowed)"));
        }
        
        // Prevent common attack patterns
        if id.contains("..") || id.starts_with('-') || id.ends_with('-') {
            return Err(anyhow!("Node ID contains invalid patterns"));
        }
        
        Ok(())
    }

    /// Validate and sanitize content input
    pub fn validate_content(content: &[u8]) -> Result<()> {
        if content.is_empty() {
            return Err(anyhow!("Content cannot be empty"));
        }
        
        if content.len() > Self::MAX_CONTENT_LENGTH {
            return Err(anyhow!("Content too large (max {} bytes)", Self::MAX_CONTENT_LENGTH));
        }
        
        // Check for null bytes and other problematic characters
        if content.contains(&0) {
            return Err(anyhow!("Content contains null bytes"));
        }
        
        Ok(())
    }

    /// Validate content type
    pub fn validate_content_type(content_type: &str) -> Result<()> {
        if content_type.is_empty() {
            return Err(anyhow!("Content type cannot be empty"));
        }
        
        if content_type.len() > Self::MAX_CONTENT_TYPE_LENGTH {
            return Err(anyhow!("Content type too long"));
        }
        
        // Basic MIME type validation
        if !content_type.contains('/') {
            return Err(anyhow!("Invalid content type format"));
        }
        
        // Prevent injection attacks
        if content_type.contains('\n') || content_type.contains('\r') {
            return Err(anyhow!("Content type contains invalid characters"));
        }
        
        Ok(())
    }

    /// Validate tags input
    pub fn validate_tags(tags: &Option<Vec<String>>) -> Result<()> {
        if let Some(tag_list) = tags {
            if tag_list.len() > Self::MAX_TAGS_COUNT {
                return Err(anyhow!("Too many tags (max {})", Self::MAX_TAGS_COUNT));
            }
            
            for tag in tag_list {
                if tag.is_empty() {
                    return Err(anyhow!("Tag cannot be empty"));
                }
                
                if tag.len() > Self::MAX_TAG_LENGTH {
                    return Err(anyhow!("Tag too long (max {} characters)", Self::MAX_TAG_LENGTH));
                }
                
                // Only allow alphanumeric, hyphens, and underscores for tags
                if !tag.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                    return Err(anyhow!("Tag '{}' contains invalid characters", tag));
                }
                
                // Prevent XSS and injection attempts
                if tag.contains('<') || tag.contains('>') || tag.contains('"') || tag.contains('\'') {
                    return Err(anyhow!("Tag '{}' contains potentially dangerous characters", tag));
                }
            }
        }
        
        Ok(())
    }

    /// Validate domain name
    pub fn validate_domain(domain: &str) -> Result<()> {
        if domain.is_empty() {
            return Err(anyhow!("Domain cannot be empty"));
        }
        
        if domain.len() > Self::MAX_DOMAIN_LENGTH {
            return Err(anyhow!("Domain too long"));
        }
        
        // Check for basic domain format
        if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
            return Err(anyhow!("Invalid domain format"));
        }
        
        // Check for valid characters (letters, digits, hyphens, dots)
        if !domain.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '.') {
            return Err(anyhow!("Domain contains invalid characters"));
        }
        
        // Must contain at least one dot (TLD requirement)
        if !domain.contains('.') {
            return Err(anyhow!("Domain must contain a valid TLD"));
        }
        
        Ok(())
    }

    /// Validate numeric input within range
    pub fn validate_numeric_input(input: &str, min: u64, max: u64) -> Result<u64> {
        if input.is_empty() {
            return Err(anyhow!("Numeric input cannot be empty"));
        }
        
        // Remove whitespace
        let trimmed = input.trim();
        
        // Parse as number
        let value = trimmed.parse::<u64>()
            .map_err(|_| anyhow!("Invalid numeric format: '{}'", input))?;
        
        // Check range
        if value < min || value > max {
            return Err(anyhow!("Value {} out of range (must be {}-{})", value, min, max));
        }
        
        Ok(value)
    }

    /// Validate search query
    pub fn validate_search_query(query: &str) -> Result<()> {
        if query.is_empty() {
            return Err(anyhow!("Search query cannot be empty"));
        }
        
        if query.len() > Self::MAX_SEARCH_QUERY_LENGTH {
            return Err(anyhow!("Search query too long (max {} characters)", Self::MAX_SEARCH_QUERY_LENGTH));
        }
        
        // Check for injection attacks
        let dangerous_patterns = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
            "<script", "</script>", "javascript:", "onload=", "onerror=",
            "../", "..\\", "/etc/passwd", "cmd.exe", "powershell",
        ];
        
        let query_lower = query.to_lowercase();
        for pattern in &dangerous_patterns {
            if query_lower.contains(&pattern.to_lowercase()) {
                return Err(anyhow!("Search query contains potentially dangerous pattern: {}", pattern));
            }
        }
        
        Ok(())
    }

    /// Sanitize input by removing or escaping dangerous characters
    pub fn sanitize_input(input: &str) -> String {
        input
            .chars()
            .filter(|&c| c.is_ascii() && !c.is_control() || c == '\n' || c == '\t')
            .collect::<String>()
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
            .replace('&', "&amp;")
    }

    /// Validate storage capacity
    pub fn validate_storage_capacity(capacity: u64) -> Result<()> {
        const MIN_CAPACITY: u64 = 1024 * 1024; // 1MB minimum
        const MAX_CAPACITY: u64 = 1024 * 1024 * 1024 * 1024; // 1TB maximum
        
        if capacity < MIN_CAPACITY {
            return Err(anyhow!("Storage capacity too small (minimum {} bytes)", MIN_CAPACITY));
        }
        
        if capacity > MAX_CAPACITY {
            return Err(anyhow!("Storage capacity too large (maximum {} bytes)", MAX_CAPACITY));
        }
        
        Ok(())
    }

    /// Validate socket address
    pub fn validate_socket_addr(addr_str: &str) -> Result<()> {
        addr_str.parse::<std::net::SocketAddr>()
            .map_err(|_| anyhow!("Invalid socket address format: {}", addr_str))?;
        Ok(())
    }

    /// Validate username for authentication
    pub fn validate_username(&self, username: &str, _context: &ValidationContext) -> ZhtpResult<()> {
        if username.is_empty() {
            return Err(ZhtpError::ValidationFailed("Username cannot be empty".to_string()));
        }
        
        if username.len() < 3 || username.len() > 32 {
            return Err(ZhtpError::ValidationFailed("Username must be 3-32 characters".to_string()));
        }
        
        // Only allow alphanumeric and underscore
        if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(ZhtpError::ValidationFailed("Username contains invalid characters".to_string()));
        }
        
        // Prevent reserved usernames
        let reserved = ["admin", "root", "system", "test", "guest", "anonymous"];
        if reserved.contains(&username.to_lowercase().as_str()) {
            return Err(ZhtpError::ValidationFailed("Username is reserved".to_string()));
        }
        
        Ok(())
    }

    /// Validate password strength
    pub fn validate_password(&self, password: &str) -> ZhtpResult<()> {
        if password.len() < 8 {
            return Err(ZhtpError::ValidationFailed("Password must be at least 8 characters".to_string()));
        }
        
        if password.len() > 128 {
            return Err(ZhtpError::ValidationFailed("Password is too long".to_string()));
        }
        
        // Check for various character types
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_digit(10));
        let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));
        
        let character_types = [has_lowercase, has_uppercase, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();
            
        if character_types < 3 {
            return Err(ZhtpError::ValidationFailed("Password must contain at least 3 of: lowercase, uppercase, digit, special character".to_string()));
        }
        
        // Check for common patterns
        if password.to_lowercase().contains("password") || 
           password.to_lowercase().contains("admin") ||
           password == "12345678" {
            return Err(ZhtpError::ValidationFailed("Password contains common patterns".to_string()));
        }
        
        Ok(())
    }

    /// Validate blockchain address
    pub fn validate_address(&self, address: &str, _context: &ValidationContext) -> ZhtpResult<()> {
        if address.is_empty() {
            return Err(ZhtpError::ValidationFailed("Address cannot be empty".to_string()));
        }
        
        if address.len() < 20 || address.len() > 100 {
            return Err(ZhtpError::ValidationFailed("Address length must be 20-100 characters".to_string()));
        }
        
        // Basic format validation (could be enhanced for specific address formats)
        if !address.chars().all(|c| c.is_alphanumeric()) {
            return Err(ZhtpError::ValidationFailed("Address contains invalid characters".to_string()));
        }
        
        Ok(())
    }
}

/// Input validation for CLI interface
pub struct CliValidator;

impl CliValidator {
    /// Read and validate user choice from a menu
    pub fn read_menu_choice(prompt: &str, max_choice: u32) -> Result<u32> {
        print!("{}", prompt);
        std::io::Write::flush(&mut std::io::stdout())?;
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        
        let choice = InputValidator::validate_numeric_input(input.trim(), 1, max_choice as u64)? as u32;
        Ok(choice)
    }

    /// Read and validate text input
    pub fn read_text_input(prompt: &str, max_length: usize, allow_empty: bool) -> Result<String> {
        print!("{}", prompt);
        std::io::Write::flush(&mut std::io::stdout())?;
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        if !allow_empty && input.is_empty() {
            return Err(anyhow!("Input cannot be empty"));
        }
        
        if input.len() > max_length {
            return Err(anyhow!("Input too long (max {} characters)", max_length));
        }
        
        Ok(InputValidator::sanitize_input(input))
    }

    /// Read and validate tags input
    pub fn read_tags_input(prompt: &str) -> Result<Option<Vec<String>>> {
        let input = Self::read_text_input(prompt, 500, true)?;
        
        if input.is_empty() {
            return Ok(None);
        }
        
        let tags: Vec<String> = input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        
        InputValidator::validate_tags(&Some(tags.clone()))?;
        Ok(Some(tags))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_validation() {
        let context = ValidationContext {
            user_agent: None,
            ip_address: None,
            user_id: None,
            session_id: None,
        };
        
        let validator = InputValidator::new();
        
        // Valid usernames
        assert!(validator.validate_username("user123", &context).is_ok());
        assert!(validator.validate_username("test_user", &context).is_ok());
        
        // Invalid usernames
        assert!(validator.validate_username("", &context).is_err()); // Empty
        assert!(validator.validate_username("ab", &context).is_err()); // Too short
        assert!(validator.validate_username("admin", &context).is_err()); // Reserved
    }

    #[test]
    fn test_password_validation() {
        let validator = InputValidator::new();
        
        // Valid passwords
        assert!(validator.validate_password("Password123!").is_ok());
        assert!(validator.validate_password("MySecure@Pass1").is_ok());
        
        // Invalid passwords
        assert!(validator.validate_password("short").is_err()); // Too short
        assert!(validator.validate_password("password123").is_err()); // Common pattern
        assert!(validator.validate_password("PASSWORD123").is_err()); // Missing character type
    }

    #[test]
    fn test_address_validation() {
        let context = ValidationContext {
            user_agent: None,
            ip_address: None,
            user_id: None,
            session_id: None,
        };
        
        let validator = InputValidator::new();
        
        // Valid addresses
        assert!(validator.validate_address("1234567890abcdef1234567890abcdef12345678", &context).is_ok());
        
        // Invalid addresses
        assert!(validator.validate_address("", &context).is_err()); // Empty
        assert!(validator.validate_address("short", &context).is_err()); // Too short
        assert!(validator.validate_address("invalid@address", &context).is_err()); // Invalid chars
    }

    #[test]
    fn test_node_id_validation() {
        // Valid node IDs
        assert!(InputValidator::validate_node_id("node-123").is_ok());
        assert!(InputValidator::validate_node_id("test_node_01").is_ok());
        
        // Invalid node IDs
        assert!(InputValidator::validate_node_id("").is_err()); // Empty
        assert!(InputValidator::validate_node_id("-invalid").is_err()); // Starts with dash
        assert!(InputValidator::validate_node_id("node..test").is_err()); // Double dots
    }

    #[test]
    fn test_domain_validation() {
        // Valid domains
        assert!(InputValidator::validate_domain("example.com").is_ok());
        assert!(InputValidator::validate_domain("sub.example.org").is_ok());
        assert!(InputValidator::validate_domain("test-site.co.uk").is_ok());
        
        // Invalid domains
        assert!(InputValidator::validate_domain("").is_err()); // Empty
        assert!(InputValidator::validate_domain(".example.com").is_err()); // Leading dot
        assert!(InputValidator::validate_domain("example..com").is_err()); // Double dots
        assert!(InputValidator::validate_domain("invalid_domain").is_err()); // No TLD
    }

    #[test]
    fn test_search_query_validation() {
        // Valid search queries
        assert!(InputValidator::validate_search_query("blockchain").is_ok());
        assert!(InputValidator::validate_search_query("smart contracts").is_ok());
        assert!(InputValidator::validate_search_query("simple search").is_ok());
        
        // Invalid queries
        assert!(InputValidator::validate_search_query("SELECT * FROM").is_err()); // SQL injection
        assert!(InputValidator::validate_search_query("<script>alert()</script>").is_err()); // XSS
        assert!(InputValidator::validate_search_query("../../../etc/passwd").is_err()); // Path traversal
    }
}
