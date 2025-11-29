# Authentication Module

Password-based authentication system for imported identities with secure session management.

## Overview

The authentication module provides password-based signin functionality for identities that have been imported using 20-word seed phrases. It implements secure password hashing, session management, and multi-factor authentication support.

## Core Components

### PasswordManager

Manages password authentication for imported identities.

```rust
pub struct PasswordManager {
    imported_identities: HashSet<IdentityId>,
    password_hashes: HashMap<IdentityId, PasswordHash>,
}
```

**Key Features:**
- Only works with imported identities (requires 20-word seed phrase import)
- Uses lib-crypto BLAKE3 hashing and key derivation
- Secure salt generation and storage
- Constant-time comparison to prevent timing attacks
- Automatic memory cleanup with zeroization

### SessionToken

Represents an authenticated session with cryptographic verification.

```rust
pub struct SessionToken {
    pub token: String,
    pub identity_id: IdentityId,
    pub created_at: u64,
    pub expires_at: u64,
}
```

## Password Management

### Setting Up Password Authentication

```rust
use lib_identity::auth::{PasswordManager, PasswordError};

let mut password_manager = PasswordManager::new();

// First, mark identity as imported (required for password auth)
password_manager.mark_identity_imported(&identity_id);

// Set password (requires identity seed from 20-word phrase)
password_manager.set_password(
    &identity_id,
    "secure_password_123",
    &identity_seed_bytes
)?;

println!("Password set for imported identity");
```

### Password Validation

```rust
use lib_identity::auth::{PasswordManager, PasswordValidation};

// Validate password during signin
let validation_result = password_manager.validate_password(
    &identity_id,
    "user_entered_password",
    &identity_seed_bytes
)?;

match validation_result.is_valid {
    true => {
        println!("Password validation successful");
        println!("Strength score: {}", validation_result.strength_score);
    },
    false => {
        println!("Password validation failed");
        for warning in &validation_result.security_warnings {
            println!("Security warning: {}", warning);
        }
    }
}
```

### Password Security Requirements

```rust
use lib_identity::auth::PasswordManager;

// Check password requirements before setting
fn validate_password_requirements(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }
    
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("Password must contain uppercase letters".to_string());
    }
    
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err("Password must contain lowercase letters".to_string());
    }
    
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain numbers".to_string());
    }
    
    if !password.chars().any(|c| "!@#$%^&*()".contains(c)) {
        return Err("Password must contain special characters".to_string());
    }
    
    Ok(())
}

// Example usage
match validate_password_requirements("MySecure123!") {
    Ok(()) => {
        // Password meets requirements
        password_manager.set_password(&identity_id, "MySecure123!", &seed)?;
    },
    Err(message) => {
        println!("Password requirement not met: {}", message);
    }
}
```

## Session Management

### Creating Sessions

```rust
use lib_identity::auth::{SessionToken, PasswordManager};
use std::time::{SystemTime, UNIX_EPOCH};

// Create session after successful password validation
fn create_authenticated_session(
    password_manager: &PasswordManager,
    identity_id: &IdentityId,
    password: &str,
    identity_seed: &[u8],
) -> Result<SessionToken, PasswordError> {
    // Validate password first
    let validation = password_manager.validate_password(identity_id, password, identity_seed)?;
    
    if !validation.is_valid {
        return Err(PasswordError::InvalidPassword);
    }
    
    // Create session token
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let session_token = SessionToken {
        token: generate_secure_token(),
        identity_id: identity_id.clone(),
        created_at: current_time,
        expires_at: current_time + 3600, // 1 hour
    };
    
    Ok(session_token)
}

fn generate_secure_token() -> String {
    use lib_crypto::random::secure_random_bytes;
    hex::encode(secure_random_bytes::<32>().unwrap())
}
```

### Session Validation

```rust
use lib_identity::auth::SessionToken;
use std::time::{SystemTime, UNIX_EPOCH};

impl SessionToken {
    pub fn is_valid(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        current_time < self.expires_at
    }
    
    pub fn time_remaining(&self) -> Option<u64> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if current_time < self.expires_at {
            Some(self.expires_at - current_time)
        } else {
            None
        }
    }
    
    pub fn extend_session(&mut self, extension_seconds: u64) {
        self.expires_at += extension_seconds;
    }
}

// Example session management
let mut session = create_authenticated_session(&password_manager, &identity_id, password, &seed)?;

if session.is_valid() {
    println!("Session valid for {} seconds", session.time_remaining().unwrap());
    
    // Extend session if needed
    session.extend_session(1800); // Add 30 minutes
    println!("Session extended");
} else {
    println!("Session expired, reauthentication required");
}
```

## Advanced Authentication Features

### Multi-Factor Authentication Setup

```rust
use lib_identity::auth::{PasswordManager, MfaMethod, MfaToken};

struct AdvancedAuthManager {
    password_manager: PasswordManager,
    mfa_methods: HashMap<IdentityId, Vec<MfaMethod>>,
}

impl AdvancedAuthManager {
    pub fn setup_mfa(
        &mut self,
        identity_id: &IdentityId,
        mfa_method: MfaMethod,
    ) -> Result<String, String> {
        // Verify identity is imported and has password
        if !self.password_manager.is_identity_imported(identity_id) {
            return Err("Identity not imported".to_string());
        }
        
        if !self.password_manager.has_password(identity_id) {
            return Err("Password not set".to_string());
        }
        
        // Add MFA method
        self.mfa_methods
            .entry(identity_id.clone())
            .or_insert_with(Vec::new)
            .push(mfa_method);
        
        Ok("MFA method added successfully".to_string())
    }
    
    pub fn authenticate_with_mfa(
        &self,
        identity_id: &IdentityId,
        password: &str,
        identity_seed: &[u8],
        mfa_token: &str,
    ) -> Result<SessionToken, String> {
        // First factor: password
        let password_validation = self.password_manager
            .validate_password(identity_id, password, identity_seed)
            .map_err(|e| format!("Password validation failed: {:?}", e))?;
        
        if !password_validation.is_valid {
            return Err("Invalid password".to_string());
        }
        
        // Second factor: MFA
        if let Some(mfa_methods) = self.mfa_methods.get(identity_id) {
            let mfa_valid = self.validate_mfa_token(mfa_methods, mfa_token)?;
            if !mfa_valid {
                return Err("Invalid MFA token".to_string());
            }
        }
        
        // Create session with MFA flag
        self.create_mfa_session(identity_id)
    }
    
    fn validate_mfa_token(&self, mfa_methods: &[MfaMethod], token: &str) -> Result<bool, String> {
        // Implementation would validate TOTP, SMS, hardware token, etc.
        // For demo purposes:
        Ok(token.len() == 6 && token.chars().all(|c| c.is_ascii_digit()))
    }
    
    fn create_mfa_session(&self, identity_id: &IdentityId) -> Result<SessionToken, String> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Ok(SessionToken {
            token: generate_secure_token(),
            identity_id: identity_id.clone(),
            created_at: current_time,
            expires_at: current_time + 7200, // 2 hours for MFA sessions
        })
    }
}

#[derive(Debug, Clone)]
pub enum MfaMethod {
    Totp, // Time-based One-Time Password
    Sms,  // SMS verification
    HardwareToken, // Hardware security key
    Biometric, // Biometric verification
}
```

### Password Reset and Recovery

```rust
use lib_identity::auth::{PasswordManager, PasswordError};
use lib_identity::recovery::RecoveryPhraseManager;

struct PasswordRecoveryManager {
    password_manager: PasswordManager,
    recovery_manager: RecoveryPhraseManager,
}

impl PasswordRecoveryManager {
    pub fn initiate_password_reset(
        &self,
        identity_id: &IdentityId,
        recovery_phrase: &str,
    ) -> Result<String, String> {
        // Verify recovery phrase
        let recovery_valid = self.recovery_manager
            .verify_recovery_phrase(identity_id, recovery_phrase)
            .map_err(|e| format!("Recovery verification failed: {:?}", e))?;
        
        if !recovery_valid {
            return Err("Invalid recovery phrase".to_string());
        }
        
        // Generate password reset token
        let reset_token = generate_secure_token();
        
        // Store reset token with expiration (implementation would use secure storage)
        println!("Password reset initiated for identity: {}", identity_id.0);
        println!("Reset token: {} (expires in 15 minutes)", reset_token);
        
        Ok(reset_token)
    }
    
    pub fn complete_password_reset(
        &mut self,
        identity_id: &IdentityId,
        reset_token: &str,
        new_password: &str,
        identity_seed: &[u8],
    ) -> Result<(), String> {
        // Verify reset token (implementation would check secure storage)
        if reset_token.len() != 64 {
            return Err("Invalid reset token".to_string());
        }
        
        // Validate new password requirements
        validate_password_requirements(new_password)
            .map_err(|e| format!("Password requirements not met: {}", e))?;
        
        // Set new password
        self.password_manager
            .set_password(identity_id, new_password, identity_seed)
            .map_err(|e| format!("Failed to set new password: {:?}", e))?;
        
        println!("Password reset completed successfully");
        Ok(())
    }
}
```

## Security Considerations

### Cryptographic Security

The authentication module implements several security measures:

- **BLAKE3 Hashing**: Uses lib-crypto's BLAKE3 for password hashing
- **Key Derivation**: Secure key derivation from identity seeds
- **Salt Generation**: Cryptographically secure salt for each password
- **Constant-Time Comparison**: Prevents timing attacks during validation
- **Memory Safety**: Automatic zeroization of sensitive data

### Attack Prevention

```rust
use lib_identity::auth::{PasswordManager, PasswordError};
use std::time::{Duration, Instant};
use std::collections::HashMap;

struct SecurityManager {
    password_manager: PasswordManager,
    failed_attempts: HashMap<IdentityId, Vec<Instant>>,
    locked_accounts: HashMap<IdentityId, Instant>,
}

impl SecurityManager {
    const MAX_ATTEMPTS: usize = 5;
    const LOCKOUT_DURATION: Duration = Duration::from_secs(900); // 15 minutes
    const ATTEMPT_WINDOW: Duration = Duration::from_secs(300); // 5 minutes
    
    pub fn secure_password_validation(
        &mut self,
        identity_id: &IdentityId,
        password: &str,
        identity_seed: &[u8],
    ) -> Result<bool, String> {
        // Check if account is locked
        if self.is_account_locked(identity_id) {
            return Err("Account temporarily locked due to failed attempts".to_string());
        }
        
        // Attempt password validation
        let validation_result = self.password_manager
            .validate_password(identity_id, password, identity_seed);
        
        match validation_result {
            Ok(validation) => {
                if validation.is_valid {
                    // Clear failed attempts on successful login
                    self.failed_attempts.remove(identity_id);
                    Ok(true)
                } else {
                    // Record failed attempt
                    self.record_failed_attempt(identity_id);
                    Ok(false)
                }
            },
            Err(PasswordError::InvalidPassword) => {
                self.record_failed_attempt(identity_id);
                Ok(false)
            },
            Err(e) => Err(format!("Authentication error: {:?}", e)),
        }
    }
    
    fn is_account_locked(&mut self, identity_id: &IdentityId) -> bool {
        if let Some(locked_until) = self.locked_accounts.get(identity_id) {
            if Instant::now() < *locked_until {
                return true; // Still locked
            } else {
                // Lock expired, remove it
                self.locked_accounts.remove(identity_id);
            }
        }
        false
    }
    
    fn record_failed_attempt(&mut self, identity_id: &IdentityId) {
        let now = Instant::now();
        
        // Get or create attempt history
        let attempts = self.failed_attempts.entry(identity_id.clone()).or_insert_with(Vec::new);
        
        // Remove attempts outside the window
        attempts.retain(|&attempt_time| now.duration_since(attempt_time) < Self::ATTEMPT_WINDOW);
        
        // Add current attempt
        attempts.push(now);
        
        // Check if we should lock the account
        if attempts.len() >= Self::MAX_ATTEMPTS {
            self.locked_accounts.insert(identity_id.clone(), now + Self::LOCKOUT_DURATION);
            self.failed_attempts.remove(identity_id); // Clear attempts after locking
            
            println!("Account {} locked for {} seconds due to failed attempts", 
                identity_id.0, Self::LOCKOUT_DURATION.as_secs());
        }
    }
}
```

## Integration Examples

### Web Application Integration

```rust
use lib_identity::auth::{PasswordManager, SessionToken};
use lib_identity::IdentityManager;

struct WebAuthService {
    identity_manager: IdentityManager,
    password_manager: PasswordManager,
    active_sessions: HashMap<String, SessionToken>,
}

impl WebAuthService {
    pub async fn signin(
        &mut self,
        identity_name: &str,
        password: &str,
    ) -> Result<String, String> {
        // Get identity
        let identity = self.identity_manager
            .get_identity_by_name(identity_name)
            .await
            .map_err(|e| format!("Identity not found: {:?}", e))?;
        
        // Get identity seed (would be derived from 20-word phrase in app)
        let identity_seed = self.identity_manager
            .get_identity_seed(&identity.id)
            .await
            .map_err(|e| format!("Cannot get identity seed: {:?}", e))?;
        
        // Validate password
        let validation = self.password_manager
            .validate_password(&identity.id, password, &identity_seed)
            .map_err(|e| format!("Password validation failed: {:?}", e))?;
        
        if !validation.is_valid {
            return Err("Invalid password".to_string());
        }
        
        // Create session
        let session = SessionToken {
            token: generate_secure_token(),
            identity_id: identity.id.clone(),
            created_at: current_timestamp(),
            expires_at: current_timestamp() + 3600,
        };
        
        let session_token = session.token.clone();
        self.active_sessions.insert(session_token.clone(), session);
        
        Ok(session_token)
    }
    
    pub fn validate_session(&self, session_token: &str) -> Result<&IdentityId, String> {
        let session = self.active_sessions
            .get(session_token)
            .ok_or("Session not found")?;
        
        if !session.is_valid() {
            return Err("Session expired");
        }
        
        Ok(&session.identity_id)
    }
    
    pub fn signout(&mut self, session_token: &str) -> Result<(), String> {
        self.active_sessions
            .remove(session_token)
            .ok_or("Session not found")?;
        
        Ok(())
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
```

### API Middleware Integration

```rust
use lib_identity::auth::{PasswordManager, SessionToken};

pub struct AuthMiddleware {
    password_manager: PasswordManager,
    sessions: HashMap<String, SessionToken>,
}

impl AuthMiddleware {
    pub fn authenticate_request(&self, auth_header: &str) -> Result<IdentityId, String> {
        // Parse Authorization header
        let token = self.parse_bearer_token(auth_header)?;
        
        // Validate session
        let session = self.sessions
            .get(&token)
            .ok_or("Invalid session token")?;
        
        if !session.is_valid() {
            return Err("Session expired".to_string());
        }
        
        Ok(session.identity_id.clone())
    }
    
    fn parse_bearer_token(&self, auth_header: &str) -> Result<String, String> {
        if !auth_header.starts_with("Bearer ") {
            return Err("Invalid authorization header format".to_string());
        }
        
        let token = auth_header.strip_prefix("Bearer ").unwrap().to_string();
        
        if token.len() != 64 {
            return Err("Invalid token format".to_string());
        }
        
        Ok(token)
    }
}

// Usage in web framework
pub async fn protected_endpoint(
    auth_middleware: &AuthMiddleware,
    auth_header: Option<&str>,
) -> Result<String, String> {
    let auth_header = auth_header.ok_or("Authorization header required")?;
    
    let identity_id = auth_middleware.authenticate_request(auth_header)?;
    
    Ok(format!("Hello, authenticated user: {}", identity_id.0))
}
```

## Error Handling

### Authentication Errors

```rust
use lib_identity::auth::{PasswordError, PasswordManager};

pub enum AuthenticationError {
    IdentityNotFound,
    IdentityNotImported,
    PasswordNotSet,
    InvalidPassword,
    WeakPassword,
    AccountLocked,
    SessionExpired,
    InvalidToken,
    MfaRequired,
    InvalidMfaToken,
    CryptographicError(String),
}

impl From<PasswordError> for AuthenticationError {
    fn from(error: PasswordError) -> Self {
        match error {
            PasswordError::IdentityNotImported => AuthenticationError::IdentityNotImported,
            PasswordError::InvalidPassword => AuthenticationError::InvalidPassword,
            PasswordError::PasswordNotSet => AuthenticationError::PasswordNotSet,
            PasswordError::WeakPassword => AuthenticationError::WeakPassword,
        }
    }
}

// Error handling example
pub fn handle_authentication_error(error: AuthenticationError) -> String {
    match error {
        AuthenticationError::IdentityNotImported => {
            "Identity must be imported using 20-word seed phrase before setting password".to_string()
        },
        AuthenticationError::InvalidPassword => {
            "Invalid password provided".to_string()
        },
        AuthenticationError::AccountLocked => {
            "Account temporarily locked due to failed login attempts".to_string()
        },
        AuthenticationError::SessionExpired => {
            "Session has expired, please sign in again".to_string()
        },
        AuthenticationError::MfaRequired => {
            "Multi-factor authentication token required".to_string()
        },
        _ => "Authentication failed".to_string(),
    }
}
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    #[test]
    fn test_password_manager_basic_flow() {
        let mut password_manager = PasswordManager::new();
        let identity_id = IdentityId(Hash::from_bytes(b"test_identity"));
        let identity_seed = b"test_seed_data_32_bytes_exactly!!";
        
        // Mark identity as imported
        password_manager.mark_identity_imported(&identity_id);
        assert!(password_manager.is_identity_imported(&identity_id));
        
        // Set password
        let result = password_manager.set_password(&identity_id, "TestPassword123!", identity_seed);
        assert!(result.is_ok());
        
        // Validate correct password
        let validation = password_manager.validate_password(&identity_id, "TestPassword123!", identity_seed);
        assert!(validation.is_ok());
        assert!(validation.unwrap().is_valid);
        
        // Validate incorrect password
        let validation = password_manager.validate_password(&identity_id, "WrongPassword", identity_seed);
        assert!(validation.is_ok());
        assert!(!validation.unwrap().is_valid);
    }
    
    #[test]
    fn test_session_token_validation() {
        let identity_id = IdentityId(Hash::from_bytes(b"test_identity"));
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Valid session
        let mut session = SessionToken {
            token: "test_token".to_string(),
            identity_id: identity_id.clone(),
            created_at: current_time,
            expires_at: current_time + 3600,
        };
        
        assert!(session.is_valid());
        assert!(session.time_remaining().is_some());
        
        // Extend session
        session.extend_session(1800);
        assert_eq!(session.expires_at, current_time + 3600 + 1800);
        
        // Expired session
        let expired_session = SessionToken {
            token: "expired_token".to_string(),
            identity_id,
            created_at: current_time - 7200,
            expires_at: current_time - 3600,
        };
        
        assert!(!expired_session.is_valid());
        assert!(expired_session.time_remaining().is_none());
    }
    
    #[test]
    fn test_password_requirements() {
        let weak_passwords = vec![
            "123456",
            "password",
            "PASSWORD",
            "12345678",
            "Password",
            "password123",
            "PASSWORD123",
        ];
        
        for password in weak_passwords {
            assert!(validate_password_requirements(password).is_err());
        }
        
        let strong_passwords = vec![
            "MySecure123!",
            "Complex$Pass2024",
            "Str0ng&Secure#",
        ];
        
        for password in strong_passwords {
            assert!(validate_password_requirements(password).is_ok());
        }
    }
}
```

## Performance Considerations

- **Constant-Time Operations**: All password comparisons use constant-time equality to prevent timing attacks
- **Memory Management**: Automatic zeroization of sensitive data
- **Session Caching**: In-memory session storage for fast validation
- **Cryptographic Operations**: Optimized using lib-crypto's performance implementations
- **Batch Operations**: Support for bulk session validation and cleanup

## Security Best Practices

1. **Import First**: Identities must be imported via 20-word seed phrase before password authentication
2. **Strong Passwords**: Enforce minimum password complexity requirements
3. **Rate Limiting**: Implement account lockout after failed attempts
4. **Session Management**: Use secure random tokens with appropriate expiration
5. **MFA Support**: Implement multi-factor authentication for sensitive operations
6. **Audit Logging**: Log authentication events for security monitoring
7. **Recovery Options**: Provide secure password reset via recovery phrases