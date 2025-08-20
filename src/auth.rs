use anyhow::{Result, anyhow};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use log::{info, warn};

/// JWT Claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,           // Subject (user ID)
    pub user_id: String,       // User identifier
    pub roles: Vec<String>,    // User roles
    pub permissions: Vec<String>, // Specific permissions
    pub session_id: String,    // Session identifier
    pub exp: u64,             // Expiration time
    pub iat: u64,             // Issued at
    pub iss: String,          // Issuer
    pub aud: String,          // Audience
}

/// User roles in the ZHTP system
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    Validator,
    User,
    Node,
    API,
    ReadOnly,
}

impl UserRole {
    /// Get permissions for this role
    pub fn permissions(&self) -> Vec<Permission> {
        match self {
            UserRole::Admin => vec![
                Permission::ReadAll,
                Permission::WriteAll,
                Permission::ManageUsers,
                Permission::ManageNodes,
                Permission::ManageConsensus,
                Permission::ViewMetrics,
                Permission::ManageConfig,
            ],
            UserRole::Validator => vec![
                Permission::ReadConsensus,
                Permission::WriteConsensus,
                Permission::ViewMetrics,
                Permission::ReadNodes,
            ],
            UserRole::User => vec![
                Permission::ReadPublic,
                Permission::WriteOwn,
                Permission::ViewOwnMetrics,
            ],
            UserRole::Node => vec![
                Permission::ReadConsensus,
                Permission::WriteConsensus,
                Permission::ReadNodes,
                Permission::WriteNodes,
            ],
            UserRole::API => vec![
                Permission::ReadPublic,
                Permission::WritePublic,
            ],
            UserRole::ReadOnly => vec![
                Permission::ReadPublic,
                Permission::ViewMetrics,
            ],
        }
    }
}

/// Specific permissions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    ReadAll,
    WriteAll,
    ReadPublic,
    WritePublic,
    ReadOwn,
    WriteOwn,
    ManageUsers,
    ManageNodes,
    ManageConsensus,
    ViewMetrics,
    ViewOwnMetrics,
    ManageConfig,
    ReadConsensus,
    WriteConsensus,
    ReadNodes,
    WriteNodes,
}

/// User account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub roles: Vec<UserRole>,
    pub enabled: bool,
    pub created_at: u64,
    pub last_login: Option<u64>,
    pub failed_login_attempts: u32,
    pub locked_until: Option<u64>,
    pub api_keys: Vec<ApiKey>,
}

/// API Key for service authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub key_hash: String,
    pub roles: Vec<UserRole>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub last_used: Option<u64>,
    pub enabled: bool,
}

/// Active session information
#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: String,
    pub user_id: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub expires_at: u64,
    pub ip_address: String,
    pub user_agent: String,
    pub roles: Vec<UserRole>,
    pub permissions: Vec<Permission>,
}

/// Authentication and Authorization system
pub struct AuthSystem {
    /// JWT encoding key
    encoding_key: EncodingKey,
    /// JWT decoding key
    decoding_key: DecodingKey,
    /// User store
    users: Arc<RwLock<HashMap<String, User>>>,
    /// Active sessions
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    /// API key store
    api_keys: Arc<RwLock<HashMap<String, ApiKey>>>,
    /// Rate limiting for authentication attempts
    auth_attempts: Arc<RwLock<HashMap<String, Vec<u64>>>>,
    /// Configuration
    config: AuthConfig,
}

impl std::fmt::Debug for AuthSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSystem")
            .field("encoding_key", &"<EncodingKey>")
            .field("decoding_key", &"<DecodingKey>")
            .field("users_count", &"<RwLock>")
            .field("sessions_count", &"<RwLock>")
            .field("api_keys_count", &"<RwLock>")
            .field("auth_attempts_count", &"<RwLock>")
            .field("config", &self.config)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_expiry_hours: u64,
    pub session_timeout_minutes: u64,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u64,
    pub rate_limit_attempts: u32,
    pub rate_limit_window_minutes: u64,
    pub require_strong_passwords: bool,
    pub issuer: String,
    pub audience: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: generate_secure_secret(),
            jwt_expiry_hours: 24,
            session_timeout_minutes: 30,
            max_failed_attempts: 5,
            lockout_duration_minutes: 15,
            rate_limit_attempts: 10,
            rate_limit_window_minutes: 15,
            require_strong_passwords: true,
            issuer: "zhtp-node".to_string(),
            audience: "zhtp-api".to_string(),
        }
    }
}

impl AuthSystem {
    /// Create new authentication system
    pub fn new(config: AuthConfig) -> Result<Self> {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        Ok(Self {
            encoding_key,
            decoding_key,
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            api_keys: Arc::new(RwLock::new(HashMap::new())),
            auth_attempts: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }

    /// Authenticate user with username/password
    pub async fn authenticate_user(
        &self,
        username: &str,
        password: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<String> {
        // Check rate limiting
        if !self.check_rate_limit(ip_address).await? {
            warn!("Rate limit exceeded for IP: {}", ip_address);
            return Err(anyhow!("Rate limit exceeded"));
        }

        let users = self.users.read().await;
        let user = users.values()
            .find(|u| u.username == username && u.enabled)
            .ok_or_else(|| anyhow!("Invalid credentials"))?
            .clone();
        drop(users);

        // Check if user is locked
        if let Some(locked_until) = user.locked_until {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if now < locked_until {
                warn!("Attempted login to locked account: {}", username);
                return Err(anyhow!("Account temporarily locked"));
            }
        }

        // Verify password
        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| anyhow!("Invalid password hash"))?;
        
        if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_err() {
            self.handle_failed_login(&user.username).await?;
            warn!("Failed login attempt for user: {}", username);
            return Err(anyhow!("Invalid credentials"));
        }

        // Reset failed attempts on successful login
        self.reset_failed_attempts(&user.username).await?;

        // Create session
        let session_id = Uuid::new_v4().to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let expires_at = now + (self.config.session_timeout_minutes * 60);

        let permissions = user.roles.iter()
            .flat_map(|role| role.permissions())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let session = Session {
            session_id: session_id.clone(),
            user_id: user.id.clone(),
            created_at: now,
            last_accessed: now,
            expires_at,
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            roles: user.roles.clone(),
            permissions,
        };

        self.sessions.write().await.insert(session_id.clone(), session);

        // Update last login
        self.update_last_login(&user.id).await?;

        // Generate JWT token
        let token = self.generate_jwt_token(&user, &session_id).await?;

        info!("User authenticated successfully: {}", username);
        Ok(token)
    }

    /// Authenticate API key
    pub async fn authenticate_api_key(&self, api_key: &str) -> Result<Claims> {
        let key_hash = hash_api_key(api_key);
        
        let api_keys = self.api_keys.read().await;
        let key_info = api_keys.values()
            .find(|k| k.key_hash == key_hash && k.enabled)
            .ok_or_else(|| anyhow!("Invalid API key"))?
            .clone();
        drop(api_keys);

        // Check expiration
        if let Some(expires_at) = key_info.expires_at {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if now > expires_at {
                return Err(anyhow!("API key expired"));
            }
        }

        // Update last used
        self.update_api_key_usage(&key_info.id).await?;

        // Generate claims
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let permissions = key_info.roles.iter()
            .flat_map(|role| role.permissions())
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|p| format!("{:?}", p))
            .collect();

        let claims = Claims {
            sub: key_info.id.clone(),
            user_id: format!("api_key_{}", key_info.id),
            roles: key_info.roles.iter().map(|r| format!("{:?}", r)).collect(),
            permissions,
            session_id: Uuid::new_v4().to_string(),
            exp: now + (self.config.jwt_expiry_hours * 3600),
            iat: now,
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
        };

        info!("API key authenticated: {}", key_info.name);
        Ok(claims)
    }

    /// Validate JWT token
    pub async fn validate_token(&self, token: &str) -> Result<Claims> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|_| anyhow!("Invalid token"))?;

        let claims = token_data.claims;

        // Check expiration
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if claims.exp < now {
            return Err(anyhow!("Token expired"));
        }

        // Validate session if it's a user token
        if !claims.user_id.starts_with("api_key_") {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(&claims.session_id) {
                if session.expires_at < now {
                    return Err(anyhow!("Session expired"));
                }
                // Update last accessed
                drop(sessions);
                self.update_session_access(&claims.session_id).await?;
            } else {
                return Err(anyhow!("Session not found"));
            }
        }

        Ok(claims)
    }

    /// Check if user has permission
    pub fn check_permission(&self, claims: &Claims, required_permission: Permission) -> bool {
        claims.permissions.contains(&format!("{:?}", required_permission))
    }

    /// Create new user
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        email: Option<String>,
        roles: Vec<UserRole>,
    ) -> Result<String> {
        if self.config.require_strong_passwords && !is_strong_password(password) {
            return Err(anyhow!("Password does not meet strength requirements"));
        }

        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| anyhow!("Failed to hash password"))?
            .to_string();

        let user_id = Uuid::new_v4().to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let user = User {
            id: user_id.clone(),
            username: username.to_string(),
            email,
            password_hash,
            roles,
            enabled: true,
            created_at: now,
            last_login: None,
            failed_login_attempts: 0,
            locked_until: None,
            api_keys: Vec::new(),
        };

        self.users.write().await.insert(user_id.clone(), user);
        info!("User created: {}", username);
        Ok(user_id)
    }

    /// Create API key
    pub async fn create_api_key(
        &self,
        user_id: &str,
        name: &str,
        roles: Vec<UserRole>,
        expires_at: Option<u64>,
    ) -> Result<String> {
        let api_key = generate_api_key();
        let key_hash = hash_api_key(&api_key);
        let key_id = Uuid::new_v4().to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let key_info = ApiKey {
            id: key_id,
            name: name.to_string(),
            key_hash,
            roles,
            created_at: now,
            expires_at,
            last_used: None,
            enabled: true,
        };

        self.api_keys.write().await.insert(key_info.id.clone(), key_info.clone());

        // Add to user's API keys
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(user_id) {
            user.api_keys.push(key_info);
        }

        info!("API key created for user: {} with name: {}", user_id, name);
        Ok(api_key)
    }

    /// Logout user (invalidate session)
    pub async fn logout(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(session_id).is_some() {
            info!("User logged out with session: {}", session_id);
            Ok(())
        } else {
            Err(anyhow!("Session not found"))
        }
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut sessions = self.sessions.write().await;
        let expired_count = sessions.len();
        sessions.retain(|_, session| session.expires_at > now);
        let remaining_count = sessions.len();
        
        if expired_count > remaining_count {
            info!("Cleaned up {} expired sessions", expired_count - remaining_count);
        }
        
        Ok(())
    }

    // Private helper methods

    async fn check_rate_limit(&self, ip_address: &str) -> Result<bool> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let window_start = now - (self.config.rate_limit_window_minutes * 60);

        let mut attempts = self.auth_attempts.write().await;
        let ip_attempts = attempts.entry(ip_address.to_string()).or_insert_with(Vec::new);
        
        // Remove old attempts
        ip_attempts.retain(|&timestamp| timestamp > window_start);
        
        // Check if under limit
        if ip_attempts.len() < self.config.rate_limit_attempts as usize {
            ip_attempts.push(now);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn handle_failed_login(&self, username: &str) -> Result<()> {
        let mut users = self.users.write().await;
        if let Some(user) = users.values_mut().find(|u| u.username == username) {
            user.failed_login_attempts += 1;
            
            if user.failed_login_attempts >= self.config.max_failed_attempts {
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                user.locked_until = Some(now + (self.config.lockout_duration_minutes * 60));
                warn!("Account locked due to failed attempts: {}", username);
            }
        }
        Ok(())
    }

    async fn reset_failed_attempts(&self, username: &str) -> Result<()> {
        let mut users = self.users.write().await;
        if let Some(user) = users.values_mut().find(|u| u.username == username) {
            user.failed_login_attempts = 0;
            user.locked_until = None;
        }
        Ok(())
    }

    async fn update_last_login(&self, user_id: &str) -> Result<()> {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(user_id) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            user.last_login = Some(now);
        }
        Ok(())
    }

    async fn update_session_access(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            session.last_accessed = now;
            session.expires_at = now + (self.config.session_timeout_minutes * 60);
        }
        Ok(())
    }

    async fn update_api_key_usage(&self, key_id: &str) -> Result<()> {
        let mut api_keys = self.api_keys.write().await;
        if let Some(key) = api_keys.get_mut(key_id) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            key.last_used = Some(now);
        }
        Ok(())
    }

    async fn generate_jwt_token(&self, user: &User, session_id: &str) -> Result<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let permissions = user.roles.iter()
            .flat_map(|role| role.permissions())
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|p| format!("{:?}", p))
            .collect();

        let claims = Claims {
            sub: user.id.clone(),
            user_id: user.id.clone(),
            roles: user.roles.iter().map(|r| format!("{:?}", r)).collect(),
            permissions,
            session_id: session_id.to_string(),
            exp: now + (self.config.jwt_expiry_hours * 3600),
            iat: now,
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|_| anyhow!("Failed to generate token"))
    }
}

// Utility functions

fn generate_secure_secret() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..64).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect()
}

fn generate_api_key() -> String {
    format!("zhtp_{}", Uuid::new_v4().to_string().replace('-', ""))
}

fn hash_api_key(api_key: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    hex::encode(hasher.finalize())
}

fn is_strong_password(password: &str) -> bool {
    password.len() >= 12
        && password.chars().any(|c| c.is_lowercase())
        && password.chars().any(|c| c.is_uppercase())
        && password.chars().any(|c| c.is_numeric())
        && password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_auth_system() {
        let config = AuthConfig::default();
        let auth = AuthSystem::new(config).unwrap();

        // Create user
        let user_id = auth.create_user(
            "testuser",
            "TestPassword123!",
            Some("test@example.com".to_string()),
            vec![UserRole::User],
        ).await.unwrap();

        // Authenticate
        let token = auth.authenticate_user(
            "testuser",
            "TestPassword123!",
            "127.0.0.1",
            "test-agent",
        ).await.unwrap();

        // Validate token
        let claims = auth.validate_token(&token).await.unwrap();
        assert_eq!(claims.user_id, user_id);
    }

    #[test]
    fn test_strong_password() {
        assert!(is_strong_password("TestPassword123!"));
        assert!(!is_strong_password("weak"));
        assert!(!is_strong_password("nouppercaseornumbers!"));
    }
}
