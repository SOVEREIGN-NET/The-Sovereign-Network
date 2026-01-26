//! Biometric-based identity recovery system


use std::collections::{HashMap, HashSet};
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm,
    Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::time::{Duration, Instant};
use anyhow::{Result as AnyhowResult, anyhow};
use rand;

const ENCRYPTION_VERSION_XOR: u32 = 1;
const ENCRYPTION_VERSION_AES_GCM: u32 = 2;
const AES_GCM_NONCE_SIZE: usize = 12;
const AES_GCM_TAG_SIZE: usize = 16;

/// Biometric recovery manager for identity restoration using biometric data
#[derive(Debug, Clone)]
pub struct BiometricRecoveryManager {
    /// Stored biometric templates (encrypted)
    biometric_templates: HashMap<String, EncryptedBiometricTemplate>,
    /// Biometric matching settings
    matching_settings: BiometricMatchingSettings,
    /// Authentication attempts tracking
    auth_attempts: HashMap<String, BiometricAuthAttempts>,
    /// Security settings
    security_settings: BiometricSecuritySettings,
    /// Track used nonces to prevent reuse
    used_nonces: HashSet<Vec<u8>>,
}

/// Encrypted biometric template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBiometricTemplate {
    pub identity_id: String,
    pub biometric_type: BiometricType,
    pub encrypted_template: Vec<u8>,
    pub template_hash: String,
    #[serde(default = "default_encryption_version")]
    pub encryption_version: u32,
    pub encryption_method: String,
    pub salt: Vec<u8>,
    pub iv: Vec<u8>,
    #[serde(default)]
    pub tag: Vec<u8>,
    pub created_at: u64,
    pub last_used: Option<u64>,
    pub usage_count: u32,
    pub quality_score: f64,
    pub expires_at: Option<u64>,
}

fn default_encryption_version() -> u32 {
    ENCRYPTION_VERSION_XOR
}

/// Biometric template in plain form (temporary use only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricTemplate {
    pub biometric_type: BiometricType,
    pub template_data: Vec<u8>,
    pub feature_points: Vec<FeaturePoint>,
    pub quality_metrics: QualityMetrics,
    pub metadata: BiometricMetadata,
}

/// Types of supported biometric data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BiometricType {
    /// Fingerprint
    Fingerprint,
    /// Facial recognition
    Face,
    /// Iris scan
    Iris,
    /// Voice print
    Voice,
    /// Retinal scan
    Retina,
    /// Palm print
    Palm,
    /// Gait analysis
    Gait,
    /// Keystroke dynamics
    Keystroke,
    /// Multi-modal (combination)
    MultiModal(Vec<BiometricType>),
}

/// Feature point in biometric template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturePoint {
    pub x: f64,
    pub y: f64,
    pub angle: f64,
    pub quality: f64,
    pub point_type: String,
}

/// Quality metrics for biometric data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    pub overall_quality: f64,
    pub clarity: f64,
    pub completeness: f64,
    pub uniqueness: f64,
    pub consistency: f64,
}

/// Metadata for biometric capture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricMetadata {
    pub capture_device: String,
    pub capture_timestamp: u64,
    pub capture_environment: String,
    pub resolution: (u32, u32),
    pub compression: String,
}

/// Biometric matching settings
#[derive(Debug, Clone)]
pub struct BiometricMatchingSettings {
    pub similarity_threshold: f64,
    pub false_acceptance_rate: f64,
    pub false_rejection_rate: f64,
    pub matching_algorithm: String,
    pub quality_threshold: f64,
    pub require_liveness_detection: bool,
}

/// Authentication attempts tracking
#[derive(Debug, Clone)]
pub struct BiometricAuthAttempts {
    pub identity_id: String,
    pub successful_attempts: u32,
    pub failed_attempts: u32,
    pub last_attempt: Option<Instant>,
    pub consecutive_failures: u32,
    pub locked_until: Option<Instant>,
}

/// Security settings for biometric recovery
#[derive(Debug, Clone)]
pub struct BiometricSecuritySettings {
    pub encryption_algorithm: String,
    pub template_encryption_required: bool,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u32,
    pub require_multi_factor: bool,
    pub liveness_detection_required: bool,
    pub anti_spoofing_enabled: bool,
}

/// Biometric capture options
#[derive(Debug, Clone)]
pub struct BiometricCaptureOptions {
    pub biometric_type: BiometricType,
    pub quality_threshold: f64,
    pub capture_device: String,
    pub environment: String,
    pub liveness_detection: bool,
    pub anti_spoofing: bool,
}

/// Result of biometric matching
#[derive(Debug, Clone)]
pub struct BiometricMatchResult {
    pub matched: bool,
    pub similarity_score: f64,
    pub confidence_level: f64,
    pub quality_score: f64,
    pub liveness_confirmed: bool,
    pub spoofing_detected: bool,
    pub match_points: usize,
    pub processing_time_ms: u64,
}

/// Biometric enrollment data
#[derive(Debug, Clone)]
pub struct BiometricEnrollment {
    pub identity_id: String,
    pub biometric_type: BiometricType,
    pub templates: Vec<BiometricTemplate>,
    pub enrollment_quality: f64,
    pub enrollment_timestamp: u64,
    pub device_info: String,
}

impl BiometricRecoveryManager {
    /// Create new biometric recovery manager
    pub fn new() -> Self {
        Self {
            biometric_templates: HashMap::new(),
            matching_settings: BiometricMatchingSettings::default(),
            auth_attempts: HashMap::new(),
            security_settings: BiometricSecuritySettings::default(),
            used_nonces: HashSet::new(),
        }
    }

    /// Enroll biometric data for identity recovery
    pub async fn enroll_biometric(
        &mut self,
        identity_id: &str,
        enrollment: BiometricEnrollment,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Validate enrollment quality
        if enrollment.enrollment_quality < self.matching_settings.quality_threshold {
            return Err(format!("Biometric enrollment quality {} below threshold {}", 
                enrollment.enrollment_quality, self.matching_settings.quality_threshold).into());
        }

        // Process each template in enrollment
        let mut enrolled_templates = Vec::new();
        for template in &enrollment.templates {
            // Validate template quality
            if template.quality_metrics.overall_quality < self.matching_settings.quality_threshold {
                return Err("Template quality below minimum threshold".into());
            }

            // Encrypt and store template
            let template_id = self.store_biometric_template(identity_id, template).await?;
            enrolled_templates.push(template_id);
        }

        println!("✓ Enrolled {} biometric templates for identity {} (type: {:?})", 
            enrolled_templates.len(), identity_id, enrollment.biometric_type);
        
        Ok(format!("enrollment_{}_{:?}", identity_id, enrollment.biometric_type))
    }

    /// Store encrypted biometric template
    async fn store_biometric_template(
        &mut self,
        identity_id: &str,
        template: &BiometricTemplate,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Serialize template data
        let template_data = self.serialize_template(template).await?;
        
        // Generate encryption materials
        let salt = self.generate_salt().await?;
        let encryption_key = self.derive_encryption_key(identity_id, &salt).await?;
        let (encrypted_template, iv, tag, encryption_version) = self.encrypt_template(&template_data, &encryption_key).await?;
        
        // Calculate template hash
        let template_hash = self.calculate_template_hash(&template_data);
        
        // Create encrypted template record
        let template_id = format!("bio_{}_{:?}_{}", identity_id, template.biometric_type, 
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs());
        
        let encrypted_template_record = EncryptedBiometricTemplate {
            identity_id: identity_id.to_string(),
            biometric_type: template.biometric_type.clone(),
            encrypted_template,
            template_hash,
            encryption_version,
            encryption_method: "AES-256-GCM".to_string(),
            salt,
            iv,
            tag,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            last_used: None,
            usage_count: 0,
            quality_score: template.quality_metrics.overall_quality,
            expires_at: None, // Biometric templates typically don't expire
        };

        // Store encrypted template
        self.biometric_templates.insert(template_id.clone(), encrypted_template_record);
        
        Ok(template_id)
    }

    /// Recover identity using biometric authentication
    pub async fn recover_identity_with_biometric(
        &mut self,
        captured_biometric: &BiometricTemplate,
        biometric_type: BiometricType,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Find matching templates of the same type
        let matching_templates: Vec<(String, EncryptedBiometricTemplate)> = self.biometric_templates
            .iter()
            .filter(|(_, template)| template.biometric_type == biometric_type)
            .map(|(id, template)| (id.clone(), template.clone()))
            .collect();

        if matching_templates.is_empty() {
            return Err("No enrolled biometric templates found for this type".into());
        }

        let mut best_match: Option<(String, BiometricMatchResult)> = None;
        let mut best_identity_id: Option<String> = None;
        let mut failed_identity_ids = Vec::new();

        // Try matching against all stored templates
        for (template_id, encrypted_template) in &matching_templates {
            // Check if identity is locked out
            if self.is_identity_locked(&encrypted_template.identity_id) {
                continue;
            }

            // Decrypt template
            match self.decrypt_template(encrypted_template).await {
                Ok(stored_template) => {
                    // Perform biometric matching
                    match self.match_biometric_templates(captured_biometric, &stored_template).await {
                        Ok(match_result) => {
                            if match_result.matched && match_result.similarity_score > self.matching_settings.similarity_threshold {
                                // Check if this is the best match so far
                                if best_match.is_none() || match_result.similarity_score > best_match.as_ref().unwrap().1.similarity_score {
                                    best_match = Some((template_id.clone(), match_result));
                                    best_identity_id = Some(encrypted_template.identity_id.clone());
                                }
                            }
                        },
                        Err(e) => {
                            println!("Warning: Failed to match template {}: {}", template_id, e);
                            failed_identity_ids.push(encrypted_template.identity_id.clone());
                        }
                    }
                },
                Err(e) => {
                    println!("Warning: Failed to decrypt template {}: {}", template_id, e);
                    failed_identity_ids.push(encrypted_template.identity_id.clone());
                }
            }
        }

        // Record failed authentications (now safe to mutate self)
        for identity_id in failed_identity_ids {
            self.record_failed_biometric_auth(&identity_id);
        }

        // Process results
        if let (Some((template_id, match_result)), Some(identity_id)) = (best_match, best_identity_id) {
            // Record successful authentication
            self.record_successful_biometric_auth(&identity_id);
            
            // Update template usage
            if let Some(template) = self.biometric_templates.get_mut(&template_id) {
                template.usage_count += 1;
                template.last_used = Some(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs());
            }

            println!("✓ Identity {} recovered using biometric authentication (similarity: {:.3}, confidence: {:.3})", 
                identity_id, match_result.similarity_score, match_result.confidence_level);
            
            Ok(identity_id)
        } else {
            // Record failed authentication for all attempted identities
            for (_, encrypted_template) in &matching_templates {
                self.record_failed_biometric_auth(&encrypted_template.identity_id);
            }
            
            Err("Biometric authentication failed - no matching identity found".into())
        }
    }

    /// Match two biometric templates
    async fn match_biometric_templates(
        &self,
        captured: &BiometricTemplate,
        stored: &BiometricTemplate,
    ) -> Result<BiometricMatchResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        
        // Check if types match
        if captured.biometric_type != stored.biometric_type {
            return Err("Biometric types do not match".into());
        }

        // Check quality thresholds
        if captured.quality_metrics.overall_quality < self.matching_settings.quality_threshold {
            return Err("Captured biometric quality below threshold".into());
        }

        // Perform liveness detection if required
        let liveness_confirmed = if self.security_settings.liveness_detection_required {
            self.detect_liveness(captured).await?
        } else {
            true
        };

        // Perform anti-spoofing detection if enabled
        let spoofing_detected = if self.security_settings.anti_spoofing_enabled {
            self.detect_spoofing(captured).await?
        } else {
            false
        };

        if spoofing_detected {
            return Ok(BiometricMatchResult {
                matched: false,
                similarity_score: 0.0,
                confidence_level: 0.0,
                quality_score: captured.quality_metrics.overall_quality,
                liveness_confirmed,
                spoofing_detected: true,
                match_points: 0,
                processing_time_ms: start_time.elapsed().as_millis() as u64,
            });
        }

        // Compute similarity based on biometric type
        let (similarity_score, match_points) = match captured.biometric_type {
            BiometricType::Fingerprint => self.match_fingerprints(captured, stored).await?,
            BiometricType::Face => self.match_faces(captured, stored).await?,
            BiometricType::Iris => self.match_iris(captured, stored).await?,
            BiometricType::Voice => self.match_voice(captured, stored).await?,
            BiometricType::Retina => self.match_retina(captured, stored).await?,
            BiometricType::Palm => self.match_palm(captured, stored).await?,
            BiometricType::Gait => self.match_gait(captured, stored).await?,
            BiometricType::Keystroke => self.match_keystroke(captured, stored).await?,
            BiometricType::MultiModal(ref types) => self.match_multimodal(captured, stored, types).await?,
        };

        // Calculate confidence level
        let confidence_level = self.calculate_confidence(similarity_score, captured, stored);
        
        // Determine if match is successful
        let matched = similarity_score >= self.matching_settings.similarity_threshold 
            && liveness_confirmed 
            && !spoofing_detected;

        Ok(BiometricMatchResult {
            matched,
            similarity_score,
            confidence_level,
            quality_score: captured.quality_metrics.overall_quality,
            liveness_confirmed,
            spoofing_detected,
            match_points,
            processing_time_ms: start_time.elapsed().as_millis() as u64,
        })
    }

    /// Match fingerprint templates
    async fn match_fingerprints(&self, captured: &BiometricTemplate, stored: &BiometricTemplate) -> Result<(f64, usize), Box<dyn std::error::Error>> {
        // Simplified fingerprint matching based on feature points
        let mut matching_points = 0;
        let max_distance = 10.0; // Maximum distance for point matching
        
        for captured_point in &captured.feature_points {
            for stored_point in &stored.feature_points {
                let distance = ((captured_point.x - stored_point.x).powi(2) + 
                               (captured_point.y - stored_point.y).powi(2)).sqrt();
                let angle_diff = (captured_point.angle - stored_point.angle).abs();
                
                if distance < max_distance && angle_diff < 0.1 {
                    matching_points += 1;
                    break;
                }
            }
        }

        let total_points = captured.feature_points.len().max(stored.feature_points.len());
        let similarity = if total_points > 0 {
            matching_points as f64 / total_points as f64
        } else {
            0.0
        };

        Ok((similarity, matching_points))
    }

    /// Match face templates
    async fn match_faces(&self, captured: &BiometricTemplate, stored: &BiometricTemplate) -> Result<(f64, usize), Box<dyn std::error::Error>> {
        // Simplified face matching using feature point distances
        if captured.feature_points.len() < 5 || stored.feature_points.len() < 5 {
            return Ok((0.0, 0));
        }

        let mut total_similarity = 0.0;
        let mut valid_comparisons = 0;

        for (i, captured_point) in captured.feature_points.iter().enumerate() {
            if i < stored.feature_points.len() {
                let stored_point = &stored.feature_points[i];
                let distance = ((captured_point.x - stored_point.x).powi(2) + 
                               (captured_point.y - stored_point.y).powi(2)).sqrt();
                
                // Normalize distance (assuming face images are normalized)
                let normalized_distance = 1.0 - (distance / 100.0).min(1.0);
                total_similarity += normalized_distance;
                valid_comparisons += 1;
            }
        }

        let similarity = if valid_comparisons > 0 {
            total_similarity / valid_comparisons as f64
        } else {
            0.0
        };

        Ok((similarity, valid_comparisons))
    }

    /// Match iris templates
    async fn match_iris(&self, captured: &BiometricTemplate, stored: &BiometricTemplate) -> Result<(f64, usize), Box<dyn std::error::Error>> {
        // Simplified iris matching using Hamming distance
        let captured_bits = &captured.template_data;
        let stored_bits = &stored.template_data;
        
        if captured_bits.len() != stored_bits.len() {
            return Ok((0.0, 0));
        }

        let mut hamming_distance = 0;
        for i in 0..captured_bits.len() {
            hamming_distance += (captured_bits[i] ^ stored_bits[i]).count_ones();
        }

        let total_bits = captured_bits.len() * 8;
        let similarity = 1.0 - (hamming_distance as f64 / total_bits as f64);
        
        Ok((similarity, total_bits - hamming_distance as usize))
    }

    /// Match voice templates
    async fn match_voice(&self, captured: &BiometricTemplate, stored: &BiometricTemplate) -> Result<(f64, usize), Box<dyn std::error::Error>> {
        // Simplified voice matching using feature correlation
        let captured_features = &captured.feature_points;
        let stored_features = &stored.feature_points;
        
        if captured_features.is_empty() || stored_features.is_empty() {
            return Ok((0.0, 0));
        }

        let min_len = captured_features.len().min(stored_features.len());
        let mut correlation_sum = 0.0;
        
        for i in 0..min_len {
            let captured_val = captured_features[i].quality;
            let stored_val = stored_features[i].quality;
            correlation_sum += captured_val * stored_val;
        }
        
        let similarity = correlation_sum / min_len as f64;
        Ok((similarity.min(1.0), min_len))
    }

    /// Match retina templates
    async fn match_retina(&self, captured: &BiometricTemplate, stored: &BiometricTemplate) -> Result<(f64, usize), Box<dyn std::error::Error>> {
        // Similar to iris but with different feature extraction
        self.match_iris(captured, stored).await
    }

    /// Match palm templates
    async fn match_palm(&self, captured: &BiometricTemplate, stored: &BiometricTemplate) -> Result<(f64, usize), Box<dyn std::error::Error>> {
        // Similar to fingerprint but larger area
        self.match_fingerprints(captured, stored).await
    }

    /// Match gait templates
    async fn match_gait(&self, captured: &BiometricTemplate, stored: &BiometricTemplate) -> Result<(f64, usize), Box<dyn std::error::Error>> {
        // Gait matching using temporal features
        let captured_features = &captured.feature_points;
        let stored_features = &stored.feature_points;
        
        if captured_features.len() < 10 || stored_features.len() < 10 {
            return Ok((0.0, 0));
        }

        // Dynamic time warping-like similarity
        let mut similarity_sum = 0.0;
        let mut comparisons = 0;

        for i in 0..(captured_features.len() - 1) {
            for j in 0..(stored_features.len() - 1) {
                let captured_stride = ((captured_features[i+1].x - captured_features[i].x).powi(2) +
                                     (captured_features[i+1].y - captured_features[i].y).powi(2)).sqrt();
                let stored_stride = ((stored_features[j+1].x - stored_features[j].x).powi(2) +
                                   (stored_features[j+1].y - stored_features[j].y).powi(2)).sqrt();
                
                let stride_similarity = 1.0 - ((captured_stride - stored_stride).abs() / captured_stride.max(stored_stride));
                similarity_sum += stride_similarity;
                comparisons += 1;
            }
        }

        let similarity = if comparisons > 0 {
            similarity_sum / comparisons as f64
        } else {
            0.0
        };

        Ok((similarity, comparisons))
    }

    /// Match keystroke templates
    async fn match_keystroke(&self, captured: &BiometricTemplate, stored: &BiometricTemplate) -> Result<(f64, usize), Box<dyn std::error::Error>> {
        // Keystroke dynamics matching using timing patterns
        let captured_timings = &captured.feature_points;
        let stored_timings = &stored.feature_points;
        
        if captured_timings.len() != stored_timings.len() {
            return Ok((0.0, 0));
        }

        let mut timing_similarity = 0.0;
        for i in 0..captured_timings.len() {
            let captured_timing = captured_timings[i].angle; // Using angle field for timing
            let stored_timing = stored_timings[i].angle;
            
            let time_diff = (captured_timing - stored_timing).abs();
            let normalized_diff = 1.0 - (time_diff / 1000.0).min(1.0); // Assuming millisecond timings
            timing_similarity += normalized_diff;
        }

        let similarity = timing_similarity / captured_timings.len() as f64;
        Ok((similarity, captured_timings.len()))
    }

    /// Match multi-modal templates
    async fn match_multimodal(&self, captured: &BiometricTemplate, stored: &BiometricTemplate, _types: &[BiometricType]) -> Result<(f64, usize), Box<dyn std::error::Error>> {
        // For multi-modal, use weighted average of different biometric scores
        // This is a simplified implementation
        let mut total_similarity = 0.0;
        let mut total_points = 0;
        
        // Split template data into segments for different modalities
        let segment_size = captured.template_data.len() / 3; // Assume 3 modalities
        
        if segment_size > 0 {
            // Create temporary templates for each modality
            for i in 0..3 {
                let start = i * segment_size;
                let end = ((i + 1) * segment_size).min(captured.template_data.len());
                
                if start < captured.template_data.len() && start < stored.template_data.len() {
                    // Simple correlation for each segment
                    let mut correlation = 0.0;
                    let segment_len = (end - start).min(stored.template_data.len() - start);
                    
                    for j in 0..segment_len {
                        if start + j < captured.template_data.len() && start + j < stored.template_data.len() {
                            let captured_val = captured.template_data[start + j] as f64;
                            let stored_val = stored.template_data[start + j] as f64;
                            correlation += (captured_val * stored_val) / (255.0 * 255.0);
                        }
                    }
                    
                    total_similarity += correlation / segment_len as f64;
                    total_points += segment_len;
                }
            }
        }

        let similarity = if total_points > 0 {
            total_similarity / 3.0 // Average of 3 modalities
        } else {
            0.0
        };

        Ok((similarity, total_points))
    }

    /// Calculate confidence level for match
    fn calculate_confidence(&self, similarity_score: f64, captured: &BiometricTemplate, stored: &BiometricTemplate) -> f64 {
        let mut confidence = similarity_score;
        
        // Adjust based on quality
        let avg_quality = (captured.quality_metrics.overall_quality + stored.quality_metrics.overall_quality) / 2.0;
        confidence *= avg_quality;
        
        // Adjust based on consistency
        let consistency_factor = (captured.quality_metrics.consistency * stored.quality_metrics.consistency).sqrt();
        confidence *= consistency_factor;
        
        confidence.min(1.0)
    }

    /// Detect liveness in biometric sample
    async fn detect_liveness(&self, template: &BiometricTemplate) -> Result<bool, Box<dyn std::error::Error>> {
        // Simplified liveness detection
        // In implementation, would use advanced algorithms specific to biometric type
        
        match template.biometric_type {
            BiometricType::Face => {
                // Check for facial movement, eye blink, etc.
                let liveness_score = template.quality_metrics.uniqueness;
                Ok(liveness_score > 0.5)
            },
            BiometricType::Fingerprint => {
                // Check for blood flow, temperature, etc.
                let liveness_score = template.quality_metrics.clarity;
                Ok(liveness_score > 0.6)
            },
            BiometricType::Iris => {
                // Check for pupil response, eye movement
                let liveness_score = template.quality_metrics.completeness;
                Ok(liveness_score > 0.7)
            },
            _ => Ok(true), // Default to true for other types
        }
    }

    /// Detect spoofing attempts
    async fn detect_spoofing(&self, template: &BiometricTemplate) -> Result<bool, Box<dyn std::error::Error>> {
        // Simplified spoofing detection
        // In implementation, would use sophisticated anti-spoofing algorithms
        
        // Check for common spoofing indicators
        let mut spoofing_indicators = 0;
        
        // Low quality could indicate printed/artificial sample
        if template.quality_metrics.overall_quality < 0.3 {
            spoofing_indicators += 1;
        }
        
        // Lack of uniqueness could indicate replay attack
        if template.quality_metrics.uniqueness < 0.2 {
            spoofing_indicators += 1;
        }
        
        // Poor consistency could indicate artificial generation
        if template.quality_metrics.consistency < 0.3 {
            spoofing_indicators += 1;
        }
        
        // If multiple indicators present, likely spoofing
        Ok(spoofing_indicators >= 2)
    }

    /// Helper methods for encryption and management
    async fn serialize_template(&self, template: &BiometricTemplate) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(bincode::serialize(template)?)
    }

    async fn generate_salt(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use rand::RngCore;
        let mut salt = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        Ok(salt)
    }

    async fn derive_encryption_key(&self, identity_id: &str, salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut key_material = identity_id.as_bytes().to_vec();
        key_material.extend_from_slice(salt);
        key_material.extend_from_slice(b"biometric_recovery");
        
        let key_hash = sha2::Sha256::digest(&key_material);
        Ok(key_hash.to_vec())
    }

    fn register_nonce(&mut self, nonce: &[u8]) -> AnyhowResult<()> {
        if !self.used_nonces.insert(nonce.to_vec()) {
            return Err(anyhow!("Nonce reuse detected"));
        }
        Ok(())
    }

    async fn encrypt_template(&mut self, template_data: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, u32), Box<dyn std::error::Error>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("Invalid key length: {}", e))?;

        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        self.register_nonce(&nonce_bytes)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut buffer = template_data.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut buffer)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        Ok((buffer, nonce_bytes.to_vec(), tag.to_vec(), ENCRYPTION_VERSION_AES_GCM))
    }

    fn decrypt_template_legacy_xor(&self, encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut decrypted = Vec::new();
        for (i, &byte) in encrypted.iter().enumerate() {
            let key_byte = key[i % key.len()];
            let iv_byte = iv[i % iv.len()];
            decrypted.push(byte ^ key_byte ^ iv_byte);
        }
        Ok(decrypted)
    }

    async fn decrypt_template_aes_gcm(&self, encrypted: &[u8], key: &[u8], nonce: &[u8], tag: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("Invalid key length: {}", e))?;
        let nonce = Nonce::from_slice(nonce);

        let mut buffer = encrypted.to_vec();
        let tag = aes_gcm::Tag::from_slice(tag);

        cipher
            .decrypt_in_place_detached(nonce, b"", &mut buffer, tag)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        Ok(buffer)
    }

    async fn decrypt_template(&self, encrypted_template: &EncryptedBiometricTemplate) -> Result<BiometricTemplate, Box<dyn std::error::Error>> {
        let encryption_key = self.derive_encryption_key(&encrypted_template.identity_id, &encrypted_template.salt).await?;
        
        // Determine encryption method: use AES-GCM for new data, XOR for legacy
        let method_is_aes = encrypted_template.encryption_method.to_lowercase().contains("aes");
        let use_aes = encrypted_template.encryption_version >= ENCRYPTION_VERSION_AES_GCM
            || (method_is_aes && encrypted_template.iv.len() == AES_GCM_NONCE_SIZE)
            || encrypted_template.iv.len() == AES_GCM_NONCE_SIZE;

        let decrypted = if use_aes {
            // AES-256-GCM decryption
            if encrypted_template.tag.is_empty() && encrypted_template.encrypted_template.len() >= AES_GCM_TAG_SIZE {
                // Tag embedded at end for backward compatibility
                let split_at = encrypted_template.encrypted_template.len() - AES_GCM_TAG_SIZE;
                let tag = &encrypted_template.encrypted_template[split_at..];
                let ciphertext = &encrypted_template.encrypted_template[..split_at];
                self.decrypt_template_aes_gcm(ciphertext, &encryption_key, &encrypted_template.iv, tag).await?
            } else {
                // Tag in separate field
                self.decrypt_template_aes_gcm(&encrypted_template.encrypted_template, &encryption_key, &encrypted_template.iv, &encrypted_template.tag).await?
            }
        } else {
            // Legacy XOR decryption for backward compatibility
            self.decrypt_template_legacy_xor(&encrypted_template.encrypted_template, &encryption_key, &encrypted_template.iv)?
        };
        
        Ok(bincode::deserialize(&decrypted)?)
    }

    fn calculate_template_hash(&self, template_data: &[u8]) -> String {
        format!("{:x}", sha2::Sha256::digest(template_data))
    }

    fn is_identity_locked(&self, identity_id: &str) -> bool {
        if let Some(attempts) = self.auth_attempts.get(identity_id) {
            if let Some(locked_until) = attempts.locked_until {
                return Instant::now() < locked_until;
            }
        }
        false
    }

    fn record_successful_biometric_auth(&mut self, identity_id: &str) {
        let entry = self.auth_attempts.entry(identity_id.to_string()).or_insert(BiometricAuthAttempts {
            identity_id: identity_id.to_string(),
            successful_attempts: 0,
            failed_attempts: 0,
            last_attempt: None,
            consecutive_failures: 0,
            locked_until: None,
        });
        
        entry.successful_attempts += 1;
        entry.consecutive_failures = 0;
        entry.last_attempt = Some(Instant::now());
        entry.locked_until = None;
    }

    fn record_failed_biometric_auth(&mut self, identity_id: &str) {
        let entry = self.auth_attempts.entry(identity_id.to_string()).or_insert(BiometricAuthAttempts {
            identity_id: identity_id.to_string(),
            successful_attempts: 0,
            failed_attempts: 0,
            last_attempt: None,
            consecutive_failures: 0,
            locked_until: None,
        });
        
        entry.failed_attempts += 1;
        entry.consecutive_failures += 1;
        entry.last_attempt = Some(Instant::now());
        
        // Lock out if too many consecutive failures
        if entry.consecutive_failures >= self.security_settings.max_failed_attempts {
            entry.locked_until = Some(Instant::now() + Duration::from_secs(self.security_settings.lockout_duration_minutes as u64 * 60));
        }
    }
}

impl Default for BiometricMatchingSettings {
    fn default() -> Self {
        Self {
            similarity_threshold: 0.8,
            false_acceptance_rate: 0.001,
            false_rejection_rate: 0.01,
            matching_algorithm: "correlation".to_string(),
            quality_threshold: 0.6,
            require_liveness_detection: true,
        }
    }
}

impl Default for BiometricSecuritySettings {
    fn default() -> Self {
        Self {
            encryption_algorithm: "AES-256-GCM".to_string(),
            template_encryption_required: true,
            max_failed_attempts: 5,
            lockout_duration_minutes: 30,
            require_multi_factor: false,
            liveness_detection_required: true,
            anti_spoofing_enabled: true,
        }
    }
}

impl Default for BiometricRecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}
