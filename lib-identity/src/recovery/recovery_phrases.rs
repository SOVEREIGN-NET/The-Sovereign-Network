//! Recovery phrase management for mnemonic-based identity recovery


use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::time::Instant;
use anyhow::{Result, anyhow};
use rand;

/// Recovery phrase manager for mnemonic-based identity recovery
#[derive(Debug, Clone)]
pub struct RecoveryPhraseManager {
    /// Stored recovery phrases (encrypted)
    phrases: HashMap<String, EncryptedRecoveryPhrase>,
    /// Phrase validation rules
    validation_rules: PhraseValidationRules,
    /// Usage tracking
    phrase_usage: HashMap<String, PhraseUsageInfo>,
    /// Security settings
    security_settings: PhraseSecuritySettings,
}

/// Encrypted recovery phrase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRecoveryPhrase {
    pub identity_id: String,
    pub encrypted_phrase: Vec<u8>,
    pub phrase_hash: String,
    pub encryption_method: String,
    pub salt: Vec<u8>,
    pub iv: Vec<u8>,
    pub created_at: u64,
    pub last_used: Option<u64>,
    pub usage_count: u32,
    pub max_usage: Option<u32>,
    pub expires_at: Option<u64>,
}

/// Recovery phrase in plain text (temporary use only)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryPhrase {
    pub words: Vec<String>,
    pub entropy: Vec<u8>,
    pub checksum: String,
    pub language: String,
    pub word_count: usize,
}

impl RecoveryPhrase {
    /// Create RecoveryPhrase from word list
    pub fn from_words(words: Vec<String>) -> Result<Self> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut entropy = vec![0u8; 32]; // 256 bits
        rng.fill_bytes(&mut entropy);
        
        Ok(Self {
            word_count: words.len(),
            checksum: format!("{:x}", sha2::Sha256::digest(words.join(" ").as_bytes())),
            language: "english".to_string(),
            words,
            entropy,
        })
    }
}

impl std::fmt::Display for RecoveryPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.words.join(" "))
    }
}

/// Phrase validation rules
#[derive(Debug, Clone)]
pub struct PhraseValidationRules {
    pub min_word_count: usize,
    pub max_word_count: usize,
    pub supported_languages: Vec<String>,
    pub require_checksum: bool,
    pub min_entropy_bits: usize,
    pub banned_words: Vec<String>,
    pub require_mixed_case: bool,
}

/// Phrase usage tracking information
#[derive(Debug, Clone)]
pub struct PhraseUsageInfo {
    pub identity_id: String,
    pub total_uses: u32,
    pub last_used: Option<Instant>,
    pub successful_recoveries: u32,
    pub failed_attempts: u32,
    pub created_at: Instant,
    pub last_validation: Option<Instant>,
}

/// Security settings for recovery phrases
#[derive(Debug, Clone)]
pub struct PhraseSecuritySettings {
    pub encryption_algorithm: String,
    pub key_derivation_iterations: u32,
    pub require_additional_auth: bool,
    pub auto_expire_days: Option<u32>,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u32,
}

/// Recovery phrase generation options
#[derive(Debug, Clone)]
pub struct PhraseGenerationOptions {
    pub word_count: usize,
    pub language: String,
    pub entropy_source: EntropySource,
    pub include_checksum: bool,
    pub custom_wordlist: Option<Vec<String>>,
}

/// Source of entropy for phrase generation
#[derive(Debug, Clone)]
pub enum EntropySource {
    /// System random number generator
    SystemRandom,
    /// Hardware random number generator
    HardwareRandom,
    /// User-provided entropy
    UserProvided(Vec<u8>),
    /// Combined sources
    Combined(Vec<EntropySource>),
}

/// Result of phrase validation
#[derive(Debug, Clone)]
pub struct PhraseValidationResult {
    pub valid: bool,
    pub word_count_valid: bool,
    pub checksum_valid: bool,
    pub entropy_sufficient: bool,
    pub language_supported: bool,
    pub banned_words_found: Vec<String>,
    pub strength_score: f64,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl RecoveryPhraseManager {
    /// Create new recovery phrase manager
    pub fn new() -> Self {
        Self {
            phrases: HashMap::new(),
            validation_rules: PhraseValidationRules::default(),
            phrase_usage: HashMap::new(),
            security_settings: PhraseSecuritySettings::default(),
        }
    }
    
    /// Create new recovery phrase manager with custom security settings
    pub fn with_security_settings(security_settings: PhraseSecuritySettings) -> Self {
        Self {
            phrases: HashMap::new(),
            validation_rules: PhraseValidationRules::default(),
            phrase_usage: HashMap::new(),
            security_settings,
        }
    }
    
    /// Get current security settings
    pub fn get_security_settings(&self) -> &PhraseSecuritySettings {
        &self.security_settings
    }

    /// Generate new recovery phrase
    pub async fn generate_recovery_phrase(
        &mut self,
        identity_id: &str,
        options: PhraseGenerationOptions,
    ) -> Result<RecoveryPhrase> {
        // Validate generation options
        self.validate_generation_options(&options)?;

        // Retry up to 10 times if generated phrase contains banned words
        const MAX_RETRIES: usize = 10;
        for attempt in 1..=MAX_RETRIES {
            // Generate entropy
            let entropy = self.generate_entropy(&options.entropy_source, options.word_count).await?;
            
            // Load wordlist for specified language
            let wordlist = self.load_wordlist(&options.language)?;
            
            // Generate words from entropy
            let words = self.entropy_to_words(&entropy, &wordlist, options.word_count)?;
            
            // Generate checksum if required
            let checksum = if options.include_checksum {
                self.generate_checksum(&words, &entropy)?
            } else {
                String::new()
            };

            let phrase = RecoveryPhrase {
                words: words.clone(),
                entropy,
                checksum,
                language: options.language.clone(),
                word_count: options.word_count,
            };

            // Validate generated phrase
            let validation_result = self.validate_phrase(&phrase).await?;
            if validation_result.valid {
                println!("✓ Generated {}-word recovery phrase for {} (attempt {})", options.word_count, identity_id, attempt);
                return Ok(phrase);
            }
            
            // If validation failed due to banned words, retry
            if !validation_result.banned_words_found.is_empty() {
                tracing::warn!(
                    "Generated phrase contains banned words: {:?} (attempt {}/{}), regenerating...",
                    validation_result.banned_words_found,
                    attempt,
                    MAX_RETRIES
                );
                continue;
            }
            
            // If validation failed for other reasons, don't retry
            return Err(anyhow!("Generated phrase failed validation: {:?}", validation_result.errors));
        }

        // If we exhausted all retries, return error
        Err(anyhow!("Failed to generate valid recovery phrase after {} attempts (kept hitting banned words)", MAX_RETRIES))
    }

    /// Store recovery phrase (encrypted)
    pub async fn store_recovery_phrase(
        &mut self,
        identity_id: &str,
        phrase: &RecoveryPhrase,
        additional_auth: Option<&str>,
    ) -> Result<String> {
        // Validate phrase before storage
        let validation_result = self.validate_phrase(phrase).await?;
        if !validation_result.valid {
            return Err(anyhow!("Cannot store invalid recovery phrase"));
        }

        // Check if additional auth is required
        if self.security_settings.require_additional_auth && additional_auth.is_none() {
            return Err(anyhow!("Additional authentication required for phrase storage"));
        }

        // Generate encryption key
        let salt = self.generate_salt().await?;
        let encryption_key = self.derive_encryption_key(identity_id, additional_auth, &salt).await?;
        
        // Encrypt phrase
        let phrase_text = phrase.words.join(" ");
        let (encrypted_phrase, iv) = self.encrypt_phrase(&phrase_text, &encryption_key).await?;
        
        // Calculate phrase hash for verification
        let phrase_hash = self.calculate_phrase_hash(&phrase_text);
        
        // Calculate expiration
        let expires_at = if let Some(expire_days) = self.security_settings.auto_expire_days {
            Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() + (expire_days as u64 * 86400))
        } else {
            None
        };

        // Create encrypted phrase record
        let encrypted_phrase_record = EncryptedRecoveryPhrase {
            identity_id: identity_id.to_string(),
            encrypted_phrase,
            phrase_hash,
            encryption_method: self.security_settings.encryption_algorithm.clone(),
            salt,
            iv,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            last_used: None,
            usage_count: 0,
            max_usage: None,
            expires_at,
        };

        // Store encrypted phrase
        let phrase_id = format!("phrase_{}", identity_id);
        self.phrases.insert(phrase_id.clone(), encrypted_phrase_record);
        
        // Initialize usage tracking
        self.phrase_usage.insert(phrase_id.clone(), PhraseUsageInfo {
            identity_id: identity_id.to_string(),
            total_uses: 0,
            last_used: None,
            successful_recoveries: 0,
            failed_attempts: 0,
            created_at: Instant::now(),
            last_validation: Some(Instant::now()),
        });

        println!("✓ Recovery phrase stored securely for identity {}", identity_id);
        Ok(phrase_id)
    }

    /// Recover identity using recovery phrase
    pub async fn recover_identity_with_phrase(
        &mut self,
        phrase_words: &[String],
        additional_auth: Option<&str>,
    ) -> Result<String> {
        // Reconstruct phrase
        let phrase_text = phrase_words.join(" ");
        let phrase_hash = self.calculate_phrase_hash(&phrase_text);
        
        // Find matching stored phrase
        let mut matching_phrase_id = None;
        let mut matching_identity_id = None;
        
        for (phrase_id, encrypted_phrase) in &self.phrases {
            if encrypted_phrase.phrase_hash == phrase_hash {
                matching_phrase_id = Some(phrase_id.clone());
                matching_identity_id = Some(encrypted_phrase.identity_id.clone());
                break;
            }
        }

        let phrase_id = matching_phrase_id
            .ok_or_else(|| anyhow!("No matching recovery phrase found"))?;
        let identity_id = matching_identity_id.unwrap();

        // Check usage limits and expiration
        self.check_phrase_usage_limits(&phrase_id)?;
        
        // Verify additional auth if required
        if self.security_settings.require_additional_auth && additional_auth.is_none() {
            return Err(anyhow!("Additional authentication required for recovery"));
        }

        // Decrypt and verify phrase
        let encrypted_phrase = self.phrases.get(&phrase_id).unwrap();
        let encryption_key = self.derive_encryption_key(&identity_id, additional_auth, &encrypted_phrase.salt).await?;
        let decrypted_phrase = self.decrypt_phrase(&encrypted_phrase.encrypted_phrase, &encryption_key, &encrypted_phrase.iv).await?;
        
        // Verify phrase matches
        if decrypted_phrase != phrase_text {
            self.record_failed_attempt(&phrase_id);
            return Err(anyhow!("Recovery phrase verification failed"));
        }

        // Update usage tracking
        self.record_successful_recovery(&phrase_id);
        
        println!("✓ Identity {} successfully recovered using recovery phrase", identity_id);
        Ok(identity_id)
    }

    /// Validate recovery phrase
    pub async fn validate_phrase(&self, phrase: &RecoveryPhrase) -> Result<PhraseValidationResult> {
        let mut result = PhraseValidationResult {
            valid: true,
            word_count_valid: false,
            checksum_valid: false,
            entropy_sufficient: false,
            language_supported: false,
            banned_words_found: Vec::new(),
            strength_score: 0.0,
            warnings: Vec::new(),
            errors: Vec::new(),
        };

        // Check word count
        if phrase.word_count >= self.validation_rules.min_word_count 
            && phrase.word_count <= self.validation_rules.max_word_count {
            result.word_count_valid = true;
        } else {
            result.valid = false;
            result.errors.push(format!("Word count {} not in range {}-{}", 
                phrase.word_count, self.validation_rules.min_word_count, self.validation_rules.max_word_count));
        }

        // Check language support
        if self.validation_rules.supported_languages.contains(&phrase.language) {
            result.language_supported = true;
        } else {
            result.valid = false;
            result.errors.push(format!("Language '{}' not supported", phrase.language));
        }

        // Check entropy
        let entropy_bits = phrase.entropy.len() * 8;
        if entropy_bits >= self.validation_rules.min_entropy_bits {
            result.entropy_sufficient = true;
        } else {
            result.valid = false;
            result.errors.push(format!("Entropy {} bits below minimum {}", 
                entropy_bits, self.validation_rules.min_entropy_bits));
        }

        // Check for banned words
        for word in &phrase.words {
            if self.validation_rules.banned_words.contains(word) {
                result.banned_words_found.push(word.clone());
                result.valid = false;
            }
        }
        if !result.banned_words_found.is_empty() {
            result.errors.push(format!("Banned words found: {:?}", result.banned_words_found));
        }

        // Check checksum if required
        if self.validation_rules.require_checksum {
            if !phrase.checksum.is_empty() {
                let calculated_checksum = self.generate_checksum(&phrase.words, &phrase.entropy)?;
                result.checksum_valid = calculated_checksum == phrase.checksum;
                if !result.checksum_valid {
                    result.valid = false;
                    result.errors.push("Checksum validation failed".to_string());
                }
            } else {
                result.valid = false;
                result.errors.push("Checksum required but not provided".to_string());
            }
        } else {
            result.checksum_valid = true;
        }

        // Calculate strength score
        result.strength_score = self.calculate_phrase_strength(phrase);
        
        // Add warnings for weak phrases
        if result.strength_score < 0.7 {
            result.warnings.push("Recovery phrase strength is below recommended level".to_string());
        }

        Ok(result)
    }

    /// Generate entropy from specified source
    fn generate_entropy<'a>(&'a self, source: &'a EntropySource, word_count: usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let entropy_bytes = (word_count * 11 + 7) / 8; // BIP39 entropy calculation
            
            match source {
                EntropySource::SystemRandom => {
                    use rand::RngCore;
                    let mut rng = rand::thread_rng();
                    let mut entropy = vec![0u8; entropy_bytes];
                    rng.fill_bytes(&mut entropy);
                    Ok(entropy)
                },
                EntropySource::HardwareRandom => {
                    // In implementation, would use hardware RNG
                    // For now, fall back to system random
                    use rand::RngCore;
                    let mut rng = rand::thread_rng();
                    let mut entropy = vec![0u8; entropy_bytes];
                    rng.fill_bytes(&mut entropy);
                    Ok(entropy)
                },
                EntropySource::UserProvided(user_entropy) => {
                    if user_entropy.len() < entropy_bytes {
                        return Err(anyhow!("Insufficient user-provided entropy"));
                    }
                    Ok(user_entropy[..entropy_bytes].to_vec())
                },
                EntropySource::Combined(sources) => {
                    let mut combined_entropy = Vec::new();
                    for source in sources {
                        let source_entropy = self.generate_entropy(source, word_count).await?;
                        combined_entropy.extend_from_slice(&source_entropy);
                    }
                    
                    // XOR all entropy sources together
                    let mut final_entropy = vec![0u8; entropy_bytes];
                    for i in 0..entropy_bytes {
                        for chunk in combined_entropy.chunks(entropy_bytes) {
                            if i < chunk.len() {
                                final_entropy[i] ^= chunk[i];
                            }
                        }
                    }
                    Ok(final_entropy)
                }
            }
        })
    }

    /// Convert entropy to mnemonic words
    fn entropy_to_words(&self, entropy: &[u8], wordlist: &[String], word_count: usize) -> Result<Vec<String>> {
        let mut words = Vec::new();
        let _entropy_bits = entropy.len() * 8;
        let bits_per_word = 11; // BIP39 standard
        
        // Convert entropy bytes to bit array
        let mut bit_array = Vec::new();
        for byte in entropy {
            for i in (0..8).rev() {
                bit_array.push((byte >> i) & 1);
            }
        }

        // Extract words from entropy
        for i in 0..word_count {
            let start_bit = i * bits_per_word;
            if start_bit + bits_per_word <= bit_array.len() {
                let mut word_index = 0usize;
                for j in 0..bits_per_word {
                    word_index = (word_index << 1) | (bit_array[start_bit + j] as usize);
                }
                
                if word_index < wordlist.len() {
                    words.push(wordlist[word_index].clone());
                } else {
                    return Err(anyhow!("Word index out of range"));
                }
            }
        }

        Ok(words)
    }

    /// Load wordlist for specified language
    fn load_wordlist(&self, language: &str) -> Result<Vec<String>> {
        // In implementation, would load actual BIP39 wordlists
        // For now, return a simplified wordlist
        match language {
            "english" => Ok(self.get_english_wordlist()),
            "spanish" => Ok(self.get_spanish_wordlist()),
            "french" => Ok(self.get_french_wordlist()),
            _ => Err(anyhow!("Wordlist for language '{}' not available", language)),
        }
    }

    /// Get English BIP39 wordlist (standard 2048 words)
    fn get_english_wordlist(&self) -> Vec<String> {
        // Standard BIP39 English wordlist - complete 2048 words for proper entropy
        vec![
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
            "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
            "advice", "aerobic", "affair", "afford", "afraid", "again", "against", "age",
            "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm",
            "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost",
            "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing",
            "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle",
            "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna",
            "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve",
            "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed",
            "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art",
            "article", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist",
            "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract",
            "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average",
            "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward",
            "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony",
            "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel",
            "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because",
            "become", "beef", "before", "begin", "behave", "behind", "believe", "below",
            "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond",
            "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter",
            "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind",
            "blood", "blossom", "blow", "blue", "blur", "blush", "board", "boat",
            "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border",
            "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket",
            "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge",
            "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom",
            "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build",
            "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst",
            "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin",
            "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp",
            "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon",
            "capable", "capital", "captain", "car", "carbon", "card", "care", "career",
            "careful", "careless", "cargo", "carpet", "carry", "cart", "case", "cash",
            "casino", "cast", "casual", "cat", "catalog", "catch", "category", "cattle",
            "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census",
            "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos",
            "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef",
            "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose",
            "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen",
            "city", "civil", "claim", "clamp", "clarify", "claw", "clay", "clean",
            "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip",
            "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump",
            "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil",
            "coin", "collect", "color", "column", "combine", "come", "comfort", "comic",
            "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider",
            "control", "convince", "cook", "cool", "copper", "copy", "coral", "core",
            "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course",
            "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane",
            "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew",
            "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd",
            "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal",
            "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve",
            "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance",
            "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate",
            "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer",
            "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise",
            "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy",
            "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail",
            "detect", "device", "devote", "diagram", "dial", "diamond", "diary", "dice",
            "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur",
            "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder",
            "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document",
            "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door",
            "dose", "double", "dove", "draft", "dragon", "drama", "drape", "draw",
            "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop",
            "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch",
            "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth",
            "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit",
            "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric",
            "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody",
            "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact",
            "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine",
            "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter",
            "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase",
            "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate",
            "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example",
            "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhale",
            "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire",
            "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric",
            "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame",
            "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat",
            "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal",
            "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever",
            "few", "fiber", "fiction", "field", "figure", "file", "fill", "film",
            "filter", "final", "find", "fine", "finger", "finish", "fire", "firm",
            "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame",
            "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor",
            "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil",
            "fold", "follow", "food", "foot", "force", "forest", "forget", "fork",
            "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "frame",
            "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown",
            "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future",
            "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage",
            "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge",
            "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost",
            "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad",
            "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory",
            "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose",
            "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain",
            "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief",
            "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide",
            "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer",
            "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat",
            "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog",
            "height", "held", "hello", "helmet", "help", "hen", "hero", "hidden",
            "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey",
            "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope",
            "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover",
            "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt",
            "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea",
            "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate",
            "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include",
            "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict",
            "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner",
            "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install",
            "intact", "interest", "into", "invest", "invite", "involve", "iron", "island",
            "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz",
            "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey",
            "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just",
            "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney",
            "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi",
            "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder",
            "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin",
            "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy",
            "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal",
            "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson",
            "letter", "level", "liar", "liberty", "library", "license", "life", "lift",
            "light", "like", "limb", "limit", "link", "lion", "liquid", "list",
            "little", "live", "lizard", "load", "loan", "lobster", "local", "lock",
            "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love",
            "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lying",
            "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major",
            "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual",
            "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask",
            "mass", "master", "match", "material", "math", "matrix", "matter", "maximum",
            "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media",
            "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge",
            "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight",
            "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle",
            "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile",
            "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month",
            "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor",
            "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply",
            "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery",
            "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature",
            "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve",
            "nest", "net", "network", "neutral", "never", "news", "next", "nice",
            "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose",
            "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number",
            "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe",
            "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer",
            "office", "often", "oil", "okay", "old", "olive", "olympic", "omit",
            "once", "one", "onion", "online", "only", "open", "opera", "opinion",
            "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ",
            "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output",
            "outside", "oval", "over", "own", "owner", "oxygen", "oyster", "ozone",
            "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel",
            "panic", "panther", "paper", "parade", "parent", "park", "parrot", "part",
            "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave",
            "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty",
            "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone",
            "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig",
            "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch",
            "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge",
            "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole",
            "police", "pond", "pony", "pool", "popular", "portion", "position", "possible",
            "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise",
            "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride",
            "primary", "print", "priority", "prison", "private", "prize", "problem", "process",
            "produce", "profit", "program", "project", "promote", "proof", "property", "prosper",
            "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse",
            "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse",
            "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question",
            "quick", "quiet", "quilt", "quit", "quiz", "quote", "rabbit", "raccoon",
            "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally",
            "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather",
            "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild",
            "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform",
            "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief",
            "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent",
            "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble",
            "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion",
            "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich",
            "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple",
            "risk", "ritual", "rival", "river", "road", "roast", "rob", "robot",
            "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate",
            "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule",
            "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail",
            "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand",
            "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan",
            "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion",
            "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season",
            "seat", "second", "secret", "section", "security", "seed", "seek", "segment",
            "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service",
            "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share",
            "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shirt",
            "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp",
            "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight",
            "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since",
            "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch",
            "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep",
            "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow",
            "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake",
            "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda",
            "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song",
            "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south",
            "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell",
            "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
            "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring",
            "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage",
            "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel",
            "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach",
            "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong",
            "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway",
            "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer",
            "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface",
            "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp",
            "swap", "swear", "sweet", "swift", "swim", "swing", "switch", "sword",
            "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail",
            "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo",
            "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent",
            "term", "test", "text", "thank", "that", "theme", "then", "theory",
            "there", "they", "thing", "this", "thought", "three", "thrive", "throw",
            "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time",
            "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today",
            "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone",
            "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch",
            "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town",
            "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap",
            "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe",
            "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true",
            "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble",
            "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice",
            "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable",
            "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy",
            "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual",
            "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban",
            "urge", "usage", "use", "used", "useful", "useless", "usual", "utility",
            "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish",
            "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture",
            "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable",
            "vibe", "vicious", "victory", "video", "view", "village", "vintage", "violin",
            "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal",
            "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon",
            "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior",
            "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon",
            "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome",
            "west", "wet", "what", "wheat", "wheel", "when", "where", "whip",
            "whisper", "wide", "width", "wife", "wild", "will", "win", "window",
            "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise",
            "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word",
            "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist",
            "write", "wrong", "yard", "year", "yellow", "you", "young", "youth",
            "zebra", "zero", "zone", "zoo"
        ].iter().map(|s| s.to_string()).collect()
    }

    /// Get Spanish BIP39 wordlist (simplified)
    fn get_spanish_wordlist(&self) -> Vec<String> {
        (0..2048).map(|i| format!("palabra{:04}", i)).collect()
    }

    /// Get French BIP39 wordlist (simplified)
    fn get_french_wordlist(&self) -> Vec<String> {
        (0..2048).map(|i| format!("mot{:04}", i)).collect()
    }

    /// Generate checksum for phrase
    fn generate_checksum(&self, words: &[String], entropy: &[u8]) -> Result<String> {
        // Simple checksum implementation
        let phrase_text = words.join(" ");
        let combined = format!("{}{}", phrase_text, hex::encode(entropy));
        Ok(format!("{:x}", md5::compute(combined.as_bytes())))
    }

    /// Calculate phrase strength score
    fn calculate_phrase_strength(&self, phrase: &RecoveryPhrase) -> f64 {
        let mut score = 0.0;
        
        // Word count contributes to strength
        score += (phrase.word_count as f64 / 24.0) * 0.4; // Max 24 words
        
        // Entropy contributes to strength
        let entropy_bits = phrase.entropy.len() * 8;
        score += (entropy_bits as f64 / 256.0) * 0.4; // Max 256 bits
        
        // Language diversity (if using multiple languages)
        score += 0.1;
        
        // Checksum presence
        if !phrase.checksum.is_empty() {
            score += 0.1;
        }
        
        score.min(1.0)
    }

    /// Additional helper methods for encryption, validation, etc.
    async fn generate_salt(&self) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut salt = vec![0u8; 32];
        rng.fill_bytes(&mut salt);
        Ok(salt)
    }

    async fn derive_encryption_key(&self, identity_id: &str, additional_auth: Option<&str>, salt: &[u8]) -> Result<Vec<u8>> {
        // Simple key derivation (in implementation, use proper KDF)
        let mut key_material = identity_id.as_bytes().to_vec();
        if let Some(auth) = additional_auth {
            key_material.extend_from_slice(auth.as_bytes());
        }
        key_material.extend_from_slice(salt);
        
        // Hash to create 32-byte key
        let key_hash = sha2::Sha256::digest(&key_material);
        Ok(key_hash.to_vec())
    }

    async fn encrypt_phrase(&self, phrase: &str, key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Simple encryption (in implementation, use proper AES encryption)
        let mut iv = vec![0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut iv);
        
        let mut encrypted = Vec::new();
        let phrase_bytes = phrase.as_bytes();
        
        for (i, &byte) in phrase_bytes.iter().enumerate() {
            let key_byte = key[i % key.len()];
            let iv_byte = iv[i % iv.len()];
            encrypted.push(byte ^ key_byte ^ iv_byte);
        }
        
        Ok((encrypted, iv))
    }

    async fn decrypt_phrase(&self, encrypted: &[u8], key: &[u8], iv: &[u8]) -> Result<String> {
        let mut decrypted = Vec::new();
        
        for (i, &byte) in encrypted.iter().enumerate() {
            let key_byte = key[i % key.len()];
            let iv_byte = iv[i % iv.len()];
            decrypted.push(byte ^ key_byte ^ iv_byte);
        }
        
        Ok(String::from_utf8(decrypted)?)
    }

    fn calculate_phrase_hash(&self, phrase: &str) -> String {
        format!("{:x}", sha2::Sha256::digest(phrase.as_bytes()))
    }

    fn check_phrase_usage_limits(&self, phrase_id: &str) -> Result<()> {
        if let Some(encrypted_phrase) = self.phrases.get(phrase_id) {
            // Check expiration
            if let Some(expires_at) = encrypted_phrase.expires_at {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                if now > expires_at {
                    return Err(anyhow!("Recovery phrase has expired"));
                }
            }
            
            // Check usage limits
            if let Some(max_usage) = encrypted_phrase.max_usage {
                if encrypted_phrase.usage_count >= max_usage {
                    return Err(anyhow!("Recovery phrase usage limit exceeded"));
                }
            }
        }
        
        Ok(())
    }

    fn record_successful_recovery(&mut self, phrase_id: &str) {
        if let Some(usage_info) = self.phrase_usage.get_mut(phrase_id) {
            usage_info.total_uses += 1;
            usage_info.successful_recoveries += 1;
            usage_info.last_used = Some(Instant::now());
        }
        
        if let Some(encrypted_phrase) = self.phrases.get_mut(phrase_id) {
            encrypted_phrase.usage_count += 1;
            encrypted_phrase.last_used = Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs());
        }
    }

    fn record_failed_attempt(&mut self, phrase_id: &str) {
        if let Some(usage_info) = self.phrase_usage.get_mut(phrase_id) {
            usage_info.failed_attempts += 1;
        }
    }

    fn validate_generation_options(&self, options: &PhraseGenerationOptions) -> Result<()> {
        if options.word_count < self.validation_rules.min_word_count 
            || options.word_count > self.validation_rules.max_word_count {
            return Err(anyhow!("Word count {} not in supported range", options.word_count));
        }
        
        if !self.validation_rules.supported_languages.contains(&options.language) {
            return Err(anyhow!("Language '{}' not supported", options.language));
        }
        
        Ok(())
    }

    /// Restore identity from 20-word recovery phrase
    pub async fn restore_from_phrase(&self, phrase_words: &[String]) -> Result<(crate::types::IdentityId, Vec<u8>, Vec<u8>, [u8; 32])> {
        use lib_crypto::{hash_blake3, derive_keys};
        use crate::types::IdentityId;
        
        // Validate phrase format
        if phrase_words.len() != 20 {
            return Err(anyhow!("Recovery phrase must be exactly 20 words, got {}", phrase_words.len()));
        }
        
        // Join words to create seed material
        let phrase_text = phrase_words.join(" ");
        
        // Derive entropy from phrase using Blake3
        let phrase_hash = hash_blake3(phrase_text.as_bytes());
        
        // Generate identity seed from phrase
        let seed_material = [
            phrase_hash.as_slice(),
            b"ZHTP_identity_seed_v1"
        ].concat();
        let identity_seed_hash = hash_blake3(&seed_material);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&identity_seed_hash);
        
        // Derive private key from seed
        let private_key_material = derive_keys(
            &seed,
            b"ZHTP_private_key_derivation",
            64
        )?;
        
        // Derive public key from private key
        let public_key_material = [
            &private_key_material[..32],
            b"ZHTP_public_key_derivation"
        ].concat();
        let public_key = hash_blake3(&public_key_material).to_vec();
        
        // Create identity ID from public key
        let identity_id_hash = hash_blake3(&[
            public_key.as_slice(),
            b"ZHTP_identity_id"
        ].concat());
        let identity_id = lib_crypto::Hash::from_bytes(&identity_id_hash);
        
        tracing::info!(
            "🔓 Identity restored from recovery phrase: {}",
            hex::encode(&identity_id.0[..8])
        );
        
        Ok((identity_id, private_key_material, public_key, seed))
    }
}

impl Default for PhraseValidationRules {
    fn default() -> Self {
        Self {
            min_word_count: 12,
            max_word_count: 24,
            supported_languages: vec!["english".to_string(), "spanish".to_string(), "french".to_string()],
            require_checksum: true,
            min_entropy_bits: 128,
            banned_words: vec!["password".to_string(), "secret".to_string(), "private".to_string()],
            require_mixed_case: false,
        }
    }
}

impl Default for PhraseSecuritySettings {
    fn default() -> Self {
        Self {
            encryption_algorithm: "AES-256-GCM".to_string(),
            key_derivation_iterations: 100000,
            require_additional_auth: true,
            auto_expire_days: Some(365),
            max_failed_attempts: 5,
            lockout_duration_minutes: 30,
        }
    }
}

impl Default for RecoveryPhraseManager {
    fn default() -> Self {
        Self::new()
    }
}
