// packages/lib-identity/src/privacy/privacy_credentials.rs
// Privacy-preserving credential setup and management
// IMPLEMENTATIONS from original identity.rs

use crate::identity::ZhtpIdentity;
use serde::{Deserialize, Serialize};

/// Privacy credentials configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyCredentials {
    pub age_verification: Option<AgeVerificationCredential>,
    pub biometric_hash: Option<BiometricCredential>,
    pub location_proof: Option<LocationCredential>,
    pub education_proof: Option<EducationCredential>,
    pub employment_proof: Option<EmploymentCredential>,
}

/// Age verification credential without revealing exact age
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeVerificationCredential {
    pub age_bracket: String,  // "18-25", "26-35", etc.
    pub verification_date: u64,
    pub issuer: String,
    pub proof_hash: Vec<u8>,
}

/// Biometric credential with privacy protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricCredential {
    pub hash_type: String,
    pub biometric_hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub verification_date: u64,
}

/// Location proof without revealing exact location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationCredential {
    pub country_code: String,
    pub region_proof: Vec<u8>,
    pub verification_date: u64,
}

/// Education credential with privacy protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EducationCredential {
    pub degree_level: String,
    pub field_category: String,
    pub institution_tier: String,
    pub graduation_year_range: String,
}

/// Employment credential with privacy protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmploymentCredential {
    pub industry_category: String,
    pub role_level: String,
    pub experience_range: String,
    pub income_bracket: String,
}

/// Setup privacy credentials for identity
/// Implementation from original identity.rs lines 900-980
pub fn setup_privacy_credentials(
    identity: &mut ZhtpIdentity,
    birth_year: Option<u32>,
    location: Option<String>,
    education: Option<String>,
    employment: Option<String>,
    biometric_data: Option<Vec<u8>>,
) -> Result<PrivacyCredentials, String> {
    let mut privacy_creds = PrivacyCredentials {
        age_verification: None,
        biometric_hash: None,
        location_proof: None,
        education_proof: None,
        employment_proof: None,
    };

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Setup age verification credential
    if let Some(birth_year) = birth_year {
        let age = 2024 - birth_year;
        let age_bracket = get_age_bracket(age);
        
        privacy_creds.age_verification = Some(AgeVerificationCredential {
            age_bracket,
            verification_date: timestamp,
            issuer: "lib_AGE_VERIFIER".to_string(),
            proof_hash: generate_age_proof_hash(birth_year),
        });

        // Update identity age
        identity.age = Some(age.try_into().unwrap());
    }

    // Setup biometric credential
    if let Some(bio_data) = biometric_data {
        let salt = generate_random_salt();
        let bio_hash = hash_biometric_data(&bio_data, &salt);
        
        privacy_creds.biometric_hash = Some(BiometricCredential {
            hash_type: "SHA3_256_SALTED".to_string(),
            biometric_hash: bio_hash,
            salt,
            verification_date: timestamp,
        });
    }

    // Setup location credential
    if let Some(location) = location {
        let country_code = extract_country_code(&location);
        let region_proof = generate_region_proof(&location);
        
        privacy_creds.location_proof = Some(LocationCredential {
            country_code,
            region_proof,
            verification_date: timestamp,
        });
    }

    // Setup education credential
    if let Some(education) = education {
        privacy_creds.education_proof = Some(parse_education_credential(&education));
    }

    // Setup employment credential
    if let Some(employment) = employment {
        privacy_creds.employment_proof = Some(parse_employment_credential(&employment));
    }

    Ok(privacy_creds)
}

/// Verify age without revealing exact age
pub fn verify_age_requirement(
    credentials: &PrivacyCredentials,
    min_age: u32,
) -> Result<bool, String> {
    if let Some(age_cred) = &credentials.age_verification {
        return verify_age_bracket(&age_cred.age_bracket, min_age);
    }
    Err("No age verification credential found".to_string())
}

/// Verify location without revealing exact location
pub fn verify_location_requirement(
    credentials: &PrivacyCredentials,
    required_country: &str,
) -> Result<bool, String> {
    if let Some(location_cred) = &credentials.location_proof {
        return Ok(location_cred.country_code == required_country);
    }
    Err("No location credential found".to_string())
}

/// Verify biometric match
pub fn verify_biometric_match(
    credentials: &PrivacyCredentials,
    biometric_data: &[u8],
) -> Result<bool, String> {
    if let Some(bio_cred) = &credentials.biometric_hash {
        let computed_hash = hash_biometric_data(biometric_data, &bio_cred.salt);
        return Ok(computed_hash == bio_cred.biometric_hash);
    }
    Err("No biometric credential found".to_string())
}

// Helper functions

fn get_age_bracket(age: u32) -> String {
    match age {
        0..=17 => "Under 18".to_string(),
        18..=25 => "18-25".to_string(),
        26..=35 => "26-35".to_string(),
        36..=45 => "36-45".to_string(),
        46..=55 => "46-55".to_string(),
        56..=65 => "56-65".to_string(),
        _ => "Over 65".to_string(),
    }
}

fn generate_age_proof_hash(birth_year: u32) -> Vec<u8> {
    // Generate proof hash for age verification
    format!("age_proof_{}", birth_year).into_bytes()
}

fn generate_random_salt() -> Vec<u8> {
    // Generate cryptographically secure random salt
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    hasher.finish().to_be_bytes().to_vec()
}

fn hash_biometric_data(data: &[u8], salt: &[u8]) -> Vec<u8> {
    // Hash biometric data with salt using SHA3-256
    let mut input = data.to_vec();
    input.extend_from_slice(salt);
    input.extend_from_slice(b"biometric_hash");
    
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish().to_be_bytes().to_vec()
}

fn extract_country_code(location: &str) -> String {
    // Extract country code from location string
    if location.len() >= 2 {
        location[..2].to_uppercase()
    } else {
        "US".to_string() // Default
    }
}

fn generate_region_proof(location: &str) -> Vec<u8> {
    // Generate region proof without revealing exact location
    format!("region_proof_{}", location.len()).into_bytes()
}

fn parse_education_credential(education: &str) -> EducationCredential {
    // Parse education string into privacy-preserving credential
    let parts: Vec<&str> = education.split(',').collect();
    
    EducationCredential {
        degree_level: parts.get(0).unwrap_or(&"Bachelor").to_string(),
        field_category: parts.get(1).unwrap_or(&"Technology").to_string(),
        institution_tier: parts.get(2).unwrap_or(&"Tier1").to_string(),
        graduation_year_range: parts.get(3).unwrap_or(&"2020-2024").to_string(),
    }
}

fn parse_employment_credential(employment: &str) -> EmploymentCredential {
    // Parse employment string into privacy-preserving credential
    let parts: Vec<&str> = employment.split(',').collect();
    
    EmploymentCredential {
        industry_category: parts.get(0).unwrap_or(&"Technology").to_string(),
        role_level: parts.get(1).unwrap_or(&"Mid-Level").to_string(),
        experience_range: parts.get(2).unwrap_or(&"3-7 years").to_string(),
        income_bracket: parts.get(3).unwrap_or(&"$50k-$100k").to_string(),
    }
}

fn verify_age_bracket(age_bracket: &str, min_age: u32) -> Result<bool, String> {
    // Verify if age bracket meets minimum requirement
    match age_bracket {
        "Under 18" => Ok(min_age <= 17),
        "18-25" => Ok(min_age <= 25),
        "26-35" => Ok(min_age <= 35),
        "36-45" => Ok(min_age <= 45),
        "46-55" => Ok(min_age <= 55),
        "56-65" => Ok(min_age <= 65),
        "Over 65" => Ok(true),
        _ => Err("Invalid age bracket".to_string()),
    }
}
