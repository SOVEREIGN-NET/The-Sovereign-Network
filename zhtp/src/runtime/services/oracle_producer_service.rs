use lib_blockchain::oracle::OraclePriceAttestation;
use lib_crypto::keypair::generation::KeyPair;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleProducerConfig {
    pub min_sources_required: usize,
    pub min_valid_sources_to_attest: usize,
    pub max_source_age_secs: u64,
    pub max_deviation_bps: u32,
}

impl Default for OracleProducerConfig {
    fn default() -> Self {
        Self {
            min_sources_required: 3,
            min_valid_sources_to_attest: 2,
            max_source_age_secs: 60,
            max_deviation_bps: 500,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleFetchedPrice {
    pub source_id: String,
    pub sov_usd_price: u128,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleProducerError {
    NotCommitteeMember([u8; 32]),
    DuplicateSources,
    NotEnoughSources { expected_min: usize, got: usize },
    ZeroMedian,
    ArithmeticOverflow,
    SignFailed(String),
}

pub struct OracleProducerService {
    config: OracleProducerConfig,
}

impl OracleProducerService {
    pub fn new(config: OracleProducerConfig) -> Self {
        Self { config }
    }

    pub fn build_attestation(
        &self,
        epoch_id: u64,
        current_timestamp: u64,
        committee_members: &[[u8; 32]],
        validator_keypair: &KeyPair,
        fetched: Vec<OracleFetchedPrice>,
    ) -> Result<Option<OraclePriceAttestation>, OracleProducerError> {
        let validator_pubkey = validator_keypair.public_key.key_id;
        if !committee_members
            .iter()
            .any(|member| *member == validator_pubkey)
        {
            return Err(OracleProducerError::NotCommitteeMember(validator_pubkey));
        }

        if fetched.len() < self.config.min_sources_required {
            return Err(OracleProducerError::NotEnoughSources {
                expected_min: self.config.min_sources_required,
                got: fetched.len(),
            });
        }

        let unique_sources = fetched
            .iter()
            .map(|s| s.source_id.clone())
            .collect::<BTreeSet<_>>()
            .len();
        if unique_sources != fetched.len() {
            return Err(OracleProducerError::DuplicateSources);
        }

        let fresh_prices = fetched
            .into_iter()
            .filter(|sample| {
                // Reject samples with timestamps in the future to prevent them from bypassing
                // staleness checks via saturating subtraction.
                if sample.timestamp > current_timestamp {
                    return false;
                }

                let age_secs = current_timestamp - sample.timestamp;
                age_secs <= self.config.max_source_age_secs
            })
            .collect::<Vec<_>>();
        if fresh_prices.len() < self.config.min_valid_sources_to_attest {
            return Ok(None);
        }

        let all_fresh_price_values = fresh_prices
            .iter()
            .map(|s| s.sov_usd_price)
            .collect::<Vec<_>>();
        let fresh_median = median_u128(&all_fresh_price_values)?;
        if fresh_median == 0 {
            return Err(OracleProducerError::ZeroMedian);
        }

        let filtered_prices = fresh_prices
            .into_iter()
            .filter(|sample| {
                let deviation =
                    deviation_bps(sample.sov_usd_price, fresh_median).unwrap_or(u32::MAX);
                deviation <= self.config.max_deviation_bps
            })
            .collect::<Vec<_>>();

        if filtered_prices.len() < self.config.min_valid_sources_to_attest {
            return Ok(None);
        }

        let local_price_values = filtered_prices
            .iter()
            .map(|s| s.sov_usd_price)
            .collect::<Vec<_>>();
        let local_price = median_u128(&local_price_values)?;

        let mut attestation = OraclePriceAttestation {
            epoch_id,
            sov_usd_price: local_price,
            timestamp: current_timestamp,
            validator_pubkey,
            signature: Vec::new(),
        };

        let digest = attestation.signing_digest().map_err(|_| {
            OracleProducerError::SignFailed("failed to create signing digest".into())
        })?;
        let signature = validator_keypair
            .sign(&digest)
            .map_err(|e| OracleProducerError::SignFailed(e.to_string()))?;
        attestation.signature = signature.signature;

        Ok(Some(attestation))
    }
}

fn median_u128(values: &[u128]) -> Result<u128, OracleProducerError> {
    if values.is_empty() {
        return Err(OracleProducerError::NotEnoughSources {
            expected_min: 1,
            got: 0,
        });
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();

    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        Ok(sorted[mid])
    } else {
        let sum = sorted[mid - 1]
            .checked_add(sorted[mid])
            .ok_or(OracleProducerError::ArithmeticOverflow)?;
        Ok(sum / 2)
    }
}

fn deviation_bps(price: u128, median: u128) -> Result<u32, OracleProducerError> {
    if median == 0 {
        return Err(OracleProducerError::ZeroMedian);
    }
    let diff = price.abs_diff(median);
    let scaled = diff
        .checked_mul(10_000)
        .ok_or(OracleProducerError::ArithmeticOverflow)?;
    let bps = scaled / median;
    u32::try_from(bps).map_err(|_| OracleProducerError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(source: &str, price: u128, timestamp: u64) -> OracleFetchedPrice {
        OracleFetchedPrice {
            source_id: source.to_string(),
            sov_usd_price: price,
            timestamp,
        }
    }

    #[test]
    fn committee_member_produces_attestation() {
        let service = OracleProducerService::new(OracleProducerConfig::default());
        let keypair = KeyPair::generate().expect("keypair generation should succeed");
        let committee = vec![keypair.public_key.key_id, [9u8; 32], [8u8; 32]];
        let now = 1_700_000_000u64;

        let attestation = service
            .build_attestation(
                10,
                now,
                &committee,
                &keypair,
                vec![
                    sample("a", 200_000_000, now),
                    sample("b", 202_000_000, now - 1),
                    sample("c", 198_000_000, now - 2),
                ],
            )
            .expect("attestation flow should succeed")
            .expect("must attest with valid sources");

        assert_eq!(attestation.epoch_id, 10);
        assert_eq!(attestation.validator_pubkey, keypair.public_key.key_id);
        assert_eq!(attestation.sov_usd_price, 200_000_000);
        assert!(!attestation.signature.is_empty());
    }

    #[test]
    fn non_committee_member_rejected() {
        let service = OracleProducerService::new(OracleProducerConfig::default());
        let keypair = KeyPair::generate().expect("keypair generation should succeed");
        let committee = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let now = 1_700_000_000u64;

        let result = service.build_attestation(
            10,
            now,
            &committee,
            &keypair,
            vec![
                sample("a", 200_000_000, now),
                sample("b", 202_000_000, now - 1),
                sample("c", 198_000_000, now - 2),
            ],
        );

        assert!(matches!(
            result,
            Err(OracleProducerError::NotCommitteeMember(_))
        ));
    }

    #[test]
    fn stale_or_outlier_sources_can_force_abstain() {
        let service = OracleProducerService::new(OracleProducerConfig::default());
        let keypair = KeyPair::generate().expect("keypair generation should succeed");
        let committee = vec![keypair.public_key.key_id, [9u8; 32], [8u8; 32]];
        let now = 1_700_000_000u64;

        let attestation = service
            .build_attestation(
                10,
                now,
                &committee,
                &keypair,
                vec![
                    // Fresh but outlier
                    sample("a", 900_000_000, now),
                    // Stale
                    sample("b", 200_000_000, now - 1_000),
                    // Single valid source remains -> abstain
                    sample("c", 201_000_000, now),
                ],
            )
            .expect("pipeline should not hard-fail");

        assert!(attestation.is_none());
    }

    #[test]
    fn even_length_median_rounds_down() {
        // Test that median of even-length list averages the two middle values and rounds down
        let values = vec![100, 200, 300, 400];
        // Sorted: [100, 200, 300, 400]
        // Middle two: 200 and 300
        // Average: (200 + 300) / 2 = 250
        let median = median_u128(&values).expect("median should succeed");
        assert_eq!(median, 250);

        // Test another case: [10, 20, 30, 40] -> median = (20 + 30) / 2 = 25
        let values2 = vec![40, 10, 30, 20];
        let median2 = median_u128(&values2).expect("median should succeed");
        assert_eq!(median2, 25);

        // Test odd number remains unchanged
        let values3 = vec![100, 200, 300];
        let median3 = median_u128(&values3).expect("median should succeed");
        assert_eq!(median3, 200);
    }

    #[test]
    fn future_timestamp_samples_rejected() {
        let service = OracleProducerService::new(OracleProducerConfig::default());
        let keypair = KeyPair::generate().expect("keypair generation should succeed");
        let committee = vec![keypair.public_key.key_id, [9u8; 32], [8u8; 32]];
        let now = 1_700_000_000u64;

        // Future timestamp should be rejected, leaving insufficient sources
        let attestation = service
            .build_attestation(
                10,
                now,
                &committee,
                &keypair,
                vec![
                    // Future timestamp - should be rejected
                    sample("a", 200_000_000, now + 1_000),
                    sample("b", 202_000_000, now - 1),
                    sample("c", 198_000_000, now - 2),
                ],
            )
            .expect("pipeline should not hard-fail");

        // Only 2 valid sources remain, which is >= min_valid_sources_to_attest (2)
        // So attestation should still be produced
        assert!(attestation.is_some());
        assert_eq!(attestation.unwrap().sov_usd_price, 200_000_000);

        // Test with more future timestamps causing abstention
        let attestation2 = service
            .build_attestation(
                10,
                now,
                &committee,
                &keypair,
                vec![
                    // All future timestamps - should be rejected
                    sample("a", 200_000_000, now + 1_000),
                    sample("b", 202_000_000, now + 2_000),
                    sample("c", 198_000_000, now + 3_000),
                ],
            )
            .expect("pipeline should not hard-fail");

        // All sources rejected, not enough to attest -> abstain
        assert!(attestation2.is_none());
    }

    #[test]
    fn insufficient_sources_returns_error() {
        let service = OracleProducerService::new(OracleProducerConfig::default());
        let keypair = KeyPair::generate().expect("keypair generation should succeed");
        let committee = vec![keypair.public_key.key_id, [9u8; 32], [8u8; 32]];
        let now = 1_700_000_000u64;

        // Only 2 sources provided, but min_sources_required is 3
        let result = service.build_attestation(
            10,
            now,
            &committee,
            &keypair,
            vec![
                sample("a", 200_000_000, now),
                sample("b", 202_000_000, now - 1),
            ],
        );

        // Should return error (not Ok(None))
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OracleProducerError::NotEnoughSources { .. }
        ));
    }
}
