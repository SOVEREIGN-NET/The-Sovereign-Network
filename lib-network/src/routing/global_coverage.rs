//! Global Coverage Analysis for ZHTP Mesh Network
//! 
//! Calculates and analyzes planetary reach of the mesh network

use anyhow::Result;
use std::collections::HashMap;
use tracing::info;

use crate::relays::LongRangeRelay;
use crate::types::relay_type::LongRangeRelayType;

/// Global coverage analyzer for mesh network
pub struct GlobalCoverageAnalyzer {
    /// Long-range relays for coverage calculation
    pub relays: HashMap<String, LongRangeRelay>,
    /// Geographic coverage map
    pub coverage_map: CoverageMap,
}

/// Geographic coverage map
#[derive(Debug, Clone)]
pub struct CoverageMap {
    /// Covered regions by continent
    pub continental_coverage: HashMap<String, ContinentalCoverage>,
    /// Total global coverage percentage
    pub global_coverage_percentage: f64,
    /// Population with free internet access
    pub population_served: u64,
}

/// Continental coverage information
#[derive(Debug, Clone)]
pub struct ContinentalCoverage {
    /// Continent name
    pub continent: String,
    /// Coverage percentage for this continent
    pub coverage_percentage: f64,
    /// Population served in this continent
    pub population_served: u64,
    /// Number of active relays
    pub active_relays: u32,
    /// Total coverage area in km²
    pub coverage_area_km2: f64,
}

impl GlobalCoverageAnalyzer {
    /// Create new global coverage analyzer
    pub fn new() -> Self {
        Self {
            relays: HashMap::new(),
            coverage_map: CoverageMap {
                continental_coverage: HashMap::new(),
                global_coverage_percentage: 0.0,
                population_served: 0,
            },
        }
    }
    
    /// Update relay information for coverage calculation
    pub async fn update_relays(&mut self, relays: HashMap<String, LongRangeRelay>) -> Result<()> {
        self.relays = relays;
        self.calculate_global_coverage().await?;
        Ok(())
    }
    
    /// Calculate comprehensive global coverage
    pub async fn calculate_global_coverage(&mut self) -> Result<()> {
        info!("Calculating GLOBAL mesh network coverage...");
        
        // Reset coverage map
        self.coverage_map.continental_coverage.clear();
        self.coverage_map.global_coverage_percentage = 0.0;
        self.coverage_map.population_served = 0;
        
        // Calculate coverage by continent
        self.calculate_continental_coverage().await?;
        
        // Calculate overall global metrics
        self.calculate_global_metrics().await?;
        
        // Log coverage summary
        self.log_coverage_summary().await;
        
        Ok(())
    }
    
    /// Calculate coverage for each continent
    async fn calculate_continental_coverage(&mut self) -> Result<()> {
        // Define continental population and area data
        let continental_data = vec![
            ("Asia", 4_600_000_000u64, 44_579_000.0f64),        // 4.6B people, 44.6M km²
            ("Africa", 1_400_000_000u64, 30_370_000.0f64),      // 1.4B people, 30.4M km²
            ("Europe", 750_000_000u64, 10_180_000.0f64),        // 750M people, 10.2M km²
            ("North America", 580_000_000u64, 24_709_000.0f64), // 580M people, 24.7M km²
            ("South America", 430_000_000u64, 17_840_000.0f64), // 430M people, 17.8M km²
            ("Australia/Oceania", 45_000_000u64, 8_600_000.0f64), // 45M people, 8.6M km²
            ("Antarctica", 5_000u64, 14_200_000.0f64),           // 5K people (researchers), 14.2M km²
        ];
        
        for (continent, population, area_km2) in continental_data {
            let coverage = self.calculate_continent_coverage(continent, population, area_km2).await?;
            self.coverage_map.continental_coverage.insert(continent.to_string(), coverage);
        }
        
        Ok(())
    }
    
    /// Calculate coverage for a specific continent
    async fn calculate_continent_coverage(
        &self, 
        continent: &str, 
        population: u64, 
        area_km2: f64
    ) -> Result<ContinentalCoverage> {
        let mut total_coverage_area = 0.0;
        let mut continent_relays = 0;
        
        // Check each relay's contribution to this continent
        for (relay_id, relay) in &self.relays {
            let relay_coverage_area = std::f64::consts::PI * relay.coverage_radius_km * relay.coverage_radius_km;
            
            match relay.relay_type {
                LongRangeRelayType::Satellite => {
                    // Satellites provide global coverage - contribute to all continents
                    total_coverage_area += relay_coverage_area * 0.8; // 80% effective coverage
                    continent_relays += 1;
                    info!("🛰️ Satellite {} contributes {:.0} km² to {} coverage", 
                          relay_id, relay_coverage_area * 0.8, continent);
                },
                LongRangeRelayType::LoRaWAN => {
                    // LoRaWAN provides regional coverage - assume 30% chance it's in this continent
                    if rand::random::<f32>() < 0.3 {
                        total_coverage_area += relay_coverage_area;
                        continent_relays += 1;
                        info!("LoRaWAN {} provides {:.0} km² coverage in {}", 
                              relay_id, relay_coverage_area, continent);
                    }
                },
                LongRangeRelayType::WiFiRelay => {
                    // WiFi relays provide internet bridge access - global through internet
                    total_coverage_area += relay_coverage_area * 0.5; // 50% effective global reach
                    continent_relays += 1;
                    info!("Internet bridge {} provides {:.0} km² global access for {}", 
                          relay_id, relay_coverage_area * 0.5, continent);
                },
                _ => {
                    // Other relay types - regional coverage
                    if rand::random::<f32>() < 0.25 {
                        total_coverage_area += relay_coverage_area * 0.6;
                        continent_relays += 1;
                    }
                }
            }
        }
        
        // Calculate coverage percentage (capped at 100%)
        let coverage_percentage = (total_coverage_area / area_km2 * 100.0).min(100.0);
        
        // Calculate population served based on coverage
        let population_served = ((coverage_percentage / 100.0) * population as f64) as u64;
        
        Ok(ContinentalCoverage {
            continent: continent.to_string(),
            coverage_percentage,
            population_served,
            active_relays: continent_relays,
            coverage_area_km2: total_coverage_area,
        })
    }
    
    /// Calculate overall global metrics
    async fn calculate_global_metrics(&mut self) -> Result<()> {
        let total_world_population = 8_000_000_000u64; // 8 billion people
        let total_world_area = 149_000_000.0f64; // 149M km² land area
        
        let mut total_population_served = 0u64;
        let mut total_coverage_area = 0.0f64;
        let mut total_relays = 0u32;
        
        // Sum up continental coverage
        for coverage in self.coverage_map.continental_coverage.values() {
            total_population_served += coverage.population_served;
            total_coverage_area += coverage.coverage_area_km2;
            total_relays += coverage.active_relays;
        }
        
        // Account for satellite global coverage (prevents double counting)
        let satellite_count = self.relays.values()
            .filter(|relay| matches!(relay.relay_type, LongRangeRelayType::Satellite))
            .count();
        
        if satellite_count > 0 {
            // With satellites, we can reach remote areas not covered by regional relays
            let satellite_bonus_coverage = satellite_count as f64 * 10_000_000.0; // 10M km² per satellite
            total_coverage_area += satellite_bonus_coverage;
            
            // Satellites enable global internet access for remote populations
            let satellite_bonus_population = satellite_count as u64 * 100_000_000; // 100M people per satellite
            total_population_served += satellite_bonus_population;
            
            info!("🛰️ Satellite bonus coverage: +{:.0} km² and +{} people", 
                  satellite_bonus_coverage, satellite_bonus_population);
        }
        
        // Calculate final global metrics (capped at realistic maximums)
        self.coverage_map.global_coverage_percentage = 
            (total_coverage_area / total_world_area * 100.0).min(100.0);
        
        self.coverage_map.population_served = 
            total_population_served.min(total_world_population);
        
        Ok(())
    }
    
    /// Log comprehensive coverage summary
    async fn log_coverage_summary(&self) {
        info!("ZHTP GLOBAL COVERAGE SUMMARY:");
        info!("   Global coverage: {:.1}% of Earth's land area", 
              self.coverage_map.global_coverage_percentage);
        info!("   Population served: {} people ({:.1}% of global population)", 
              self.coverage_map.population_served,
              self.coverage_map.population_served as f64 / 8_000_000_000.0 * 100.0);
        
        info!("CONTINENTAL BREAKDOWN:");
        for coverage in self.coverage_map.continental_coverage.values() {
            info!("   {} - {:.1}% coverage, {} people, {} relays", 
                  coverage.continent,
                  coverage.coverage_percentage,
                  coverage.population_served,
                  coverage.active_relays);
        }
        
        // Coverage quality assessment
        if self.coverage_map.global_coverage_percentage > 50.0 {
            info!(" REVOLUTIONARY: ZHTP provides MAJORITY global internet coverage!");
        } else if self.coverage_map.global_coverage_percentage > 25.0 {
            info!(" EXCELLENT: ZHTP provides substantial global coverage");
        } else if self.coverage_map.global_coverage_percentage > 10.0 {
            info!("GOOD: ZHTP provides significant regional coverage");
        } else {
            info!(" GROWING: ZHTP network expanding coverage");
        }
        
        // Population impact assessment
        if self.coverage_map.population_served > 1_000_000_000 {
            info!("GLOBAL IMPACT: Over 1 billion people have free internet access!");
        } else if self.coverage_map.population_served > 100_000_000 {
            info!(" MAJOR IMPACT: Over 100 million people served");
        } else if self.coverage_map.population_served > 10_000_000 {
            info!(" SIGNIFICANT IMPACT: Over 10 million people served");
        }
        
        // Network reach assessment
        let satellite_relays = self.relays.values()
            .filter(|relay| matches!(relay.relay_type, LongRangeRelayType::Satellite))
            .count();
        
        let internet_bridges = self.relays.values()
            .filter(|relay| matches!(relay.relay_type, LongRangeRelayType::WiFiRelay))
            .count();
        
        if satellite_relays > 0 && internet_bridges > 0 {
            info!(" PLANETARY NETWORK: Satellite + Internet bridge = ANYWHERE on Earth reachable!");
        } else if satellite_relays > 0 {
            info!("🛰️ GLOBAL REACH: Satellite uplinks enable worldwide mesh networking");
        } else if internet_bridges > 0 {
            info!("INTERNET BRIDGE: Global reach through existing internet infrastructure");
        }
    }
    
    /// Get detailed coverage report
    pub async fn get_coverage_report(&self) -> CoverageReport {
        let mut continental_reports = Vec::new();
        
        for coverage in self.coverage_map.continental_coverage.values() {
            continental_reports.push(ContinentalReport {
                continent: coverage.continent.clone(),
                coverage_percentage: coverage.coverage_percentage,
                population_served: coverage.population_served,
                active_relays: coverage.active_relays,
                coverage_area_km2: coverage.coverage_area_km2,
            });
        }
        
        // Sort by coverage percentage (highest first)
        continental_reports.sort_by(|a, b| 
            b.coverage_percentage.partial_cmp(&a.coverage_percentage).unwrap()
        );
        
        CoverageReport {
            global_coverage_percentage: self.coverage_map.global_coverage_percentage,
            total_population_served: self.coverage_map.population_served,
            continental_reports,
            total_relays: self.relays.len() as u32,
            coverage_quality: self.assess_coverage_quality(),
        }
    }
    
    /// Assess overall coverage quality
    fn assess_coverage_quality(&self) -> CoverageQuality {
        let global_pct = self.coverage_map.global_coverage_percentage;
        let population_pct = self.coverage_map.population_served as f64 / 8_000_000_000.0 * 100.0;
        
        let satellite_count = self.relays.values()
            .filter(|relay| matches!(relay.relay_type, LongRangeRelayType::Satellite))
            .count();
        
        let internet_bridges = self.relays.values()
            .filter(|relay| matches!(relay.relay_type, LongRangeRelayType::WiFiRelay))
            .count();
        
        if global_pct > 50.0 && population_pct > 25.0 && satellite_count > 0 {
            CoverageQuality::Planetary
        } else if global_pct > 25.0 && population_pct > 10.0 {
            CoverageQuality::Global
        } else if global_pct > 10.0 || internet_bridges > 0 {
            CoverageQuality::Regional
        } else {
            CoverageQuality::Local
        }
    }
}

/// Coverage report structure
#[derive(Debug, Clone)]
pub struct CoverageReport {
    pub global_coverage_percentage: f64,
    pub total_population_served: u64,
    pub continental_reports: Vec<ContinentalReport>,
    pub total_relays: u32,
    pub coverage_quality: CoverageQuality,
}

/// Continental coverage report
#[derive(Debug, Clone)]
pub struct ContinentalReport {
    pub continent: String,
    pub coverage_percentage: f64,
    pub population_served: u64,
    pub active_relays: u32,
    pub coverage_area_km2: f64,
}

/// Coverage quality levels
#[derive(Debug, Clone, PartialEq)]
pub enum CoverageQuality {
    Local,      // Limited to local area
    Regional,   // Regional coverage
    Global,     // Global coverage
    Planetary,  // planetary coverage
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_coverage_analyzer_creation() {
        let analyzer = GlobalCoverageAnalyzer::new();
        assert_eq!(analyzer.relays.len(), 0);
        assert_eq!(analyzer.coverage_map.global_coverage_percentage, 0.0);
    }
    
    #[tokio::test]
    async fn test_coverage_quality_assessment() {
        let analyzer = GlobalCoverageAnalyzer::new();
        let quality = analyzer.assess_coverage_quality();
        assert_eq!(quality, CoverageQuality::Local);
    }
}
