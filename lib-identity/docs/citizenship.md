# Citizenship Module

Digital citizenship system providing verifiable citizenship credentials, voting rights management, and civic participation within the Sovereign Network.

## Overview

The citizenship module implements a comprehensive digital citizenship framework that enables users to establish verifiable citizenship status, participate in governance, exercise voting rights, and engage in civic activities while maintaining privacy and security.

## Core Components

### DigitalCitizen

The fundamental structure representing a digital citizen.

```rust
pub struct DigitalCitizen {
    pub citizen_id: String,
    pub identity_id: IdentityId,
    pub citizenship_level: CitizenshipLevel,
    pub voting_rights: VotingRights,
    pub civic_participation: CivicParticipation,
    pub reputation_score: f64,
    pub citizenship_proof: CitizenshipProof,
    pub established_at: u64,
}
```

**Key Features:**
- **Verifiable Citizenship**: Cryptographically provable citizenship status
- **Voting Rights**: Secure and private voting capabilities
- **Civic Participation**: Engagement tracking and incentives
- **Reputation System**: Merit-based reputation scoring
- **Privacy Preservation**: Zero-knowledge citizenship proofs

### CitizenshipRegistry

Central registry managing all digital citizenship records.

```rust
pub struct CitizenshipRegistry {
    pub citizens: HashMap<String, DigitalCitizen>,
    pub voting_systems: HashMap<String, VotingSystem>,
    pub governance_proposals: Vec<GovernanceProposal>,
    pub civic_activities: Vec<CivicActivity>,
    pub reputation_engine: ReputationEngine,
}
```

## Establishing Digital Citizenship

### Citizenship Application Process

```rust
use lib_identity::citizenship::{CitizenshipRegistry, CitizenshipApplication, CitizenshipLevel};

let mut citizenship_registry = CitizenshipRegistry::new();

// Submit citizenship application
let citizenship_application = CitizenshipApplication {
    applicant_identity: user_identity.id.clone(),
    requested_level: CitizenshipLevel::Full,
    supporting_documents: vec![
        government_id_credential,
        address_verification_credential,
        background_check_credential,
    ],
    civic_knowledge_test_score: Some(92.5),
    sponsor_references: vec![sponsor1_id, sponsor2_id],
    community_endorsements: endorsement_proofs,
};

// Process application
let application_result = citizenship_registry.process_application(
    citizenship_application
).await?;

match application_result.status {
    ApplicationStatus::Approved => {
        println!("Citizenship application approved!");
        println!("Citizen ID: {}", application_result.citizen_id);
        println!("Citizenship level: {:?}", application_result.citizenship_level);
    },
    ApplicationStatus::UnderReview => {
        println!("Application under review");
        println!("Expected decision: {}", application_result.expected_decision_date);
    },
    ApplicationStatus::RequiresAdditionalInfo => {
        println!("Additional information required:");
        for requirement in &application_result.additional_requirements {
            println!("- {}", requirement.description);
        }
    },
    ApplicationStatus::Rejected => {
        println!("Application rejected: {}", application_result.rejection_reason);
    }
}
```

### Citizenship Verification Process

```rust
use lib_identity::citizenship::verification::{CitizenshipVerifier, VerificationLevel};

let citizenship_verifier = CitizenshipVerifier::new();

// Comprehensive citizenship verification
let verification_result = citizenship_verifier.verify_citizenship(
    CitizenshipVerificationRequest {
        citizen_id: citizen.citizen_id.clone(),
        verification_level: VerificationLevel::Comprehensive,
        check_voting_eligibility: true,
        check_civic_participation: true,
        check_reputation_standing: true,
        privacy_preserving: true,
    }
).await?;

println!("Citizenship verification results:");
println!("Status: {:?}", verification_result.citizenship_status);
println!("Level: {:?}", verification_result.citizenship_level);
println!("Voting eligible: {}", verification_result.voting_eligible);
println!("Civic participation score: {:.2}", verification_result.civic_participation_score);
println!("Reputation score: {:.2}", verification_result.reputation_score);

// Generate zero-knowledge citizenship proof
let zk_citizenship_proof = citizenship_verifier.generate_zk_proof(
    &citizen.citizen_id,
    ZkProofRequirements {
        prove_citizenship_level: Some(CitizenshipLevel::Full),
        prove_voting_eligibility: true,
        prove_good_standing: true,
        hide_personal_details: true,
    }
).await?;

println!("Zero-knowledge citizenship proof generated");
```

## Citizenship Levels and Rights

### Citizenship Hierarchy

```rust
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CitizenshipLevel {
    Visitor,        // Limited rights, temporary status
    Resident,       // Extended rights, permanent residency  
    Citizen,        // Full rights except governance
    Full,           // Complete rights including governance participation
    Elder,          // Enhanced rights and responsibilities
}
```

### Rights and Privileges Management

```rust
use lib_identity::citizenship::rights::{CitizenshipRights, RightsManager};

let rights_manager = RightsManager::new();

// Define rights for each citizenship level
let visitor_rights = CitizenshipRights {
    can_vote: false,
    can_propose_governance: false,
    can_hold_office: false,
    can_access_services: true,
    can_participate_forums: true,
    economic_participation: EconomicRights::Limited,
    reputation_influence: 0.1,
};

let full_citizen_rights = CitizenshipRights {
    can_vote: true,
    can_propose_governance: true,
    can_hold_office: true,
    can_access_services: true,
    can_participate_forums: true,
    economic_participation: EconomicRights::Full,
    reputation_influence: 1.0,
};

// Check citizen rights
let citizen_rights = rights_manager.get_citizen_rights(&citizen.citizen_id).await?;

if citizen_rights.can_vote {
    println!("Citizen has voting rights");
    
    // Enable voting capabilities
    let voting_access = enable_voting_access(&citizen.citizen_id).await?;
    println!("Voting access granted for: {:?}", voting_access.eligible_elections);
}

if citizen_rights.can_propose_governance {
    println!("Citizen can propose governance measures");
    
    // Enable governance participation
    let governance_access = enable_governance_participation(&citizen.citizen_id).await?;
    println!("Governance participation enabled");
}
```

### Rights Progression System

```rust
use lib_identity::citizenship::progression::{CitizenshipProgression, ProgressionRequirements};

let progression_system = CitizenshipProgression::new();

// Check progression eligibility
let progression_status = progression_system.check_progression_eligibility(
    &citizen.citizen_id,
    CitizenshipLevel::Full
).await?;

if progression_status.eligible {
    println!("Eligible for citizenship level progression");
    println!("Requirements met:");
    
    for requirement in &progression_status.met_requirements {
        println!("✓ {}", requirement.description);
    }
    
    if !progression_status.pending_requirements.is_empty() {
        println!("Remaining requirements:");
        for requirement in &progression_status.pending_requirements {
            println!("- {}", requirement.description);
            println!("  Progress: {:.1}%", requirement.progress_percentage);
        }
    }
    
    // Process progression if all requirements met
    if progression_status.pending_requirements.is_empty() {
        let progression_result = progression_system.process_progression(
            &citizen.citizen_id,
            CitizenshipLevel::Full
        ).await?;
        
        println!("Citizenship progression successful!");
        println!("New level: {:?}", progression_result.new_citizenship_level);
    }
}
```

## Voting and Governance

### Secure Voting System

```rust
use lib_identity::citizenship::voting::{VotingSystem, Vote, VoteVerification};

let voting_system = VotingSystem::new();

// Create election/proposal
let election = voting_system.create_election(
    ElectionParams {
        election_id: "governance_proposal_2024_001".to_string(),
        title: "Network Infrastructure Upgrade Proposal".to_string(),
        description: "Proposal to upgrade network infrastructure".to_string(),
        voting_options: vec![
            "Approve".to_string(),
            "Reject".to_string(),
            "Abstain".to_string(),
        ],
        voting_period: VotingPeriod {
            start_time: current_time(),
            end_time: current_time() + Duration::days(7),
        },
        eligibility_requirements: EligibilityRequirements {
            minimum_citizenship_level: CitizenshipLevel::Citizen,
            minimum_reputation_score: 0.6,
            minimum_participation_history: 3,
        },
    }
).await?;

println!("Election created: {}", election.election_id);

// Citizen casting vote
let vote_result = voting_system.cast_vote(
    VoteRequest {
        election_id: election.election_id.clone(),
        voter_citizen_id: citizen.citizen_id.clone(),
        vote_choice: "Approve".to_string(),
        privacy_level: VotePrivacyLevel::Anonymous,
        vote_proof: voter_eligibility_proof,
    }
).await?;

match vote_result.status {
    VoteStatus::Recorded => {
        println!("Vote successfully recorded");
        println!("Vote ID: {}", vote_result.vote_id);
        println!("Privacy level: {:?}", vote_result.privacy_level);
    },
    VoteStatus::Rejected => {
        println!("Vote rejected: {}", vote_result.rejection_reason);
    }
}
```

### Anonymous and Verifiable Voting

```rust
use lib_identity::citizenship::voting::{AnonymousVoting, VoteVerifiability};

// Cast anonymous vote with zero-knowledge proof of eligibility
let anonymous_vote = voting_system.cast_anonymous_vote(
    AnonymousVoteRequest {
        election_id: election.election_id.clone(),
        vote_choice: "Approve".to_string(),
        eligibility_proof: generate_eligibility_proof(
            &citizen.citizen_id,
            &election.eligibility_requirements,
            &citizen_private_key
        ).await?,
        anonymity_level: AnonymityLevel::High,
    }
).await?;

println!("Anonymous vote cast successfully");
println!("Vote can be verified but not traced to voter");

// Vote verification (anyone can verify)
let vote_verification = voting_system.verify_vote(
    &anonymous_vote.vote_id,
    &election.verification_key
).await?;

if vote_verification.valid {
    println!("Vote verification successful:");
    println!("- Vote is cryptographically valid");
    println!("- Voter was eligible");
    println!("- Vote was cast during valid period");
    println!("- No double voting detected");
}
```

### Governance Participation

```rust
use lib_identity::citizenship::governance::{GovernanceSystem, Proposal, ProposalType};

let governance_system = GovernanceSystem::new();

// Submit governance proposal
let proposal = governance_system.submit_proposal(
    ProposalSubmission {
        proposer_citizen_id: citizen.citizen_id.clone(),
        proposal_type: ProposalType::NetworkUpgrade,
        title: "Implement Quantum-Resistant Cryptography".to_string(),
        description: proposal_description,
        implementation_details: technical_specifications,
        budget_requirements: Some(budget_breakdown),
        timeline: implementation_timeline,
        impact_assessment: governance_impact_analysis,
    }
).await?;

println!("Governance proposal submitted");
println!("Proposal ID: {}", proposal.proposal_id);
println!("Review period: {} days", proposal.review_period_days);

// Participate in proposal discussion
let discussion_participation = governance_system.participate_in_discussion(
    DiscussionParticipation {
        proposal_id: proposal.proposal_id.clone(),
        participant_citizen_id: citizen.citizen_id.clone(),
        participation_type: ParticipationType::Comment,
        content: thoughtful_analysis_comment,
        expertise_areas: vec!["Cryptography", "Network Security"],
    }
).await?;

println!("Participated in governance discussion");
```

## Civic Participation and Reputation

### Civic Activity Tracking

```rust
use lib_identity::citizenship::civic::{CivicParticipation, CivicActivity, ActivityType};

let civic_participation = CivicParticipation::new(&citizen.citizen_id);

// Record civic activities
let activities = vec![
    CivicActivity {
        activity_type: ActivityType::VotingParticipation,
        description: "Participated in governance vote".to_string(),
        impact_score: 10.0,
        verification_proof: voting_participation_proof,
        timestamp: current_time(),
    },
    CivicActivity {
        activity_type: ActivityType::CommunityService,
        description: "Contributed to network security audit".to_string(), 
        impact_score: 25.0,
        verification_proof: community_service_proof,
        timestamp: current_time(),
    },
    CivicActivity {
        activity_type: ActivityType::GovernanceParticipation,
        description: "Proposed network improvement".to_string(),
        impact_score: 50.0,
        verification_proof: proposal_submission_proof,
        timestamp: current_time(),
    },
];

for activity in activities {
    let activity_result = civic_participation.record_activity(activity).await?;
    println!("Civic activity recorded: {}", activity_result.activity_id);
}

// Calculate civic participation score
let participation_score = civic_participation.calculate_participation_score().await?;
println!("Civic participation score: {:.2}", participation_score.total_score);
println!("Activities completed: {}", participation_score.activity_count);
println!("Community impact: {:.2}", participation_score.community_impact);
```

### Reputation System

```rust
use lib_identity::citizenship::reputation::{ReputationEngine, ReputationFactors};

let reputation_engine = ReputationEngine::new();

// Calculate comprehensive reputation score
let reputation_assessment = reputation_engine.calculate_reputation(
    ReputationCalculationRequest {
        citizen_id: citizen.citizen_id.clone(),
        assessment_period: Duration::days(365), // Last year
        include_factors: ReputationFactors {
            civic_participation: true,
            voting_consistency: true,
            community_contributions: true,
            governance_engagement: true,
            peer_endorsements: true,
            conflict_resolution: true,
        },
    }
).await?;

println!("Reputation assessment:");
println!("Overall score: {:.2}", reputation_assessment.overall_score);
println!("Reputation level: {:?}", reputation_assessment.reputation_level);

println!("Factor breakdown:");
for (factor, score) in &reputation_assessment.factor_scores {
    println!("- {}: {:.2}", factor, score);
}

// Reputation trends
let reputation_trend = reputation_engine.get_reputation_trend(
    &citizen.citizen_id,
    Duration::days(180)
).await?;

println!("Reputation trend (6 months): {:+.2}", reputation_trend.trend_direction);
println!("Trend stability: {:.2}", reputation_trend.stability_score);
```

### Community Recognition and Rewards

```rust
use lib_identity::citizenship::recognition::{CommunityRecognition, Achievement, RewardSystem};

let recognition_system = CommunityRecognition::new();

// Award achievements based on civic participation
let achievements = recognition_system.evaluate_achievements(
    &citizen.citizen_id
).await?;

for achievement in achievements {
    println!(" Achievement unlocked: {}", achievement.title);
    println!("Description: {}", achievement.description);
    println!("Reputation bonus: +{:.1}", achievement.reputation_bonus);
    
    // Award achievement
    let award_result = recognition_system.award_achievement(
        &citizen.citizen_id,
        &achievement.achievement_id
    ).await?;
    
    println!("Achievement awarded with proof: {}", award_result.proof_hash);
}

// Community endorsements
let endorsement_result = recognition_system.receive_community_endorsement(
    CommunityEndorsement {
        endorser_citizen_id: endorsing_citizen_id,
        endorsed_citizen_id: citizen.citizen_id.clone(),
        endorsement_type: EndorsementType::CivicLeadership,
        endorsement_strength: EndorsementStrength::Strong,
        supporting_evidence: endorsement_evidence,
        endorser_reputation_stake: 10.0, // Endorser stakes reputation
    }
).await?;

println!("Community endorsement received");
println!("Endorsement value: {:.2}", endorsement_result.endorsement_value);
```

## Digital Identity Integration

### Citizenship Credential Integration

```rust
use lib_identity::{citizenship::DigitalCitizen, credentials::ZkCredential, IdentityManager};

let mut identity_manager = IdentityManager::new();

// Link citizenship to identity
let citizenship_credential = create_citizenship_credential(
    &citizen,
    CredentialCreationParams {
        include_citizenship_level: true,
        include_voting_rights: true,
        include_reputation_score: false, // Keep private
        privacy_preserving: true,
    }
).await?;

// Add credential to identity
identity_manager.add_credential_reference(
    &citizen.identity_id,
    &citizenship_credential.credential_id
).await?;

// Present citizenship proof when needed
let citizenship_presentation = present_citizenship_credential(
    &citizenship_credential,
    PresentationContext {
        verifier: service_provider_id,
        required_proofs: vec![
            "citizenship_level_minimum_citizen".to_string(),
            "voting_eligibility".to_string(),
        ],
        privacy_requirements: PrivacyRequirements::high(),
    }
).await?;

println!("Citizenship credential presented");
println!("Proves citizenship level without revealing personal details");
```

## Testing and Validation

### Citizenship System Testing

```rust
#[cfg(test)]
mod citizenship_tests {
    use super::*;

    #[tokio::test]
    async fn test_citizenship_application_process() {
        let mut registry = CitizenshipRegistry::new();
        
        let application = create_test_citizenship_application();
        let result = registry.process_application(application).await.unwrap();
        
        assert_eq!(result.status, ApplicationStatus::Approved);
        assert!(registry.citizens.contains_key(&result.citizen_id));
    }

    #[tokio::test]
    async fn test_voting_system_integrity() {
        let voting_system = VotingSystem::new();
        
        let election = voting_system.create_test_election().await.unwrap();
        
        // Cast multiple votes
        let vote1 = cast_test_vote(&election, "Approve").await.unwrap();
        let vote2 = cast_test_vote(&election, "Reject").await.unwrap();
        
        // Verify vote integrity
        assert!(voting_system.verify_vote(&vote1.vote_id, &election.verification_key).await.unwrap().valid);
        assert!(voting_system.verify_vote(&vote2.vote_id, &election.verification_key).await.unwrap().valid);
        
        // Check election results
        let results = voting_system.get_election_results(&election.election_id).await.unwrap();
        assert_eq!(results.total_votes, 2);
    }

    #[tokio::test]
    async fn test_reputation_calculation() {
        let reputation_engine = ReputationEngine::new();
        
        let citizen_id = "test_citizen_123";
        
        // Record test civic activities
        record_test_civic_activities(citizen_id).await;
        
        let reputation = reputation_engine.calculate_reputation(
            ReputationCalculationRequest {
                citizen_id: citizen_id.to_string(),
                assessment_period: Duration::days(30),
                include_factors: ReputationFactors::all(),
            }
        ).await.unwrap();
        
        assert!(reputation.overall_score > 0.0);
        assert!(reputation.overall_score <= 1.0);
    }
}
```

## Integration Examples

### Complete Citizenship Workflow

```rust
use lib_identity::{IdentityManager, citizenship::*, credentials::*, verification::*};

async fn complete_citizenship_workflow() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Create identity
    let mut identity_manager = IdentityManager::new();
    let identity = identity_manager.create_identity("new_citizen").await?;
    
    // Step 2: Obtain required credentials
    let government_id = obtain_government_id_credential(&identity.id).await?;
    let address_verification = obtain_address_verification(&identity.id).await?;
    
    // Step 3: Apply for citizenship
    let mut citizenship_registry = CitizenshipRegistry::new();
    let application = CitizenshipApplication {
        applicant_identity: identity.id.clone(),
        requested_level: CitizenshipLevel::Full,
        supporting_documents: vec![government_id, address_verification],
        civic_knowledge_test_score: Some(95.0),
        sponsor_references: vec![],
        community_endorsements: vec![],
    };
    
    let application_result = citizenship_registry.process_application(application).await?;
    
    if application_result.status == ApplicationStatus::Approved {
        let citizen_id = application_result.citizen_id;
        
        // Step 4: Participate in governance
        let voting_system = VotingSystem::new();
        let elections = voting_system.get_active_elections().await?;
        
        for election in elections {
            if check_voting_eligibility(&citizen_id, &election).await? {
                cast_informed_vote(&citizen_id, &election).await?;
            }
        }
        
        // Step 5: Build reputation through civic participation
        let civic_participation = CivicParticipation::new(&citizen_id);
        engage_in_civic_activities(&civic_participation).await?;
        
        println!("Complete citizenship workflow successful!");
        println!("Citizen ID: {}", citizen_id);
    }
    
    Ok(())
}
```
