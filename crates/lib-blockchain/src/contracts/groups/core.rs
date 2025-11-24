use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::PublicKey;
use std::collections::HashMap;

/// Group chat structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupChat {
    /// Unique group identifier
    pub group_id: [u8; 32],
    /// Group name
    pub name: String,
    /// Group description
    pub description: String,
    /// Group creator
    pub creator: PublicKey,
    /// List of group administrators
    pub admins: Vec<PublicKey>,
    /// List of group members
    pub members: Vec<PublicKey>,
    /// Maximum number of members allowed
    pub max_members: u32,
    /// Whether the group is private (invite-only)
    pub is_private: bool,
    /// Timestamp when group was created
    pub created_timestamp: u64,
    /// Cost in WHISPER tokens to join the group
    pub whisper_token_cost: u64,
}

impl GroupChat {
    /// Create a new group
    pub fn new(
        name: String,
        description: String,
        creator: PublicKey,
        max_members: u32,
        is_private: bool,
        whisper_token_cost: u64,
    ) -> Self {
        let created_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let group_id = crate::contracts::utils::generate_group_id(
            &creator.key_id,
            &name,
            created_timestamp as u128 * 1_000_000_000,
        );

        Self {
            group_id,
            name,
            description,
            creator: creator.clone(),
            admins: vec![creator.clone()],
            members: vec![creator],
            max_members,
            is_private,
            created_timestamp,
            whisper_token_cost,
        }
    }

    /// Check if a user is a member
    pub fn is_member(&self, user: &PublicKey) -> bool {
        self.members.contains(user)
    }

    /// Check if a user is an admin
    pub fn is_admin(&self, user: &PublicKey) -> bool {
        self.admins.contains(user)
    }

    /// Check if the group can accept new members
    pub fn can_add_member(&self) -> bool {
        (self.members.len() as u32) < self.max_members
    }

    /// Add a new member to the group
    pub fn add_member(&mut self, user: PublicKey) -> Result<(), String> {
        if self.is_member(&user) {
            return Err("User is already a member".to_string());
        }

        if !self.can_add_member() {
            return Err("Group is at maximum capacity".to_string());
        }

        self.members.push(user);
        Ok(())
    }

    /// Remove a member from the group
    pub fn remove_member(&mut self, user: &PublicKey) -> Result<(), String> {
        if !self.is_member(user) {
            return Err("User is not a member".to_string());
        }

        // Creator cannot be removed
        if *user == self.creator {
            return Err("Cannot remove group creator".to_string());
        }

        self.members.retain(|m| m != user);
        self.admins.retain(|a| a != user); // Also remove from admins if they were one
        Ok(())
    }

    /// Add a new admin
    pub fn add_admin(&mut self, user: PublicKey) -> Result<(), String> {
        if !self.is_member(&user) {
            return Err("User must be a member to become admin".to_string());
        }

        if self.is_admin(&user) {
            return Err("User is already an admin".to_string());
        }

        self.admins.push(user);
        Ok(())
    }

    /// Remove an admin
    pub fn remove_admin(&mut self, user: &PublicKey) -> Result<(), String> {
        if *user == self.creator {
            return Err("Cannot remove creator from admin role".to_string());
        }

        if !self.is_admin(user) {
            return Err("User is not an admin".to_string());
        }

        self.admins.retain(|a| a != user);
        Ok(())
    }

    /// Get member count
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Get storage key for this group
    pub fn storage_key(&self) -> Vec<u8> {
        crate::contracts::utils::generate_storage_key("group", &self.group_id)
    }

    /// Validate group structure
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Group name cannot be empty".to_string());
        }

        if self.name.len() > 64 {
            return Err("Group name too long (max 64 characters)".to_string());
        }

        if self.description.len() > 512 {
            return Err("Group description too long (max 512 characters)".to_string());
        }

        if self.max_members == 0 {
            return Err("Maximum members must be greater than 0".to_string());
        }

        if self.max_members > 10000 {
            return Err("Maximum members too high (max 10000)".to_string());
        }

        if !self.is_member(&self.creator) {
            return Err("Creator must be a member of the group".to_string());
        }

        if !self.is_admin(&self.creator) {
            return Err("Creator must be an admin of the group".to_string());
        }

        // Check for duplicate members
        let mut unique_members = self.members.clone();
        unique_members.sort_by_key(|k| k.key_id.clone());
        unique_members.dedup();
        if unique_members.len() != self.members.len() {
            return Err("Duplicate members found".to_string());
        }

        // Check that all admins are members
        for admin in &self.admins {
            if !self.is_member(admin) {
                return Err("Admin must also be a member".to_string());
            }
        }

        Ok(())
    }
}

/// Group management contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupContract {
    /// All groups in the system
    pub groups: HashMap<[u8; 32], GroupChat>,
    /// User group memberships (user -> group_ids)
    pub user_groups: HashMap<PublicKey, Vec<[u8; 32]>>,
    /// Group invitation system (group_id -> pending_invites)
    pub pending_invites: HashMap<[u8; 32], Vec<GroupInvite>>,
    /// Group join requests for private groups
    pub join_requests: HashMap<[u8; 32], Vec<JoinRequest>>,
}

impl GroupContract {
    /// Create a new group contract
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            user_groups: HashMap::new(),
            pending_invites: HashMap::new(),
            join_requests: HashMap::new(),
        }
    }

    /// Create a new group
    pub fn create_group(
        &mut self,
        name: String,
        description: String,
        creator: PublicKey,
        max_members: u32,
        is_private: bool,
        whisper_token_cost: u64,
    ) -> Result<[u8; 32], String> {
        let group = GroupChat::new(
            name,
            description,
            creator.clone(),
            max_members,
            is_private,
            whisper_token_cost,
        );
        
        group.validate()?;
        
        let group_id = group.group_id;
        
        // Add creator to user groups
        self.user_groups
            .entry(creator)
            .or_insert_with(Vec::new)
            .push(group_id);
        
        // Store the group
        self.groups.insert(group_id, group);
        
        Ok(group_id)
    }

    /// Get a group by ID
    pub fn get_group(&self, group_id: &[u8; 32]) -> Option<&GroupChat> {
        self.groups.get(group_id)
    }

    /// Get all groups a user is a member of
    pub fn get_user_groups(&self, user: &PublicKey) -> Vec<&GroupChat> {
        self.user_groups
            .get(user)
            .map(|group_ids| {
                group_ids
                    .iter()
                    .filter_map(|id| self.groups.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Join a public group
    pub fn join_group(
        &mut self,
        group_id: &[u8; 32],
        user: PublicKey,
    ) -> Result<(), String> {
        let group = self.groups.get_mut(group_id)
            .ok_or("Group not found")?;
        
        if group.is_private {
            return Err("Cannot join private group without invitation".to_string());
        }
        
        group.add_member(user.clone())?;
        
        // Add to user groups
        self.user_groups
            .entry(user)
            .or_insert_with(Vec::new)
            .push(*group_id);
        
        Ok(())
    }

    /// Request to join a private group
    pub fn request_to_join(
        &mut self,
        group_id: &[u8; 32],
        user: PublicKey,
        message: String,
    ) -> Result<(), String> {
        let group = self.groups.get(group_id)
            .ok_or("Group not found")?;
        
        if !group.is_private {
            return Err("Use join_group for public groups".to_string());
        }
        
        if group.is_member(&user) {
            return Err("User is already a member".to_string());
        }
        
        // Check if request already exists
        if let Some(requests) = self.join_requests.get(group_id) {
            if requests.iter().any(|r| r.user == user) {
                return Err("Join request already pending".to_string());
            }
        }
        
        let request = JoinRequest {
            user,
            message,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        self.join_requests
            .entry(*group_id)
            .or_insert_with(Vec::new)
            .push(request);
        
        Ok(())
    }

    /// Approve a join request (admin only)
    pub fn approve_join_request(
        &mut self,
        group_id: &[u8; 32],
        requesting_user: &PublicKey,
        approver: &PublicKey,
    ) -> Result<(), String> {
        let group = self.groups.get(group_id)
            .ok_or("Group not found")?;
        
        if !group.is_admin(approver) {
            return Err("Only admins can approve join requests".to_string());
        }
        
        // Remove the join request
        if let Some(requests) = self.join_requests.get_mut(group_id) {
            requests.retain(|r| r.user != *requesting_user);
            if requests.is_empty() {
                self.join_requests.remove(group_id);
            }
        }
        
        // Add user to group
        let group = self.groups.get_mut(group_id).unwrap();
        group.add_member(requesting_user.clone())?;
        
        // Add to user groups
        self.user_groups
            .entry(requesting_user.clone())
            .or_insert_with(Vec::new)
            .push(*group_id);
        
        Ok(())
    }

    /// Invite a user to a group (admin only)
    pub fn invite_user(
        &mut self,
        group_id: &[u8; 32],
        inviter: &PublicKey,
        invitee: PublicKey,
        message: String,
    ) -> Result<(), String> {
        let group = self.groups.get(group_id)
            .ok_or("Group not found")?;
        
        if !group.is_admin(inviter) {
            return Err("Only admins can invite users".to_string());
        }
        
        if group.is_member(&invitee) {
            return Err("User is already a member".to_string());
        }
        
        // Check if invitation already exists
        if let Some(invites) = self.pending_invites.get(group_id) {
            if invites.iter().any(|i| i.invitee == invitee) {
                return Err("User already has a pending invitation".to_string());
            }
        }
        
        let invite = GroupInvite {
            group_id: *group_id,
            inviter: inviter.clone(),
            invitee: invitee.clone(),
            message,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        self.pending_invites
            .entry(*group_id)
            .or_insert_with(Vec::new)
            .push(invite);
        
        Ok(())
    }

    /// Accept a group invitation
    pub fn accept_invitation(
        &mut self,
        group_id: &[u8; 32],
        user: &PublicKey,
    ) -> Result<(), String> {
        // Remove the invitation
        if let Some(invites) = self.pending_invites.get_mut(group_id) {
            let had_invite = invites.iter().any(|i| i.invitee == *user);
            if !had_invite {
                return Err("No pending invitation found".to_string());
            }
            invites.retain(|i| i.invitee != *user);
            if invites.is_empty() {
                self.pending_invites.remove(group_id);
            }
        } else {
            return Err("No pending invitation found".to_string());
        }
        
        // Add user to group
        let group = self.groups.get_mut(group_id)
            .ok_or("Group not found")?;
        group.add_member(user.clone())?;
        
        // Add to user groups
        self.user_groups
            .entry(user.clone())
            .or_insert_with(Vec::new)
            .push(*group_id);
        
        Ok(())
    }

    /// Leave a group
    pub fn leave_group(
        &mut self,
        group_id: &[u8; 32],
        user: &PublicKey,
    ) -> Result<(), String> {
        let group = self.groups.get_mut(group_id)
            .ok_or("Group not found")?;
        
        group.remove_member(user)?;
        
        // Remove from user groups
        if let Some(user_groups) = self.user_groups.get_mut(user) {
            user_groups.retain(|id| id != group_id);
            if user_groups.is_empty() {
                self.user_groups.remove(user);
            }
        }
        
        Ok(())
    }

    /// Promote a member to admin (admin only)
    pub fn promote_to_admin(
        &mut self,
        group_id: &[u8; 32],
        promoter: &PublicKey,
        user_to_promote: PublicKey,
    ) -> Result<(), String> {
        let group = self.groups.get_mut(group_id)
            .ok_or("Group not found")?;
        
        if !group.is_admin(promoter) {
            return Err("Only admins can promote users".to_string());
        }
        
        group.add_admin(user_to_promote)
    }

    /// Remove admin privileges (creator only)
    pub fn remove_admin(
        &mut self,
        group_id: &[u8; 32],
        remover: &PublicKey,
        admin_to_remove: &PublicKey,
    ) -> Result<(), String> {
        let group = self.groups.get_mut(group_id)
            .ok_or("Group not found")?;
        
        if group.creator != *remover {
            return Err("Only group creator can remove admin privileges".to_string());
        }
        
        group.remove_admin(admin_to_remove)
    }

    /// Get pending invitations for a user
    pub fn get_user_invitations(&self, user: &PublicKey) -> Vec<&GroupInvite> {
        self.pending_invites
            .values()
            .flatten()
            .filter(|invite| invite.invitee == *user)
            .collect()
    }

    /// Get pending join requests for a group (admin only)
    pub fn get_join_requests(
        &self,
        group_id: &[u8; 32],
        requester: &PublicKey,
    ) -> Result<Vec<&JoinRequest>, String> {
        let group = self.groups.get(group_id)
            .ok_or("Group not found")?;
        
        if !group.is_admin(requester) {
            return Err("Only admins can view join requests".to_string());
        }
        
        Ok(self.join_requests
            .get(group_id)
            .map(|requests| requests.iter().collect())
            .unwrap_or_default())
    }

    /// Search public groups by name
    pub fn search_public_groups(&self, search_term: &str) -> Vec<&GroupChat> {
        self.groups
            .values()
            .filter(|group| {
                !group.is_private && 
                group.name.to_lowercase().contains(&search_term.to_lowercase())
            })
            .collect()
    }

    /// Get group statistics
    pub fn get_group_stats(&self, group_id: &[u8; 32]) -> Option<GroupStats> {
        self.groups.get(group_id).map(|group| GroupStats {
            group_id: *group_id,
            member_count: group.member_count(),
            admin_count: group.admins.len(),
            is_private: group.is_private,
            created_timestamp: group.created_timestamp,
            capacity_utilization: (group.member_count() as f64 / group.max_members as f64) * 100.0,
        })
    }

    /// Get total group count
    pub fn total_group_count(&self) -> usize {
        self.groups.len()
    }

    /// Get system-wide group statistics
    pub fn get_system_stats(&self) -> GroupSystemStats {
        let total_groups = self.groups.len();
        let public_groups = self.groups.values().filter(|g| !g.is_private).count();
        let private_groups = total_groups - public_groups;
        let total_members: usize = self.groups.values().map(|g| g.member_count()).sum();
        let total_admins: usize = self.groups.values().map(|g| g.admins.len()).sum();
        
        GroupSystemStats {
            total_groups,
            public_groups,
            private_groups,
            total_members,
            total_admins,
            average_group_size: if total_groups > 0 {
                total_members as f64 / total_groups as f64
            } else {
                0.0
            },
        }
    }
}

/// Group invitation structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupInvite {
    pub group_id: [u8; 32],
    pub inviter: PublicKey,
    pub invitee: PublicKey,
    pub message: String,
    pub timestamp: u64,
}

/// Join request structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    pub user: PublicKey,
    pub message: String,
    pub timestamp: u64,
}

/// Group statistics
#[derive(Debug, Clone)]
pub struct GroupStats {
    pub group_id: [u8; 32],
    pub member_count: usize,
    pub admin_count: usize,
    pub is_private: bool,
    pub created_timestamp: u64,
    pub capacity_utilization: f64,
}

/// System-wide group statistics
#[derive(Debug, Clone)]
pub struct GroupSystemStats {
    pub total_groups: usize,
    pub public_groups: usize,
    pub private_groups: usize,
    pub total_members: usize,
    pub total_admins: usize,
    pub average_group_size: f64,
}

impl Default for GroupContract {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 1312])
    }

    #[test]
    fn test_group_creation() {
        let creator = create_test_public_key(1);
        let mut contract = GroupContract::new();
        
        let group_id = contract.create_group(
            "Test Group".to_string(),
            "A test group".to_string(),
            creator.clone(),
            100,
            false,
            1000,
        ).unwrap();
        
        let group = contract.get_group(&group_id).unwrap();
        assert_eq!(group.name, "Test Group");
        assert_eq!(group.creator, creator);
        assert!(group.is_member(&creator));
        assert!(group.is_admin(&creator));
    }

    #[test]
    fn test_public_group_joining() {
        let creator = create_test_public_key(1);
        let user = create_test_public_key(2);
        let mut contract = GroupContract::new();
        
        let group_id = contract.create_group(
            "Public Group".to_string(),
            "A public group".to_string(),
            creator.clone(),
            100,
            false, // public
            1000,
        ).unwrap();
        
        // User joins public group
        contract.join_group(&group_id, user.clone()).unwrap();
        
        let group = contract.get_group(&group_id).unwrap();
        assert!(group.is_member(&user));
        
        let user_groups = contract.get_user_groups(&user);
        assert_eq!(user_groups.len(), 1);
    }

    #[test]
    fn test_private_group_invitation() {
        let creator = create_test_public_key(1);
        let user = create_test_public_key(2);
        let mut contract = GroupContract::new();
        
        let group_id = contract.create_group(
            "Private Group".to_string(),
            "A private group".to_string(),
            creator.clone(),
            100,
            true, // private
            1000,
        ).unwrap();
        
        // Cannot join private group directly
        assert!(contract.join_group(&group_id, user.clone()).is_err());
        
        // Creator invites user
        contract.invite_user(
            &group_id,
            &creator,
            user.clone(),
            "Welcome!".to_string(),
        ).unwrap();
        
        // User accepts invitation
        contract.accept_invitation(&group_id, &user).unwrap();
        
        let group = contract.get_group(&group_id).unwrap();
        assert!(group.is_member(&user));
    }

    #[test]
    fn test_join_request() {
        let creator = create_test_public_key(1);
        let user = create_test_public_key(2);
        let mut contract = GroupContract::new();
        
        let group_id = contract.create_group(
            "Private Group".to_string(),
            "A private group".to_string(),
            creator.clone(),
            100,
            true, // private
            1000,
        ).unwrap();
        
        // User requests to join
        contract.request_to_join(
            &group_id,
            user.clone(),
            "Please let me join!".to_string(),
        ).unwrap();
        
        // Creator approves request
        contract.approve_join_request(&group_id, &user, &creator).unwrap();
        
        let group = contract.get_group(&group_id).unwrap();
        assert!(group.is_member(&user));
    }

    #[test]
    fn test_admin_management() {
        let creator = create_test_public_key(1);
        let user = create_test_public_key(2);
        let mut contract = GroupContract::new();
        
        let group_id = contract.create_group(
            "Test Group".to_string(),
            "A test group".to_string(),
            creator.clone(),
            100,
            false,
            1000,
        ).unwrap();
        
        // Add user to group
        contract.join_group(&group_id, user.clone()).unwrap();
        
        // Promote user to admin
        contract.promote_to_admin(&group_id, &creator, user.clone()).unwrap();
        
        let group = contract.get_group(&group_id).unwrap();
        assert!(group.is_admin(&user));
        
        // Remove admin privileges
        contract.remove_admin(&group_id, &creator, &user).unwrap();
        
        let group = contract.get_group(&group_id).unwrap();
        assert!(!group.is_admin(&user));
    }

    #[test]
    fn test_group_search() {
        let creator = create_test_public_key(1);
        let mut contract = GroupContract::new();
        
        contract.create_group(
            "Rust Programming".to_string(),
            "Learn Rust".to_string(),
            creator.clone(),
            100,
            false, // public
            1000,
        ).unwrap();
        
        contract.create_group(
            "JavaScript Developers".to_string(),
            "JS development".to_string(),
            creator.clone(),
            100,
            false, // public
            1000,
        ).unwrap();
        
        contract.create_group(
            "Private Club".to_string(),
            "Secret group".to_string(),
            creator.clone(),
            50,
            true, // private
            2000,
        ).unwrap();
        
        let results = contract.search_public_groups("programming");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Rust Programming");
        
        let results = contract.search_public_groups("developers");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "JavaScript Developers");
        
        // Private groups should not appear in search
        let results = contract.search_public_groups("club");
        assert_eq!(results.len(), 0);
    }
}
