//! WiFi Direct Invitation Manager
//!
//! Handles:
//! - Sending P2P invitations
//! - Receiving and accepting invitations
//! - Declining invitations
//! - Reinvoking persistent groups

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use crate::protocols::wifi_direct::wifi_direct::{
    P2PInvitationRequest, P2PInvitationResponse, InvitationType,
    InvitationStatus, PersistentGroup,
};

pub struct InvitationManager {
    sent_invitations: Arc<RwLock<HashMap<String, P2PInvitationRequest>>>,
    received_invitations: Arc<RwLock<HashMap<String, P2PInvitationRequest>>>,
    persistent_groups: Arc<RwLock<HashMap<String, PersistentGroup>>>,
}

impl InvitationManager {
    pub fn new(
        sent_invitations: Arc<RwLock<HashMap<String, P2PInvitationRequest>>>,
        received_invitations: Arc<RwLock<HashMap<String, P2PInvitationRequest>>>,
        persistent_groups: Arc<RwLock<HashMap<String, PersistentGroup>>>,
    ) -> Result<Self> {
        debug!("Initializing Invitation Manager");
        Ok(Self {
            sent_invitations,
            received_invitations,
            persistent_groups,
        })
    }

    /// Send P2P invitation to a peer
    pub async fn send_invitation(
        &self,
        peer_address: &str,
        invitation_type: InvitationType,
        group_id: Option<String>,
    ) -> Result<P2PInvitationResponse> {
        debug!(peer = peer_address, "Sending P2P invitation");

        let invitation = P2PInvitationRequest {
            invitee_address: peer_address.to_string(),
            persistent_group_id: group_id.unwrap_or_default(),
            operating_channel: 6,
            group_bssid: None,
            invitation_flags: crate::protocols::wifi_direct::wifi_direct::InvitationFlags {
                invitation_type,
            },
            config_timeout: 100,
        };

        // Store invitation
        self.sent_invitations
            .write()
            .await
            .insert(peer_address.to_string(), invitation.clone());

        // Perform platform-specific invitation
        self.send_invitation_platform(peer_address, &invitation)
            .await
    }

    /// Accept a P2P invitation
    pub async fn accept_invitation(&self, peer_address: &str) -> Result<P2PInvitationResponse> {
        debug!(peer = peer_address, "Accepting P2P invitation");

        info!(peer = peer_address, "P2P invitation accepted");
        Ok(P2PInvitationResponse {
            status: InvitationStatus::Success,
            config_timeout: 100,
            operating_channel: Some(6),
            group_bssid: None,
        })
    }

    /// Decline a P2P invitation
    pub async fn decline_invitation(
        &self,
        peer_address: &str,
        reason: InvitationStatus,
    ) -> Result<P2PInvitationResponse> {
        debug!(peer = peer_address, "Declining P2P invitation");

        warn!(peer = peer_address, "P2P invitation declined");
        Ok(P2PInvitationResponse {
            status: reason,
            config_timeout: 100,
            operating_channel: None,
            group_bssid: None,
        })
    }

    /// Handle a received invitation
    pub async fn handle_received_invitation(
        &self,
        invitation: P2PInvitationRequest,
    ) -> Result<()> {
        debug!(
            peer = &invitation.invitee_address,
            "Handling received P2P invitation"
        );

        // Store received invitation
        self.received_invitations
            .write()
            .await
            .insert(invitation.invitee_address.clone(), invitation.clone());

        // Determine response based on invitation type
        match &invitation.invitation_flags.invitation_type {
            InvitationType::JoinActiveGroup => {
                self.join_active_group(&invitation).await?;
            }
            InvitationType::ReinvokePersistentGroup => {
                self.reinvoke_persistent_group(&invitation).await?;
            }
        }

        Ok(())
    }

    /// Join an active P2P group
    async fn join_active_group(&self, invitation: &P2PInvitationRequest) -> Result<()> {
        debug!(
            peer = &invitation.invitee_address,
            "Joining active P2P group"
        );

        #[cfg(target_os = "linux")]
        {
            self.linux_join_active_group(invitation).await?;
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_join_active_group(invitation).await?;
        }

        #[cfg(target_os = "macos")]
        {
            self.macos_join_active_group(invitation).await?;
        }

        info!(
            peer = &invitation.invitee_address,
            "Joined active P2P group"
        );
        Ok(())
    }

    /// Reinvoke a persistent group
    async fn reinvoke_persistent_group(
        &self,
        invitation: &P2PInvitationRequest,
    ) -> Result<()> {
        debug!(
            group_id = &invitation.persistent_group_id,
            "Reinvoking persistent P2P group"
        );

        let groups = self.persistent_groups.read().await;
        if let Some(group) = groups.get(&invitation.persistent_group_id) {
            #[cfg(target_os = "linux")]
            {
                self.linux_reinvoke_persistent_group(group).await?;
            }

            #[cfg(target_os = "windows")]
            {
                self.windows_reinvoke_persistent_group(group).await?;
            }

            #[cfg(target_os = "macos")]
            {
                self.macos_reinvoke_persistent_group(group).await?;
            }

            info!(
                group_id = &invitation.persistent_group_id,
                "Reinvoked persistent P2P group"
            );
        }

        Ok(())
    }

    /// Platform-specific invitation sending
    async fn send_invitation_platform(
        &self,
        peer_address: &str,
        invitation: &P2PInvitationRequest,
    ) -> Result<P2PInvitationResponse> {
        #[cfg(target_os = "linux")]
        {
            self.linux_send_invitation(invitation).await
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_send_invitation(invitation).await
        }

        #[cfg(target_os = "macos")]
        {
            self.macos_send_invitation(invitation).await
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            Ok(P2PInvitationResponse {
                status: InvitationStatus::Success,
                config_timeout: 100,
                operating_channel: Some(6),
                group_bssid: None,
            })
        }
    }

    // Linux implementations
    #[cfg(target_os = "linux")]
    async fn linux_send_invitation(
        &self,
        invitation: &P2PInvitationRequest,
    ) -> Result<P2PInvitationResponse> {
        debug!("Sending P2P invitation on Linux");

        Ok(P2PInvitationResponse {
            status: InvitationStatus::Success,
            config_timeout: 100,
            operating_channel: Some(6),
            group_bssid: None,
        })
    }

    #[cfg(target_os = "linux")]
    async fn linux_join_active_group(
        &self,
        _invitation: &P2PInvitationRequest,
    ) -> Result<()> {
        debug!("Joining active P2P group on Linux");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn linux_reinvoke_persistent_group(&self, _group: &PersistentGroup) -> Result<()> {
        debug!("Reinvoking persistent P2P group on Linux");
        Ok(())
    }

    // Windows implementations (stubs)
    #[cfg(target_os = "windows")]
    async fn windows_send_invitation(
        &self,
        _invitation: &P2PInvitationRequest,
    ) -> Result<P2PInvitationResponse> {
        Ok(P2PInvitationResponse {
            status: InvitationStatus::Success,
            config_timeout: 100,
            operating_channel: Some(6),
            group_bssid: None,
        })
    }

    #[cfg(target_os = "windows")]
    async fn windows_join_active_group(
        &self,
        _invitation: &P2PInvitationRequest,
    ) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn windows_reinvoke_persistent_group(&self, _group: &PersistentGroup) -> Result<()> {
        Ok(())
    }

    // macOS implementations (stubs)
    #[cfg(target_os = "macos")]
    async fn macos_send_invitation(
        &self,
        _invitation: &P2PInvitationRequest,
    ) -> Result<P2PInvitationResponse> {
        Ok(P2PInvitationResponse {
            status: InvitationStatus::Success,
            config_timeout: 100,
            operating_channel: Some(6),
            group_bssid: None,
        })
    }

    #[cfg(target_os = "macos")]
    async fn macos_join_active_group(
        &self,
        _invitation: &P2PInvitationRequest,
    ) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn macos_reinvoke_persistent_group(&self, _group: &PersistentGroup) -> Result<()> {
        Ok(())
    }
}
