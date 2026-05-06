//! Phase 4 integration tests — Issue #2077
//!
//! Covers only NEW Phase 4 functionality. Phases 1-3 tests live in:
//! - lib-identity/src/auth/mobile_delegation.rs (store-level unit tests)
//! - zhtp/src/api/handlers/mobile_auth/mod.rs   (handler-level HTTP tests)

#[cfg(test)]
mod tests {
    use lib_identity::auth::mobile_delegation::{
        Capability, MobileAuthStore, SessionEvent,
    };
    use std::sync::Arc;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    async fn make_store_with_session() -> (
        Arc<MobileAuthStore>,
        String, // access_token
        String, // challenge_session_id
    ) {
        let store = Arc::new(MobileAuthStore::new());
        let identity_id = lib_crypto::Hash::from_bytes(&[42u8; 32]);
        let session = store
            .create_session(
                identity_id,
                "deadbeef".repeat(164),
                vec![Capability::ReadBalance],
                "127.0.0.1".to_string(),
                "TestAgent/1.0".to_string(),
                "test-challenge-sid".to_string(),
                None,
            )
            .await
            .unwrap();
        (store, session.access_token, session.challenge_session_id)
    }

    // -----------------------------------------------------------------------
    // Session event polling (get_session_events_since)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn event_poll_returns_empty_before_any_events() {
        let store = Arc::new(MobileAuthStore::new());
        let events = store.get_session_events_since("no-such-sid", 0).await;
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn event_poll_returns_published_events_in_order() {
        let store = Arc::new(MobileAuthStore::new());
        let sid = "sid-poll-001";

        store
            .publish_session_event(
                sid,
                SessionEvent::ChallengeIssued {
                    session_id: sid.to_string(),
                    expires_at: 1_000_000,
                },
            )
            .await;
        store
            .publish_session_event(
                sid,
                SessionEvent::SessionApproved {
                    session_id: sid.to_string(),
                    identity_id: "did:zhtp:abc".to_string(),
                },
            )
            .await;

        let all = store.get_session_events_since(sid, 0).await;
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, 0); // seq 0
        assert_eq!(all[1].0, 1); // seq 1
        assert!(matches!(all[0].1, SessionEvent::ChallengeIssued { .. }));
        assert!(matches!(all[1].1, SessionEvent::SessionApproved { .. }));
    }

    #[tokio::test]
    async fn event_poll_since_filters_correctly() {
        let store = Arc::new(MobileAuthStore::new());
        let sid = "sid-poll-002";

        for i in 0..5u64 {
            store
                .publish_session_event(
                    sid,
                    SessionEvent::SessionExpired {
                        session_id: format!("sid-{}", i),
                    },
                )
                .await;
        }

        // Poll from seq 3 onwards — should get seqs 3 and 4 only
        let tail = store.get_session_events_since(sid, 3).await;
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].0, 3);
        assert_eq!(tail[1].0, 4);
    }

    #[tokio::test]
    async fn event_poll_since_beyond_end_returns_empty() {
        let store = Arc::new(MobileAuthStore::new());
        let sid = "sid-poll-003";
        store
            .publish_session_event(
                sid,
                SessionEvent::BiometricVerified {
                    session_id: sid.to_string(),
                },
            )
            .await;

        // Asking for seq >= 99 when only seq 0 exists
        let result = store.get_session_events_since(sid, 99).await;
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // Push token registry
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn push_token_register_and_retrieve() {
        let store = Arc::new(MobileAuthStore::new());
        let identity_id = lib_crypto::Hash::from_bytes(&[1u8; 32]);

        assert!(store.get_push_token(&identity_id).await.is_none());
        store
            .register_push_token(identity_id.clone(), "fcm-token-abc123".to_string())
            .await;
        assert_eq!(
            store.get_push_token(&identity_id).await.as_deref(),
            Some("fcm-token-abc123")
        );
    }

    #[tokio::test]
    async fn push_token_overwrite_updates_value() {
        let store = Arc::new(MobileAuthStore::new());
        let identity_id = lib_crypto::Hash::from_bytes(&[2u8; 32]);
        store
            .register_push_token(identity_id.clone(), "old-token".to_string())
            .await;
        store
            .register_push_token(identity_id.clone(), "new-token".to_string())
            .await;
        assert_eq!(
            store.get_push_token(&identity_id).await.as_deref(),
            Some("new-token")
        );
    }

    // -----------------------------------------------------------------------
    // Biometric gate
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn biometric_confirm_marks_session_verified() {
        let (store, access_token, _) = make_store_with_session().await;
        store
            .confirm_biometric(&access_token, "deadbeef")
            .await
            .expect("biometric confirm should succeed on valid hex");

        let session = store
            .validate_access_token(&access_token, "127.0.0.1", "TestAgent/1.0")
            .await
            .unwrap();
        assert!(session.biometric_verified);
    }

    #[tokio::test]
    async fn biometric_confirm_rejects_invalid_hex() {
        let (store, access_token, _) = make_store_with_session().await;
        assert!(store.confirm_biometric(&access_token, "not-valid-hex!!").await.is_err());
    }

    #[tokio::test]
    async fn biometric_confirm_rejects_unknown_token() {
        let store = Arc::new(MobileAuthStore::new());
        assert!(store.confirm_biometric("ghost-token", "deadbeef").await.is_err());
    }

    #[tokio::test]
    async fn biometric_confirm_rejects_revoked_session() {
        let (store, access_token, _) = make_store_with_session().await;
        store.revoke_session(&access_token, "test").await.unwrap();
        assert!(store.confirm_biometric(&access_token, "deadbeef").await.is_err());
    }

    // -----------------------------------------------------------------------
    // SessionEvent serialisation
    // -----------------------------------------------------------------------

    #[test]
    fn session_event_serialises_with_event_tag() {
        let events: Vec<SessionEvent> = vec![
            SessionEvent::ChallengeIssued { session_id: "s1".into(), expires_at: 1_000 },
            SessionEvent::SessionApproved { session_id: "s2".into(), identity_id: "did:zhtp:x".into() },
            SessionEvent::SessionExpired { session_id: "s3".into() },
            SessionEvent::SessionRevoked { session_id: "s4".into(), reason: "test".into() },
            SessionEvent::BiometricVerified { session_id: "s5".into() },
        ];
        for event in events {
            let json = serde_json::to_string(&event).unwrap();
            assert!(json.contains(r#""event""#), "missing event discriminant: {}", json);
        }
    }

    // -----------------------------------------------------------------------
    // New session defaults
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn new_session_biometric_false_and_no_node_did() {
        let (store, access_token, _) = make_store_with_session().await;
        let session = store
            .validate_access_token(&access_token, "127.0.0.1", "TestAgent/1.0")
            .await
            .unwrap();
        assert!(!session.biometric_verified);
        assert!(session.bound_node_did.is_none());
    }
}
