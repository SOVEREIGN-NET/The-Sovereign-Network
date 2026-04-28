//! `ConsensusEngine` and timer primitives.
//!
//! Populated by CONS-305 (handler migration to `transition()`) and
//! CONS-306/307 (action channel). The engine becomes a thin event-translator
//! that consumes `fsm::Event` and emits `fsm::Action` through an
//! `mpsc::UnboundedSender<Action>`.
