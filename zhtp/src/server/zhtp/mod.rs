//! ZHTP Protocol Handler - Native ZHTP Over QUIC
//!
//! This module implements the native ZHTP protocol directly over QUIC streams,
//! replacing the HTTP layer entirely for Web4 communications.

pub mod router;
pub mod serialization;

pub use router::ZhtpRouter;
pub use serialization::{
    deserialize_request, deserialize_request_with_format, deserialize_response,
    deserialize_response_with_format, serialize_request, serialize_request_with_format,
    serialize_response, serialize_response_with_format, PayloadFormat,
};
