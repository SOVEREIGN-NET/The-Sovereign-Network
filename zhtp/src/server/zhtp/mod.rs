//! ZHTP Protocol Handler - Native ZHTP Over QUIC
//!
//! This module implements the native ZHTP protocol directly over QUIC streams,
//! replacing the HTTP layer entirely for Web4 communications.

pub mod router;
pub mod serialization;

pub use router::ZhtpRouter;
pub use serialization::{
    serialize_request, deserialize_request, serialize_response, deserialize_response,
    serialize_request_with_format, deserialize_request_with_format,
    serialize_response_with_format, deserialize_response_with_format,
    PayloadFormat,
};
