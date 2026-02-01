pub mod id_generation;
pub mod math;

// Re-export utility functions
pub use id_generation::{
    hash_data, generate_lib_token_id, generate_custom_token_id, generate_contract_id,
    generate_message_id, generate_contact_id, generate_group_id, generate_file_id,
    generate_storage_key, generate_indexed_storage_key, validate_id, id_to_hex, hex_to_id,
    generate_deterministic_id, generate_time_based_id,
};
pub use math::integer_sqrt;
