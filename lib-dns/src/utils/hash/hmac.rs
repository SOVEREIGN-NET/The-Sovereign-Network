use crate::utils::hash::inter::hash::Hash;

pub fn hmac<H>(key: &[u8], message: &[u8]) -> H::Output
where
    H: Hash,
{
    let mut key_block = vec![0u8; H::BLOCK_SIZE];

    if key.len() > H::BLOCK_SIZE {
        let mut hasher = H::new();
        hasher.update(key, 0, key.len());
        let digest = hasher.get_value();
        key_block[..digest.as_ref().len()].copy_from_slice(digest.as_ref());

    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut o_key_pad = vec![0u8; H::BLOCK_SIZE];
    let mut i_key_pad = vec![0u8; H::BLOCK_SIZE];

    for i in 0..H::BLOCK_SIZE {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }

    let mut inner = H::new();
    inner.update(&i_key_pad, 0, H::BLOCK_SIZE);
    inner.update(message, 0, message.len());
    let inner_hash = inner.get_value();

    let mut outer = H::new();
    outer.update(&o_key_pad, 0, H::BLOCK_SIZE);
    outer.update(inner_hash.as_ref(), 0, inner_hash.as_ref().len());

    outer.get_value()
}
