use std::collections::HashMap;
use crate::keyring::inter::algorithms::Algorithms;
use crate::keyring::key::Key;

#[derive(Debug, Clone)]
pub struct KeyRing {
    ring: HashMap<String, Vec<Key>>
}

impl KeyRing {

    pub fn new() -> Self {
        Self {
            ring: HashMap::new()
        }
    }

    pub fn put_key(&mut self, fqdn: &str, key: Key) {
        self.ring.entry(String::from(fqdn)).or_insert_with(Vec::new).push(key)
    }

    pub fn get_key(&self, fqdn: &str, algorithm: &Algorithms) -> Option<&Key> {
        self.ring.get(fqdn)?.iter().find(|r| r.algorithm().eq(algorithm))
    }
}
