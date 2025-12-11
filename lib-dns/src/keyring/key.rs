use crate::keyring::inter::algorithms::Algorithms;

#[derive(Debug, Clone)]
pub struct Key {
    secret: Vec<u8>,
    algorithm: Algorithms
}

impl Key {

    pub fn new(secret: Vec<u8>, algorithm: Algorithms) -> Self {
        Self {
            secret,
            algorithm
        }
    }

    pub fn set_secret(&mut self, secret: &[u8]) {
        self.secret = secret.to_vec();
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub fn set_algorithm(&mut self, algorithm: Algorithms) {
        self.algorithm = algorithm;
    }

    pub fn algorithm(&self) -> Algorithms {
        self.algorithm
    }
}


