use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const BURST: usize = 10;
const PER_SECOND: usize = 2;

#[derive(Clone)]
pub struct SpamThrottle {
    hit_counter: Arc<Mutex<HashMap<IpAddr, usize>>>,
    last_decay_time: Arc<Mutex<Instant>>
}

impl SpamThrottle {

    pub fn new() -> Self {
        Self {
            hit_counter: Arc::new(Mutex::new(HashMap::new())),
            last_decay_time: Arc::new(Mutex::new(Instant::now()))
        }
    }

    pub fn add_and_test(&self, address: IpAddr) -> bool {
        let count = self.saturating_add(address);
        count >= BURST
    }

    pub fn remove(&self, address: IpAddr) {
        let mut hit_counter = self.hit_counter.lock().unwrap();
        hit_counter.remove(&address);
    }

    pub fn test(&self, address: IpAddr) -> bool {
        let hit_counter = self.hit_counter.lock().unwrap();
        hit_counter.get(&address).cloned().unwrap_or(0) >= BURST
    }

    pub fn calculate_delay_and_add(&self, address: IpAddr) -> usize {
        let mut hit_counter = self.hit_counter.lock().unwrap();
        let counter = hit_counter.entry(address).or_insert(0);
        *counter += 1;

        let diff = if *counter > BURST {
            *counter - BURST
        } else {
            0
        };
        (diff * 1000) / PER_SECOND
    }

    pub fn saturating_dec(&self, address: IpAddr) {
        let mut hit_counter = self.hit_counter.lock().unwrap();
        if let Some(count) = hit_counter.get_mut(&address) {
            if *count <= 1 {
                hit_counter.remove(&address);
            } else {
                *count -= 1;
            }
        }
    }

    pub fn saturating_add(&self, address: IpAddr) -> usize {
        let mut hit_counter = self.hit_counter.lock().unwrap();
        let counter = hit_counter.entry(address).or_insert(0);
        *counter = (*counter + 1).min(BURST);
        *counter
    }

    pub fn decay(&self) {
        let now = Instant::now();
        let mut last_decay_time = self.last_decay_time.lock().unwrap();
        let delta_t = now.duration_since(*last_decay_time).as_secs();

        if delta_t < 1 {
            return;
        }

        *last_decay_time = now;

        let delta_count = (delta_t * PER_SECOND as u64) as usize;

        let mut hit_counter = self.hit_counter.lock().unwrap();
        hit_counter.retain(|_, v| *v > delta_count);
        for value in hit_counter.values_mut() {
            *value = value.saturating_sub(delta_count);
        }
    }
}
