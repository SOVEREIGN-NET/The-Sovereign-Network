//! Sled-backed Persistent Event Indexer

use super::events::{BondingCurveEvent, EventIndexer};

/// Sled-backed persistent event indexer
#[derive(Debug)]
pub struct SledEventIndexer {
    db: sled::Db,
    events: sled::Tree,
    token_index: sled::Tree,
    block_index: sled::Tree,
    type_index: sled::Tree,
    event_counter: std::sync::atomic::AtomicU64,
}

const TREE_EVENTS: &str = "bonding_curve_events";
const TREE_TOKEN_INDEX: &str = "bc_events_token_idx";
const TREE_BLOCK_INDEX: &str = "bc_events_block_idx";
const TREE_TYPE_INDEX: &str = "bc_events_type_idx";
const KEY_COUNTER: &str = "meta:counter";

impl SledEventIndexer {
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        Self::from_db(db)
    }

    pub fn from_db(db: sled::Db) -> Result<Self, sled::Error> {
        let events = db.open_tree(TREE_EVENTS)?;
        let token_index = db.open_tree(TREE_TOKEN_INDEX)?;
        let block_index = db.open_tree(TREE_BLOCK_INDEX)?;
        let type_index = db.open_tree(TREE_TYPE_INDEX)?;

        let counter = events
            .get(KEY_COUNTER)?
            .map(|v| {
                let bytes: [u8; 8] = v.as_ref().try_into().unwrap_or([0u8; 8]);
                u64::from_be_bytes(bytes)
            })
            .unwrap_or(0);

        Ok(Self {
            db,
            events,
            token_index,
            block_index,
            type_index,
            event_counter: std::sync::atomic::AtomicU64::new(counter),
        })
    }

    fn generate_event_key(&self, token_id: &[u8; 32], block_height: u64) -> String {
        let counter = self
            .event_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("{}/{}/{}", hex::encode(&token_id[..8]), block_height, counter)
    }

    fn save_counter(&self) -> Result<(), sled::Error> {
        let counter = self.event_counter.load(std::sync::atomic::Ordering::SeqCst);
        self.events.insert(KEY_COUNTER, &counter.to_be_bytes())?;
        Ok(())
    }

    pub fn event_count(&self) -> usize {
        self.events.len().saturating_sub(1)
    }

    pub fn flush(&self) -> Result<(), sled::Error> {
        self.events.flush()?;
        self.token_index.flush()?;
        self.block_index.flush()?;
        self.type_index.flush()?;
        Ok(())
    }

    pub fn index_event_owned(&mut self, event: BondingCurveEvent) {
        let event_key = self.generate_event_key(event.token_id(), event.block_height());
        let event_type = event.event_type();
        let token_id = *event.token_id();
        let block_height = event.block_height();

        let serialized = match bincode::serialize(&event) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Failed to serialize event: {}", e);
                return;
            }
        };

        if let Err(e) = self.events.insert(event_key.as_bytes(), serialized) {
            tracing::error!("Failed to store event: {}", e);
            return;
        }

        let token_idx_key = format!("{}/{}", hex::encode(&token_id), &event_key);
        if let Err(e) = self.token_index.insert(token_idx_key.as_bytes(), event_key.as_bytes()) {
            tracing::error!("Failed to update token index: {}", e);
        }

        let block_idx_key = format!("{}/{}", block_height, &event_key);
        if let Err(e) = self.block_index.insert(block_idx_key.as_bytes(), event_key.as_bytes()) {
            tracing::error!("Failed to update block index: {}", e);
        }

        let type_idx_key = format!("{}/{}", event_type, &event_key);
        if let Err(e) = self.type_index.insert(type_idx_key.as_bytes(), event_key.as_bytes()) {
            tracing::error!("Failed to update type index: {}", e);
        }
    }

    pub fn get_token_events(&self, token_id: [u8; 32]) -> Vec<BondingCurveEvent> {
        let prefix = hex::encode(&token_id);
        let mut events = Vec::new();

        for result in self.token_index.scan_prefix(prefix.as_bytes()) {
            match result {
                Ok((_, event_key)) => {
                    if let Ok(Some(data)) = self.events.get(&event_key) {
                        if let Ok(event) = bincode::deserialize::<BondingCurveEvent>(&data) {
                            events.push(event);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading token index: {}", e);
                }
            }
        }

        events.sort_by_key(|e| e.block_height());
        events
    }

    pub fn get_token_events_by_type(&self, token_id: [u8; 32], event_type: &str) -> Vec<BondingCurveEvent> {
        let mut events = Vec::new();

        for result in self.type_index.scan_prefix(event_type.as_bytes()) {
            match result {
                Ok((_, event_key)) => {
                    if let Ok(Some(data)) = self.events.get(&event_key) {
                        if let Ok(event) = bincode::deserialize::<BondingCurveEvent>(&data) {
                            if event.token_id() == &token_id {
                                events.push(event);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading type index: {}", e);
                }
            }
        }

        events.sort_by_key(|e| e.block_height());
        events
    }

    pub fn get_events_in_range(&self, start_block: u64, end_block: u64) -> Vec<BondingCurveEvent> {
        let mut events = Vec::new();

        for block_height in start_block..=end_block {
            let prefix = block_height.to_string();

            for result in self.block_index.scan_prefix(prefix.as_bytes()) {
                match result {
                    Ok((_, event_key)) => {
                        if let Ok(Some(data)) = self.events.get(&event_key) {
                            if let Ok(event) = bincode::deserialize::<BondingCurveEvent>(&data) {
                                events.push(event);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error reading block index: {}", e);
                    }
                }
            }
        }

        events
    }

    pub fn get_latest_event(&self, token_id: [u8; 32]) -> Option<BondingCurveEvent> {
        let events = self.get_token_events(token_id);
        events.into_iter().max_by_key(|e| e.block_height())
    }

    pub fn get_purchase_events(&self, token_id: [u8; 32]) -> Vec<BondingCurveEvent> {
        self.get_token_events_by_type(token_id, "token_purchased")
    }

    pub fn get_sale_events(&self, token_id: [u8; 32]) -> Vec<BondingCurveEvent> {
        self.get_token_events_by_type(token_id, "token_sold")
    }

    pub fn get_swap_events(&self, token_id: [u8; 32]) -> Vec<BondingCurveEvent> {
        self.get_token_events_by_type(token_id, "swap_executed")
    }

    pub fn get_liquidity_events(&self, token_id: [u8; 32]) -> Vec<BondingCurveEvent> {
        let mut events = self.get_token_events_by_type(token_id, "liquidity_added");
        events.extend(self.get_token_events_by_type(token_id, "liquidity_removed"));
        events.sort_by_key(|e| e.block_height());
        events
    }
}

impl EventIndexer for SledEventIndexer {
    fn index_event(&mut self, event: BondingCurveEvent) {
        self.index_event_owned(event);
    }

    fn get_token_events(&self, _token_id: [u8; 32]) -> Vec<&BondingCurveEvent> {
        vec![]
    }

    fn get_purchase_events(&self, _token_id: [u8; 32]) -> Vec<&BondingCurveEvent> {
        vec![]
    }

    fn get_sale_events(&self, _token_id: [u8; 32]) -> Vec<&BondingCurveEvent> {
        vec![]
    }

    fn get_swap_events(&self, _token_id: [u8; 32]) -> Vec<&BondingCurveEvent> {
        vec![]
    }

    fn get_liquidity_events(&self, _token_id: [u8; 32]) -> Vec<&BondingCurveEvent> {
        vec![]
    }

    fn get_events_in_range(&self, _start_block: u64, _end_block: u64) -> Vec<&BondingCurveEvent> {
        vec![]
    }

    fn get_latest_event(&self, _token_id: [u8; 32]) -> Option<&BondingCurveEvent> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::events::{BondingCurveEvent, ReserveUpdateReason};
    use tempfile::TempDir;

    fn create_test_event(token_id: [u8; 32], block_height: u64, event_type: &str) -> BondingCurveEvent {
        match event_type {
            "token_purchased" => BondingCurveEvent::TokenPurchased {
                token_id,
                buyer: [2u8; 32],
                stable_amount: 100_000_000,
                token_amount: 1000,
                price: 100_000,
                block_height,
                timestamp: 1_600_000_000 + block_height,
            },
            "token_sold" => BondingCurveEvent::TokenSold {
                token_id,
                seller: [3u8; 32],
                token_amount: 500,
                stable_amount: 50_000_000,
                price: 100_000,
                block_height,
                timestamp: 1_600_000_000 + block_height,
            },
            "graduated" => BondingCurveEvent::Graduated {
                token_id,
                final_reserve: 10_000_000,
                final_supply: 100_000,
                threshold_met: "reserve".to_string(),
                block_height,
                timestamp: 1_600_000_000 + block_height,
            },
            _ => BondingCurveEvent::TokenPurchased {
                token_id,
                buyer: [2u8; 32],
                stable_amount: 100_000_000,
                token_amount: 1000,
                price: 100_000,
                block_height,
                timestamp: 1_600_000_000 + block_height,
            },
        }
    }

    #[test]
    fn test_sled_event_indexer_basic() {
        let temp_dir = TempDir::new().unwrap();
        let mut indexer = SledEventIndexer::open(temp_dir.path()).unwrap();

        let token1 = [1u8; 32];
        let token2 = [2u8; 32];

        indexer.index_event_owned(create_test_event(token1, 100, "token_purchased"));
        indexer.index_event_owned(create_test_event(token1, 101, "token_purchased"));
        indexer.index_event_owned(create_test_event(token2, 150, "graduated"));

        indexer.flush().unwrap();

        let token1_events = indexer.get_token_events(token1);
        assert_eq!(token1_events.len(), 2);

        let token2_events = indexer.get_token_events(token2);
        assert_eq!(token2_events.len(), 1);

        println!("Sled event indexer basic test passed!");
    }

    #[test]
    fn test_sled_event_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let token1 = [1u8; 32];

        {
            let mut indexer = SledEventIndexer::open(&path).unwrap();
            indexer.index_event_owned(create_test_event(token1, 100, "token_purchased"));
            indexer.index_event_owned(create_test_event(token1, 101, "token_sold"));
            indexer.flush().unwrap();
        }

        {
            let indexer = SledEventIndexer::open(&path).unwrap();
            let events = indexer.get_token_events(token1);
            assert_eq!(events.len(), 2);

            let purchases = indexer.get_purchase_events(token1);
            assert_eq!(purchases.len(), 1);

            let sales = indexer.get_sale_events(token1);
            assert_eq!(sales.len(), 1);
        }

        println!("Sled event persistence test passed!");
    }

    #[test]
    fn test_sled_event_range_query() {
        let temp_dir = TempDir::new().unwrap();
        let mut indexer = SledEventIndexer::open(temp_dir.path()).unwrap();

        let token1 = [1u8; 32];

        for block in 100..=110 {
            indexer.index_event_owned(create_test_event(token1, block, "token_purchased"));
        }

        indexer.flush().unwrap();

        let events = indexer.get_events_in_range(105, 108);
        assert_eq!(events.len(), 4);

        println!("Sled event range query test passed!");
    }
}
