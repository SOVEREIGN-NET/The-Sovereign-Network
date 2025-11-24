use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::kad::server::TID_LENGTH;
use crate::rpc::call::Call;
use crate::rpc::events::inter::message_event::MessageEvent;
use crate::rpc::events::stalled_event::StalledEvent;

pub const MAX_ACTIVE_CALLS: usize = 512;
pub const STALLED_TIME: u128 = 60000;

pub struct ResponseTracker {
    calls: HashMap<[u8; TID_LENGTH], Call>
}

impl ResponseTracker {

    pub fn new() -> Self {
        Self {
            calls: HashMap::with_capacity(MAX_ACTIVE_CALLS),
        }
    }

    pub fn add(&mut self, tid: [u8; TID_LENGTH], call: Call) {
        self.calls.insert(tid, call);
    }

    pub fn get(&self, tid: &[u8; TID_LENGTH]) -> Option<&Call> {
        self.calls.get(tid)
    }

    pub fn contains(&self, tid: &[u8; TID_LENGTH]) -> bool {
        self.calls.contains_key(tid)
    }

    pub fn remove(&mut self, tid: &[u8; TID_LENGTH]) -> Option<Call> {
        self.calls.remove(tid)
    }

    pub fn poll(&mut self, tid: &[u8; TID_LENGTH]) -> Option<Call> {
        self.calls.remove(tid)
    }

    pub fn remove_stalled(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        let mut stalled = Vec::new();

        for (&tid, call) in self.calls.iter() {
            if !call.is_stalled(now) {
                break;
            }

            stalled.push(tid);
        }

        for tid in stalled {
            if let Some(call) = self.calls.remove(&tid) {
                //println!("STALLED {}", call.get_node().to_string());

                let mut event = StalledEvent::new(call.get_message().upcast());
                event.set_sent_time(call.get_sent_time());

                if call.has_node() {
                    event.set_node(call.get_node());
                }

                call.get_response_callback().on_stalled(event);
            }
        }
    }
}
