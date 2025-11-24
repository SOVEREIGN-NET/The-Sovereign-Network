use std::time::{SystemTime, UNIX_EPOCH};
use crate::messages::inter::message_base::MessageBase;
use crate::rpc::events::inter::event::Event;
use crate::rpc::events::inter::message_event::MessageEvent;
use crate::utils::node::Node;

pub struct StalledEvent<'a> {
    prevent_default: bool,
    message: &'a dyn MessageBase,
    node: Option<Node>,
    received_time: u128,
    sent_time: u128
}

impl<'a> StalledEvent<'a> {

    pub fn new(message: &'a dyn MessageBase) -> Self {
        Self {
            prevent_default: false,
            message,
            node: None,
            received_time: 0,
            sent_time: 0
        }
    }

    pub fn set_sent_time(&mut self, sent_time: u128) {
        self.sent_time = sent_time;
    }

    pub fn get_sent_time(&self) -> u128 {
        self.sent_time
    }
}

impl<'a> Event for StalledEvent<'a> {

    fn is_prevent_default(&self) -> bool {
        self.prevent_default
    }

    fn prevent_default(&mut self) {
        self.prevent_default = true;
    }
}

impl<'a> MessageEvent for StalledEvent<'a> {

    fn get_message(&self) -> &dyn MessageBase {
        self.message
    }

    fn has_node(&self) -> bool {
        self.node.is_some()
    }

    fn set_node(&mut self, node: Node) {
        self.node = Some(node);
    }

    fn get_node(&self) -> Node {
        self.node.unwrap()
    }

    fn set_received_time(&mut self, received_time: u128) {
        self.received_time = received_time;
    }

    fn get_received_time(&self) -> u128 {
        self.received_time
    }

    fn received(&mut self) {
        self.received_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();
    }
}
