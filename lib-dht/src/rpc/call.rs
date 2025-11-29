use std::time::{SystemTime, UNIX_EPOCH};
use crate::messages::inter::method_message_base::MethodMessageBase;
use crate::rpc::events::inter::response_callback::ResponseCallback;
use crate::rpc::response_tracker::STALLED_TIME;
use crate::utils::node::Node;

pub struct Call {
    message: Box<dyn MethodMessageBase>,
    node: Option<Node>,
    callback: Box<dyn ResponseCallback>,
    sent_time: u128
}

impl Call {

    pub fn new(message: &dyn MethodMessageBase, callback: Box<dyn ResponseCallback>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        Self {
            message: message.dyn_clone(),
            node: None,
            callback,
            sent_time: now
        }
    }

    pub fn get_message(&self) -> &dyn MethodMessageBase {
        self.message.as_ref()
    }

    pub fn has_node(&self) -> bool {
        self.node.is_some()
    }

    pub fn set_node(&mut self, node: Node) {
        self.node = Some(node);
    }

    pub fn get_node(&self) -> Node {
        self.node.unwrap()
    }

    pub fn get_response_callback(&self) -> &dyn ResponseCallback {
        self.callback.as_ref()
    }

    pub fn set_response_callback(&mut self, callback: Box<dyn ResponseCallback>) {
        self.callback = callback;
    }

    pub fn set_sent_time(&mut self, sent_time: u128) {
        self.sent_time = sent_time;
    }

    pub fn get_sent_time(&self) -> u128 {
        self.sent_time
    }

    pub fn is_stalled(&self, now: u128) -> bool {
        now-self.sent_time > STALLED_TIME
    }
}
