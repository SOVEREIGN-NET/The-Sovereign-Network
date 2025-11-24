use crate::messages::inter::message_base::MessageBase;
use crate::rpc::events::inter::event::Event;
use crate::utils::node::Node;

pub trait MessageEvent: Event {

    fn get_message(&self) -> &dyn MessageBase;

    fn has_node(&self) -> bool;

    fn set_node(&mut self, node: Node);

    fn get_node(&self) -> Node;

    fn set_received_time(&mut self, received_time: u128);

    fn get_received_time(&self) -> u128;

    fn received(&mut self);
}
