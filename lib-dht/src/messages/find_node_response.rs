use std::any::Any;
use std::net::SocketAddr;
use rlibbencode::variables::bencode_bytes::BencodeBytes;
use rlibbencode::variables::bencode_object::{BencodeObject, GetObject, ObjectOptions, PutObject};
use crate::kad::server::TID_LENGTH;
use crate::messages::inter::message_base::{MessageBase, TID_KEY};
use crate::messages::inter::message_exception::MessageException;
use crate::messages::inter::message_type::{MessageType, TYPE_KEY};
use crate::utils::net::address_types::AddressTypes;
use crate::utils::net::address_utils::{pack_address, unpack_address};
use crate::utils::node::Node;
use crate::utils::node_utils::{pack_nodes, unpack_nodes};
use crate::utils::uid::{ID_LENGTH, UID};
use super::inter::method_message_base::MethodMessageBase;

pub const NODE_CAP: usize = 20;

#[derive(Clone)]
pub struct FindNodeResponse {
    uid: Option<UID>,
    tid: [u8; TID_LENGTH],
    public: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    origin: Option<SocketAddr>,
    nodes: Vec<Node>
}

impl FindNodeResponse {

    pub fn new(tid: [u8; TID_LENGTH]) -> Self {
        Self {
            tid,
            ..Default::default()
        }
    }

    pub fn add_node(&mut self, node: Node) {
        self.nodes.push(node);
    }

    pub fn get_node(&self, i: usize) -> Option<&Node> {
        self.nodes.get(i)
    }

    pub fn remove_node(&mut self, i: usize) {
        self.nodes.remove(i);
    }

    pub fn contains_node(&self, node: &Node) -> bool {
        self.nodes.contains(node)
    }

    pub fn has_nodes(&self) -> bool {
        !self.nodes.is_empty()
    }

    pub fn add_nodes(&mut self, nodes: Vec<Node>) {
        if nodes.len()+self.nodes.len() > NODE_CAP {
            //throw new IllegalArgumentException("Adding nodes would exceed Node Cap of "+NODE_CAP);
        }
        self.nodes.extend(nodes);
    }

    pub fn get_all_nodes(&self) -> Vec<Node> {
        self.nodes.clone()
    }

    pub fn get_all_ipv4_nodes(&self) -> Vec<Node> {
        let mut r = Vec::new();

        for node in &self.nodes {
            if node.address.is_ipv4() {
                r.push(node.clone());
            }
        }

        r
    }

    pub fn get_all_ipv6_nodes(&self) -> Vec<Node> {
        let mut r = Vec::new();

        for node in &self.nodes {
            if node.address.is_ipv6() {
                r.push(node.clone());
            }
        }

        r
    }
}

impl Default for FindNodeResponse {

    fn default() -> Self {
        Self {
            uid: None,
            tid: [0u8; TID_LENGTH],
            public: None,
            destination: None,
            origin: None,
            nodes: Vec::new()
        }
    }
}

//I WONDER IF WE CAN MACRO THIS SHIT FOR EVERY CLASS...?
impl MessageBase for FindNodeResponse {

    fn set_uid(&mut self, uid: UID) {
        self.uid = Some(uid);
    }

    fn get_uid(&self) -> Option<UID> {
        self.uid
    }

    fn set_transaction_id(&mut self, tid: [u8; TID_LENGTH]) {
        self.tid = tid;
    }

    fn get_transaction_id(&self) -> &[u8; TID_LENGTH] {
        &self.tid
    }

    fn set_public(&mut self, public: SocketAddr) {
        self.public = Some(public);
    }

    fn get_public(&self) -> Option<SocketAddr> {
        self.public
    }

    fn set_destination(&mut self, destination: SocketAddr) {
        self.destination = Some(destination);
    }

    fn get_destination(&self) -> Option<SocketAddr> {
        self.destination
    }

    fn set_origin(&mut self, origin: SocketAddr) {
        self.origin = Some(origin);
    }

    fn get_origin(&self) -> Option<SocketAddr> {
        self.origin
    }

    fn get_type(&self) -> MessageType {
        MessageType::RspMsg
    }

    fn encode(&self) -> BencodeObject {
        let mut ben = BencodeObject::new();

        ben.put(TID_KEY, self.tid.clone());
        ben.put("v", "1.0");
        ben.put(TYPE_KEY, self.get_type().rpc_type_name());

        ben.put(self.get_type().rpc_type_name(), self.get_method());
        ben.put(self.get_type().inner_key(), BencodeObject::new());
        ben.get_mut::<BencodeObject>(self.get_type().inner_key()).unwrap().put("id", self.uid.unwrap().bytes().clone());

        if let Some(public) = self.public {
            ben.put("ip", pack_address(&public));
        }

        if self.nodes.is_empty() {
            return ben;
        }

        let nodes = self.get_all_ipv4_nodes();
        if !nodes.is_empty() {
            ben.get_mut::<BencodeObject>(self.get_type().inner_key()).unwrap().put("nodes", pack_nodes(nodes, AddressTypes::Ipv4));
        }

        let nodes = self.get_all_ipv6_nodes();
        if !nodes.is_empty() {
            ben.get_mut::<BencodeObject>(self.get_type().inner_key()).unwrap().put("nodes6", pack_nodes(nodes, AddressTypes::Ipv6));
        }

        ben
    }

    fn decode(&mut self, ben: &BencodeObject) -> Result<(), MessageException> {
        if !ben.contains_key(self.get_type().inner_key()) {
            return Err(MessageException::new("Protocol Error, such as a malformed packet.", 203));
        }

        match ben.get::<BencodeObject>(self.get_type().inner_key()).unwrap().get::<BencodeBytes>("id") {
            Some(id) => {
                let mut bid = [0u8; ID_LENGTH];
                bid.copy_from_slice(&id.as_bytes()[..ID_LENGTH]);
                self.uid = Some(UID::from(bid));
            }
            _ => return Err(MessageException::new("Protocol Error, such as a malformed packet.", 203))
        }

        match ben.get::<BencodeBytes>("ip") {
            Some(addr) => {
                self.public = match unpack_address(addr.as_bytes()) {
                    Ok(addr) => Some(addr),
                    _ => None
                }
            }
            _ => {}
        }

        match ben.get::<BencodeObject>(self.get_type().inner_key()).unwrap().get::<BencodeBytes>("nodes") {
            Some(nodes) => self.nodes.extend(unpack_nodes(nodes.as_bytes(), AddressTypes::Ipv4)),
            _ => {}
        }

        match ben.get::<BencodeObject>(self.get_type().inner_key()).unwrap().get::<BencodeBytes>("nodes6") {
            Some(nodes) => self.nodes.extend(unpack_nodes(nodes.as_bytes(), AddressTypes::Ipv6)),
            _ => {}
        }

        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl MethodMessageBase for FindNodeResponse {

    fn get_method(&self) -> &str {
        "find_node"
    }

    fn upcast(&self) -> &dyn MessageBase {
        self
    }

    fn upcast_mut(&mut self) -> &mut dyn MessageBase {
        self
    }

    fn dyn_clone(&self) -> Box<dyn MethodMessageBase> {
        Box::new(self.clone())
    }
}
