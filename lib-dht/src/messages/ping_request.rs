use std::any::Any;
use std::net::SocketAddr;
use rlibbencode::variables::bencode_bytes::BencodeBytes;
use rlibbencode::variables::bencode_object::{BencodeObject, GetObject, ObjectOptions, PutObject};
use crate::kad::server::TID_LENGTH;
use crate::messages::inter::message_base::{MessageBase, TID_KEY};
use crate::messages::inter::message_exception::MessageException;
use crate::messages::inter::message_type::{MessageType, TYPE_KEY};
use crate::utils::uid::{ID_LENGTH, UID};
use super::inter::method_message_base::MethodMessageBase;

#[derive(Clone)]
pub struct PingRequest {
    uid: Option<UID>,
    tid: [u8; TID_LENGTH],
    public: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    origin: Option<SocketAddr>
}

impl PingRequest {

    pub fn new(tid: [u8; TID_LENGTH]) -> Self {
        Self {
            tid,
            ..Default::default()
        }
    }
}

impl Default for PingRequest {

    fn default() -> Self {
        Self {
            uid: None,
            tid: [0u8; TID_LENGTH],
            public: None,
            destination: None,
            origin: None
        }
    }
}

//I WONDER IF WE CAN MACRO THIS SHIT FOR EVERY CLASS...?
impl MessageBase for PingRequest {

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
        MessageType::ReqMsg
    }

    fn encode(&self) -> BencodeObject {
        let mut ben = BencodeObject::new();

        ben.put(TID_KEY, self.tid.clone());
        ben.put("v", "1.0");
        ben.put(TYPE_KEY, self.get_type().rpc_type_name());

        ben.put(self.get_type().rpc_type_name(), self.get_method());
        ben.put(self.get_type().inner_key(), BencodeObject::new());
        ben.get_mut::<BencodeObject>(self.get_type().inner_key()).unwrap().put("id", self.uid.unwrap().bytes().clone());

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

        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl MethodMessageBase for PingRequest {

    fn get_method(&self) -> &str {
        "ping"
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
