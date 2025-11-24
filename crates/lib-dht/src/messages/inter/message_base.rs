use std::any::Any;
use crate::utils::uid::UID;
use std::net::SocketAddr;
use rlibbencode::variables::bencode_object::BencodeObject;
use crate::kad::server::TID_LENGTH;
use crate::messages::inter::message_exception::MessageException;
use crate::messages::inter::message_type::MessageType;

pub const TID_KEY: &str = "t";

pub trait MessageBase: Send {

    fn set_uid(&mut self, uid: UID);

    fn get_uid(&self) -> Option<UID>;

    fn set_transaction_id(&mut self, tid: [u8; TID_LENGTH]);

    fn get_transaction_id(&self) -> &[u8; TID_LENGTH];

    fn set_public(&mut self, public_address: SocketAddr);

    fn get_public(&self) -> Option<SocketAddr>;

    fn set_destination(&mut self, destination_address: SocketAddr);

    fn get_destination(&self) -> Option<SocketAddr>;

    fn set_origin(&mut self, origin_address: SocketAddr);

    fn get_origin(&self) -> Option<SocketAddr>;

    fn get_type(&self) -> MessageType;

    fn encode(&self) -> BencodeObject;

    fn decode(&mut self, ben: &BencodeObject) -> Result<(), MessageException>;

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn to_string(&self) -> String {
        self.encode().to_string()
    }
}
