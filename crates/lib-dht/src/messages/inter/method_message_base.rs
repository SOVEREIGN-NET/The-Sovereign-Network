use super::message_base::MessageBase;

pub trait MethodMessageBase: MessageBase {

    fn get_method(&self) -> &str;

    fn upcast(&self) -> &dyn MessageBase;

    fn upcast_mut(&mut self) -> &mut dyn MessageBase;

    fn dyn_clone(&self) -> Box<dyn MethodMessageBase>;
}

/*
    fn encode(&self) -> BencodeObject {
        let mut ben = BencodeObject::new();

        ben.put(TID_KEY, self.tid.clone());
        ben.put("v", "1.0");
        ben.put(TYPE_KEY, self.get_type().rpc_type_name());

        match self.get_type() {
            MessageType::ReqMsg => {
                ben.put(self.get_type().rpc_type_name(), self.get_method());
                ben.put(self.get_type().inner_key(), BencodeObject::new());
                ben.get_object_mut(self.get_type().inner_key()).unwrap().put("id", self.uid.unwrap().bid.clone());
            },
            MessageType::RspMsg => {
                ben.put(self.get_type().inner_key(), BencodeObject::new());
                ben.get_object_mut(self.get_type().inner_key()).unwrap().put("id", self.uid.unwrap().bid.clone());

                if let Some(public) = self.public {
                    ben.put("ip", pack_address(&public));
                }
            },
            _ => unimplemented!()
        }

        ben
    }

    fn decode(&mut self, ben: &BencodeObject) {
        if !ben.contains_key(self.get_type().inner_key()) {
            //throw new MessageException("Protocol Error, such as a malformed packet.", 203);
        }

        if !ben.get_object(self.get_type().inner_key()).unwrap().contains_key("id") {
            //throw new MessageException("Protocol Error, such as a malformed packet.", 203);
        }

        let mut bid = [0u8; ID_LENGTH];
        bid.copy_from_slice(&ben.get_object(self.get_type().inner_key()).unwrap().get_bytes("id").unwrap()[..ID_LENGTH]);
        self.uid = Some(UID::from(bid));

        match self.get_type() {
            MessageType::RspMsg => {
                if ben.contains_key("ip") {
                    self.public = unpack_address(ben.get_bytes("ip").unwrap());
                }
            },
            _ => ()
        };
    }
*/
