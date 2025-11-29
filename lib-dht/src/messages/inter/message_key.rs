use crate::messages::inter::message_type::MessageType;

#[derive(Eq, PartialEq, Hash)]
pub struct MessageKey {
    method: String,
    type_: MessageType
}

impl MessageKey {

    pub fn new(method: &str, type_: MessageType) -> Self {
        Self {
            method: method.to_string(),
            type_
        }
    }

    pub fn get_method(&self) -> &String {
        &self.method
    }

    pub fn get_type(&self) -> &MessageType {
        &self.type_
    }
}
