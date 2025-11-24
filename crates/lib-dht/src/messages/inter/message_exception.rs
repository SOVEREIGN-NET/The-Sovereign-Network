
#[derive(Debug)]
pub struct MessageException {
    message: String,
    code: i32
}

impl MessageException {

    pub fn new(message: &str, code: i32) -> Self {
        Self {
            message: message.to_string(),
            code
        }
    }

    pub fn get_message(&self) -> &String {
        &self.message
    }

    pub fn get_code(&self) -> i32 {
        self.code
    }
}
