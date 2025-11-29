use crate::utils::node::Node;

pub const MAX_BUCKET_SIZE: usize = 5; //SHOULD PROBABLY CHANGE THIS IN SOME WAY...
const MAX_STALE_COUNT: u32 = 1;

pub struct MBucket {
    pub(crate) nodes: Vec<Node>,
    pub(crate) cache: Vec<Node>
}

impl MBucket {

    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            cache: Vec::new()
        }
    }

    pub fn is_full(&self) -> bool {
        self.nodes.len() >= MAX_BUCKET_SIZE
    }
}
