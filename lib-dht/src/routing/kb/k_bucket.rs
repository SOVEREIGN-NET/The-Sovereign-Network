use crate::routing::kb::ls_comparator::ls_compare;
use crate::utils::node::Node;

pub const MAX_BUCKET_SIZE: usize = 5; //SHOULD PROBABLY CHANGE THIS IN SOME WAY... - USAGES ARE HIGH - WONT ALLOW FOR M_BUCKET TO UTILIZE THIS
const MAX_STALE_COUNT: u32 = 1;

pub struct KBucket {
    pub(crate) nodes: Vec<Node>,
    pub(crate) cache: Vec<Node>
}

impl KBucket {

    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            cache: Vec::new()
        }
    }

    pub fn insert(&mut self, n: Node) {
        if let Some(node) = self.nodes.iter_mut().find(|c| n.eq(c)) {
            node.seen();
            self.nodes.sort_by(|a, b| ls_compare(a, b));

        } else if self.nodes.len() >= MAX_BUCKET_SIZE {
            if let Some(node) = self.cache.iter_mut().find(|c| n.eq(c)) {
                node.seen();

            } else if self.cache.len() >= MAX_BUCKET_SIZE {
                let mut index = MAX_BUCKET_SIZE+1;

                for i in 0..self.cache.len() {
                    if self.cache.get(i).unwrap().stale >= MAX_STALE_COUNT {
                        if index < MAX_BUCKET_SIZE && self.cache.get(i).unwrap().stale > self.cache.get(index).unwrap().stale {
                            index = i;
                        }
                    }
                }

                if index < MAX_BUCKET_SIZE {
                    self.cache.remove(index);
                    self.cache.push(n);
                }

            }else{
                self.cache.push(n);
            }
        }else{
            self.nodes.push(n);
            self.nodes.sort_by(|a, b| ls_compare(a, b));
        }
    }

    pub fn contains_ip(&self, n: &Node) -> bool {
        self.nodes.contains(&n) || self.cache.contains(&n)
    }

    pub fn contains_uid(&self, n: &Node) -> bool {
        self.nodes.iter().any(|c| c.verify(&n)) || self.cache.iter().any(|c| c.verify(&n))
    }

    pub fn has_queried(&self, n: &Node, now: u128) -> bool {
        for c in &self.nodes {
            if c.eq(&n) {
                return c.has_queried(now);
            }
        }

        false
    }

    /*
    fn all_nodes(&self) -> Vec<Node> {
        self.nodes.clone()
    }
    */

    pub fn unqueried_nodes(&self, now: u128) -> Vec<Node> {
        self.nodes.iter().filter(|&n| !n.has_queried(now)).cloned().collect()
    }

    /*
    fn size(&self) -> usize {
        self.nodes.len()
    }

    fn csize(&self) -> usize {
        self.cache.len()
    }
    */
}
