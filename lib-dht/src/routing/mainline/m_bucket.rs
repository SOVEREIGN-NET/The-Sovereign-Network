use crate::routing::kb::ls_comparator::ls_compare;
use crate::utils::node::Node;

pub const MAX_BUCKET_SIZE: usize = 5;
const MAX_STALE_COUNT: u32 = 1;

pub struct MBucket {
    pub(crate) nodes: Vec<Node>,
    pub(crate) cache: Vec<Node>,
}

impl MBucket {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            cache: Vec::new(),
        }
    }

    pub fn is_full(&self) -> bool {
        self.nodes.len() >= MAX_BUCKET_SIZE
    }

    pub fn insert(&mut self, n: Node) {
        if let Some(node) = self.nodes.iter_mut().find(|c| n.eq(c)) {
            node.seen();
            self.nodes.sort_by(|a, b| ls_compare(a, b));
        } else if self.nodes.len() >= MAX_BUCKET_SIZE {
            // Bucket full — try to evict a stale cache entry.
            if let Some(node) = self.cache.iter_mut().find(|c| n.eq(c)) {
                node.seen();
            } else if self.cache.len() >= MAX_BUCKET_SIZE {
                let mut worst = None;
                for i in 0..self.cache.len() {
                    if self.cache[i].stale >= MAX_STALE_COUNT {
                        if worst.map_or(true, |w: usize| self.cache[i].stale > self.cache[w].stale)
                        {
                            worst = Some(i);
                        }
                    }
                }
                if let Some(idx) = worst {
                    self.cache.remove(idx);
                    self.cache.push(n);
                }
            } else {
                self.cache.push(n);
            }
        } else {
            self.nodes.push(n);
            self.nodes.sort_by(|a, b| ls_compare(a, b));
        }
    }

    pub fn contains_ip(&self, n: &Node) -> bool {
        self.nodes.contains(n) || self.cache.contains(n)
    }

    pub fn contains_uid(&self, n: &Node) -> bool {
        self.nodes.iter().any(|c| c.verify(n)) || self.cache.iter().any(|c| c.verify(n))
    }

    pub fn has_queried(&self, n: &Node, now: u128) -> bool {
        for c in &self.nodes {
            if c.eq(n) {
                return c.has_queried(now);
            }
        }
        false
    }

    pub fn unqueried_nodes(&self, now: u128) -> Vec<Node> {
        self.nodes
            .iter()
            .filter(|n| !n.has_queried(now))
            .cloned()
            .collect()
    }
}
