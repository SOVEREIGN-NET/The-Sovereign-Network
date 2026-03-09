use crate::utils::node::Node;
use std::cmp::Ordering;

pub fn ls_compare(a: &Node, b: &Node) -> Ordering {
    if a.eq(b) {
        return Ordering::Equal;
    } else if a.last_seen > b.last_seen {
        return Ordering::Greater;
    }

    Ordering::Less
}
