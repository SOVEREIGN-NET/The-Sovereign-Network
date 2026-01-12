//! Delegation tree index for parent-child relationships.

use std::collections::HashMap;
use super::types::NameHash;

#[derive(Debug, Clone, Default)]
pub struct DelegationTree {
    children_by_parent: HashMap<NameHash, Vec<NameHash>>,
}

impl DelegationTree {
    pub fn new() -> Self {
        Self {
            children_by_parent: HashMap::new(),
        }
    }

    pub fn add_child(&mut self, parent: NameHash, child: NameHash) {
        let entry = self.children_by_parent.entry(parent).or_default();
        if !entry.contains(&child) {
            entry.push(child);
        }
    }

    pub fn remove_child(&mut self, parent: &NameHash, child: &NameHash) {
        if let Some(children) = self.children_by_parent.get_mut(parent) {
            children.retain(|existing| existing != child);
        }
    }

    pub fn children_of(&self, parent: &NameHash) -> Vec<NameHash> {
        self.children_by_parent
            .get(parent)
            .cloned()
            .unwrap_or_default()
    }
}
