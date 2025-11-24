use std::sync::{Arc, Mutex};
use crate::routing::inter::routing_table::RoutingTable;
use crate::routing::kb::k_routing_table::KRoutingTable;
use crate::routing::mainline::m_routing_table::MRoutingTable;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum BucketTypes {
    MainLine,
    Kademlia
}

impl BucketTypes {

    pub fn from_string(name: &str) -> Option<Self> {
        for value in [Self::MainLine, Self::Kademlia] {
            if value.value() == name {
                return Some(value);
            }
        }

        None
    }

    pub fn value(&self) -> &str {
        match self {
            Self::MainLine => "MainLine",
            Self::Kademlia => "Kademlia"
        }
    }

    pub fn routing_table(&self) -> Arc<Mutex<dyn RoutingTable>> {
        match self {
            Self::MainLine => Arc::new(Mutex::new(MRoutingTable::new())),
            Self::Kademlia => Arc::new(Mutex::new(KRoutingTable::new()))
        }
    }
}
