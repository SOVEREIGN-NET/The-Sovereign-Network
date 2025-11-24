use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use core::array::from_fn;
use std::any::Any;
use std::sync::{Arc, Mutex};
use crate::routing::inter::routing_table::{RestartListener, RoutingTable};
use crate::utils;
use crate::utils::hash::crc32c::Crc32c;
use crate::utils::linked_hashmap::LinkedHashMap;
use crate::utils::net::address_utils::is_global_unicast;
use super::k_bucket::KBucket;
use super::k_comparator::KComparator;
use crate::utils::node::{Node, V4_MASK, V6_MASK};
use crate::utils::uid::{ UID, ID_LENGTH };

pub struct KRoutingTable {
    uid: Option<UID>,
    listeners: Vec<RestartListener>,
    consensus_external_address: IpAddr,
    origin_pairs: LinkedHashMap<IpAddr, IpAddr>,
    secure_only: bool,
    k_buckets: [KBucket; ID_LENGTH*8]
}

impl KRoutingTable {

    pub fn new() -> Self {
        let mut routing_table = Self {
            uid: None,
            listeners: Vec::new(),
            consensus_external_address: IpAddr::from([127, 0, 1, 1]),
            origin_pairs: LinkedHashMap::with_capacity(64),
            secure_only: true,
            k_buckets: from_fn(|_| KBucket::new())
        };

        routing_table.derive_uid();
        routing_table
    }
}

impl RoutingTable for KRoutingTable {

    fn get_update_public_ip_consensus(&self) -> fn(Arc<Mutex<dyn RoutingTable>>, IpAddr, IpAddr) {
        Self::update_public_ip_consensus
    }

    fn update_public_ip_consensus(routing_table: Arc<Mutex<dyn RoutingTable>>, source: IpAddr, addr: IpAddr) {
        if !is_global_unicast(addr) {
            return;
        }

        routing_table.lock().unwrap().as_any_mut().downcast_mut::<Self>().unwrap().origin_pairs.insert(source, addr);

        if routing_table.lock().unwrap().as_any().downcast_ref::<Self>().unwrap().origin_pairs.len() > 20 &&
                addr != routing_table.lock().unwrap().as_any().downcast_ref::<Self>().unwrap().consensus_external_address {
            let k: Vec<IpAddr> = routing_table.lock().unwrap().as_any().downcast_ref::<Self>().unwrap().origin_pairs.values();
            let mut res = 0;
            let mut count: i16 = 1;

            for i in 1..k.len() {
                count += if k[i] == k[res] { 1 } else { -1 };

                if count == 0 {
                    res = i;
                    count = 1;
                }
            }

            if routing_table.lock().unwrap().as_any().downcast_ref::<Self>().unwrap().consensus_external_address != k[res] {
                routing_table.lock().unwrap().as_any_mut().downcast_mut::<Self>().unwrap().consensus_external_address = k[res];
                Self::restart(routing_table);
            }
        }
    }

    fn set_external_address(&mut self, address: IpAddr) {
        self.consensus_external_address = address;
    }

    fn get_consensus_external_address(&self) -> IpAddr {
        self.consensus_external_address
    }

    fn insert(&mut self, n: Node) {
        if self.secure_only && !n.has_secure_id() {
            return
        }

        if let Some(uid) = &self.uid {
            if *uid != n.uid {
                let id = self.bucket_uid(&n.uid);

                let mut contains_ip = false;
                for b in &self.k_buckets {
                    if b.contains_ip(&n) {
                        contains_ip = true;
                        break;
                    }
                }

                let contains_uid = self.k_buckets[id].contains_uid(&n);

                if contains_ip == contains_uid {
                    self.k_buckets[id].insert(n);
                }
            }
        }
    }

    fn derive_uid(&mut self) {
        let mut ip: Vec<u8> = match self.consensus_external_address {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        let mask: Vec<u8> = if ip.len() == 4 {
            V4_MASK.to_vec()
        } else {
            V6_MASK.to_vec()
        };

        for i in 0..mask.len() {
            ip[i] &= mask[i];
        }

        //let mut rng = rand::thread_rng();
        let rand: u8 = /*rng.gen::<u8>()*/utils::random::gen::<u8>() & 0xFF;
        let r = rand & 0x7;

        ip[0] |= r << 5;

        let mut c = Crc32c::new();
        c.update(&ip, 0, ip.len());
        let crc = c.get_value();

        let mut bid = [0u8; ID_LENGTH];
        bid[0] = (crc >> 24) as u8;
        bid[1] = (crc >> 16) as u8;
        bid[2] = ((crc >> 8) as u8 & 0xF8) | (/*rng.gen::<u8>()*/utils::random::gen::<u8>() & 0x7);

        for i in 3..19 {
            bid[i] = /*rng.gen::<u8>()*/utils::random::gen::<u8>() & 0xFF;
        }

        bid[19] = rand & 0xFF;

        self.uid = Some(UID::from(bid));
    }

    fn get_derived_uid(&self) -> UID {
        self.uid.unwrap()
    }

    fn is_secure_only(&self) -> bool {
        self.secure_only
    }

    fn set_secure_only(&mut self, secure_only: bool) {
        self.secure_only = secure_only;
    }

    fn add_restart_listener(&mut self, listener: RestartListener) {
        self.listeners.push(listener);
    }

    fn remove_restart_listener(&mut self, index: usize) {
        let _ = self.listeners.remove(index);
    }

    fn has_queried(&self, n: &Node, now: u128) -> bool {
        let id = self.bucket_uid(&n.uid);

        if !self.k_buckets[id].contains_uid(n) {
            return false;
        }

        self.k_buckets[id].has_queried(n, now)
    }

    fn bucket_uid(&self, k: &UID) -> usize {
        self.uid.unwrap().distance(k)-1
    }

    fn all_nodes(&self) -> Vec<Node> {
        let mut nodes = Vec::new();

        for b in &self.k_buckets {
            nodes.extend(&b.nodes);
        }

        nodes
    }

    fn find_closest(&self, k: &UID, r: usize) -> Vec<Node> {
        let mut nodes = self.all_nodes();
        let comparator = KComparator::new(k);
        nodes.sort_by(|a, b| comparator.compare(a, b));

        if nodes.len() > r {
            return nodes[0..r].to_vec();
        }

        nodes
    }

    fn bucket_size(&self, i: usize) -> usize {
        self.k_buckets[i].nodes.len()
    }

    fn all_unqueried_nodes(&self) -> Vec<Node> {
        let mut nodes = Vec::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        for b in &self.k_buckets {
            nodes.extend(&b.unqueried_nodes(now));
        }

        nodes
    }

    fn get_restart(&self) -> fn(Arc<Mutex<dyn RoutingTable>>) {
        Self::restart
    }

    fn restart(routing_table: Arc<Mutex<dyn RoutingTable>>) {
        routing_table.lock().unwrap().as_any_mut().downcast_mut::<Self>().unwrap().derive_uid();

        let nodes = routing_table.lock().unwrap().all_nodes();
        routing_table.lock().unwrap().as_any_mut().downcast_mut::<Self>().unwrap().k_buckets = from_fn(|_| KBucket::new());

        for node in nodes {
            routing_table.lock().unwrap().as_any_mut().downcast_mut::<Self>().unwrap().insert(node);
        }

        if routing_table.lock().unwrap().as_any().downcast_ref::<Self>().unwrap().listeners.is_empty() {
            return;
        }

        let listeners = routing_table.lock().unwrap().as_any().downcast_ref::<Self>().unwrap().listeners.clone();
        for listener in &listeners {
            listener();
        }
    }

    fn upcast(&self) -> &dyn RoutingTable {
        self
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
