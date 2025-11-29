use std::any::Any;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use crate::utils::node::Node;
use crate::utils::uid::UID;

pub trait RoutingTable: Send {

    fn get_update_public_ip_consensus(&self) -> fn(Arc<Mutex<dyn RoutingTable>>, IpAddr, IpAddr);

    fn update_public_ip_consensus(routing_table: Arc<Mutex<dyn RoutingTable>>, source: IpAddr, addr: IpAddr) where Self: Sized;

    fn set_external_address(&mut self, address: IpAddr);

    fn get_consensus_external_address(&self) -> IpAddr;

    fn insert(&mut self, n: Node);

    fn derive_uid(&mut self);

    fn get_derived_uid(&self) -> UID;

    fn is_secure_only(&self) -> bool;

    fn set_secure_only(&mut self, secure_only: bool);

    fn add_restart_listener(&mut self, listener: RestartListener);

    fn remove_restart_listener(&mut self, index: usize);

    fn has_queried(&self, n: &Node, now: u128) -> bool;

    fn bucket_uid(&self, k: &UID) -> usize;

    fn all_nodes(&self) -> Vec<Node>;

    fn find_closest(&self, k: &UID, r: usize) -> Vec<Node>;

    fn bucket_size(&self, i: usize) -> usize;

    fn all_unqueried_nodes(&self) -> Vec<Node>;

    fn get_restart(&self) -> fn(Arc<Mutex<dyn RoutingTable>>);

    fn restart(routing_table: Arc<Mutex<dyn RoutingTable>>) where Self: Sized;

    fn upcast(&self) -> &dyn RoutingTable;

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;
}

pub type RestartListener = Arc<dyn Fn() + Send + Sync>;
