use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::kad::kademlia_base::KademliaBase;
use crate::messages::find_node_request::FindNodeRequest;
use crate::messages::find_node_response::FindNodeResponse;
use crate::messages::inter::message_base::MessageBase;
use crate::messages::ping_request::PingRequest;
use crate::routing::kb::k_bucket::MAX_BUCKET_SIZE;
use crate::rpc::events::error_response_event::ErrorResponseEvent;
use crate::rpc::events::inter::message_event::MessageEvent;
use crate::rpc::events::inter::response_callback::ResponseCallback;
use crate::rpc::events::response_event::ResponseEvent;
use crate::rpc::events::stalled_event::StalledEvent;
use crate::rpc::ping_response_listener::PingResponseListener;
use crate::utils::node::Node;
use crate::utils::uid::ID_LENGTH;
use super::inter::task::Task;

#[derive(Clone)]
pub struct BucketRefreshTask {
    kademlia: Box<dyn KademliaBase>
}

impl BucketRefreshTask {

    pub fn new(kademlia: &dyn KademliaBase) -> Self {
        Self {
            kademlia: kademlia.clone_dyn()
        }
    }
}

impl Task for BucketRefreshTask {

    fn execute(&self) {
        let listener = Box::new(FindNodeResponseListener::new(self.kademlia.as_ref()));
        println!("EXECUTING BUCKET REFRESH");

        for i in 1..ID_LENGTH*8 {
            if self.kademlia.get_routing_table().lock().unwrap().bucket_size(i) < MAX_BUCKET_SIZE {
                let k = self.kademlia.get_routing_table().lock().unwrap().get_derived_uid().generate_node_id_by_distance(i);

                let closest = self.kademlia.get_routing_table().lock().unwrap().find_closest(&k, MAX_BUCKET_SIZE);
                if closest.is_empty() {
                    continue;
                }

                for node in closest {
                    let mut request = FindNodeRequest::default();
                    request.set_destination(node.address);
                    request.set_target(k);

                    self.kademlia.get_server().lock().unwrap().send_with_node_callback(&mut request, node, listener.clone()).unwrap();
                }
            }
        }
    }

    fn clone_dyn(&self) -> Box<dyn Task> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
pub struct FindNodeResponseListener {
    kademlia: Box<dyn KademliaBase>,
    listener: PingResponseListener,
    queries: Arc<Mutex<Vec<Node>>> //MAY NEED TO BE RC
}

impl FindNodeResponseListener {

    pub fn new(kademlia: &dyn KademliaBase) -> Self {
        Self {
            kademlia: kademlia.clone_dyn(),
            listener: PingResponseListener::new(kademlia.get_routing_table().clone()),
            queries: Arc::new(Mutex::new(Vec::new()))
        }
    }
}

impl ResponseCallback for FindNodeResponseListener {

    fn on_response(&self, _event: ResponseEvent) {
        _event.get_node().seen();
        println!("SEEN FN {}", _event.get_node().to_string());
        let response = _event.get_message().as_any().downcast_ref::<FindNodeResponse>().unwrap();

        if response.has_nodes() {
            let mut nodes = response.get_all_nodes();

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis();

            let uid = self.kademlia.get_routing_table().lock().unwrap().get_derived_uid();
            nodes.retain(|node| {
                if uid == node.uid ||
                        self.queries.lock().unwrap().contains(node) ||
                        self.kademlia.get_routing_table().lock().unwrap().has_queried(node, now) {
                    false

                } else {
                    true
                }
            });

            for node in &nodes {
                self.queries.lock().unwrap().push(node.clone());
            }

            for node in &nodes {
                if self.kademlia.get_routing_table().lock().unwrap().is_secure_only() && !node.has_secure_id() {
                    println!("SKIPPING {}  {}  {}", now, node.last_seen, node.to_string());
                    continue;
                }

                let mut req = PingRequest::default();
                req.set_destination(node.address);
                self.kademlia.get_server().lock().unwrap().send_with_node_callback(&mut req, node.clone(), Box::new(self.listener.clone())).unwrap();
            }
        }
    }

    fn on_error_response(&self, _event: ErrorResponseEvent) {
        _event.get_node().seen();
    }

    fn on_stalled(&self, _event: StalledEvent) {
        _event.get_node().mark_stale();
    }
}
