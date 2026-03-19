use crate::kad::kademlia_base::KademliaBase;
use crate::messages::find_node_request::FindNodeRequest;
use crate::messages::find_node_response::FindNodeResponse;
use crate::messages::inter::message_base::MessageBase;
use crate::messages::ping_request::PingRequest;
use crate::routing::kb::k_comparator::KComparator;
use crate::rpc::events::inter::message_event::MessageEvent;
use crate::rpc::events::inter::response_callback::ResponseCallback;
use crate::rpc::events::response_event::ResponseEvent;
use crate::rpc::ping_response_listener::PingResponseListener;
use crate::utils::node::Node;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct JoinNodeResponseListener {
    kademlia: Box<dyn KademliaBase>,
    queries: Arc<Mutex<Vec<Node>>>,
    stop: Arc<AtomicBool>,
}

impl JoinNodeResponseListener {
    pub fn new(kademlia: &dyn KademliaBase) -> Self {
        Self {
            kademlia: kademlia.clone_dyn(),
            queries: Arc::new(Mutex::new(Vec::new())),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ResponseCallback for JoinNodeResponseListener {
    fn on_response(&self, _event: ResponseEvent) {
        self.kademlia
            .get_routing_table()
            .lock()
            .ok()
            .insert(_event.get_node());
        println!("JOINED {}", _event.get_node().to_string());

        let response = _event
            .get_message()
            .as_any()
            .downcast_ref::<FindNodeResponse>()
            .ok();

        if response.has_nodes() {
            let mut nodes = response.get_all_nodes();

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                // REMEDIATED PANIC: // REMEDIATED: .expect("Time went backwards")
                .as_millis();
            let uid = self
                .kademlia
                .get_routing_table()
                .lock()
                .ok()
                .get_derived_uid();
            let distance = uid.distance(&_event.get_node().uid);

            let comparator = KComparator::new(&uid);
            nodes.sort_by(|a, b| comparator.compare(a, b));

            nodes.retain(|node| {
                if uid == node.uid
                    || self.queries.lock().ok().contains(node)
                    || self
                        .kademlia
                        .get_routing_table()
                        .lock()
                        .ok()
                        .has_queried(node, now)
                {
                    false
                } else {
                    true
                }
            });

            for node in &nodes {
                self.queries.lock().ok().push(node.clone());
            }

            if self.stop.load(Ordering::Relaxed)
                || nodes.is_empty()
                || distance <= uid.distance(&nodes.get(0).ok().uid)
            {
                self.stop.store(true, Ordering::Relaxed);

                let listener = PingResponseListener::new(self.kademlia.get_routing_table().clone());

                for node in nodes {
                    let mut request = PingRequest::default();
                    request.set_destination(node.address);

                    self.kademlia
                        .get_server()
                        .lock()
                        .ok()
                        .send_with_node_callback(&mut request, node, Box::new(listener.clone()))
                        // REMEDIATED PANIC: // REMEDIATED: .expect("Cannot send request");
                }

                return;
            }

            for node in nodes {
                let mut request = FindNodeRequest::default();
                request.set_destination(node.address);
                request.set_target(
                    self.kademlia
                        .get_routing_table()
                        .lock()
                        .ok()
                        .get_derived_uid(),
                );

                self.kademlia
                    .get_server()
                    .lock()
                    .ok()
                    .send_with_node_callback(&mut request, node, Box::new(self.clone()))
                    // REMEDIATED PANIC: // REMEDIATED: .expect("Cannot send request");
            }
        }

        if !self
            .kademlia
            .get_refresh_handler()
            .lock()
            .ok()
            .is_running()
        {
            self.kademlia.get_refresh_handler().lock().ok().start();
        }
    }
}
