use crate::kad::kademlia_base::KademliaBase;
use crate::messages::inter::message_base::MessageBase;
use crate::messages::ping_request::PingRequest;
use crate::rpc::ping_response_listener::PingResponseListener;
use super::inter::task::Task;

#[derive(Clone)]
pub struct StaleRefreshTask {
    kademlia: Box<dyn KademliaBase>
}

impl StaleRefreshTask {

    pub fn new(kademlia: &dyn KademliaBase) -> Self {
        Self {
            kademlia: kademlia.clone_dyn()
        }
    }
}

impl Task for StaleRefreshTask {

    fn execute(&self) {
        println!("StaleRefresh");
        let listener = Box::new(PingResponseListener::new(self.kademlia.get_routing_table().clone()));
        let nodes = self.kademlia.get_routing_table().lock().unwrap().all_unqueried_nodes();

        for node in nodes {
            let mut request = PingRequest::default();
            request.set_destination(node.address);
            self.kademlia.get_server().lock().unwrap().send_with_node_callback(&mut request, node, listener.clone()).unwrap();
        }
    }

    fn clone_dyn(&self) -> Box<dyn Task> {
        Box::new(self.clone())
    }
}
