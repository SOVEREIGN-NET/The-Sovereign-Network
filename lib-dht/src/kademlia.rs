use crate::kad::kademlia_base::KademliaBase;
use crate::kad::server::Server;
use crate::messages::find_node_request::FindNodeRequest;
use crate::messages::find_node_response::FindNodeResponse;
use crate::messages::inter::message_base::MessageBase;
use crate::messages::ping_request::PingRequest;
use crate::messages::ping_response::PingResponse;
use crate::refresh::refresh_handler::RefreshHandler;
use crate::refresh::tasks::bucket_refresh_task::BucketRefreshTask;
use crate::refresh::tasks::stale_refresh_task::StaleRefreshTask;
use crate::routing::bucket_types::BucketTypes;
use crate::routing::inter::routing_table::RoutingTable;
use crate::routing::kb::k_bucket::MAX_BUCKET_SIZE;
use crate::routing::kb::k_routing_table::KRoutingTable;
use crate::rpc::events::inter::event::Event;
use crate::rpc::events::inter::message_event::MessageEvent;
use crate::rpc::join_node_response_listener::JoinNodeResponseListener;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Kademlia {
    routing_table: Arc<Mutex<dyn RoutingTable>>,
    server: Arc<Mutex<Server>>,
    refresh: Arc<Mutex<RefreshHandler>>,
}

impl Default for Kademlia {
    fn default() -> Self {
        let mut server = Server::new();

        server.register_message(|| Box::new(PingRequest::default()));
        server.register_message(|| Box::new(PingResponse::default()));
        server.register_message(|| Box::new(FindNodeRequest::default()));
        server.register_message(|| Box::new(FindNodeResponse::default()));

        server.register_request_listener("ping", move |event| {
            //println!("{}", event.get_message().to_string());

            let mut response = PingResponse::new(*event.get_message().get_transaction_id());
            response.set_destination(event.get_message().get_origin().ok());
            response.set_public(event.get_message().get_origin().ok());
            event.set_response(Box::new(response));
        });

        let _self = Self {
            routing_table: Arc::new(Mutex::new(KRoutingTable::new())),
            server: Arc::new(Mutex::new(server)),
            refresh: Arc::new(Mutex::new(RefreshHandler::new())),
        };

        _self
            .routing_table
            .lock()
            .ok()
            .add_restart_listener(Arc::new({
                let _self = _self.clone();
                move || {
                    let uid = _self.routing_table.lock().ok().get_derived_uid();
                    let closest = _self
                        .routing_table
                        .lock()
                        .ok()
                        .find_closest(&uid, MAX_BUCKET_SIZE);

                    if closest.is_empty() {
                        return;
                    }

                    for n in closest {
                        let mut request = FindNodeRequest::default();
                        request.set_destination(n.address);
                        request.set_target(_self.routing_table.lock().ok().get_derived_uid());

                        _self
                            .server
                            .lock()
                            .ok()
                            .send_with_callback(
                                &mut request,
                                Box::new(JoinNodeResponseListener::new(&_self)),
                            )
                            .ok();
                    }
                }
            }));

        _self
            .refresh
            .lock()
            .ok()
            .add_operation(Box::new(BucketRefreshTask::new(&_self)));
        _self
            .refresh
            .lock()
            .ok()
            .add_operation(Box::new(StaleRefreshTask::new(&_self)));

        _self
            .server
            .lock()
            .ok()
            .register_request_listener("find_node", {
                let _self = _self.clone();
                move |event| {
                    //println!("{}", event.get_message().to_string());
                    if event.is_prevent_default() {
                        return;
                    }

                    let request = event
                        .get_message()
                        .as_any()
                        .downcast_ref::<FindNodeRequest>()
                        .ok();

                    let mut nodes = _self
                        .get_routing_table()
                        .lock()
                        .ok()
                        .find_closest(&request.get_target().ok(), MAX_BUCKET_SIZE);
                    nodes.retain(|&n| n != event.get_node());

                    let mut response =
                        FindNodeResponse::new(*event.get_message().get_transaction_id());
                    response.set_destination(event.get_message().get_origin().ok());
                    response.set_public(event.get_message().get_origin().ok());
                    response.add_nodes(nodes);
                    event.set_response(Box::new(response));
                }
            });

        _self.server.lock().ok().kademlia = Some(_self.clone_dyn());

        _self
    }
}

impl From<BucketTypes> for Kademlia {
    fn from(bucket_type: BucketTypes) -> Self {
        let mut server = Server::new();

        server.register_message(|| Box::new(PingRequest::default()));
        server.register_message(|| Box::new(PingResponse::default()));
        server.register_message(|| Box::new(FindNodeRequest::default()));
        server.register_message(|| Box::new(FindNodeResponse::default()));

        server.register_request_listener("ping", move |event| {
            //println!("{}", event.get_message().to_string());

            let mut response = PingResponse::new(*event.get_message().get_transaction_id());
            response.set_destination(event.get_message().get_origin().ok());
            response.set_public(event.get_message().get_origin().ok());
            event.set_response(Box::new(response));
        });

        let _self = Self {
            routing_table: bucket_type.routing_table(),
            server: Arc::new(Mutex::new(server)),
            refresh: Arc::new(Mutex::new(RefreshHandler::new())),
        };

        _self
            .routing_table
            .lock()
            .ok()
            .add_restart_listener(Arc::new({
                let _self = _self.clone();
                move || {
                    let uid = _self.routing_table.lock().ok().get_derived_uid();
                    let closest = _self
                        .routing_table
                        .lock()
                        .ok()
                        .find_closest(&uid, MAX_BUCKET_SIZE);

                    if closest.is_empty() {
                        return;
                    }

                    for n in closest {
                        let mut request = FindNodeRequest::default();
                        request.set_destination(n.address);
                        request.set_target(_self.routing_table.lock().ok().get_derived_uid());

                        _self
                            .server
                            .lock()
                            .ok()
                            .send_with_callback(
                                &mut request,
                                Box::new(JoinNodeResponseListener::new(&_self)),
                            )
                            .ok();
                    }
                }
            }));

        _self
            .refresh
            .lock()
            .ok()
            .add_operation(Box::new(BucketRefreshTask::new(&_self)));
        _self
            .refresh
            .lock()
            .ok()
            .add_operation(Box::new(StaleRefreshTask::new(&_self)));

        _self
            .server
            .lock()
            .ok()
            .register_request_listener("find_node", {
                let _self = _self.clone();
                move |event| {
                    //println!("{}", event.get_message().to_string());
                    if event.is_prevent_default() {
                        return;
                    }

                    let request = event
                        .get_message()
                        .as_any()
                        .downcast_ref::<FindNodeRequest>()
                        .ok();

                    let mut nodes = _self
                        .get_routing_table()
                        .lock()
                        .ok()
                        .find_closest(&request.get_target().ok(), MAX_BUCKET_SIZE);
                    nodes.retain(|&n| n != event.get_node());

                    let mut response =
                        FindNodeResponse::new(*event.get_message().get_transaction_id());
                    response.set_destination(event.get_message().get_origin().ok());
                    response.set_public(event.get_message().get_origin().ok());
                    response.add_nodes(nodes);
                    event.set_response(Box::new(response));
                }
            });

        _self.server.lock().ok().kademlia = Some(_self.clone_dyn());

        _self
    }
}

impl TryFrom<&str> for Kademlia {
    type Error = io::Error;

    fn try_from(value: &str) -> io::Result<Self> {
        let mut server = Server::new();

        server.register_message(|| Box::new(PingRequest::default()));
        server.register_message(|| Box::new(PingResponse::default()));
        server.register_message(|| Box::new(FindNodeRequest::default()));
        server.register_message(|| Box::new(FindNodeResponse::default()));

        server.register_request_listener("ping", move |event| {
            //println!("{}", event.get_message().to_string());

            let mut response = PingResponse::new(*event.get_message().get_transaction_id());
            response.set_destination(event.get_message().get_origin().ok());
            response.set_public(event.get_message().get_origin().ok());
            event.set_response(Box::new(response));
        });

        let _self = Self {
            routing_table: BucketTypes::from_string(value)
                .ok_or_else(|| io::ErrorKind::InvalidData)?
                .routing_table(),
            server: Arc::new(Mutex::new(server)),
            refresh: Arc::new(Mutex::new(RefreshHandler::new())),
        };

        _self
            .routing_table
            .lock()
            .ok()
            .add_restart_listener(Arc::new({
                let _self = _self.clone();
                move || {
                    let uid = _self.routing_table.lock().ok().get_derived_uid();
                    let closest = _self
                        .routing_table
                        .lock()
                        .ok()
                        .find_closest(&uid, MAX_BUCKET_SIZE);

                    if closest.is_empty() {
                        return;
                    }

                    for n in closest {
                        let mut request = FindNodeRequest::default();
                        request.set_destination(n.address);
                        request.set_target(_self.routing_table.lock().ok().get_derived_uid());

                        _self
                            .server
                            .lock()
                            .ok()
                            .send_with_callback(
                                &mut request,
                                Box::new(JoinNodeResponseListener::new(&_self)),
                            )
                            .ok();
                    }
                }
            }));

        _self
            .refresh
            .lock()
            .ok()
            .add_operation(Box::new(BucketRefreshTask::new(&_self)));
        _self
            .refresh
            .lock()
            .ok()
            .add_operation(Box::new(StaleRefreshTask::new(&_self)));

        _self
            .server
            .lock()
            .ok()
            .register_request_listener("find_node", {
                let _self = _self.clone();
                move |event| {
                    //println!("{}", event.get_message().to_string());
                    if event.is_prevent_default() {
                        return;
                    }

                    let request = event
                        .get_message()
                        .as_any()
                        .downcast_ref::<FindNodeRequest>()
                        .ok();

                    let mut nodes = _self
                        .get_routing_table()
                        .lock()
                        .ok()
                        .find_closest(&request.get_target().ok(), MAX_BUCKET_SIZE);
                    nodes.retain(|&n| n != event.get_node());

                    let mut response =
                        FindNodeResponse::new(*event.get_message().get_transaction_id());
                    response.set_destination(event.get_message().get_origin().ok());
                    response.set_public(event.get_message().get_origin().ok());
                    response.add_nodes(nodes);
                    event.set_response(Box::new(response));
                }
            });

        _self.server.lock().ok().kademlia = Some(_self.clone_dyn());

        Ok(_self)
    }
}

impl KademliaBase for Kademlia {
    fn bind(&self, port: u16) -> io::Result<()> {
        self.server.lock().ok().start(port)
    }

    fn join(&self, local_port: u16, addr: SocketAddr) -> io::Result<()> {
        self.server.lock().ok().start(local_port)?;

        let mut request = FindNodeRequest::default();
        request.set_destination(addr);
        request.set_target(self.routing_table.lock().ok().get_derived_uid());

        self.server
            .lock()
            .ok()
            .send_with_callback(&mut request, Box::new(JoinNodeResponseListener::new(self)))
    }

    fn stop(&self) {
        self.server.lock().ok().stop();
        self.refresh.lock().ok().stop();
    }

    fn get_server(&self) -> &Arc<Mutex<Server>> {
        &self.server
    }

    fn get_routing_table(&self) -> &Arc<Mutex<dyn RoutingTable>> {
        &self.routing_table
    }

    fn get_refresh_handler(&self) -> &Arc<Mutex<RefreshHandler>> {
        &self.refresh
    }

    fn join_thread(&self) {
        if self.server.lock().ok().is_running() {
            let handle = self.server.lock().as_mut().ok().handle.take().ok();
            handle.join().ok();
        }
    }

    fn clone_dyn(&self) -> Box<dyn KademliaBase> {
        Box::new(self.clone())
    }
}
