use std::cmp::min;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{io, thread};
use std::sync::mpsc::{channel, Sender, TryRecvError};
use std::thread::{sleep, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use rlibbencode::variables::bencode_bytes::BencodeBytes;
use rlibbencode::variables::bencode_object::{BencodeObject, GetObject, ObjectOptions};
use rlibbencode::variables::inter::bencode_variable::{BencodeVariable, FromBencode, ToBencode};
use crate::kad::kademlia_base::KademliaBase;
use crate::messages::error_response::ErrorResponse;
use crate::messages::inter::message_base::{MessageBase, TID_KEY};
use crate::messages::inter::message_exception::MessageException;
use crate::messages::inter::message_key::MessageKey;
use crate::messages::inter::message_type::{MessageType, TYPE_KEY};
use crate::messages::inter::method_message_base::MethodMessageBase;
use crate::rpc::call::Call;
use crate::rpc::events::error_response_event::ErrorResponseEvent;
use crate::rpc::events::inter::event::Event;
use crate::rpc::events::inter::message_event::MessageEvent;
use crate::rpc::events::inter::response_callback::ResponseCallback;
use crate::rpc::events::request_event::RequestEvent;
use crate::rpc::events::response_event::ResponseEvent;
use crate::rpc::response_tracker::ResponseTracker;
use crate::utils;
use crate::utils::net::address_utils::is_bogon;
use crate::utils::node::Node;
use crate::utils::spam_throttle::SpamThrottle;

pub const TID_LENGTH: usize = 6;

pub struct Server {
    pub kademlia: Option<Box<dyn KademliaBase>>,
    pub (crate) handle: Option<JoinHandle<()>>,
    server: Option<UdpSocket>,
    allow_bogon: bool,
    tracker: ResponseTracker,
    running: Arc<AtomicBool>, //MAY NOT BE NEEDED
    tx_sender_pool: Option<Sender<(Vec<u8>, SocketAddr)>>,
    request_mapping: HashMap<String, Vec<Box<dyn Fn(&mut RequestEvent) + Send>>>,
    messages: HashMap<MessageKey, fn() -> Box<dyn MethodMessageBase>>,
    sender_throttle: SpamThrottle
}

impl Server {

    pub fn new(/*kademlia: Box<dyn KademliaBase>*/) -> Self {
        Self {
            kademlia: None,
            handle: None,
            server: None,
            allow_bogon: false,
            tracker: ResponseTracker::new(),
            running: Arc::new(AtomicBool::new(false)), //MAY NOT BE NEEDED
            tx_sender_pool: None,
            request_mapping: HashMap::new(),
            messages: HashMap::new(),
            sender_throttle: SpamThrottle::new()
        }
    }

    pub fn start(&mut self, port: u16) -> io::Result<()> {
        if self.is_running() {
            return Err(io::Error::new(io::ErrorKind::Other, "Server is already running"));
        }

        self.running.store(true, Ordering::Relaxed);

        self.server = Some(UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?);
        self.server.as_ref().unwrap().set_nonblocking(true)?;

        let (tx_sender_pool, rx_sender_pool) = channel();
        self.tx_sender_pool = Some(tx_sender_pool);

        self.handle = Some(thread::spawn({
            let kademlia = self.kademlia.clone();
            let server = self.server.as_ref().unwrap().try_clone()?;
            let running = Arc::clone(&self.running);
            let receiver_throttle = SpamThrottle::new();

            move || {
                let mut kademlia = kademlia.unwrap();
                let mut buf = [0u8; 65535];
                let mut last_decay_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis();

                while running.load(Ordering::Relaxed) {
                    match server.recv_from(&mut buf) {
                        Ok((size, src_addr)) => {
                            if !receiver_throttle.add_and_test(src_addr.ip()) {
                                Self::on_receive(kademlia.as_mut(), buf[..size].to_vec().as_slice(), src_addr);
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        _ => break
                    }

                    match rx_sender_pool.try_recv() {
                        Ok((data, dst_addr)) => {
                            if !kademlia.get_server().lock().unwrap().sender_throttle.test(dst_addr.ip()) {
                                server.send_to(data.as_slice(), dst_addr);
                            }
                        }
                        Err(TryRecvError::Empty) => {}
                        Err(TryRecvError::Disconnected) => break
                    }

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_millis();

                    if now - last_decay_time >= 1000 {
                        receiver_throttle.decay();
                        kademlia.get_server().lock().unwrap().sender_throttle.decay();
                        kademlia.get_server().lock().unwrap().tracker.remove_stalled();

                        last_decay_time = now;
                    }

                    sleep(Duration::from_millis(1));
                }
            }
        }));

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn register_request_listener<F>(&mut self, key: &str, callback: F)
    where
        F: Fn(&mut RequestEvent) + Send + 'static
    {
        let key = key.to_string();
        if self.request_mapping.contains_key(&key) {
            self.request_mapping.get_mut(&key).unwrap().push(Box::new(callback));
            return;
        }
        let mut mapping: Vec<Box<dyn Fn(&mut RequestEvent) + Send>> = Vec::new();
        mapping.push(Box::new(callback));
        self.request_mapping.insert(key.to_string(), mapping);
    }

    pub fn register_message(&mut self, constructor: fn() -> Box<dyn MethodMessageBase>) {
        let message = constructor();
        self.messages.insert(MessageKey::new(message.get_method(), message.get_type()), constructor);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn is_allow_bogon(&self) -> bool {
        self.allow_bogon
    }

    pub fn set_allow_bogon(&mut self, allow_bogon: bool) {
        self.allow_bogon = allow_bogon;
    }

    pub fn on_receive(kademlia: &mut dyn KademliaBase, data: &[u8], src_addr: SocketAddr) {
        if !kademlia.get_server().lock().unwrap().allow_bogon && is_bogon(src_addr) {
            return;
        }

        match BencodeObject::from_bencode(data) {
            Ok(ben) => {
                if !ben.contains_key(TID_KEY) || !ben.contains_key(TYPE_KEY) {
                    //panic
                    return;
                }

                let t = MessageType::from_rpc_type_name(ben.get::<BencodeBytes>(TYPE_KEY).unwrap().to_string()).unwrap();

                match t {
                    MessageType::ReqMsg => {
                        if let Err(e) = || -> Result<(), MessageException> {
                            let message_key = MessageKey::new(ben.get::<BencodeBytes>(t.rpc_type_name())
                                    .ok_or_else(|| MessageException::new("Method Unknown", 204))?.as_str(), t);

                            let mut m = kademlia.get_server().lock().as_ref().unwrap().messages.get(&message_key).ok_or(MessageException::new("Method Unknown", 204))?();
                            //let mut m = constructor();

                            let mut tid = [0u8; TID_LENGTH];
                            let slice = ben.get::<BencodeBytes>(TID_KEY).ok_or_else(|| MessageException::new("Method Unknown", 204))?.as_bytes();
                            let len_to_copy = min(slice.len(), TID_LENGTH);
                            tid[..len_to_copy].copy_from_slice(&slice[..len_to_copy]);
                            //tid.copy_from_slice(ben.get_bytes(TID_KEY).map_err(|e| MessageException::new("Method Unknown", 204))?);

                            m.set_transaction_id(tid);
                            m.decode(&ben)?;
                            m.set_origin(src_addr);

                            let node = Node::new(m.get_uid().unwrap(), m.get_origin().unwrap());
                            kademlia.get_routing_table().lock().unwrap().insert(node);
                            println!("SEEN REQ {}", node.to_string());

                            let k = ben.get::<BencodeBytes>(t.rpc_type_name()).unwrap().to_string();

                            if !kademlia.get_server().lock().as_ref().unwrap().request_mapping.contains_key(&k) {
                                return Err(MessageException::new("Method Unknown", 204));
                            }

                            let mut event = RequestEvent::new(m.upcast());
                            event.set_node(node);

                            for callback in kademlia.get_server().lock().as_ref().unwrap().request_mapping.get(&k).unwrap() {
                                callback(&mut event);
                            }

                            if event.is_prevent_default() {
                                //RETURN NOTHING - NO ERROR
                                return Err(MessageException::new("Method Unknown", 204));
                            }

                            if !event.has_response() {
                                return Err(MessageException::new("Method Unknown", 204));
                            }

                            kademlia.get_server().lock().as_ref().unwrap().send(event.get_response().unwrap()).unwrap();

                            Ok(())

                        }() {
                            //println!("{}", ben.to_string());

                            let mut tid = [0u8; TID_LENGTH];
                            let slice = ben.get::<BencodeBytes>(TID_KEY).unwrap().as_bytes();
                            let len_to_copy = min(slice.len(), TID_LENGTH);
                            tid[..len_to_copy].copy_from_slice(&slice[..len_to_copy]);

                            let mut response = ErrorResponse::new(tid);
                            response.set_destination(src_addr);
                            response.set_public(src_addr);
                            response.set_code(e.get_code());
                            response.set_description(e.get_message());

                            kademlia.get_server().lock().as_ref().unwrap().send(&mut response).unwrap();
                        }

                        if !kademlia.get_refresh_handler().lock().unwrap().is_running() {
                            kademlia.get_refresh_handler().lock().unwrap().start();
                        }
                    },
                    MessageType::RspMsg => {
                        if let Err(e) = || -> Result<(), MessageException> {
                            let mut tid = [0u8; TID_LENGTH];
                            let slice = ben.get::<BencodeBytes>(TID_KEY).ok_or_else(|| MessageException::new("Method Unknown", 204))?.as_bytes();
                            let len_to_copy = min(slice.len(), TID_LENGTH);
                            tid[..len_to_copy].copy_from_slice(&slice[..len_to_copy]);

                            let call = kademlia.get_server().lock().as_mut().unwrap().tracker.poll(&tid).ok_or(MessageException::new("Server Error", 202))?;

                            //PROBLEM LINE BELOW... - NEED TO MAKE THE MESSAGE FIND_NODE_RESPONSE...
                            let message_key = MessageKey::new(call.get_message().get_method(), t);

                            let mut m = kademlia.get_server().lock().as_ref().unwrap().messages.get(&message_key).ok_or(MessageException::new("Method Unknown", 204))?();

                            m.set_transaction_id(tid);
                            m.decode(&ben)?;
                            m.set_origin(src_addr);

                            if m.get_public().is_some() {
                                let update = kademlia.get_routing_table().lock().unwrap().get_update_public_ip_consensus();
                                update(kademlia.get_routing_table().clone(), m.get_origin().unwrap().ip(), m.get_public().unwrap().ip());
                            }

                            if call.get_message().get_destination() != m.get_origin() {
                                return Err(MessageException::new("Generic Error", 201));
                            }

                            let mut event;

                            if call.has_node() {
                                if call.get_node().uid != m.get_uid().unwrap() {
                                    return Err(MessageException::new("Generic Error", 201));
                                }

                                event = ResponseEvent::new(m.as_ref().upcast(), call.get_node());

                            } else {
                                event = ResponseEvent::new(m.as_ref().upcast(), Node::new(m.get_uid().unwrap(), m.get_origin().unwrap()));
                            }

                            event.received();
                            event.set_sent_time(call.get_sent_time());
                            event.set_request(call.get_message().upcast());

                            call.get_response_callback().on_response(event);

                            Ok(())

                        }() {
                            println!("{}", e.get_message());
                        }
                    },
                    MessageType::ErrMsg => {
                        //println!("ERR  {}", ben.to_string());

                        if let Err(e) = || -> Result<(), MessageException> {
                            let mut tid = [0u8; TID_LENGTH];
                            let slice = ben.get::<BencodeBytes>(TID_KEY).ok_or_else(|| MessageException::new("Method Unknown", 204))?.as_bytes();
                            let len_to_copy = min(slice.len(), TID_LENGTH);
                            tid[..len_to_copy].copy_from_slice(&slice[..len_to_copy]);

                            let call = kademlia.get_server().lock().as_mut().unwrap().tracker.poll(&tid).ok_or(MessageException::new("Server Error", 202))?;

                            let mut m = ErrorResponse::new(tid);
                            m.decode(&ben)?;
                            m.set_origin(src_addr);

                            if m.get_public().is_some() {
                                let update = kademlia.get_routing_table().lock().unwrap().get_update_public_ip_consensus();
                                update(kademlia.get_routing_table().clone(), m.get_origin().unwrap().ip(), m.get_public().unwrap().ip());
                            }

                            if call.get_message().get_destination() != m.get_origin() {
                                return Err(MessageException::new("Generic Error", 201));
                            }

                            let mut event = ErrorResponseEvent::new(&m);

                            if call.has_node() {
                                event.set_node(call.get_node());
                            }

                            event.received();
                            event.set_sent_time(call.get_sent_time());
                            event.set_request(call.get_message().upcast());

                            call.get_response_callback().on_error_response(event);

                            Ok(())

                        }() {
                            println!("{}", e.get_message());
                        }
                    }
                }
            },
            Err(e) => {
                println!("{}", e.to_string());
            }
        }
    }

    pub fn send(&self, message: &mut dyn MessageBase) -> io::Result<()> {
        if message.get_destination().is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Message destination set to null"));
        }

        if !self.allow_bogon && is_bogon(message.get_destination().unwrap()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Message destination set to bogon"));
        }

        if message.get_type() != MessageType::ErrMsg {
            message.set_uid(self.kademlia.as_ref().unwrap().get_routing_table().lock().unwrap().get_derived_uid());
        }

        //if let Some(server) = &self.server {
        //    server.send_to(message.encode().encode().as_slice(), message.get_destination().unwrap()).map_err(|e| e.to_string())?;
        //}
        if !self.sender_throttle.add_and_test(message.get_destination().unwrap().ip()) {
            self.tx_sender_pool.as_ref().unwrap().send((message.encode().to_bencode(), message.get_destination().unwrap())).unwrap();
        }

        Ok(())
    }

    pub fn send_with_callback(&mut self, message: &mut dyn MethodMessageBase, callback: Box<dyn ResponseCallback>) -> io::Result<()> {
        if message.get_type() != MessageType::ReqMsg {
            return self.send(message.upcast_mut());
        }

        let tid = self.generate_transaction_id();
        message.set_transaction_id(tid);
        self.tracker.add(tid, Call::new(message, callback));
        self.send(message.upcast_mut())
    }

    pub fn send_with_node_callback(&mut self, message: &mut dyn MethodMessageBase, node: Node, callback: Box<dyn ResponseCallback>) -> io::Result<()> {
        if message.get_type() != MessageType::ReqMsg {
            return self.send(message.upcast_mut());
        }

        let tid = self.generate_transaction_id();
        message.set_transaction_id(tid);
        let mut call = Call::new(message, callback);
        call.set_node(node);
        self.tracker.add(tid, call);
        self.send(message.upcast_mut())
    }

    pub fn generate_transaction_id(&self) -> [u8; TID_LENGTH] {
        utils::random::gen_array::<u8, TID_LENGTH>()
    }
}
