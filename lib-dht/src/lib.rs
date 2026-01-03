pub mod utils;
pub mod messages;
pub mod routing;
pub mod kad;
pub mod kademlia;
pub mod refresh;
pub mod rpc;
pub extern crate rlibbencode;

//MAYBE MAKE ROUTING TABLE A BASE SET - IE ABSTRACT - NOT TRAIT
//echo -n "hello" >/dev/udp/localhost/8080
//netcat -ul 8080
//test --package kad4 --lib tests -- --nocapture

//server redo - decrease arc mutexes...
//possibly redo entire system regarding RPC

#[cfg(test)]
mod tests {

    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
    use std::thread::sleep;
    use std::time::Duration;
    use crate::kad::kademlia_base::KademliaBase;
    use crate::kademlia::Kademlia;

    #[test]
    #[ignore = "Manual network smoke test (long-running/infinite loop)."]
    fn test() {
        let kad = Kademlia::try_from("Kademlia").unwrap();
        kad.get_routing_table().lock().unwrap().set_secure_only(false);
        kad.get_server().lock().unwrap().set_allow_bogon(true);
        //kad.bind(8080);
        kad.join(8080, SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 8070)).unwrap();
        //kad.join(6881, SocketAddr::new(resolve_hostname("router.sectorrent.com").unwrap(), 6881)).unwrap();

        //kad.join_thread();

        loop {
            sleep(Duration::from_secs(10));
            let routing_table = kad.get_routing_table().lock().unwrap();
            println!("CONSENSUS: {}  {}  {}",
                     routing_table.get_derived_uid().to_string(),
                     routing_table.get_consensus_external_address().to_string(),
                     routing_table.all_nodes().len());
        }
    }

    fn resolve_hostname(hostname: &str) -> Result<IpAddr, std::io::Error> {
        let addresses: Vec<SocketAddr> = (hostname, 0).to_socket_addrs()?.collect();
        let ip_addresses: Vec<IpAddr> = addresses.into_iter().map(|addr| addr.ip()).collect();
        Ok(*ip_addresses.get(0).unwrap())
    }
}
