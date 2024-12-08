use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::NetHeaders;

use super::{packet::Packet, Sender};

pub struct PacketFilter {
    master_endpoint: String,
    slave_endpoint: String,
}

impl PacketFilter {
    pub fn new(packet: &Packet) -> Self {
        let (source_ip, source_port, dest_ip, dest_port) = Self::get_packet_info(packet);

        Self {
            master_endpoint: format!("{source_ip}:{source_port}"),
            slave_endpoint: format!("{dest_ip}:{dest_port}"),
        }
    }

    pub fn compare(&self, packet: &Packet, sender: Option<Sender>) -> bool {
        let (source_ip, source_port, dest_ip, dest_port) = Self::get_packet_info(packet);

        match sender {
            None => {
                self.master_endpoint == format!("{source_ip}:{source_port}")
                    && self.slave_endpoint == format!("{dest_ip}:{dest_port}")
                    || self.slave_endpoint == format!("{source_ip}:{source_port}")
                        && self.master_endpoint == format!("{dest_ip}:{dest_port}")
            }
            Some(Sender::Master) => self.master_endpoint == format!("{source_ip}:{source_port}"),
            Some(Sender::Slave) => self.slave_endpoint == format!("{source_ip}:{source_port}"),
        }
    }

    pub fn identify_sender(&self, packet: &Packet) -> Sender {
        if self.compare(packet, Some(Sender::Master)) {
            Sender::Master
        } else if self.compare(packet, Some(Sender::Slave)) {
            Sender::Slave
        } else {
            unreachable!()
        }
    }

    pub fn master_endpoint(&self) -> &str {
        &self.master_endpoint
    }

    pub fn slave_endpoint(&self) -> &str {
        &self.slave_endpoint
    }

    fn get_packet_info(packet: &Packet) -> (String, u16, String, u16) {
        let (source_ip, dest_ip) = match packet.network() {
            NetHeaders::Ipv4(header, _) => (
                Ipv4Addr::from(header.source).to_string(),
                Ipv4Addr::from(header.destination).to_string(),
            ),
            NetHeaders::Ipv6(header, _) => (
                Ipv6Addr::from(header.source).to_string(),
                Ipv6Addr::from(header.destination).to_string(),
            ),
        };

        (
            source_ip,
            packet.tcp().source_port,
            dest_ip,
            packet.tcp().destination_port,
        )
    }
}
