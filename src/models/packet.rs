use std::io::{Error, ErrorKind, Result};

use etherparse::{LinuxSllProtocolType, NetHeaders, TcpHeader, TransportHeader};

pub struct Packet(NetHeaders, TcpHeader, Vec<u8>);

impl Packet {
    pub fn from_packet(packet: pcap::Packet<'_>) -> Result<Self> {
        Self::try_parse_ether(packet.data)
            .or_else(|_| Self::try_parse_sll(packet.data))
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid TCP packet"))
    }

    pub fn network(&self) -> &NetHeaders {
        &self.0
    }

    pub fn tcp(&self) -> &TcpHeader {
        &self.1
    }

    pub fn payload(&self) -> &[u8] {
        &self.2
    }

    fn try_parse_ether(data: &[u8]) -> Result<Self> {
        let headers = etherparse::PacketHeaders::from_ethernet_slice(data)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid ethernet packet"))?;

        let Some(TransportHeader::Tcp(tcp)) = headers.transport else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Packet is not a TCP packet",
            ));
        };

        let network = headers.net.ok_or_else(|| {
            Error::new(ErrorKind::InvalidData, "Packet is not an IPv4/IPv6 packet")
        })?;

        Ok(Self(network, tcp, headers.payload.slice().to_vec()))
    }

    fn try_parse_sll(data: &[u8]) -> Result<Self> {
        let sll = etherparse::LinuxSllSlice::from_slice(data)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid SLL packet"))?;

        let LinuxSllProtocolType::EtherType(ether) = sll.payload().protocol_type else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid protocol type in SSL packet",
            ));
        };

        let headers = etherparse::PacketHeaders::from_ether_type(ether, sll.payload().payload)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid ethernet packet"))?;

        let Some(TransportHeader::Tcp(tcp)) = headers.transport else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Packet is not a TCP packet",
            ));
        };

        let network = headers.net.ok_or_else(|| {
            Error::new(ErrorKind::InvalidData, "Packet is not an IPv4/IPv6 packet")
        })?;

        Ok(Self(network, tcp, headers.payload.slice().to_vec()))
    }
}
