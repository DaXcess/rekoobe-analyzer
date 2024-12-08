use std::{collections::VecDeque, io::{Error, ErrorKind, Result}};

use log::trace;
use pcap::{Capture, Offline};

use crate::{
    encryption::{decrypt, Aes128Cbc},
    models::{filter::PacketFilter, packet::Packet, Sender},
};

pub struct Context {
    aes_1: Aes128Cbc,
    aes_2: Aes128Cbc,
    capture: Capture<Offline>,
    filter: PacketFilter,

    last_sender: Option<Sender>,
    decrypted: VecDeque<(Sender, Vec<u8>)>,
}

impl Context {
    pub fn new(
        aes_1: Aes128Cbc,
        aes_2: Aes128Cbc,
        capture: Capture<Offline>,
        filter: PacketFilter,
    ) -> Self {
        Self {
            aes_1,
            aes_2,
            capture,
            filter,

            last_sender: None,
            decrypted: VecDeque::new(),
        }
    }

    pub fn get_data(&mut self, sender: Option<Sender>) -> Result<Option<(Sender, Vec<u8>)>> {
        if let Some(packet) = self.decrypted.pop_front() {
            if sender != self.last_sender {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "Sender changed even though there are still packets available. Perhaps multiple TCP streams got intertwined? Expected: {:?}, Got: {:?}", 
                        self.last_sender, 
                        sender
                    ),
                ));
            };

            return Ok(Some(packet));
        }

        let Some(packet) = self.advance(sender) else {
            return Ok(None);
        };

        let liable = match sender {
            Some(sender) => sender,
            None => self.filter.identify_sender(&packet),
        };

        self.last_sender = sender;

        let decrypted = decrypt(self, packet.payload(), liable)?;
        self.decrypted.extend(decrypted.into_iter().map(|packet| (liable, packet)));

        return self.get_data(sender);
    }

    pub fn get_aes_context(&mut self, sender: Sender) -> &mut Aes128Cbc {
        match sender {
            Sender::Slave => &mut self.aes_1,
            Sender::Master => &mut self.aes_2,
        }
    }

    fn advance(&mut self, sender: Option<Sender>) -> Option<Packet> {
        loop {
            let Ok(packet) = self.capture.next_packet() else {
                return None;
            };

            let Ok(packet) = Packet::from_packet(packet) else {
                continue;
            };

            if packet.payload().is_empty() {
                continue;
            }

            if !self.filter.compare(&packet, sender) {
                trace!("Ignored a non-empty packet");
                continue;
            }

            return Some(packet);
        }
    }
}
