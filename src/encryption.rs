use std::io::{Error, ErrorKind, Result};

use aes::cipher::BlockDecryptMut;
use cipher::block_padding::Block;
use log::trace;

use crate::{
    logging,
    models::{context::Context, Sender},
};

pub type Aes128Cbc = cbc::Decryptor<aes::Aes128>;

pub fn decrypt(context: &mut Context, data: &[u8], sender: Sender) -> Result<Vec<Vec<u8>>> {
    let mut aes = context.get_aes_context(sender);

    let header = decrypt_raw(&mut aes, &data[..16]);
    let content_size = get_content_size(&header)?;
    let mut buffer = header[2..].to_vec();

    let packet_size = if content_size <= 14 {
        buffer = buffer[..content_size].to_vec();
        16
    } else {
        let packet_size = ((2 + content_size + 15) / 16) * 16;
        let remain_data = &data[16..packet_size];
        let decrypted = &decrypt_raw(&mut aes, &remain_data)[..content_size - 14];

        buffer.extend_from_slice(decrypted);

        packet_size
    };

    let Some(hmac) = data.get(packet_size..packet_size + 20) else {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Packet signature length is invalid",
        ));
    };

    trace!(
        "Packet:\n• Size: {content_size}\n• HMAC: {}",
        hex::encode(hmac),
    );
    logging::hexdump(&buffer, 16, vec![]);

    let mut packets = vec![buffer];

    let next_packet = &data[packet_size + 20..];
    if next_packet.len() > 0 {
        trace!("TCP packet contains multiple C2 packets");

        packets.extend(decrypt(context, next_packet, sender)?);
    }

    Ok(packets)
}

pub fn decrypt_raw(decrypter: &mut Aes128Cbc, data: &[u8]) -> Vec<u8> {
    const CHUNK_SIZE: usize = 16;

    let mut result = vec![0; data.len()];

    for (idx, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
        let mut block = Block::clone_from_slice(chunk);
        decrypter.decrypt_block_mut(&mut block);

        result[idx * CHUNK_SIZE..idx * CHUNK_SIZE + chunk.len()].copy_from_slice(&block);
    }

    result
}

fn get_content_size(header: &[u8]) -> Result<usize> {
    let binary: [u8; 2] = header[..2].try_into().unwrap();
    let result = i16::from_be_bytes(binary);

    trace!("Packet header:");
    logging::hexdump(header, 16, vec![(0, 2)]);

    if result < 0 || result > 4096 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Packet size is outside of valid range (expected: 0-4096, got: {result})"),
        ));
    }

    Ok(result as usize)
}
