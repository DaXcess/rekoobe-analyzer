mod encryption;
mod logging;
mod models;

use std::{
    io::{Error, ErrorKind, Result},
    path::PathBuf,
};

use aes::cipher::KeyIvInit;
use colored::Colorize;
use encryption::Aes128Cbc;
use log::{debug, error, info, trace};
use models::{context::Context, filter::PacketFilter, packet::Packet, Sender};
use pcap::{Capture, Offline};
use sha1::{Digest, Sha1};
use structopt::StructOpt;

type Bytes = Vec<u8>;

#[derive(StructOpt)]
struct Opts {
    /// The path to a pcap file containing Rekoobe C2 communication
    #[structopt(long, short, default_value = "capture.pcap", parse(from_os_str))]
    file: PathBuf,

    /// The shared secret used to decrypt the communication
    #[structopt(long, short)]
    secret: String,

    /// (Optional) The signature to verify the authenticity of both the client and the server
    #[structopt(long, parse(try_from_str = hex::decode))]
    signature: Option<Bytes>,

    /// Enable verbose logging
    #[structopt(long, short, parse(from_occurrences))]
    verbose: u8,
}

fn main() {
    let Opts {
        file,
        secret,
        signature,
        verbose,
    } = Opts::from_args();

    logging::init(verbose);

    let capture = match Capture::from_file(file) {
        Ok(capture) => capture,
        Err(why) => {
            error!(
                "{} {}",
                "Failed to open capture file:".white().bold(),
                format!("{why}").red()
            );

            return;
        }
    };

    let mut context = match build_context(capture, &secret, signature.as_deref()) {
        Ok(context) => context,
        Err(why) => {
            error!(
                "{} {}",
                "Failed to create context:".white().bold(),
                format!("{why}").red()
            );
            return;
        }
    };

    loop {
        let (_, command) = match context.get_data(Some(Sender::Master)) {
            Err(why) => {
                error!(
                    "{} {}",
                    "Error while trying to fetch next command:".white().bold(),
                    format!("{why}").red()
                );
                return;
            }
            Ok(None) => break,
            Ok(Some(command)) => command,
        };

        if command.len() != 1 {
            error!(
                "{} {}",
                "Received command with invalid size:".white().bold(),
                format!("expected: 1, got: {}", command.len()).red()
            );
            return;
        }

        let command = command[0];

        debug!("Execute command: {command}");

        if command != 0x3 {
            eprintln!("Received unknown or unimplemented command: {command}");
            return;
        }

        if let Err(why) = reverse_shell(&mut context) {
            eprintln!("Failed to handle reverse shell data: {why}");
        }
    }
}

fn build_context(
    mut capture: Capture<Offline>,
    passphrase: &str,
    signature: Option<&[u8]>,
) -> Result<Context> {
    let mut handshake: Option<Packet> = None;

    while let Ok(packet) = capture.next_packet() {
        let Ok(packet) = Packet::from_packet(packet) else {
            continue;
        };

        if packet.payload().len() == 40 {
            handshake = Some(packet);
            break;
        }
    }

    let Some(handshake) = handshake else {
        return Err(Error::new(
            ErrorKind::NotFound,
            "Could not find initial packet",
        ));
    };

    info!("Found initial packet");

    let salts: [u8; 40] = handshake.payload().to_vec().try_into().map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "Initial handshake has an invalid size",
        )
    })?;
    let secret = passphrase.as_bytes();

    let salt_1 = &salts[0..20];
    let salt_2 = &salts[20..];

    let key_1 = Sha1::digest([secret, salt_2].concat()).as_slice()[..16].to_vec();
    let key_2 = Sha1::digest([secret, salt_1].concat()).as_slice()[..16].to_vec();

    let iv_1 = &salt_2[..16];
    let iv_2 = &salt_1[..16];

    let filter = PacketFilter::new(&handshake);

    debug!(
        "Participants:\n• Master: {}\n• Slave:  {}",
        filter.master_endpoint(),
        filter.slave_endpoint()
    );

    trace!("Initial packet payload:");
    logging::hexdump(&salts, 20, vec![(0, 16), (20, 36)]);

    debug!(
        "Encryption information:\n• Send: AES(key={}, iv={})\n• Recv: AES(key={}, iv={})",
        hex::encode(&key_1),
        hex::encode(&iv_1),
        hex::encode(&key_2),
        hex::encode(&iv_2)
    );

    let aes_1 =
        Aes128Cbc::new_from_slices(&key_1, &iv_1).expect("Somehow the key sizes became invalid");
    let aes_2 =
        Aes128Cbc::new_from_slices(&key_2, &iv_2).expect("Somehow the key sizes became invalid");

    let mut context = Context::new(aes_1, aes_2, capture, filter);

    let (_, sig_client) = match context.get_data(Some(Sender::Master)) {
        Ok(Some(sig)) => sig,
        Ok(None) => {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Stream ended before client signature transmission",
            ));
        }
        Err(why) => {
            return Err(Error::new(
                why.kind(),
                format!(
                    "Signature initialization failed, this might mean that the provided secret ({passphrase}) is invalid: {why}"
                ),
            ));
        }
    };

    let (_, sig_server) = match context.get_data(Some(Sender::Slave)) {
        Ok(Some(sig)) => sig,
        Ok(None) => {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Stream ended before server signature transmission",
            ));
        }
        Err(why) => {
            return Err(Error::new(
                why.kind(),
                format!(
                    "Signature initialization failed, this might mean that the provided secret ({passphrase}) is invalid: {why}"
                ),
            ));
        }
    };

    if let Some(signature) = signature {
        if signature != sig_client {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Signature mismatch, you can omit the --signature flag to bypass this check (expected: {}, got: {})",
                    hex::encode(signature),
                    hex::encode(&sig_client)
                ),
            ));
        }
    }

    if sig_client != sig_server {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Client and server signature mismatch, client: {}, server: {}",
                hex::encode(&sig_client),
                hex::encode(&sig_server)
            ),
        ));
    }

    info!("Client and server signature validated");

    Ok(context)
}

fn reverse_shell(context: &mut Context) -> Result<()> {
    fn read(context: &mut Context) -> Result<Vec<u8>> {
        let (_, data) = context
            .get_data(Some(Sender::Master))?
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "Stream ended unexpectedly"))?;

        Ok(data)
    }

    // Terminal color mode
    let color = read(context)?;

    // IOCTL arg
    let argp = read(context)?;

    // Terminal executable command line
    let cmd = read(context)?;

    debug!("Color mode: {}", String::from_utf8_lossy(&color));
    debug!("IOCTL argp: {}", hex::encode(argp));
    debug!("Command: {}", String::from_utf8_lossy(&cmd));

    let mut stdin = String::new();
    let mut stdout = String::new();

    loop {
        let Some((sender, binary)) = context.get_data(None)? else {
            break;
        };

        match sender {
            Sender::Master => stdin += &String::from_utf8_lossy(&binary).to_string(),
            Sender::Slave => stdout += &String::from_utf8_lossy(&binary).to_string(),
        }
    }

    info!(
        "{} {}",
        "Reverse shell".white().bold(),
        "stdin".red().bold()
    );
    println!(
        "{}",
        format!("← {}\n", stdin.replace("\r", "\n← ")).dimmed()
    );

    info!(
        "{} {}",
        "Reverse shell".white().bold(),
        "stdout".green().bold()
    );
    println!("{}", format!("→ {}", stdout.replace("\n", "\n→ ")).white());

    Ok(())
}
