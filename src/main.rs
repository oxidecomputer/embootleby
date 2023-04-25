// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{bail, Context, Result, anyhow};
use byteorder::ByteOrder;
use clap::Parser;
use lpc55_areas::{CMPAPage, CFPAPage};
use lpc55_isp::cmd::*;
use lpc55_isp::isp::{do_ping, BootloaderProperty, KeyType};
use serialport::{DataBits, FlowControl, Parity, StopBits};
use zip::ZipArchive;
use std::io::{Read, Write, ErrorKind};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
struct Embootleby {
    port: String,
    #[clap(short, long, default_value = "57600", global = true)]
    baud_rate: u32,
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Parser)]
enum Cmd {
    Ping,
    Install {
        bundle: PathBuf,
    },
}

fn main() -> Result<()> {
    let cmd = Embootleby::parse();

    // The target _technically_ has autobaud but it's very flaky
    // and these seem to be the preferred settings
    let mut port = serialport::new(&cmd.port, cmd.baud_rate)
        .timeout(Duration::from_millis(50))
        .data_bits(DataBits::Eight)
        .flow_control(FlowControl::None)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .open()?;

    // Drain anything that's pending at the port.
    let drain_start = Instant::now();
    loop {
        if drain_start.elapsed() > Duration::from_secs(1) {
            println!("ERROR: can't empty serial port.");
            println!("Is device in ISP mode?");
            println!("Try: humility debugmailbox isp");
            bail!("failed to initialize port");
        }
        let mut buffer = [0; 16];
        match port.read(&mut buffer) {
            Ok(0) => break,
            Ok(_) => (),
            Err(e) if e.kind() == ErrorKind::TimedOut => break,
            Err(e) => return Err(e.into()),
        }
    }

    // Increase timeout now that we're doing real things.
    port.set_timeout(Duration::from_secs(1))
        .context("changing port timeout")?;

    match cmd.cmd {
        Cmd::Ping => {
            do_ping(&mut *port)?;
            println!("ping success.");
        }
        Cmd::Install { bundle } => {
            // Load bundle
            let bundle_reader = std::fs::File::open(&bundle)
                .with_context(|| format!("loading {}", bundle.display()))?;
            let mut zip = ZipArchive::new(bundle_reader)
                .context("opening bundle file as ZIP")?;

            let img_bootleby = {
                let mut entry = zip.by_name("bootleby.bin")
                    .context("can't find bootleby.bin in bundle")?;
                let mut data = vec![];
                entry.read_to_end(&mut data)
                    .context("reading bootleby.bin")?;
                data
            };
            let img_cmpa = {
                let mut entry = zip.by_name("cmpa.bin")
                    .context("can't find cmpa.bin in bundle")?;
                let mut data = vec![];
                entry.read_to_end(&mut data)
                    .context("reading cmpa.bin")?;
                data
            };
            let img_cfpa = {
                let mut entry = zip.by_name("cfpa.bin")
                    .context("can't find cfpa.bin in bundle")?;
                let mut data = vec![];
                entry.read_to_end(&mut data)
                    .context("reading cfpa.bin")?;
                data
            };

            let img_cmpa: &[u8; 512] = img_cmpa[..].try_into()
                .map_err(|_| anyhow!("CMPA file is wrong length!"))?;
            let img_cfpa: &[u8; 512] = img_cfpa[..].try_into()
                .map_err(|_| anyhow!("CFPA file is wrong length!"))?;

            let cmpa = CMPAPage::from_bytes(img_cmpa)
                .context("parsing CMPA")?;
            let mut cfpa = CFPAPage::from_bytes(img_cfpa)
                .context("parsing CFPA")?;

            // Basic checks to try and detect mixups.
            lpc55_sign::verify::verify_image(
                &img_bootleby,
                cmpa,
                cfpa.clone(),
            ).context("verifying image")?;

            println!("bundle appears ok");

            println!("checking serial connection and ISP mode...");
            // Do a ping to check basic connectivity.
            do_ping(&mut *port)?;
            println!("success.");

            // Write bootleby image.
            println!("Erasing boot area...");
            do_isp_flash_erase_region(&mut *port, 0, 0x10000)
                .context("erasing boot area")?;
            println!("Writing bootleby image...");
            do_isp_write_memory(&mut *port, 0, img_bootleby)
                .context("writing bootleby")?;
            println!("written OK");

            // Write CFPA - determine correct version for chip.
            println!("checking current CFPA...");
            {
                // Read the current CFPA areas to figure out what version we
                // need to set.
                let ping = do_isp_read_memory(&mut *port, 0x9_e000, 512)?;
                let pong = do_isp_read_memory(&mut *port, 0x9_e200, 512)?;

                let ping = lpc55_areas::CFPAPage::from_bytes(ping[..].try_into().unwrap())?;
                let pong = lpc55_areas::CFPAPage::from_bytes(pong[..].try_into().unwrap())?;

                let start_version = u32::max(ping.version, pong.version);
                cfpa.version = start_version + 1;
                println!("note: new CFPA version is {}", cfpa.version);
            }
            println!("Writing CFPA...");
            {
                let new_bytes = cfpa.to_vec()?;
                do_isp_write_memory(&mut *port, 0x9_de00, new_bytes)?;
            }
            println!("done");

            // Write CMPA
            println!("Erasing CMPA...");
            do_isp_write_memory(&mut *port, 0x9e400, vec![0; 512])?;
            println!("Writing new CMPA...");
            do_isp_write_memory(&mut *port, 0x9e400, img_cmpa.to_vec())?;
            println!("done");

            // Enroll
            println!("Generating new PUF activation code...");
            do_enroll(&mut *port)?;

            // Generate-UDS
            println!("Generating new UDS...");
            do_generate_uds(&mut *port)?;

            // Write key store
            println!("Writing results to flash...");
            do_save_keystore(&mut *port)?;

            // reboot
            println!("***********************************");
            println!("*             SUCCESS             *");
            println!("***********************************");
            println!();
            println!("You now need to load a bootleby-compatible Hubris image.");
            println!("e.g.");
            println!("humility -a the-image-i-want.zip flash");
        }
    }

    Ok(())
}
