// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use hubtools::RawHubrisArchive;
use lpc55_areas::{CFPAPage, CMPAPage};
use lpc55_isp::cmd::*;
use lpc55_isp::isp::do_ping;
use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zip::ZipArchive;

/// A tool for upgrading an Oxide board to verified boot using bogus keys.
#[derive(Debug, Parser)]
#[command(version)]
struct Embootleby {
    /// Name of serial port where the LPC55 is connected.
    port: String,
    /// Speed of serial connection -- don't mess with this unless you're really
    /// bored.
    #[clap(short, long, default_value = "57600", global = true)]
    baud_rate: u32,
    /// Action to take.
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Parser)]
enum Cmd {
    /// Do a basic UART connectivity check. This will verify that the board is
    /// in ISP mode and is talking to your computer.
    Ping,
    /// Install the configuration from a bundle file.
    Install {
        /// Rather than just erasing bootleby's area, erases all of the
        /// nonprotected flash region. This will blow away any previous
        /// non-bootleby firmware, stored data, identity keys, and the like.
        #[clap(long, short)]
        erase_all: bool,

        /// Path to a Bootleby Bundle, which is a ZIP file containing three
        /// files:
        /// - `cmpa.bin` gives the CMPA contents.
        /// - `cfpa.bin` gives the CFPA contents.
        /// - `bootleby.bin` gives the Bootleby code as a raw image.
        bundle: PathBuf,
        /// Requires that a subset of keys are enabled (and only that subset).
        /// This flag takes a 4 character string where 'E' represents
        /// enabled, 'R' revoked, and 'I' invalid. Keys are specified
        /// in order from 3 to 0. A string of EERR means keys 0 and 1
        /// are revoked and keys 2 and 3 are enabled.
        #[clap(long)]
        require_key_enable_shape: Option<KeyStateTable>,
    },
    /// Reads the configuration out of an embootleby'd processor and looks for
    /// problems that would prevent booting.
    #[clap(alias = "wtf")]
    Check {
        /// Requires that a subset of keys are enabled (and only that subset).
        /// This flag takes a 4 character string where 'E' represents
        /// enabled, 'R' revoked, and 'I' invalid. Keys are specified
        /// in order from 3 to 0. A string of EERR means keys 0 and 1
        /// are revoked and keys 2 and 3 are enabled.
        #[clap(long)]
        require_key_enable_shape: Option<KeyStateTable>,
    },
    /// Permanently lock the CMPA contents on a device. Make really sure you
    /// want to do this before doing it.
    ///
    /// If the device has previously booted using the existing
    /// CMPA/CFPA/firmware contents, then locking it will _probably_ not brick
    /// it, because we read out and modify the existing CMPA.
    Lock {
        /// Read out the CMPA and compute the lock hash, but don't make any
        /// changes to the chip.
        #[clap(short = 'n', long)]
        dry_run: bool,
        /// Required to actually perform locking as positive confirmation (as
        /// opposed to simply the absence of `--dry-run`).
        #[clap(long)]
        yes_really: bool,
        /// Set this if you'd like to leave the debug port open. Don't do this
        /// with prod keys, it's rude.
        #[clap(long)]
        leave_debug_open: bool,
        /// Requires that a subset of keys are enabled (and only that subset).
        /// This flag takes a 4 character string where 'E' represents
        /// enabled, 'R' revoked, and 'I' invalid. Keys are specified
        /// in order from 3 to 0. A string of EERR means keys 0 and 1
        /// are revoked and keys 2 and 3 are enabled.
        /// If the bits do not match this will decline to lock!
        #[clap(long)]
        require_key_enable_shape: Option<KeyStateTable>,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum KeyState {
    Invalid,
    Enabled,
    Revoked,
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            KeyState::Invalid => write!(f, "i"),
            KeyState::Enabled => write!(f, "e"),
            KeyState::Revoked => write!(f, "r"),
        }
    }
}

// Definitions for these come from the NXP manual
impl TryFrom<u32> for KeyState {
    type Error = anyhow::Error;
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        Ok(match v {
            0b00 => Self::Invalid,
            0b01 => Self::Enabled,
            0b10 | 0b11 => Self::Revoked,
            _ => bail!("invalid value {v}"),
        })
    }
}

impl TryFrom<char> for KeyState {
    type Error = anyhow::Error;
    fn try_from(v: char) -> Result<Self, Self::Error> {
        Ok(match v {
            'i' | 'I' => Self::Invalid,
            'e' | 'E' => Self::Enabled,
            'r' | 'R' => Self::Revoked,
            _ => bail!("invalid value {v}"),
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct KeyStateTable([KeyState; 4]);

impl std::str::FromStr for KeyStateTable {
    type Err = anyhow::Error;

    // Each letter in the string represents one entry in the
    // ROTKH_REVOKE field. There are 4 keys, each of which
    // is represented by 2 bits.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 4 {
            bail!("invalid length, must be 4");
        }
        let mut out: [Option<KeyState>; 4] = [None; 4];
        // Keys are specified in 3210 order. Reverse puts
        // key 0 in index 0.
        for (slot, entry) in s.chars().rev().enumerate() {
            out[slot] = Some(entry.try_into()?);
        }
        Ok(Self(out.map(Option::unwrap)))
    }
}

impl std::fmt::Display for KeyStateTable {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Display in reverse to match the 3210 order used
        write!(f, "{}{}{}{}", self.0[3], self.0[2], self.0[1], self.0[0])
    }
}

impl KeyStateTable {
    fn from_rotkh_revoke(revoke: u32) -> Self {
        KeyStateTable([
            KeyState::try_from(revoke & 0x3).unwrap(),
            KeyState::try_from((revoke >> 2) & 0x3).unwrap(),
            KeyState::try_from((revoke >> 4) & 0x3).unwrap(),
            KeyState::try_from((revoke >> 6) & 0x3).unwrap(),
        ])
    }
}

// A struct is just a named tuple that prevents us from mixing up
// CMPA and CFPA
struct BootlebyFiles {
    bootleby: Vec<u8>,
    cmpa: Vec<u8>,
    cfpa: Vec<u8>,
}

fn get_files(bundle: PathBuf) -> Result<BootlebyFiles> {
    if let Ok(archive) = RawHubrisArchive::load(&bundle) {
        Ok(BootlebyFiles {
            // bootleby is packaged as the final archive
            bootleby: archive.extract_file("img/final.bin")?,
            cmpa: archive.extract_file("cmpa.bin")?,
            cfpa: archive.extract_file("cfpa.bin")?,
        })
    } else {
        let bundle_reader = std::fs::File::open(&bundle)
            .with_context(|| format!("loading {}", bundle.display()))?;
        let mut zip = ZipArchive::new(bundle_reader).context("opening bundle file as ZIP")?;

        let bootleby = {
            let mut entry = zip
                .by_name("bootleby.bin")
                .context("can't find bootleby.bin in bundle")?;
            let mut data = vec![];
            entry
                .read_to_end(&mut data)
                .context("reading bootleby.bin")?;
            data
        };
        let cmpa = {
            let mut entry = zip
                .by_name("cmpa.bin")
                .context("can't find cmpa.bin in bundle")?;
            let mut data = vec![];
            entry.read_to_end(&mut data).context("reading cmpa.bin")?;
            data
        };
        let cfpa = {
            let mut entry = zip
                .by_name("cfpa.bin")
                .context("can't find cfpa.bin in bundle")?;
            let mut data = vec![];
            entry.read_to_end(&mut data).context("reading cfpa.bin")?;
            data
        };

        Ok(BootlebyFiles {
            bootleby,
            cfpa,
            cmpa,
        })
    }
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
        Cmd::Install {
            erase_all,
            bundle,
            require_key_enable_shape,
        } => {
            let files = get_files(bundle)?;

            let img_bootleby = files.bootleby;

            let img_cmpa: &[u8; 512] = files.cmpa[..]
                .try_into()
                .map_err(|_| anyhow!("CMPA file is wrong length!"))?;
            let img_cfpa: &[u8; 512] = files.cfpa[..]
                .try_into()
                .map_err(|_| anyhow!("CFPA file is wrong length!"))?;

            let cmpa = CMPAPage::from_bytes(img_cmpa).context("parsing CMPA")?;
            let mut cfpa = CFPAPage::from_bytes(img_cfpa).context("parsing CFPA")?;

            // Basic checks to try and detect mixups.
            log_verify_only_on_failure();
            lpc55_sign::verify::verify_image(&img_bootleby, cmpa, cfpa.clone())
                .context("verifying image")?;

            if let Some(keymask) = require_key_enable_shape {
                let found = KeyStateTable::from_rotkh_revoke(cfpa.rkth_revoke);
                if found != keymask {
                    println!("**** FAILED KEY CHECKS ****");
                    println!("You provided a key shape requirement mask,");
                    println!("but the bundle's CFPA doesn't meet it.");
                    println!("required: {keymask}");
                    println!("found:    {found}");
                    println!("Keys are listed 3, 2, 1, 0");
                    println!("e = enable, r = revoked, i = invalid");

                    bail!("cannot proceed, key requirements not met");
                }
            }

            println!("bundle appears ok");

            // This is the point where we begin interacting with the part.

            println!("checking serial connection and ISP mode...");
            // Do a ping to check basic connectivity.
            do_ping(&mut *port)?;
            println!("success.");

            println!("checking current CFPA...");
            {
                let current_cfpa = read_current_cfpa(&mut *port).context("reading current CFPA")?;

                // RKTH_REVOKE bits may only be changed from 0 to 1.  Check if
                // new CFPA would attempt to change any from 1 to 0.
                if (current_cfpa.rkth_revoke | cfpa.rkth_revoke) != cfpa.rkth_revoke {
                    println!("**** FAILED KEY CHECKS ****");
                    println!("Bundle's CFPA would attempt to change an");
                    println!("RKTH_REVOKE bit from 1 to 0.  Only 0 to 1");
                    println!("transitions are allowed.");
                    println!(
                        "bundle RKTH_REVOKE: {:#04x} {}",
                        cfpa.rkth_revoke,
                        KeyStateTable::from_rotkh_revoke(cfpa.rkth_revoke)
                    );
                    println!(
                        "device RKTH_REVOKE: {:#04x} {}",
                        current_cfpa.rkth_revoke,
                        KeyStateTable::from_rotkh_revoke(current_cfpa.rkth_revoke)
                    );
                    println!("Keys are listed 3, 2, 1, 0");
                    println!("e = enable, r = revoked, i = invalid");

                    bail!("cannot proceed, CFPA would be rejected by ROM");
                }

                cfpa.version = current_cfpa.version + 1;
                println!("note: new CFPA version is {}", cfpa.version);
            }

            // This is the part where we begin doing things that are potentially
            // side-effecting.

            // Write bootleby image.
            let (name, size) = if erase_all {
                ("all of flash", 0x9_de00)
            } else {
                ("boot area", 0x1_0000)
            };
            println!("Erasing {name}...");
            do_isp_flash_erase_region(&mut *port, 0, size).context("erasing requested section")?;
            println!("Writing bootleby image...");
            do_isp_write_memory(&mut *port, 0, &img_bootleby).context("writing bootleby")?;
            println!("written OK");

            // Write CFPA - determine correct version for chip.
            println!("Writing CFPA...");
            {
                let new_bytes = cfpa.to_vec()?;
                do_isp_write_memory(&mut *port, 0x9_de00, &new_bytes)?;
            }
            println!("done");

            // Write CMPA
            println!("Erasing CMPA...");
            do_isp_write_memory(&mut *port, 0x9e400, &[0; 512])?;
            println!("Writing new CMPA...");
            do_isp_write_memory(&mut *port, 0x9e400, img_cmpa)?;
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
            println!("You need to switch back out of ISP mode first.");
            println!("e.g.");
            println!("humility debugmailbox debug");
            println!("humility -a the-image-i-want.zip flash");
        }
        Cmd::Check {
            require_key_enable_shape,
        } => {
            println!("*** Extracting stuff from the chip ***");
            println!("(Failures in this section indicate either a comms problem,");
            println!("or your chip is locked. See if you can raise the chip via");
            println!("embootleby ping a few times to check comms.)");

            // Read first 512 bytes of flash to get Bootleby image geometry. We
            // have to do this to avoid reading erased sectors, because reading
            // erased sectors makes ISP mad.
            let first_sector = do_isp_read_memory(&mut *port, 0, 512)
                .context("reading first sector (is flash empty?)")?;
            // NXP-style images have the image length at 0x20 as a u32.
            let bb_size = u32::from_le_bytes(first_sector[0x20..0x24].try_into().unwrap());
            // Round up to page count.
            let bb_pages = (bb_size + 512 - 1) / 512;
            // Extract Bootleby image.
            let mut bootleby =
                do_isp_read_memory(&mut *port, 0, bb_pages * 512).context("reading bootleby")?;
            // Trim off trailing bytes.
            bootleby.truncate(bb_size as usize);

            // Extract CMPA.
            println!("reading CMPA");
            let img_cmpa = do_isp_read_memory(&mut *port, 0x9e400, 512).context("reading CMPA")?;
            let img_cmpa: &[u8; 512] = img_cmpa[..].try_into().unwrap();

            let cmpa = CMPAPage::from_bytes(img_cmpa).context("parsing CMPA")?;

            // Extract CFPA.
            println!("reading CFPA(s)");
            let cfpa = read_current_cfpa(&mut *port).context("reading CFPA")?;

            if let Some(keymask) = require_key_enable_shape {
                let found = KeyStateTable::from_rotkh_revoke(cfpa.rkth_revoke);
                if found != keymask {
                    println!("**** FAILED KEY CHECKS ****");
                    println!("You provided a key shape requirement mask,");
                    println!("but the CFPA doesn't meet it.");
                    println!("required: {keymask}");
                    println!("found:    {found}");
                    println!("Keys are listed 3, 2, 1, 0");
                    println!("e = enable, r = revoked, i = invalid");

                    bail!("cannot proceed, key requirements not met");
                }
            }

            println!("*** Checking Bootleby Image - begin verification spam! ***");
            log_verify_verbose();
            lpc55_sign::verify::verify_image(&bootleby, cmpa, cfpa.clone())
                .context("verifying image")?;

            println!("*** Bootleby image is intact and matches CMPA/CFPA ***");

            println!("Your slot A/B firmware images might still be bad.");
            println!("Someday this tool will check them for you!");
            println!("Today is not that day.");
        }
        Cmd::Lock {
            dry_run,
            yes_really,
            leave_debug_open,
            require_key_enable_shape,
        } => {
            println!("Reading current CMPA contents...");
            let img_cmpa = do_isp_read_memory(&mut *port, 0x9_e400, 512).context("reading CMPA")?;
            let cmpa: [u8; 512] = img_cmpa.try_into().unwrap();

            // For the heck of it -- parse the CMPA and decline to proceed if it
            // won't parse, to try and prevent locking nonsense into the CMPA.
            let mut cmpa = CMPAPage::from_bytes(&cmpa).context("parsing CMPA")?;

            // Note: PIN=0 + DEFAULT=0 means debug-auth-only
            let cc_socu_target = 0xFFFF_0000;
            if !leave_debug_open {
                if cmpa.cc_socu_pin != cc_socu_target {
                    println!("Note: CMPA.CC_SOCU_PIN was permissive, overriding to disable debug.");
                    cmpa.cc_socu_pin = cc_socu_target;
                }
                if cmpa.cc_socu_dflt != cc_socu_target {
                    println!(
                        "Note: CMPA.CC_SOCU_DFLT was permissive, overriding to disable debug."
                    );
                    cmpa.cc_socu_dflt = cc_socu_target;
                }
            }

            println!("Reading current CFPA contents...");
            let mut cfpa = read_current_cfpa(&mut *port).context("reading CFPA")?;
            println!("CFPA version = {}", cfpa.version);
            let mut cfpa_update_required = false;
            if !leave_debug_open {
                if cfpa.dcfg_cc_socu_ns_pin != cc_socu_target {
                    println!(
                        "Note: CFPA.CC_SOCU_NS_PIN was permissive, overriding to disable debug."
                    );
                    cfpa.dcfg_cc_socu_ns_pin = cc_socu_target;
                    cfpa_update_required = true;
                }
                if cfpa.dcfg_cc_socu_ns_dflt != cc_socu_target {
                    println!(
                        "Note: CFPA.CC_SOCU_NS_DFLT was permissive, overriding to disable debug."
                    );
                    cfpa.dcfg_cc_socu_ns_dflt = cc_socu_target;
                    cfpa_update_required = true;
                }
            }
            if let Some(keytable) = require_key_enable_shape {
                let found_keytable = KeyStateTable::from_rotkh_revoke(cfpa.rkth_revoke);
                if found_keytable != keytable {
                    println!("**** FAILED KEY CHECKS ****");
                    println!("You provided a key shape requirement mask,");
                    println!("but the CFPA doesn't meet it.");
                    println!("required: {keytable}");
                    println!("found:    {found_keytable}");
                    println!("Keys are listed 3, 2, 1, 0");
                    println!("e = enable, r = revoked, i = invalid");

                    bail!("cannot proceed, key requirements not met");
                }
            }

            if cfpa_update_required {
                cfpa.version = cfpa.version.wrapping_add(1);
                println!("Bumping CFPA version to {}", cfpa.version);
            }

            println!("Computing locking hash...");
            let img_cmpa = cmpa.to_vec().context("Re-packing CMPA failed")?;
            let mut image_hash = Sha256::new();
            image_hash.update(&img_cmpa[..512 - 32]);
            let image_hash = image_hash.finalize();

            print!("image hash: ");
            for byte in &image_hash {
                print!("{byte:02x}");
            }
            println!();

            // Overwrite the last 32 bytes with the SHA2-256 hash of the first
            // 480 bytes, which is what indicates to the ROM that it is locked.
            let mut locked_cmpa = img_cmpa;
            locked_cmpa[512 - 32..].copy_from_slice(&image_hash);

            let final_cfpa = cfpa.to_vec().unwrap();

            if cfpa_update_required {
                println!("Intended CFPA contents:");
                println!("{}", pretty_hex::pretty_hex(&final_cfpa));
            } else {
                println!("CFPA update not required.");
            }

            println!("Intended CMPA contents:");
            println!("{}", pretty_hex::pretty_hex(&locked_cmpa));

            if dry_run {
                println!(
                    "You requested a dry run; no changes have been \
                    written back."
                );

                return Ok(());
            }

            if !yes_really {
                println!("This operation will IRREVERSIBLY lock the device.");
                println!("If this is really what you wanted, re-run with the flag:");
                println!("    --yes-really");
                bail!("user did not confirm lock action");
            }

            if cfpa_update_required {
                println!("Writing CFPA scratch page...");
                do_isp_write_memory(&mut *port, 0x9_de00, &final_cfpa)?;
                println!("done!");
            }

            println!("Erasing CMPA...");
            do_isp_write_memory(&mut *port, 0x9_e400, &[0; 512])?;
            println!("Writing new CMPA...");
            do_isp_write_memory(&mut *port, 0x9_e400, &locked_cmpa)?;
            println!("done!");
        }
    }

    Ok(())
}

/// The only way the `lpc55_sign` verify code produces any useful output is
/// through human-readable log messages sent to the system logger. So if we want
/// to have any control over its behavior, we have to set up such a logger.
///
/// Here's the minimal setup I could come up with that filters out its
/// "everything is okay" chatter at info and finer levels:
fn log_verify_only_on_failure() {
    let mut builder = env_logger::Builder::from_default_env();
    builder
        .filter(Some("lpc55_sign"), log::LevelFilter::Warn)
        .init();
}

/// Produces more verbose output from `lpc55_sign`.
fn log_verify_verbose() {
    let mut builder = env_logger::Builder::from_default_env();
    builder
        .filter(Some("lpc55_sign"), log::LevelFilter::Info)
        .init();
}

/// Read the current CFPA areas and find the active one.
fn read_current_cfpa(port: &mut dyn SerialPort) -> Result<lpc55_areas::CFPAPage> {
    let ping = do_isp_read_memory(port, 0x9_e000, 512)?;
    let pong = do_isp_read_memory(port, 0x9_e200, 512)?;

    let ping = lpc55_areas::CFPAPage::from_bytes(ping[..].try_into().unwrap())?;
    let pong = lpc55_areas::CFPAPage::from_bytes(pong[..].try_into().unwrap())?;

    Ok(if ping.version > pong.version {
        ping
    } else {
        pong
    })
}
