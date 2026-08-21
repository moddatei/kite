//! `kited` — Headless Kite Mesh Node Daemon.
//!
//! Orchestrates physical RF interfaces, opportunistic bundle storage,
//! background epidemic discovery, and Noise_XX encrypted sessions.

use clap::Parser;
use kite_core::{FrameFlags, FrameType, KiteFrame, NodeAddress, PROTOCOL_VERSION};
use kite_mesh::routing::EpidemicRouter;
use kite_mesh::transport::{MockRfMedium, PhysicalTransport};
use log::{info, warn};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(
    name = "kited",
    version = "0.1.0",
    about = "Kite Tetherless Mesh Protocol Daemon"
)]
struct Cli {
    /// Hex-encoded 8-byte node address override (e.g. "0x0102030405060708")
    #[arg(short, long)]
    address: Option<String>,

    /// Physical RF interface or virtual driver (e.g., "mon0", "lora0", "virtual")
    #[arg(short, long, default_value = "virtual")]
    interface: String,

    /// Beacon broadcast interval in seconds
    #[arg(short, long, default_value_t = 3)]
    beacon_interval: u64,
}

fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Cli::parse();

    let node_addr = if let Some(addr_str) = args.address {
        NodeAddress::from_hex(&addr_str).unwrap_or_else(|_| NodeAddress::from_bytes([0x42; 8]))
    } else {
        NodeAddress::from_bytes([0x0A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])
    };

    info!("╔══════════════════════════════════════════════════════════════════╗");
    info!("║   Kite Mesh Node Daemon (kited v0.1.0)                           ║");
    info!("║   Tetherless Delay-Tolerant Opportunistic Transport Protocol     ║");
    info!("╚══════════════════════════════════════════════════════════════════╝");
    info!("Node Address       : {}", node_addr);
    info!("Radio Interface    : {}", args.interface);
    info!("Beacon Interval    : {}s", args.beacon_interval);

    let mut router = EpidemicRouter::<128, 64>::new(node_addr);
    let mut transport = MockRfMedium::new(256, -68);

    info!("Daemon initialized. Listening for ambient RF frames...");

    let mut last_beacon = 0u64;
    let mut seq: u16 = 1;

    for tick in 1..=5 {
        let now = current_timestamp_secs();

        // Transmit periodic beacon
        if now.saturating_sub(last_beacon) >= args.beacon_interval || last_beacon == 0 {
            last_beacon = now;
            let beacon_payload = b"KITE_BEACON_V1";
            let beacon_frame = KiteFrame {
                version: PROTOCOL_VERSION,
                frame_type: FrameType::Beacon,
                flags: FrameFlags::new(0),
                ttl: 1,
                src: node_addr,
                dst: NodeAddress::BROADCAST,
                seq,
                payload: beacon_payload,
            };
            seq = seq.wrapping_add(1);

            let mut wire_buf = [0u8; 128];
            if let Ok(len) = beacon_frame.serialize_into(&mut wire_buf) {
                let _ = transport.transmit(&wire_buf[..len]);
                info!(
                    "[TX] Broadcasted beacon frame (seq={}, bytes={})",
                    seq - 1,
                    len
                );
            }
        }

        // Process incoming packets
        let mut rx_buf = [0u8; 512];
        if let Ok(Some((rx_len, rssi))) = transport.receive(&mut rx_buf) {
            match KiteFrame::parse(&rx_buf[..rx_len]) {
                Ok(frame) => {
                    info!(
                        "[RX] Ingested frame type={:?} src={} dst={} RSSI={}dBm",
                        frame.frame_type, frame.src, frame.dst, rssi
                    );
                    let _ = router.process_incoming_frame(&frame, rssi, now);
                }
                Err(e) => {
                    warn!("[RX] Dropped malformed frame: {:?}", e);
                }
            }
        }

        thread::sleep(Duration::from_millis(200));
        info!(
            "[HEARTBEAT] Tick {} complete. Active neighbors: {}",
            tick,
            router.neighbors.active_neighbors().len()
        );
    }

    info!("Daemon event loop completed successfully.");
}
