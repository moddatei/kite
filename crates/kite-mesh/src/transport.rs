//! Physical RF transport traits and virtual testbed mediums.

use kite_core::error::Result;

/// Physical hardware link layer trait (e.g. Raw 802.11 monitor injection, LoRa SX1262, BLE).
pub trait PhysicalTransport {
    /// Transmit a raw frame over the RF channel.
    fn transmit(&mut self, frame: &[u8]) -> Result<()>;

    /// Poll for an incoming raw frame from the medium.
    /// Returns the number of bytes received and the RSSI measurement in dBm.
    fn receive(&mut self, buf: &mut [u8]) -> Result<Option<(usize, i8)>>;

    /// Return hardware link MTU.
    fn mtu(&self) -> usize;
}

/// In-memory virtual RF medium simulating broadcast, path loss, and packet drops.
pub struct MockRfMedium {
    queue: Vec<Vec<u8>>,
    mtu: usize,
    simulated_rssi: i8,
}

impl MockRfMedium {
    pub fn new(mtu: usize, simulated_rssi: i8) -> Self {
        Self {
            queue: Vec::new(),
            mtu,
            simulated_rssi,
        }
    }

    pub fn inject_frame(&mut self, frame: Vec<u8>) {
        self.queue.push(frame);
    }
}

impl PhysicalTransport for MockRfMedium {
    fn transmit(&mut self, frame: &[u8]) -> Result<()> {
        self.queue.push(frame.to_vec());
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<Option<(usize, i8)>> {
        if self.queue.is_empty() {
            Ok(None)
        } else {
            let packet = self.queue.remove(0);
            let len = core::cmp::min(packet.len(), buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(Some((len, self.simulated_rssi)))
        }
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}
