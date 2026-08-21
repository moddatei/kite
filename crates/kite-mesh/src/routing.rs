//! Epidemic discovery and opportunistic link-quality routing.

use kite_core::error::Result;
use kite_core::identity::NodeAddress;
use kite_core::frame::KiteFrame;

/// Link quality record for an adjacent physical RF peer.
#[derive(Debug, Clone, Copy)]
pub struct NeighborEntry {
    pub address: NodeAddress,
    pub last_seen_timestamp: u64,
    pub rssi_dbm: i8,
    pub packet_delivery_ratio: u8, // 0 - 100%
    pub hop_distance: u8,
}

/// Dynamic neighbor table tracking nodes currently within ambient RF range.
pub struct NeighborTable<const MAX_NEIGHBORS: usize> {
    entries: [Option<NeighborEntry>; MAX_NEIGHBORS],
    count: usize,
}

impl<const MAX_NEIGHBORS: usize> NeighborTable<MAX_NEIGHBORS> {
    pub const fn new() -> Self {
        const NONE_ENTRY: Option<NeighborEntry> = None;
        Self {
            entries: [NONE_ENTRY; MAX_NEIGHBORS],
            count: 0,
        }
    }

    /// Record receipt of a beacon or frame from an adjacent peer.
    pub fn update_neighbor(
        &mut self,
        address: NodeAddress,
        rssi_dbm: i8,
        timestamp: u64,
    ) {
        // Look for existing entry
        for slot in &mut self.entries {
            if let Some(entry) = slot {
                if entry.address == address {
                    entry.last_seen_timestamp = timestamp;
                    entry.rssi_dbm = rssi_dbm;
                    entry.packet_delivery_ratio = ((entry.packet_delivery_ratio as u16 * 7 + 100) / 8) as u8;
                    return;
                }
            }
        }

        // Insert new entry in first free slot
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(NeighborEntry {
                    address,
                    last_seen_timestamp: timestamp,
                    rssi_dbm,
                    packet_delivery_ratio: 100,
                    hop_distance: 1,
                });
                self.count += 1;
                return;
            }
        }
    }

    /// Evict stale neighbors not heard from within `timeout_secs`.
    pub fn prune_stale(&mut self, current_time: u64, timeout_secs: u64) {
        for slot in &mut self.entries {
            if let Some(entry) = slot {
                if current_time.saturating_sub(entry.last_seen_timestamp) > timeout_secs {
                    *slot = None;
                    if self.count > 0 {
                        self.count -= 1;
                    }
                }
            }
        }
    }

    /// List all currently active direct neighbors.
    pub fn active_neighbors(&self) -> Vec<NeighborEntry> {
        self.entries.iter().filter_map(|e| *e).collect()
    }
}

/// Epidemic routing coordinator for Kite nodes.
pub struct EpidemicRouter<const CAPACITY: usize, const MAX_NEIGHBORS: usize> {
    pub self_addr: NodeAddress,
    pub neighbors: NeighborTable<MAX_NEIGHBORS>,
    pub buffer: crate::buffer::BundleRingBuffer<CAPACITY>,
}

impl<const CAPACITY: usize, const MAX_NEIGHBORS: usize> EpidemicRouter<CAPACITY, MAX_NEIGHBORS> {
    pub fn new(self_addr: NodeAddress) -> Self {
        Self {
            self_addr,
            neighbors: NeighborTable::new(),
            buffer: crate::buffer::BundleRingBuffer::new(),
        }
    }

    /// Ingest an incoming over-the-air frame.
    pub fn process_incoming_frame(&mut self, frame: &KiteFrame, rssi_dbm: i8, now: u64) -> Result<bool> {
        self.neighbors.update_neighbor(frame.src, rssi_dbm, now);

        if frame.dst == self.self_addr {
            // Frame is directly for us
            Ok(true)
        } else if frame.dst.is_broadcast() {
            // Broadcast frame, accept and buffer for forwarding
            let _ = self.buffer.push(frame);
            Ok(true)
        } else if frame.ttl > 1 {
            // Store-and-forward candidate
            let mut forwarded = frame.clone();
            if forwarded.decrement_ttl() {
                let _ = self.buffer.push(&forwarded);
            }
            Ok(false)
        } else {
            Ok(false)
        }
    }
}
