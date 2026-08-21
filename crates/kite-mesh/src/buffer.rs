//! Bounded opportunistic Store-Carry-Forward packet buffer.
//!
//! Stores bundles in memory/NVRAM when no destination route is available,
//! awaiting opportunistic encounters with adjacent nodes in radio range.

use kite_core::error::{Error, Result};
use kite_core::frame::KiteFrame;
use kite_core::identity::NodeAddress;

/// Maximum payload buffer size stored within a single in-flight bundle.
pub const MAX_BUNDLE_PAYLOAD: usize = 256;

/// An individual bundle stored for opportunistic dissemination.
#[derive(Debug, Clone)]
pub struct StoredBundle {
    pub bundle_id: u64,
    pub src: NodeAddress,
    pub dst: NodeAddress,
    pub ttl: u8,
    pub priority: u8,
    pub replication_budget: u8,
    pub payload_len: usize,
    pub payload: [u8; MAX_BUNDLE_PAYLOAD],
}

impl StoredBundle {
    pub fn from_frame(frame: &KiteFrame, bundle_id: u64, replication_budget: u8) -> Result<Self> {
        if frame.payload.len() > MAX_BUNDLE_PAYLOAD {
            return Err(Error::BufferOverflow);
        }

        let mut payload = [0u8; MAX_BUNDLE_PAYLOAD];
        payload[..frame.payload.len()].copy_from_slice(frame.payload);

        let priority = if frame.flags.contains(kite_core::FrameFlags::URGENT) {
            255
        } else {
            100
        };

        Ok(Self {
            bundle_id,
            src: frame.src,
            dst: frame.dst,
            ttl: frame.ttl,
            priority,
            replication_budget,
            payload_len: frame.payload.len(),
            payload,
        })
    }
}

/// Bounded in-memory ring buffer for delay-tolerant opportunistic forwarding.
pub struct BundleRingBuffer<const CAPACITY: usize> {
    storage: [Option<StoredBundle>; CAPACITY],
    head: usize,
    count: usize,
    next_bundle_id: u64,
}

impl<const CAPACITY: usize> Default for BundleRingBuffer<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> BundleRingBuffer<CAPACITY> {
    pub const fn new() -> Self {
        const NONE_SLOT: Option<StoredBundle> = None;
        Self {
            storage: [NONE_SLOT; CAPACITY],
            head: 0,
            count: 0,
            next_bundle_id: 1,
        }
    }

    /// Number of active bundles stored in the buffer.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if buffer has zero items.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Enqueue a frame into the store-and-forward buffer.
    /// If full, evicts the lowest-priority or oldest bundle.
    pub fn push(&mut self, frame: &KiteFrame) -> Result<u64> {
        let bundle_id = self.next_bundle_id;
        self.next_bundle_id += 1;

        let bundle = StoredBundle::from_frame(frame, bundle_id, 3)?;

        if self.count < CAPACITY {
            self.storage[self.head] = Some(bundle);
            self.head = (self.head + 1) % CAPACITY;
            self.count += 1;
        } else {
            // Evict slot at head (oldest)
            self.storage[self.head] = Some(bundle);
            self.head = (self.head + 1) % CAPACITY;
        }

        Ok(bundle_id)
    }

    /// Find bundles destined for or relevant to a specific discovered neighbor.
    pub fn get_dispatchable_bundles(&self, neighbor: &NodeAddress) -> Vec<&StoredBundle> {
        let mut dispatchable = Vec::new();
        for bundle in self.storage.iter().flatten() {
            if bundle.dst.is_broadcast() || &bundle.dst == neighbor || bundle.replication_budget > 0
            {
                dispatchable.push(bundle);
            }
        }
        dispatchable
    }

    /// Clean up bundles whose TTL has expired.
    pub fn decay_and_prune(&mut self) {
        for slot in &mut self.storage {
            if let Some(bundle) = slot {
                if bundle.ttl <= 1 {
                    *slot = None;
                    if self.count > 0 {
                        self.count -= 1;
                    }
                } else {
                    bundle.ttl -= 1;
                }
            }
        }
    }
}
