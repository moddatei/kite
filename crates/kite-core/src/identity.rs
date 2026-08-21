//! Cryptographic node identities and addresses for the Kite mesh network.

use crate::error::{Error, Result};
use core::fmt;

/// Length of standard 32-byte public key (Ed25519 / X25519).
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of short truncated address for high-density, low-bandwidth frames.
pub const SHORT_ADDR_LEN: usize = 8;

/// Full 32-byte cryptographic node identifier (Curve25519 public key).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; PUBLIC_KEY_LEN]);

impl NodeId {
    /// Create a NodeId from raw bytes.
    pub const fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Return reference to the underlying byte slice.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Truncate to a compact 8-byte network address for low-overhead routing frames.
    pub fn to_short_address(&self) -> NodeAddress {
        let mut addr = [0u8; SHORT_ADDR_LEN];
        addr.copy_from_slice(&self.0[0..SHORT_ADDR_LEN]);
        NodeAddress(addr)
    }

    /// Broadcast address (all ones).
    pub const BROADCAST: Self = Self([0xFF; PUBLIC_KEY_LEN]);
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId(")?;
        for b in &self.0[..4] {
            write!(f, "{:02x}", b)?;
        }
        write!(f, "..")?;
        for b in &self.0[28..] {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Compact 8-byte network node address for opportunistic link-layer routing.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NodeAddress(pub [u8; SHORT_ADDR_LEN]);

impl NodeAddress {
    /// Broadcast address representation (all 0xFF).
    pub const BROADCAST: Self = Self([0xFF; SHORT_ADDR_LEN]);

    /// Unspecified / Null address (all 0x00).
    pub const NULL: Self = Self([0x00; SHORT_ADDR_LEN]);

    /// Construct address from 8-byte slice.
    pub const fn from_bytes(bytes: [u8; SHORT_ADDR_LEN]) -> Self {
        Self(bytes)
    }

    /// Reference to underlying bytes.
    pub fn as_bytes(&self) -> &[u8; SHORT_ADDR_LEN] {
        &self.0
    }

    /// Check if this address matches the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        self == &Self::BROADCAST
    }

    /// Parse from a hexadecimal string (with or without '0x' prefix).
    pub fn from_hex(s: &str) -> Result<Self> {
        let cleaned = s.trim_start_matches("0x").trim_start_matches("0X");
        if cleaned.len() > SHORT_ADDR_LEN * 2 {
            return Err(Error::InvalidAddress);
        }
        let mut bytes = [0u8; SHORT_ADDR_LEN];
        let pad_len = SHORT_ADDR_LEN * 2 - cleaned.len();
        for (i, c) in cleaned.chars().enumerate() {
            let digit = c.to_digit(16).ok_or(Error::InvalidAddress)? as u8;
            let target_pos = pad_len + i;
            let byte_idx = target_pos / 2;
            if target_pos.is_multiple_of(2) {
                bytes[byte_idx] |= digit << 4;
            } else {
                bytes[byte_idx] |= digit;
            }
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for NodeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
