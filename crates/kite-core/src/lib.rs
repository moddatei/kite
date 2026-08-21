//! # `kite-core`
//!
//! Zero-allocation core types, wire frame parsing, identity abstractions,
//! and protocol constants for the Kite mesh transport protocol.
//!
//! Designed for `no_std` environments, bare-metal microcontrollers (ARM Cortex-M, RISC-V),
//! and high-throughput userspace daemons.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod error;
pub mod frame;
pub mod identity;

pub use error::{Error, Result};
pub use frame::{FrameFlags, FrameType, KiteFrame, MAX_FRAME_SIZE, MIN_FRAME_SIZE};
pub use identity::{NodeAddress, NodeId, SHORT_ADDR_LEN};

/// Protocol version number (Semantic byte)
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Default MTU for standard physical frames (e.g. 802.11 monitor injection / LoRa)
pub const DEFAULT_LINK_MTU: usize = 256;
