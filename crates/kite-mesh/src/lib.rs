//! # `kite-mesh`
//!
//! Store-Carry-Forward opportunistic mesh routing, epidemic neighbor discovery,
//! and physical radio transport abstraction layer.

pub mod buffer;
pub mod routing;
pub mod transport;

pub use buffer::{BundleRingBuffer, StoredBundle};
pub use routing::{EpidemicRouter, NeighborEntry, NeighborTable};
pub use transport::{MockRfMedium, PhysicalTransport};
