//! NAT traversal — turning a fleet peer's directory address into a working socket.
//!
//! [`super::phonebook`] answers "where does this device live" (identity → device → address).
//! This module is the next step of that same job: taking the address the phonebook returns and
//! hole-punching a path that actually carries traffic. It lives in `fgtw` rather than a
//! separate crate because both consumers already depend on `fgtw`, and reachability is the
//! phonebook's concern continued, not a new one.
//!
//! # Sans-io by design
//!
//! Everything here is a pure state machine: it decides *what to send* and *what an arriving
//! packet means*, and never touches a socket. That is what lets two very different callers
//! share it — photon drives these from its own multiplexed receive loop, and the rustdesk fork
//! drives them from a small dedicated loop that hands the punched socket to KCP. The async
//! driver is therefore each app's concern, which keeps `fgtw` free of any tokio/network deps.

pub mod candidate;
pub mod gather;
pub mod reflexive;
pub mod session;
pub mod wire;

pub use candidate::{Candidate, CandidateKind, CandidateSet};
pub use reflexive::ReflexiveState;
pub use session::{PeerSession, PunchState, Unreachable, ValidatedPath, KEEPALIVE_INTERVAL, PATH_TTL};
pub use wire::PunchMessage;

/// A device's ed25519 public key — the identity a fleet peer is addressed by, and the same
/// `[u8; 32]` the phonebook keys device addresses on.
pub type DevicePubkey = [u8; 32];
