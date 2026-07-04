//! # FGTW — Fractal Gradient Trust Web
//!
//! The client substrate for **TOKEN identity**: one identity, many apps.
//! A calendar, a messenger (photon), any TOKEN app rides the *same* fleet — same device keys, same membership chain, same per-member fan-out — and stores its own state in its own sealed scope.
//! This crate is that substrate, shared by every app and by the FGTW worker itself.
//!
//! ## Status: 0.0.0 scaffold
//!
//! Name reservation + architecture map.
//! The modules below are **stubs**; code migrates in from `photon/src/network/fgtw/` per `MIGRATION.md`.
//! Nothing here is load-bearing yet — photon and the worker still run their own copies until each module is moved and re-pointed, keeping both green at every step.
//!
//! ## The split: `core` (no_std) vs `client` (std)
//!
//! - **core** — fleet fold/verify, fan-out crypto, protocol codec.
//!   Compiles to WASM; the worker and every client share it.
//!   This is where the current client/worker duplication (photon `fleet.rs` ↔ worker `fleet.rs`, "kept in lockstep via a known-answer test") collapses into one source of truth.
//! - **client** (feature) — the std HTTP oracle: fetch-then-sign, announce, publish.
//!   Only real clients enable it; the worker never does.
//!
//! ## What lives here (generic) vs stays in photon (messaging)
//!
//! **Here:** identity/device-key derivation, attestation/announce, the fleet membership chain, the fan-out of scoped-key bundles (see [`fanout`]), fleet-shared state ([`fstate`]), avatar/blob storage, and the FGTW wire protocol ([`protocol`]).
//!
//! **NOT here — stays in photon:** CLUTCH (friendship key exchange), Photon Transfer / the braid, presence ping/pong, contacts/conversations.
//! That's *messaging*, not *identity* — the calendar doesn't want it.

#![cfg_attr(not(feature = "client"), no_std)]

/// Fleet membership chain — `FleetOp` / `MembershipBlob` / `fold` / `extends` / `is_member`.
/// The authority: valid signature + hash-chain link + signer-was-a-prior-member.
/// no_std core, shared by the worker (verify) and clients (fetch-then-sign).
/// ⏳ migrate from photon `fleet.rs`.
pub mod fleet {}

/// Per-member fan-out — sealing a per-device **bundle of scoped keys** and opening your own.
/// Full / scoped / route-only / loaner / revoked are all just different bundles.
/// The KEK/DEK hierarchy (rotate keys, not data) lives here.
/// ⏳ migrate the fan-out half of photon `fleet.rs`. See `docs/fleet-vault-security.md`.
pub mod fanout {}

/// Fleet-shared encrypted state — the sealed slot each app writes its shared state into (photon: the contact roster; calendar: events).
/// Membership-gated write, sealed read.
/// ⏳ migrate the fstate half of photon `fleet.rs` + the worker's `fstate_put/get`.
pub mod fstate {}

/// The FGTW wire protocol — the GENERIC messages: announce/challenge, fleet ops, avatar, blob.
/// The photon-specific messages (chat, CLUTCH, PT) stay in photon; `protocol.rs` gets SPLIT.
/// no_std codec.
/// ⏳ migrate the generic half of photon `protocol.rs`.
pub mod protocol {}

/// Avatar + blob content storage on FGTW (put/get, per-identity, rate-limited).
/// Generic.
/// ⏳ migrate from photon `blob.rs`.
pub mod blob {}

/// The std HTTP oracle: fetch-then-sign, announce, publish — the client's reach to the web.
/// Gated behind the `client` feature; the worker never compiles it.
/// ⏳ migrate from photon `bootstrap.rs` + the client halves of `fleet.rs`.
#[cfg(feature = "client")]
pub mod client {}
