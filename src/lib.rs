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
//! ## The split: `core` vs `client` (feature)
//!
//! - **core** — fleet fold/verify, fan-out crypto, protocol codec.
//!   Compiles to WASM; the worker and every client share it.
//!   This is where the old client/worker duplication (photon `fleet.rs` ↔ worker `fleet.rs`, kept in lockstep by hand via a known-answer test) collapses into one source of truth.
//! - **client** (feature) — the std HTTP oracle: fetch-then-sign, announce, publish.
//!   Only real clients enable it; the worker never does.
//!
//! The crate is `std` for now: its only consumers (photon and the FGTW worker, a wasm32 cdylib) are both `std`, and the `vsf` codec it rides pulls `std` transitively (via `crypto`/`inspect`).
//! A `#![no_std]` core is a later step, once a genuinely `no_std` consumer (an embedded signer) exists and `vsf`'s crypto/clock surface is factored for it — until then it would be `alloc::` friction with no `no_std` binary to show for it.
//!
//! ## What lives here (generic) vs stays in photon (messaging)
//!
//! **Here:** identity/device-key derivation ([`keys`]), attestation/announce, the fleet membership chain ([`fleet`]), the fan-out of scoped-key bundles (see [`fanout`]), fleet-shared state ([`fstate`]), avatar/blob storage, and the FGTW wire protocol ([`protocol`]).
//!
//! **NOT here — stays in photon:** CLUTCH (friendship key exchange), Photon Transfer / the braid, presence ping/pong, contacts/conversations.
//! That's *messaging*, not *identity* — the calendar doesn't want it.

/// Device identity keypair — the deterministic Ed25519 signing key (`Keypair`) fleet ops and attestations are signed with.
pub mod keys;

/// Fleet membership chain — `FleetOp` / `MembershipBlob` / `fold` / `extends` / `is_member`, plus the VSF op codec and the device-signed builders.
/// The authority: valid signature + hash-chain link + signer-was-a-prior-member.
/// The one source of truth shared by the worker (verify) and clients (fetch-then-sign).
pub mod fleet;

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
