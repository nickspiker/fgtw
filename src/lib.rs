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
//! The crate is `no_std` + `alloc` without the `std` feature (on by default): the `no_std` consumer arrived 2026-10-26 — ferros's Photon client folds its fleet's chain, verifies a sponsor's eggs, opens its fan-out wrap and shows its pairing words on a bare-metal phone with no OS clock to stamp a document. Everything a verifier or a joiner needs lives in the base; what needs an OS (the seed oracle, the OS RNG for sealing, std::net, vsf's text tables) sits behind `std`.
//!
//! ## What lives here (generic) vs stays in photon (messaging)
//!
//! **Here:** identity/device-key derivation ([`keys`]), attestation/announce, the fleet membership chain ([`fleet`]), the fan-out of scoped-key bundles (see [`fanout`]), fleet-shared state ([`fstate`]), avatar/blob storage, and the FGTW wire protocol ([`protocol`]).
//!
//! **NOT here — stays in photon:** CLUTCH (friendship key exchange), Photon Transfer / the braid, presence ping/pong, contacts/conversations.
//! That's *messaging*, not *identity* — the calendar doesn't want it.

#![cfg_attr(not(feature = "std"), no_std)]
#[macro_use]
extern crate alloc;

/// Eagle time now, in oscillations — what every document this crate builds is stamped with. With `std` it is the OS clock (`vsf::eagle_time_oscillations`); without it there is no clock to read, so the embedding tells the crate the time with [`set_clock`] (a bare-metal consumer reads its own RTC first) and this returns the last value set, 0 until then.
#[cfg(feature = "std")]
pub fn now_oscillations() -> i64 {
    vsf::eagle_time_oscillations()
}

#[cfg(not(feature = "std"))]
static CLOCK: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

/// The time a `no_std` embedding knows (eagle oscillations), for the documents this crate stamps — set it before building one.
#[cfg(not(feature = "std"))]
pub fn set_clock(oscillations: i64) {
    CLOCK.store(oscillations, core::sync::atomic::Ordering::Relaxed);
}

#[cfg(not(feature = "std"))]
pub fn now_oscillations() -> i64 {
    CLOCK.load(core::sync::atomic::Ordering::Relaxed)
}

/// Thirty-two fresh random bytes — a fleet key, a fan-out ephemeral. With `std` the OS RNG (`rand`); without it the entropy source the embedding registers with [`set_entropy`] (a bare-metal consumer's kernel entropy).
#[cfg(feature = "std")]
pub fn random32() -> [u8; 32] {
    rand::random()
}

#[cfg(not(feature = "std"))]
static ENTROPY: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The entropy a `no_std` embedding supplies for the keys this crate mints — register it before minting or sealing anything.
#[cfg(not(feature = "std"))]
pub fn set_entropy(fill: fn(&mut [u8])) {
    ENTROPY.store(fill as usize, core::sync::atomic::Ordering::Release);
}

/// Panics when no entropy source was registered — fail loud: a key minted from a fixed pattern would be a skeleton key.
#[cfg(not(feature = "std"))]
pub fn random32() -> [u8; 32] {
    let p = ENTROPY.load(core::sync::atomic::Ordering::Acquire);
    assert!(p != 0, "fgtw: no entropy source registered (set_entropy) — refusing to mint a key from nothing");
    // SAFETY: ENTROPY is only ever stored from a `fn(&mut [u8])` in set_entropy, and is nonzero here, so the usize is that function pointer.
    let fill: fn(&mut [u8]) = unsafe { core::mem::transmute::<usize, fn(&mut [u8])>(p) };
    let mut out = [0u8; 32];
    fill(&mut out);
    out
}

static LOG: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Where the crate's own account of what it did goes (a seed mirror that failed, a grow refused): the embedding's log (Photon's log file, a ferros process's console). Nothing is said until one is registered; the crate never fails for want of one.
pub fn set_log(sink: fn(&str)) {
    LOG.store(sink as usize, core::sync::atomic::Ordering::Release);
}

/// One line to the registered log sink, if any.
pub(crate) fn log(line: &str) {
    let p = LOG.load(core::sync::atomic::Ordering::Acquire);
    if p != 0 {
        // SAFETY: LOG is only ever stored from a `fn(&str)` in set_log, and is nonzero here, so the usize is that function pointer.
        let sink: fn(&str) = unsafe { core::mem::transmute::<usize, fn(&str)>(p) };
        sink(line);
    }
}

/// Device identity keypair — the deterministic Ed25519 signing key (`Keypair`) fleet ops and attestations are signed with.
pub mod keys;

/// The chains and fan-outs a device HOLDS (peers first, the seed last: photon docs/peers-are-fgtw.md), and the seed calls that consult and update them: a held copy answers when the seed does not, and a copy a peer hands over is adopted by the same rule a seed copy is. Storage of the held set is the embedding's ([`held::ChainHold`], [`held::FanoutHold`]).
#[cfg(feature = "protocol")]
pub mod held;

/// The sponsor's half of the device-ADD ceremony (photon docs/pairing-v2.md) and the approver's half of a departure: the candidate set from the registry and the LAN, the live word matcher, the tap and the beacon matches, the Add, the fan-out grow, the approval of a sibling's departure. Transport (UDP, HTTP, BLE, NFC) stays the caller's.
#[cfg(feature = "protocol")]
pub mod sponsor;

/// Fleet membership chain — `FleetOp` / `MembershipBlob` / `fold` / `extends` / `is_member`, plus the VSF op codec and the device-signed builders.
/// The authority: valid signature + hash-chain link + signer-was-a-prior-member.
/// The one source of truth shared by the worker (verify) and clients (fetch-then-sign).
pub mod fleet;

/// The attest verdict — resume, join, mint or wait, from every chain this device can see (its own, its LAN peers', the seed's); one pure function so every client decides identically.
pub mod attest;
/// Multi-scheme signing: key bundles, scheme-dispatched verification (base), and the deterministic signing side (`client`). The worker verifies three-egg chains with this.
pub mod pq;

/// The epoch of any fan-out blob, readable WITHOUT the `fanout` feature — the worker's monotonic guard needs it but compiles none of the fan-out crypto.
/// Version-agnostic on purpose: the 3-byte magic leads and the big-endian epoch sits at 4..12 in every layout (the 4th byte was the ASCII '0' of the original tag, now a binary version numeral), so a reader can order blobs whose BODY it cannot parse. That is what lets a new-format rotation step over an old-format blob instead of proposing epoch 1 and being refused as stale forever.
pub fn fanout_blob_epoch(bytes: &[u8]) -> Option<u64> {
    // WHY/PROOF: fan-out blobs are fetched from FGTW and may be truncated — the epoch slice would panic.
    if bytes.len() >= 12 && &bytes[0..3] == b"PFO" {
        Some(u64::from_be_bytes(bytes[4..12].try_into().unwrap()))
    } else {
        None
    }
}

/// The fan-out's EPOCH PUBLIC BUNDLE, readable without the `fanout` feature: the keys a verifier checks a current-membership proof against. `None` for a pre-v3 blob or a malformed one. Layout: magic(3) ‖ version(1) ‖ revision(8) ‖ kfp(32) ‖ rotator(32) ‖ u16 BE len ‖ bundle.
pub fn fanout_blob_epoch_pub(bytes: &[u8]) -> Option<pq::KeyBundle> {
    // WHY/PROOF: fan-out blobs are fetched from FGTW and may be truncated — the fixed header slices would panic.
    if bytes.len() < 78 || &bytes[0..3] != b"PFO" || bytes[3] != 3 {
        return None;
    }
    let n = u16::from_be_bytes([bytes[76], bytes[77]]) as usize;
    // WHY/PROOF: the bundle length is read from the blob itself and may run past its end — slicing would panic.
    let b = bytes.get(78..78 + n)?;
    pq::KeyBundle::from_bytes(b).ok()
}

/// Per-member fan-out — sealing the fleet key to each current member's device key, and opening your own.
/// A device recovers the current key by trial-decrypting its own wrap; a removed device just isn't a wrap target next epoch.
/// The scoped-key-bundle / KEK-DEK generalisation (rotate keys, not data) grows from here — see `docs/fleet-vault-security.md` in photon.
#[cfg(feature = "fanout")]
pub mod fanout;

/// Scoped blobs — one ciphertext, many keyholders: a data key wrapped per reader into a private slot only that reader can find. The sharing primitive for avatars now and attachments later; see photon docs/scoped-blobs.md.
#[cfg(all(feature = "fanout", feature = "std"))]
pub mod scoped_blob;

/// The person's identity space: their facts across their fleet (kists, answers, the home screen's arrangement), merged by a total order, sealed under the fleet key, reconciled with a device's own copy. no_std; the seal behind `fanout`.
pub mod space;

/// Fleet-shared encrypted state — the codec for the slot each app writes its shared state into (photon: the contact roster; calendar: events).
/// Data model + serialize + CRDT merge; the seal-and-push transport is the client's.
#[cfg(all(feature = "fanout", feature = "std"))]
pub mod fstate;

/// Pairing — the device-ADD ceremony word codec (voca words, fleet-masked device pubkey), spell-check, and the BLE beacon/lock-word primitives for the later radio transport. The binding-request signing bytes live in [`fleet`] (the fold verifies consent there; the worker folds without this feature).
#[cfg(feature = "fanout")]
pub mod pair;

/// The phonebook — the peer registry as two hash-addressed registries (identity → device set, device → address) over one uniform fixed-stride keyspace. Base feature: the worker serves slices with the SAME codec clients write with, exactly as it folds chains with the same [`fleet`] code.
pub mod phonebook;
pub mod traverse;
pub mod pipe;

/// The FGTW wire protocol — the GENERIC frames between fleet devices: the LAN beacon, the binding and departure requests, the membership chain and fan-out over the mesh (2026-10-31). no_std codec, behind `fanout` (the pairing commitments and words).
/// The photon-specific messages (chat, CLUTCH, PT) stay in photon; announce/challenge, avatar and blob are still photon's ⏳.
#[cfg(feature = "fanout")]
pub mod protocol;

/// Avatar + blob content storage on FGTW (put/get, per-identity, rate-limited).
/// Generic.
/// ⏳ migrate from photon `blob.rs`.
pub mod blob {}

/// The FGTW client oracle: fetch-then-sign, publish, pairing, fan-out + roster transport, epoch rotation.
/// Transport- and AEAD-agnostic via the [`client::FgtwTransport`] + [`client::FleetSealer`] traits — the app injects its own HTTP + roster crypto, so this crate stays reqwest-free.
/// Gated behind the `client` feature; the worker never compiles it.
#[cfg(feature = "protocol")]
pub mod client;
