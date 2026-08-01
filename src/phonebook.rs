//! The phonebook — the peer registry, as two hash-addressed registries over one uniform keyspace.
//!
//! Replaces the single global `peers.vsf` blob (read-modify-write, no concurrency control, whole-file rewrite per address change) with fixed-stride records addressed by BLAKE3, so a record's key IS its location: there is no index to build, and storing a key is storing a pointer.
//!
//! PRIMARY (identity → device set)   `IdentityCount` at `key_identity(handle_proof)`, `DevicePointer` at `key_pointer(handle_proof, i)` for dense `i ∈ [0, N)`.
//! SECONDARY (device → address)      `DeviceAddress` at `key_address(device_pubkey)`.
//!
//! Split so that an address change — the overwhelmingly common write — touches ONE slot in place: same key, same length, no run shift, no lock, no epoch bump.
//! Membership changes are rare and are the only thing that moves anything.
//!
//! Addressing is a shift and a mask.
//! Capacity is a power of two and keys are BLAKE3 output (uniform over 2^256), so the top bits of the key are literally the slice and slot index — no division, no float, no rounding, and the same 32-byte key doubles as the Kademlia id, which is the key→node mapping `docs/peers-are-fgtw.md` Phase D leaves undefined.
//!
//! ENUMERATION IS OPEN by design (peers-are-fgtw.md): every record is self-describing so a slice host can dump its whole range and a reader can make sense of it.
//! Privacy comes from the consent gate — a `handle_proof` grants nothing to someone who lacks the identity seed — never from address obscurity.
//!
//! `identity_seed` DERIVATION RULE (nothing here uses it today; addresses are all `handle_proof`-derived): it is the Ed25519 *secret* seed for the identity key, so it is never hashed raw.
//! Any future derivation goes through a domain separator and/or a keyed hash AND through `ihi::spaghettify` (which BLAKE3s internally) — the precedent is photon's log tag, `spaghettify(b"photon_log_v1" ‖ identity_seed)`, with a domain deliberately distinct from the encryption key so the two cannot collide.

use blake3::Hasher;

/// Bytes per record.
/// Divides 4 KiB exactly (16 records per block), which keeps a probe inside one read and leaves a block-level Merkle tree an option later without records straddling block boundaries.
pub const STRIDE: usize = 256;

/// Slots in one slice. 1 MiB / 256 B.
/// Power of two so the slot index is a bit-field of the key.
pub const SLICE_SLOTS: usize = 4096;
/// `log2(SLICE_SLOTS)` — the slot bit-field width.
pub const SLOT_BITS: u32 = 12;

/// The slice-index bit-field width the network is CURRENTLY using.
/// Not a constant of the format — growth is `n → n+1`, which halves every slice and lets each host keep the half matching its own handle (purely local; the sort order already puts the two halves contiguous).
/// Every addressing call takes `slice_bits` explicitly so a node can serve one width while the network moves to the next, and so a small width is testable. 2^24 = 16.7M slices ≈ 40B devices at ~58% fill in 1 MiB slices.
pub const SLICE_BITS_DEFAULT: u32 = 24;

/// Fill band.
/// Below `FILL_MIN` halve, above `FILL_MAX` double.
/// The gaps are not slack — they are what make the computed slot land EXACTLY instead of approximately.
/// A dense array's rank drifts binomially from the interpolated guess (±√N/2 ≈ 16k records at 1e9); a gapped one is off only by collision displacement, which the band caps.
pub const FILL_MIN: f32 = 0.375;
pub const FILL_MAX: f32 = 0.75;

/// Probe runway reserved at each end of a slice (~0.83%, 8.7 KiB).
/// A key crowding the tail belongs to a neighbouring slice that centres it; the probe must never wrap to slot 0, which would manufacture a seam in a structure whose sortedness the range scans depend on.
pub const EDGE_MARGIN: usize = 34;

// Domain separators.
// Every key is domain-tagged so the phonebook keyspace cannot collide with any other use of the same `handle_proof` or `device_pubkey` as a lookup key (fleet chain, fstate, fanout, bindreq, inbox all key on handle_proof today).
const DOMAIN_IDENTITY: &[u8] = b"PHOTON_PB_IDENTITY_v1";
const DOMAIN_POINTER: &[u8] = b"PHOTON_PB_POINTER_v1";
const DOMAIN_ADDRESS: &[u8] = b"PHOTON_PB_ADDRESS_v1";

// Signing domains, separate from the key domains so a signature can never be replayed as a key preimage or vice versa.
/// The device's own claim: "I consent to be a device of this identity, and I am at this address."
pub const SIGN_ADDRESS: &[u8] = b"PHOTON_PB_ADDR_SIG_v1";
/// A current member's claim: "I placed this device's pointer at this index at this epoch."
pub const SIGN_PLACEMENT: &[u8] = b"PHOTON_PB_PLACE_SIG_v1";
/// A current member's claim: "the device count for this identity is N as of this epoch."
pub const SIGN_COUNT: &[u8] = b"PHOTON_PB_COUNT_SIG_v1";
/// The departing device's own claim: "I am leaving this identity." Consent-only removal — no device removes another, so this signature is required alongside a CURRENT member's witness.
pub const SIGN_DEPART: &[u8] = b"PHOTON_PB_DEPART_SIG_v1";

/// What kind of record occupies a slot.
/// Stored as the first byte, so a slice dump is interpretable without external context (the phonebook is enumerable by design).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    /// Slot has never been written, or was vacated.
    /// An empty slot terminates a probe: nothing is ever placed left of its ideal slot, so if the key existed it would be at or before this gap.
    Empty = 0,
    /// PRIMARY: how many devices this identity has.
    /// `key_identity(handle_proof)`.
    IdentityCount = 1,
    /// PRIMARY: the device at index `i` of this identity.
    /// `key_pointer(handle_proof, i)`.
    DevicePointer = 2,
    /// SECONDARY: where this device is.
    /// `key_address(device_pubkey)`.
    DeviceAddress = 3,
}

impl RecordKind {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => RecordKind::Empty,
            1 => RecordKind::IdentityCount,
            2 => RecordKind::DevicePointer,
            3 => RecordKind::DeviceAddress,
            _ => return None,
        })
    }
}

/// A 32-byte record address.
/// Uniform BLAKE3 output, so it is simultaneously the storage address, the sort key, and the Kademlia node-distance key.
pub type Key = [u8; 32];

/// `key_identity(handle_proof)` — where an identity's device count lives.
pub fn key_identity(handle_proof: &[u8; 32]) -> Key {
    let mut h = Hasher::new();
    h.update(DOMAIN_IDENTITY);
    h.update(handle_proof);
    *h.finalize().as_bytes()
}

/// `key_pointer(handle_proof, i)` — where the pointer to this identity's i-th device lives.
/// `i` is little-endian u32: indices are dense in `[0, N)`, maintained by pop-and-swap on removal.
pub fn key_pointer(handle_proof: &[u8; 32], index: u32) -> Key {
    let mut h = Hasher::new();
    h.update(DOMAIN_POINTER);
    h.update(handle_proof);
    h.update(&index.to_le_bytes());
    *h.finalize().as_bytes()
}

/// `key_address(device_pubkey)` — where a device's address record lives.
/// Keyed on the device alone, so a targeted lookup is one read at ANY fleet size — the relay needs exactly this, since `pipe_deliver` routes by device pubkey and has no handle in hand.
pub fn key_address(device_pubkey: &[u8; 32]) -> Key {
    let mut h = Hasher::new();
    h.update(DOMAIN_ADDRESS);
    h.update(device_pubkey);
    *h.finalize().as_bytes()
}

/// Which slice holds this key — the top `slice_bits` of the key, big-endian.
/// `slice_bits == 0` means one slice covers the whole keyspace.
pub fn slice_of(key: &Key, slice_bits: u32) -> u32 {
    if slice_bits == 0 { return 0; }
    let top = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
    top >> (32 - slice_bits)
}

/// Which slot within its slice — the `SLOT_BITS` immediately below the slice field.
/// Shift and mask only: the key IS the address, so there is no arithmetic to get wrong and no estimate to refine.
pub fn slot_of(key: &Key, slice_bits: u32) -> usize {
    let top = u64::from_be_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let shift = 64 - slice_bits - SLOT_BITS;
    ((top >> shift) & ((1u64 << SLOT_BITS) - 1)) as usize
}

/// The full (slice ‖ slot) address as one value — for the Kademlia bucket walk and for tests.
pub fn address_of(key: &Key, slice_bits: u32) -> u64 {
    let top = u64::from_be_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    top >> (64 - slice_bits - SLOT_BITS)
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// RECORD — a typed view over exactly STRIDE bytes.
//
// There is no separate serialisation: the record IS its bytes, which is what makes a slice mmap-able and an address update a byte patch at a computed offset rather than a re-encode.
//
// No record stores its own key.
// The key is RECOMPUTED from the fields that define it, so the two can never disagree — a record moved to the wrong slot is detectable, and a record whose contents were edited addresses itself somewhere else.
//
// Field offsets are explicit and every layout leaves reserve bytes.
// That reserve is the migration budget: a field added inside the stride costs nothing, a field that overflows 256 is a flag day.
// Spend it deliberately.
// ════════════════════════════════════════════════════════════════════════════════════════════

/// One slot's worth of bytes, interpreted by its leading kind byte.
#[derive(Clone, Copy)]
pub struct Record(pub [u8; STRIDE]);

impl core::fmt::Debug for Record {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Record").field("kind", &self.kind()).finish()
    }
}

// IdentityCount layout (PRIMARY). 237 used, 19 reserved.
const IC_HANDLE: usize = 1; // ..33
const IC_COUNT: usize = 33; // ..37   u32 LE
const IC_EPOCH: usize = 37; // ..45   i64 LE
const IC_WITNESS: usize = 45; // ..77   the CURRENT member that signed this transition
const IC_WITNESS_SIG: usize = 77; // ..141
const IC_DEPARTING: usize = 141; // ..173  zero when the transition was an ADD
const IC_DEPART_SIG: usize = 173; // ..237  the departing device's OWN consent; no device removes another

// DevicePointer layout (PRIMARY). 173 used, 83 reserved.
const DP_HANDLE: usize = 1; // ..33
const DP_INDEX: usize = 33; // ..37   u32 LE
const DP_DEVICE: usize = 37; // ..69
const DP_EPOCH: usize = 69; // ..77   i64 LE
const DP_PLACER: usize = 77; // ..109
const DP_PLACE_SIG: usize = 109; // ..173

// DeviceAddress layout (SECONDARY). 171 used, 85 reserved.
const DA_DEVICE: usize = 1; // ..33
const DA_HANDLE: usize = 33; // ..65   signed, so a device cannot be planted under another identity
const DA_IP: usize = 65; // ..81   v6; v4 as ::ffff:a.b.c.d so the field is fixed width
const DA_PORT: usize = 81; // ..83   u16 LE
const DA_LOCAL_IP: usize = 83; // ..99
const DA_TIMESTAMP: usize = 99; // ..107  i64 LE eagle-time; the monotonic guard for address replay
const DA_SIG: usize = 107; // ..171

fn rd32(b: &[u8; STRIDE], at: usize) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(&b[at..at + 32]);
    o
}
fn rd64(b: &[u8; STRIDE], at: usize) -> [u8; 64] {
    let mut o = [0u8; 64];
    o.copy_from_slice(&b[at..at + 64]);
    o
}
fn rd_u32(b: &[u8; STRIDE], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn rd_i64(b: &[u8; STRIDE], at: usize) -> i64 {
    i64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

impl Record {
    /// An unwritten slot.
    /// All zeros, so a zeroed page reads as empty and a sparse file needs no initialisation pass.
    pub fn empty() -> Self {
        Record([0u8; STRIDE])
    }

    pub fn kind(&self) -> RecordKind {
        RecordKind::from_byte(self.0[0]).unwrap_or(RecordKind::Empty)
    }
    pub fn is_empty(&self) -> bool {
        self.kind() == RecordKind::Empty
    }

    /// The address this record belongs at, recomputed from its own defining fields.
    /// `None` for an empty slot.
    /// Because it is derived rather than stored, a record cannot claim a slot its contents do not entitle it to.
    pub fn key(&self) -> Option<Key> {
        match self.kind() {
            RecordKind::Empty => None,
            RecordKind::IdentityCount => Some(key_identity(&rd32(&self.0, IC_HANDLE))),
            RecordKind::DevicePointer => Some(key_pointer(
                &rd32(&self.0, DP_HANDLE),
                rd_u32(&self.0, DP_INDEX),
            )),
            RecordKind::DeviceAddress => Some(key_address(&rd32(&self.0, DA_DEVICE))),
        }
    }

    /// The monotonic guard for this slot.
    /// Epoch for the primary records, timestamp for an address.
    /// One rule at every level: a write must be strictly GREATER than what the slot holds, or it is refused.
    /// That single comparison gives replay protection and serialises concurrent writers without any old/new bookkeeping.
    pub fn epoch(&self) -> i64 {
        match self.kind() {
            RecordKind::Empty => i64::MIN,
            RecordKind::IdentityCount => rd_i64(&self.0, IC_EPOCH),
            RecordKind::DevicePointer => rd_i64(&self.0, DP_EPOCH),
            RecordKind::DeviceAddress => rd_i64(&self.0, DA_TIMESTAMP),
        }
    }

    // ── IdentityCount ──
    pub fn new_identity_count(
        handle_proof: &[u8; 32],
        count: u32,
        epoch: i64,
        witness: &[u8; 32],
        witness_sig: &[u8; 64],
        departing: Option<(&[u8; 32], &[u8; 64])>,
    ) -> Self {
        let mut b = [0u8; STRIDE];
        b[0] = RecordKind::IdentityCount as u8;
        b[IC_HANDLE..IC_HANDLE + 32].copy_from_slice(handle_proof);
        b[IC_COUNT..IC_COUNT + 4].copy_from_slice(&count.to_le_bytes());
        b[IC_EPOCH..IC_EPOCH + 8].copy_from_slice(&epoch.to_le_bytes());
        b[IC_WITNESS..IC_WITNESS + 32].copy_from_slice(witness);
        b[IC_WITNESS_SIG..IC_WITNESS_SIG + 64].copy_from_slice(witness_sig);
        if let Some((dev, sig)) = departing {
            b[IC_DEPARTING..IC_DEPARTING + 32].copy_from_slice(dev);
            b[IC_DEPART_SIG..IC_DEPART_SIG + 64].copy_from_slice(sig);
        }
        Record(b)
    }
    pub fn count(&self) -> u32 {
        rd_u32(&self.0, IC_COUNT)
    }
    pub fn witness(&self) -> [u8; 32] {
        rd32(&self.0, IC_WITNESS)
    }
    pub fn witness_sig(&self) -> [u8; 64] {
        rd64(&self.0, IC_WITNESS_SIG)
    }
    /// The device that left, and its own departure signature — `None` when this transition was an add.
    /// Removal requires BOTH this and a witness that is a CURRENT member: the leaver consents, a live member attests.
    /// Neither alone suffices, and a member that has itself departed is not a witness.
    pub fn departing(&self) -> Option<([u8; 32], [u8; 64])> {
        let d = rd32(&self.0, IC_DEPARTING);
        if d == [0u8; 32] {
            return None;
        }
        Some((d, rd64(&self.0, IC_DEPART_SIG)))
    }

    // ── DevicePointer ──
    pub fn new_device_pointer(
        handle_proof: &[u8; 32],
        index: u32,
        device_pubkey: &[u8; 32],
        epoch: i64,
        placer: &[u8; 32],
        placement_sig: &[u8; 64],
    ) -> Self {
        let mut b = [0u8; STRIDE];
        b[0] = RecordKind::DevicePointer as u8;
        b[DP_HANDLE..DP_HANDLE + 32].copy_from_slice(handle_proof);
        b[DP_INDEX..DP_INDEX + 4].copy_from_slice(&index.to_le_bytes());
        b[DP_DEVICE..DP_DEVICE + 32].copy_from_slice(device_pubkey);
        b[DP_EPOCH..DP_EPOCH + 8].copy_from_slice(&epoch.to_le_bytes());
        b[DP_PLACER..DP_PLACER + 32].copy_from_slice(placer);
        b[DP_PLACE_SIG..DP_PLACE_SIG + 64].copy_from_slice(placement_sig);
        Record(b)
    }
    pub fn index(&self) -> u32 {
        rd_u32(&self.0, DP_INDEX)
    }
    pub fn device_pubkey(&self) -> [u8; 32] {
        match self.kind() {
            RecordKind::DeviceAddress => rd32(&self.0, DA_DEVICE),
            _ => rd32(&self.0, DP_DEVICE),
        }
    }
    pub fn placer(&self) -> [u8; 32] {
        rd32(&self.0, DP_PLACER)
    }
    pub fn placement_sig(&self) -> [u8; 64] {
        rd64(&self.0, DP_PLACE_SIG)
    }

    // ── DeviceAddress ──
    #[allow(clippy::too_many_arguments)]
    pub fn new_device_address(
        device_pubkey: &[u8; 32],
        handle_proof: &[u8; 32],
        ip: &[u8; 16],
        port: u16,
        local_ip: &[u8; 16],
        timestamp: i64,
        sig: &[u8; 64],
    ) -> Self {
        let mut b = [0u8; STRIDE];
        b[0] = RecordKind::DeviceAddress as u8;
        b[DA_DEVICE..DA_DEVICE + 32].copy_from_slice(device_pubkey);
        b[DA_HANDLE..DA_HANDLE + 32].copy_from_slice(handle_proof);
        b[DA_IP..DA_IP + 16].copy_from_slice(ip);
        b[DA_PORT..DA_PORT + 2].copy_from_slice(&port.to_le_bytes());
        b[DA_LOCAL_IP..DA_LOCAL_IP + 16].copy_from_slice(local_ip);
        b[DA_TIMESTAMP..DA_TIMESTAMP + 8].copy_from_slice(&timestamp.to_le_bytes());
        b[DA_SIG..DA_SIG + 64].copy_from_slice(sig);
        Record(b)
    }
    /// Mint a SIGNED address record in one step: build, sign the covered bytes, rebuild with the signature in place.
    ///
    /// The two-step dance is easy to get subtly wrong at a call site (sign the wrong bytes, or sign before a field is final and ship a record that cannot verify), and an address record that fails verification is silently dropped by every reader — so the mistake is invisible until nobody can be found.
    /// Doing it here once means a caller cannot express the broken version.
    pub fn sign_device_address(
        signing_key: &ed25519_dalek::SigningKey,
        handle_proof: &[u8; 32],
        ip: &[u8; 16],
        port: u16,
        local_ip: &[u8; 16],
        timestamp: i64,
    ) -> Self {
        use ed25519_dalek::Signer;
        let device_pubkey = signing_key.verifying_key().to_bytes();
        let unsigned =
            Self::new_device_address(&device_pubkey, handle_proof, ip, port, local_ip, timestamp, &[0u8; 64]);
        let sig = signing_key.sign(&unsigned.address_signing_bytes()).to_bytes();
        Self::new_device_address(&device_pubkey, handle_proof, ip, port, local_ip, timestamp, &sig)
    }

    pub fn handle_proof(&self) -> [u8; 32] {
        match self.kind() {
            RecordKind::DeviceAddress => rd32(&self.0, DA_HANDLE),
            _ => rd32(&self.0, IC_HANDLE), // IC_HANDLE == DP_HANDLE == 1
        }
    }
    pub fn ip(&self) -> [u8; 16] {
        let mut o = [0u8; 16];
        o.copy_from_slice(&self.0[DA_IP..DA_IP + 16]);
        o
    }
    pub fn port(&self) -> u16 {
        u16::from_le_bytes(self.0[DA_PORT..DA_PORT + 2].try_into().unwrap())
    }
    pub fn local_ip(&self) -> [u8; 16] {
        let mut o = [0u8; 16];
        o.copy_from_slice(&self.0[DA_LOCAL_IP..DA_LOCAL_IP + 16]);
        o
    }
    pub fn address_sig(&self) -> [u8; 64] {
        rd64(&self.0, DA_SIG)
    }

    /// The bytes a DEVICE signs to claim both membership and address: domain ‖ handle_proof ‖ device_pubkey ‖ ip ‖ port ‖ local_ip ‖ timestamp.
    /// Deliberately excludes any slot or index, so the record is portable — compaction can relocate it with the device offline, which is the whole reason removal never stalls on a device in a drawer.
    pub fn address_signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SIGN_ADDRESS.len() + 32 + 32 + 16 + 2 + 16 + 8);
        v.extend_from_slice(SIGN_ADDRESS);
        v.extend_from_slice(&rd32(&self.0, DA_HANDLE));
        v.extend_from_slice(&rd32(&self.0, DA_DEVICE));
        v.extend_from_slice(&self.ip());
        v.extend_from_slice(&self.port().to_le_bytes());
        v.extend_from_slice(&self.local_ip());
        v.extend_from_slice(&self.epoch().to_le_bytes());
        v
    }

    /// The bytes a CURRENT MEMBER signs to place a pointer: domain ‖ handle_proof ‖ index ‖ epoch ‖ device_pubkey.
    /// The index IS covered here — that is what stops a placement being replayed into a different slot.
    /// Combined with the slot's monotonic epoch (which this placement itself set), a placement can never be replayed into its own slot either.
    pub fn placement_signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SIGN_PLACEMENT.len() + 32 + 4 + 8 + 32);
        v.extend_from_slice(SIGN_PLACEMENT);
        v.extend_from_slice(&rd32(&self.0, DP_HANDLE));
        v.extend_from_slice(&self.index().to_le_bytes());
        v.extend_from_slice(&self.epoch().to_le_bytes());
        v.extend_from_slice(&rd32(&self.0, DP_DEVICE));
        v
    }

    /// The bytes a CURRENT MEMBER signs to attest a device count: domain ‖ handle_proof ‖ count ‖ epoch ‖ departing_pubkey.
    /// The departing pubkey is inside the signature so a witness cannot be replayed to attest a different removal.
    pub fn count_signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SIGN_COUNT.len() + 32 + 4 + 8 + 32);
        v.extend_from_slice(SIGN_COUNT);
        v.extend_from_slice(&rd32(&self.0, IC_HANDLE));
        v.extend_from_slice(&self.count().to_le_bytes());
        v.extend_from_slice(&self.epoch().to_le_bytes());
        v.extend_from_slice(&rd32(&self.0, IC_DEPARTING));
        v
    }

    /// The bytes a DEPARTING DEVICE signs to consent to its own removal: domain ‖ handle_proof ‖ device_pubkey ‖ epoch.
    /// Consent-only: no device removes another, so this is required alongside the witness — and it is the departing device's own key, which nobody else holds.
    pub fn departure_signing_bytes(handle_proof: &[u8; 32], device: &[u8; 32], epoch: i64) -> Vec<u8> {
        let mut v = Vec::with_capacity(SIGN_DEPART.len() + 32 + 32 + 8);
        v.extend_from_slice(SIGN_DEPART);
        v.extend_from_slice(handle_proof);
        v.extend_from_slice(device);
        v.extend_from_slice(&epoch.to_le_bytes());
        v
    }
}


// ════════════════════════════════════════════════════════════════════════════════════════════
// SLICE — a gapped, sorted, fixed-stride array of one slice's records.
//
// TWO INVARIANTS, and every operation exists to preserve them:
// (1) SORTED by key ascending.
// (2) NO RECORD LEFT OF ITS IDEAL SLOT — `slot_of(key) <= actual`.
//
// (2) is what makes an empty slot prove absence: a lookup starts at the ideal slot and walks RIGHT, so anything that existed would be at or before the first gap.
// Break (2) and records silently become unfindable while still sitting in the file.
//
// The gaps are not slack.
// They are why the computed slot lands exactly rather than approximately, and why a lookup is one block read instead of a multi-probe search.
// ════════════════════════════════════════════════════════════════════════════════════════════

/// Why a write was refused.
/// Every variant is a refusal to corrupt an invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceError {
    /// No gap between the ideal slot and the end of the slice — the slice must grow, or the key belongs to a neighbour.
    Full,
    /// Not strictly greater than the epoch the slot already holds.
    /// The monotonic rule doing its job: replay, a stale writer, or the loser of a concurrent write.
    StaleEpoch { stored: i64, incoming: i64 },
    /// The record's own contents do not hash into this slice.
    WrongSlice { expected: u32, got: u32 },
    /// An empty record was offered for insertion.
    EmptyRecord,
}

/// One slice:
/// `SLICE_SLOTS` records, flat, addressed by slot index.
/// A flat byte buffer rather than parsed structs, because that IS the on-disk / mmap layout — an address update is a byte patch at `slot * STRIDE`, not a re-encode.
pub struct Slice {
    slice_bits: u32,
    slice_id: u32,
    buf: Vec<u8>,
    fill: usize,
}

impl Slice {
    pub fn new(slice_bits: u32, slice_id: u32) -> Self {
        Slice { slice_bits, slice_id, buf: vec![0u8; SLICE_SLOTS * STRIDE], fill: 0 }
    }

    pub fn slice_id(&self) -> u32 { self.slice_id }
    pub fn slice_bits(&self) -> u32 { self.slice_bits }
    pub fn fill(&self) -> usize { self.fill }
    pub fn fill_ratio(&self) -> f32 { self.fill as f32 / SLICE_SLOTS as f32 }
    /// Past the band's top the network should move to `slice_bits + 1`; below its floor, back down.
    /// The caller owns storage, so it owns the resize.
    pub fn wants_grow(&self) -> bool { self.fill_ratio() > FILL_MAX }
    pub fn wants_shrink(&self) -> bool { self.fill_ratio() < FILL_MIN }

    fn ideal(&self, key: &Key) -> usize { slot_of(key, self.slice_bits) }

    pub fn at(&self, slot: usize) -> Record {
        let mut r = [0u8; STRIDE];
        r.copy_from_slice(&self.buf[slot * STRIDE..(slot + 1) * STRIDE]);
        Record(r)
    }
    fn put(&mut self, slot: usize, rec: &Record) {
        self.buf[slot * STRIDE..(slot + 1) * STRIDE].copy_from_slice(&rec.0);
    }
    fn clear(&mut self, slot: usize) {
        self.buf[slot * STRIDE..(slot + 1) * STRIDE].fill(0);
    }

    /// Find a key.
    /// Walks right from the ideal slot; stops on a match, on an empty slot (absence proven), or once sort order has passed the target (also absence).
    /// Returns the slot so callers can patch in place — an address update is same key, same length, same slot, which is why it takes no lock and shifts nothing.
    pub fn lookup(&self, key: &Key) -> Option<(usize, Record)> {
        let mut s = self.ideal(key);
        while s < SLICE_SLOTS {
            let rec = self.at(s);
            match rec.key() {
                None => return None,
                Some(k) if &k == key => return Some((s, rec)),
                Some(k) if k.as_slice() > key.as_slice() => return None,
                _ => s += 1,
            }
        }
        None
    }

    /// Insert or replace, enforcing the monotonic epoch rule on replace.
    ///
    /// At the ideal slot: step right past SMALLER keys; on a LARGER key, shift that run one slot right and drop in.
    /// Shifting on larger is what preserves sort order — stepping past everything would let a late arrival land after a bigger key, and range scans (a handle's devices, a slice dump) would quietly stop being ordered while every lookup still passed.
    pub fn insert(&mut self, rec: &Record) -> Result<usize, SliceError> {
        let key = rec.key().ok_or(SliceError::EmptyRecord)?;
        let sid = slice_of(&key, self.slice_bits);
        if sid != self.slice_id {
            return Err(SliceError::WrongSlice { expected: self.slice_id, got: sid });
        }

        let mut s = self.ideal(&key);
        while s < SLICE_SLOTS {
            let occ = self.at(s);
            match occ.key() {
                None => {
                    self.put(s, rec);
                    self.fill += 1;
                    return Ok(s);
                }
                Some(k) if k == key => {
                    if rec.epoch() <= occ.epoch() {
                        return Err(SliceError::StaleEpoch { stored: occ.epoch(), incoming: rec.epoch() });
                    }
                    self.put(s, rec);
                    return Ok(s);
                }
                Some(k) if k.as_slice() < key.as_slice() => s += 1,
                Some(_) => {
                    let gap = self.next_gap(s).ok_or(SliceError::Full)?;
                    let mut j = gap;
                    while j > s {
                        let prev = self.at(j - 1);
                        self.put(j, &prev);
                        j -= 1;
                    }
                    self.put(s, rec);
                    self.fill += 1;
                    return Ok(s);
                }
            }
        }
        Err(SliceError::Full)
    }

    fn next_gap(&self, from: usize) -> Option<usize> {
        (from..SLICE_SLOTS).find(|&s| self.at(s).is_empty())
    }

    /// Remove — the exact inverse of insert, so nothing accumulates.
    /// No tombstones: whatever insert does, remove undoes, and the slice is indistinguishable from one the record never entered.
    ///
    /// Pulls the following run LEFT into the freed slot, but only while a record's ideal slot is at or before its destination.
    /// A record dragged left of its own ideal becomes permanently unfindable, because lookups start at the ideal and only ever scan right.
    /// Sorted order means the first record that cannot move left implies none after it can — every later key is larger, so its ideal is at least as far right.
    pub fn remove(&mut self, key: &Key) -> bool {
        let Some((slot, _)) = self.lookup(key) else { return false };
        self.clear(slot);
        self.fill -= 1;

        let mut free = slot;
        let mut j = slot + 1;
        while j < SLICE_SLOTS {
            let rec = self.at(j);
            let Some(k) = rec.key() else { break };
            if self.ideal(&k) > free { break; }
            self.put(free, &rec);
            free = j;
            j += 1;
        }
        self.clear(free);
        true
    }

    /// Every occupied slot in key order — the enumeration a slice host serves.
    /// The phonebook is deliberately open and every record is self-describing, so a dump is meaningful to any reader.
    pub fn iter(&self) -> impl Iterator<Item = (usize, Record)> + '_ {
        (0..SLICE_SLOTS).filter_map(move |s| {
            let r = self.at(s);
            (!r.is_empty()).then_some((s, r))
        })
    }

    /// The raw fixed-stride body — what an mmap'd file holds verbatim and what ships inside a VSF document.
    pub fn as_bytes(&self) -> &[u8] { &self.buf }

    /// Adopt a raw body, recounting fill.
    /// Rejects a body that is not exactly one slice.
    pub fn from_bytes(slice_bits: u32, slice_id: u32, buf: Vec<u8>) -> Option<Self> {
        if buf.len() != SLICE_SLOTS * STRIDE { return None; }
        let mut s = Slice { slice_bits, slice_id, buf, fill: 0 };
        s.fill = (0..SLICE_SLOTS).filter(|&i| !s.at(i).is_empty()).count();
        Some(s)
    }

    /// Do both invariants hold?
    /// The property tests lean on this; it is also the cheapest possible repair check for a host that has just adopted a slice from a peer.
    pub fn check_invariants(&self) -> Result<(), String> {
        let mut last: Option<Key> = None;
        for (slot, rec) in self.iter() {
            let k = rec.key().ok_or("occupied slot with no key")?;
            if self.ideal(&k) > slot {
                return Err(format!("record left of its ideal: ideal {} at slot {slot}", self.ideal(&k)));
            }
            if let Some(prev) = last {
                if k.as_slice() <= prev.as_slice() {
                    return Err(format!("out of order at slot {slot}"));
                }
            }
            last = Some(k);
        }
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// VERIFICATION
//
// Each check answers exactly one question, and the split matters: a signature proves WHO wrote something, never that they were ENTITLED to.
// Membership is the caller's check, because only the caller holds the registry state to answer it.
// ════════════════════════════════════════════════════════════════════════════════════════════

fn verify_ed25519(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else { return false }; // unknown key → fail closed
    vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

impl Record {
    /// Self-verifying: the device signed its own address, and the key it signed with is in the record.
    /// Proves "the holder of this device key claims this address under this identity".
    ///
    /// Does NOT prove the device belongs to that identity's fleet — a stranger can sign a row for any `handle_proof` they scraped.
    /// That binding is the PRIMARY registry's job (a current member placed a pointer to this device), and it is the gap the gossip path has today.
    pub fn verify_address(&self) -> bool {
        self.kind() == RecordKind::DeviceAddress
            && verify_ed25519(&self.device_pubkey(), &self.address_signing_bytes(), &self.address_sig())
    }

    /// The placement was signed by the device that claims to have made it.
    ///
    /// The caller MUST separately confirm that `placer()` is a CURRENT member — a departed member's signature is still cryptographically valid forever, and treating it as authority would let a device removed months ago keep rearranging the registry.
    pub fn verify_placement(&self) -> bool {
        self.kind() == RecordKind::DevicePointer
            && verify_ed25519(&self.placer(), &self.placement_signing_bytes(), &self.placement_sig())
    }

    /// The count was attested by the device that claims to have witnessed it.
    /// Same caveat: the caller confirms the witness is current.
    pub fn verify_count(&self) -> bool {
        self.kind() == RecordKind::IdentityCount
            && verify_ed25519(&self.witness(), &self.count_signing_bytes(), &self.witness_sig())
    }

    /// A removal is only consented if the DEPARTING device signed its own departure.
    /// No device removes another, so this is required in addition to a current member's witness — and it is the leaver's own key, which nobody else holds.
    ///
    /// `true` for an add (nothing departed).
    /// A removal missing this signature is NOT consent.
    pub fn verify_departure(&self) -> bool {
        if self.kind() != RecordKind::IdentityCount { return false; }
        let Some((dev, sig)) = self.departing() else { return true };
        let msg = Record::departure_signing_bytes(&self.handle_proof(), &dev, self.epoch());
        verify_ed25519(&dev, &msg, &sig)
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// PROJECTION — the fold is the truth, the registry is its readable shadow.
//
// Any CURRENT member converges its own identity's registry onto the folded member set: appends get placement-signed pointers at fresh tail indices, removals pop-and-swap (the tail pointer relocates into the hole — the address core is index-free by design, so relocation needs nobody online), and the count re-attests.
// Writes are idempotent and epoch-guarded, so racing siblings settle on whichever plan lands last — race-and-converge, no lease, no owner.
// ════════════════════════════════════════════════════════════════════════════════════════════

/// The stored primary-registry state for one identity, as read back from storage: the count record plus the dense pointer run.
/// `pointers[i]` is expected to carry index `i`.
#[derive(Debug, Clone, Default)]
pub struct RegistryView {
    pub count: Option<Record>,
    pub pointers: Vec<Record>,
}

impl RegistryView {
    /// Structural + cryptographic verification: right kinds, right identity, dense indices, every signature checks.
    /// Membership of the SIGNERS is deliberately not checked here — that needs the fold, which the caller holds (verify_placement's caveat applies).
    pub fn verify(&self, handle_proof: &[u8; 32]) -> bool {
        if let Some(c) = &self.count {
            if !c.verify_count() || !c.verify_departure() || c.handle_proof() != *handle_proof {
                return false;
            }
            if c.count() as usize != self.pointers.len() {
                return false;
            }
        } else if !self.pointers.is_empty() {
            return false; // pointers without a count have no attested extent
        }
        for (i, p) in self.pointers.iter().enumerate() {
            if !p.verify_placement() || p.handle_proof() != *handle_proof || p.index() as usize != i {
                return false;
            }
        }
        true
    }

    /// The device set the registry currently points at, in index order.
    pub fn devices(&self) -> Vec<[u8; 32]> {
        self.pointers.iter().map(|p| p.device_pubkey()).collect()
    }
}

/// The minimal record writes that converge the stored registry onto the folded member set.
/// Empty when already in sync.
/// Every emitted record carries `epoch` (strictly newer than any stored, or storage rejects it — pass eagle-now).
/// `departing` is the leaver's own consent signature over [`Record::departure_signing_bytes`] when this convergence removes it; a fold-driven removal whose consent already lives in the CHAIN may pass `None` — chain readers still see the consent, registry-only readers see an unconsented shrink and can fetch the chain.
pub fn registry_plan(
    signer: &ed25519_dalek::SigningKey,
    handle_proof: &[u8; 32],
    fold: &[[u8; 32]],
    view: &RegistryView,
    epoch: i64,
    departing: Option<(&[u8; 32], &[u8; 64])>,
) -> Vec<Record> {
    use ed25519_dalek::Signer;
    let placer: [u8; 32] = signer.verifying_key().to_bytes();
    let current = view.devices();

    // Pop-and-swap: a removed slot takes the tail pointer, the run stays dense, untouched indices keep their records (and their epochs) exactly as stored.
    let mut list = current.clone();
    let mut i = 0;
    while i < list.len() {
        if fold.contains(&list[i]) {
            i += 1;
        } else {
            let last = list.len() - 1;
            list.swap(i, last);
            list.pop();
            // Do not advance: the swapped-in tail needs the same check.
        }
    }
    for d in fold {
        if !list.contains(d) {
            list.push(*d);
        }
    }

    let mut out = Vec::new();
    for (idx, dev) in list.iter().enumerate() {
        if current.get(idx) == Some(dev) {
            continue; // this slot is already right — leave its stored record alone
        }
        let unsigned = Record::new_device_pointer(handle_proof, idx as u32, dev, epoch, &placer, &[0u8; 64]);
        let sig = signer.sign(&unsigned.placement_signing_bytes()).to_bytes();
        out.push(Record::new_device_pointer(handle_proof, idx as u32, dev, epoch, &placer, &sig));
    }

    let count_stale = view
        .count
        .as_ref()
        .map(|c| c.count() as usize != list.len())
        .unwrap_or(true);
    if !out.is_empty() || count_stale {
        let unsigned = Record::new_identity_count(handle_proof, list.len() as u32, epoch, &placer, &[0u8; 64], departing);
        let sig = signer.sign(&unsigned.count_signing_bytes()).to_bytes();
        out.push(Record::new_identity_count(handle_proof, list.len() as u32, epoch, &placer, &sig, departing));
    }
    out
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// TRANSPORT — a slice body inside a complete VSF document.
//
// COMPLETE FILES ONLY: the body ships with a header carrying its geometry (slice_bits, slice_id, fill) and a BLAKE3 provenance hash, so a receiving host knows how to address what it was handed and can reject a torn transfer.
// The body itself is an UNBOXED section — raw fixed-stride bytes, byte-addressable, exactly what an mmap'd file holds — because wrapping a million records as schema fields would defeat the entire point of the layout.
//
// The provenance hash covers a SNAPSHOT in transit.
// It is not maintained across in-place updates (that would be 33 minutes of BLAKE3 per IP change at 10 TB); per-record signatures are the durable integrity, and this hash only says "the bytes you received are the bytes that were sent".
// ════════════════════════════════════════════════════════════════════════════════════════════

/// The unboxed section holding the fixed-stride body.
pub const SLICE_SECTION: &str = "pb_slice";

impl Slice {
    /// Wrap this slice as a complete VSF document for transport.
    pub fn to_document(&self) -> Result<Vec<u8>, String> {
        use vsf::VsfType;
        vsf::VsfBuilder::new()
            .creation_time_oscillations(vsf::eagle_time_oscillations())
            .provenance_only()
            .add_inline_field("slice_bits", vec![VsfType::u3(self.slice_bits as u8)])
            .add_inline_field("slice_id", vec![VsfType::u5(self.slice_id)])
            .add_inline_field("fill", vec![VsfType::u5(self.fill as u32)])
            .add_unboxed(SLICE_SECTION, self.buf.clone())
            .build()
    }

    /// Read a slice back from a transport document.
    /// Verified: the header must decode and its provenance hash must be self-consistent before a single record is trusted.
    ///
    /// Geometry comes from the document, not from the caller's assumption — a host serving width `n` while the network moves to `n+1` must not silently reinterpret a body at the wrong width.
    pub fn from_document(doc: &[u8]) -> Result<Self, String> {
        let (header, _) = vsf::verification::read_verified(doc, None)
            .map_err(|e| format!("phonebook slice failed verified read: {e}"))?;

        let field = header
            .fields
            .iter()
            .find(|f| f.name == SLICE_SECTION)
            .ok_or_else(|| format!("no '{SLICE_SECTION}' section in document TOC"))?;
        let start = field.offset_bytes;
        let end = start
            .checked_add(field.size_bytes)
            .ok_or("slice byte range overflows")?;
        if end > doc.len() {
            return Err(format!("slice range {start}..{end} out of bounds ({} bytes)", doc.len()));
        }

        let read_num = |name: &str| -> Result<u64, String> {
            header
                .fields
                .iter()
                .find(|f| f.name == name)
                .and_then(|f| f.inline_values.first())
                .and_then(vsf_u64)
                .ok_or_else(|| format!("missing header field '{name}'"))
        };
        let slice_bits = read_num("slice_bits")? as u32;
        let slice_id = read_num("slice_id")? as u32;

        Slice::from_bytes(slice_bits, slice_id, doc[start..end].to_vec())
            .ok_or_else(|| format!("body is {} bytes, expected {}", end - start, SLICE_SLOTS * STRIDE))
    }
}

/// Unsigned VSF integers arrive at whatever width fits, so match every one rather than assuming.
fn vsf_u64(v: &vsf::VsfType) -> Option<u64> {
    use vsf::VsfType as T;
    Some(match v {
        T::u3(n) => *n as u64,
        T::u4(n) => *n as u64,
        T::u5(n) => *n as u64,
        T::u6(n) => *n,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests run at `slice_bits = 0` — ONE slice covering the whole keyspace — so a few thousand records land in it directly.
    /// At the production width (2^24 slices) hitting one specific slice by brute force would take ~3e10 hashes.
    /// The slot arithmetic under test is identical either way; only the field above it moves.
    const TB: u32 = 0;

    fn ptr(seed: u32, epoch: i64) -> Record {
        let hp = *blake3::hash(&seed.to_le_bytes()).as_bytes();
        Record::new_device_pointer(&hp, seed % 7, &[9u8; 32], epoch, &[8u8; 32], &[0u8; 64])
    }

    fn populate(n: usize) -> (Slice, Vec<Record>) {
        let mut s = Slice::new(TB, 0);
        let mut made = Vec::new();
        for seed in 0..n as u32 {
            let r = ptr(seed, 100);
            if s.insert(&r).is_ok() { made.push(r); }
        }
        (s, made)
    }

    // ── addressing ──

    /// The slot must be a pure bit-field of the key.
    /// If this ever needs a division or a float, the "one read, no refine step" guarantee is gone.
    #[test]
    fn slot_is_a_bitfield_not_arithmetic() {
        for n in 0u32..2000 {
            let key = *blake3::hash(&n.to_le_bytes()).as_bytes();
            let top = u64::from_be_bytes(key[..8].try_into().unwrap());
            for bits in [0u32, 4, 12, 24] {
                let expect_slot = ((top >> (64 - bits - SLOT_BITS)) & ((1 << SLOT_BITS) - 1)) as usize;
                assert_eq!(slot_of(&key, bits), expect_slot);
                assert!(slot_of(&key, bits) < SLICE_SLOTS);
            }
            assert_eq!(slice_of(&key, 0), 0, "width 0 = one slice for everything");
        }
    }

    /// Domain separation. handle_proof already keys the fleet chain, fstate, fanout, bindreq and inbox — an undomained hash would put the phonebook in all of their keyspaces at once.
    #[test]
    fn domains_do_not_collide() {
        let x = [7u8; 32];
        assert_ne!(key_identity(&x), key_pointer(&x, 0));
        assert_ne!(key_pointer(&x, 0), key_address(&x));
        assert_ne!(key_identity(&x), key_address(&x));
        assert_ne!(key_pointer(&x, 0), key_pointer(&x, 1), "index must change the address");
    }

    /// Consecutive device indices must scatter.
    /// If they clustered, one identity's devices would collide with each other by construction and probe distance would scale with fleet size — the clumping this addressing exists to avoid.
    #[test]
    fn pointer_indices_scatter() {
        let hp = [3u8; 32];
        let mut slots: Vec<usize> = (0..8).map(|i| slot_of(&key_pointer(&hp, i), TB)).collect();
        slots.sort_unstable();
        slots.dedup();
        assert_eq!(slots.len(), 8, "eight indices must not share slots");
    }

    /// A record's key is DERIVED, never stored, so contents and address cannot disagree.
    #[test]
    fn key_is_derived_from_contents() {
        let hp = [1u8; 32];
        let r = Record::new_device_pointer(&hp, 3, &[2u8; 32], 5, &[4u8; 32], &[0u8; 64]);
        assert_eq!(r.key().unwrap(), key_pointer(&hp, 3));
        assert!(Record::empty().key().is_none());
    }

    // ── slice invariants ──

    /// The core promise: findable at or after the computed slot, and the walk stays inside one 4 KiB block (16 slots).
    /// If this regresses, "one read per lookup" is gone.
    #[test]
    fn every_record_findable_within_one_block() {
        let (s, made) = populate(2400); // ~58% fill, the production design point
        assert!(made.len() > 2000);
        for r in &made {
            let k = r.key().unwrap();
            let (slot, found) = s.lookup(&k).expect("must be findable");
            assert_eq!(found.key().unwrap(), k);
            assert!(slot - slot_of(&k, TB) < 16, "walk escaped one block");
        }
    }

    /// Invariant (2).
    /// Violating it is silent corruption: the record is still in the file, but a lookup starting at its ideal and scanning right never reaches it.
    #[test]
    fn no_record_left_of_its_ideal_slot() {
        let (s, _) = populate(3000);
        s.check_invariants().expect("invariants hold after inserts");
    }

    /// Invariant (1).
    /// Catches stepping right past a LARGER key instead of shifting it — every lookup would still pass while the array quietly stopped being sorted.
    #[test]
    fn insert_preserves_sort_order() {
        let (s, made) = populate(3000);
        let keys: Vec<Key> = s.iter().map(|(_, r)| r.key().unwrap()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "slice must read back in ascending key order");
        let mut d = keys.clone();
        d.dedup();
        assert_eq!(d.len(), made.len(), "no key lost or duplicated");
    }

    /// An empty slot must PROVE absence — that is what bounds the walk.
    #[test]
    fn empty_slot_proves_absence() {
        let (s, _) = populate(1200);
        assert!(s.lookup(&ptr(999_999, 1).key().unwrap()).is_none());
    }

    /// Remove is the exact inverse of insert.
    /// Both invariants must survive every single removal.
    #[test]
    fn remove_is_the_inverse_of_insert() {
        let (mut s, made) = populate(2000);
        for (n, r) in made.iter().enumerate() {
            let k = r.key().unwrap();
            assert!(s.remove(&k), "remove must find the key");
            assert!(s.lookup(&k).is_none(), "removed key must be gone");
            s.check_invariants().unwrap_or_else(|e| panic!("after removal {n}: {e}"));
        }
        assert_eq!(s.fill(), 0);
    }

    /// Interleaved churn — the case a hand-written sequence misses.
    /// A wrong left-shift guard shows up here as a record still in the buffer but unfindable.
    #[test]
    fn random_churn_keeps_every_record_findable() {
        let (mut s, made) = populate(1500);
        let mut live = made;
        let mut rng = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; rng };

        for _ in 0..400 {
            if live.is_empty() { break; }
            let i = (next() % live.len() as u64) as usize;
            if next() % 2 == 0 {
                assert!(s.remove(&live[i].key().unwrap()));
                live.swap_remove(i);
            } else {
                let b = live[i];
                let bumped = Record::new_device_pointer(
                    &b.handle_proof(), b.index(), &b.device_pubkey(),
                    b.epoch() + 1, &b.placer(), &b.placement_sig());
                s.insert(&bumped).expect("epoch bump accepted");
                live[i] = bumped;
            }
            s.check_invariants().expect("invariants hold through churn");
        }
        for r in &live {
            assert!(s.lookup(&r.key().unwrap()).is_some(), "live record became unfindable");
        }
    }

    // ── the monotonic rule, and the attacks it closes ──

    /// Strictly greater or nothing.
    /// Equal is refused too — that is what serialises two concurrent writers without any old/new bookkeeping.
    #[test]
    fn epoch_must_strictly_increase() {
        let mut s = Slice::new(TB, 0);
        let r = ptr(1, 100);
        s.insert(&r).expect("first insert");
        for e in [100i64, 99, 0, -5] {
            let same = Record::new_device_pointer(
                &r.handle_proof(), r.index(), &r.device_pubkey(), e, &r.placer(), &r.placement_sig());
            assert!(matches!(s.insert(&same), Err(SliceError::StaleEpoch { .. })),
                "epoch {e} must be refused against stored 100");
        }
        let newer = Record::new_device_pointer(
            &r.handle_proof(), r.index(), &r.device_pubkey(), 101, &r.placer(), &r.placement_sig());
        assert!(s.insert(&newer).is_ok());
    }

    /// The shuffle attack, all three replay targets.
    /// Each is closed by a DIFFERENT rule, so this asserts all three are still present.
    /// Remove any one and reordering opens up.
    #[test]
    fn placement_replay_fails_at_every_target() {
        let mut s = Slice::new(TB, 0);
        let victim = ptr(11, 100);
        let vkey = victim.key().unwrap();
        s.insert(&victim).expect("place victim");

        // (a) into its OWN slot: the placement itself set that epoch, and epochs only rise.
        assert!(matches!(s.insert(&victim), Err(SliceError::StaleEpoch { .. })),
            "a placement can never be replayed into the slot it belongs to");

        // (b) into a DIFFERENT index: the index is inside both the key derivation and the placement signature, so it cannot be moved without becoming a different record.
        let moved = Record::new_device_pointer(
            &victim.handle_proof(), victim.index() + 1, &victim.device_pubkey(),
            victim.epoch(), &victim.placer(), &victim.placement_sig());
        assert_ne!(moved.key().unwrap(), vkey, "changing the index changes the address");
        assert_ne!(moved.placement_signing_bytes(), victim.placement_signing_bytes(),
            "the signature covers the index, so it does not carry over");

        // (c) into an EMPTIED slot: only the tail is ever emptied, and it is emptied because it is now out of range.
        // Landing there is inert until the count rises, which needs a current member's witness signature.
        s.remove(&vkey);
        assert!(s.insert(&victim).is_ok(), "an emptied slot accepts it");
        assert!(s.lookup(&vkey).is_some(), "…but readers gate on index < N, so it is never read");
    }

    /// Signing bytes must be domain-separated and must commit to what they claim.
    /// A signature over one role must never verify in another.
    #[test]
    fn signing_bytes_are_domain_separated() {
        let hp = [1u8; 32];
        let p = Record::new_device_pointer(&hp, 0, &[2u8; 32], 5, &[3u8; 32], &[0u8; 64]);
        let a = Record::new_device_address(&[2u8; 32], &hp, &[0u8; 16], 80, &[0u8; 16], 5, &[0u8; 64]);
        let c = Record::new_identity_count(&hp, 3, 5, &[3u8; 32], &[0u8; 64], None);

        assert!(p.placement_signing_bytes().starts_with(SIGN_PLACEMENT));
        assert!(a.address_signing_bytes().starts_with(SIGN_ADDRESS));
        assert!(c.count_signing_bytes().starts_with(SIGN_COUNT));
        assert!(Record::departure_signing_bytes(&hp, &[2u8; 32], 5).starts_with(SIGN_DEPART));

        // The address signature covers handle_proof, so a device cannot be planted under another identity — the gap that lets a stranger mint a row for any scraped handle_proof today.
        let other = Record::new_device_address(&[2u8; 32], &[9u8; 32], &[0u8; 16], 80, &[0u8; 16], 5, &[0u8; 64]);
        assert_ne!(a.address_signing_bytes(), other.address_signing_bytes());
    }

    /// Removal is consent-only: the departing device's own signature AND a current member's witness.
    /// The record carries both, and the witness commits to WHICH device departed, so a witness cannot be replayed to attest a different removal.
    #[test]
    fn removal_carries_consent_and_witness() {
        let hp = [1u8; 32];
        let leaver = [7u8; 32];
        let add = Record::new_identity_count(&hp, 3, 10, &[3u8; 32], &[1u8; 64], None);
        assert!(add.departing().is_none(), "an add has no departing device");

        let rem = Record::new_identity_count(&hp, 2, 11, &[3u8; 32], &[1u8; 64], Some((&leaver, &[2u8; 64])));
        let (dev, sig) = rem.departing().expect("a removal names the departing device");
        assert_eq!(dev, leaver);
        assert_eq!(sig, [2u8; 64]);
        assert_ne!(add.count_signing_bytes(), rem.count_signing_bytes(),
            "the witness signature commits to which device departed");
    }

    // ── structure ──

    /// A record must not be insertable into a slice its own contents do not address.
    #[test]
    fn record_must_belong_to_its_slice() {
        let mut s = Slice::new(4, 15); // width 4, slice 15
        let r = ptr(1, 100);
        let actual = slice_of(&r.key().unwrap(), 4);
        if actual != 15 {
            assert!(matches!(s.insert(&r), Err(SliceError::WrongSlice { .. })));
        }
    }

    /// Round-tripping the raw body preserves both invariants and the fill count — the body is what an mmap'd file holds and what ships inside a VSF document, so it must survive verbatim.
    #[test]
    fn raw_body_round_trips() {
        let (s, made) = populate(1500);
        let restored = Slice::from_bytes(TB, 0, s.as_bytes().to_vec()).expect("valid body");
        assert_eq!(restored.fill(), made.len());
        restored.check_invariants().expect("invariants survive a round trip");
        for r in &made {
            assert!(restored.lookup(&r.key().unwrap()).is_some());
        }
        assert!(Slice::from_bytes(TB, 0, vec![0u8; 10]).is_none(), "a short body is rejected");
    }

    // ── signatures ──

    fn sk(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }
    fn pk(k: &ed25519_dalek::SigningKey) -> [u8; 32] {
        k.verifying_key().to_bytes()
    }
    fn sign(k: &ed25519_dalek::SigningKey, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        k.sign(msg).to_bytes()
    }

    /// The one-step mint must produce exactly what the hand-rolled two-step produces, and must verify.
    /// This is the helper the client publishes through, so a regression here is an unfindable device rather than a visible error.
    #[test]
    fn sign_device_address_mints_a_verifying_record() {
        let dev = sk(3);
        let hp = [8u8; 32];
        let minted = Record::sign_device_address(&dev, &hp, &[4u8; 16], 4383, &[5u8; 16], 99);
        assert!(minted.verify_address(), "a minted record must verify");

        let unsigned = Record::new_device_address(&pk(&dev), &hp, &[4u8; 16], 4383, &[5u8; 16], 99, &[0u8; 64]);
        let expected = Record::new_device_address(
            &pk(&dev),
            &hp,
            &[4u8; 16],
            4383,
            &[5u8; 16],
            99,
            &sign(&dev, &unsigned.address_signing_bytes()),
        );
        assert_eq!(minted.0, expected.0, "the one-step mint must equal the two-step");
        assert_eq!(minted.key(), Some(key_address(&pk(&dev))), "keyed by device pubkey alone");
    }

    /// The record crosses the wire to the seed as its raw 256 bytes and is reconstructed there before `verify_address` runs.
    /// A stride change or a lossy copy would break publication silently, so pin the exact byte-for-byte round trip the worker's `pb_put` performs.
    #[test]
    fn address_record_survives_a_raw_stride_round_trip() {
        let dev = sk(4);
        let r = Record::sign_device_address(&dev, &[2u8; 32], &[7u8; 16], 4383, &[6u8; 16], 1234);

        let wire: Vec<u8> = r.0.to_vec();
        assert_eq!(wire.len(), STRIDE, "the wire form is exactly one stride");

        let mut back = [0u8; STRIDE];
        back.copy_from_slice(&wire);
        let restored = Record(back);
        assert!(restored.verify_address(), "a round-tripped record still verifies");
        assert_eq!(restored.key(), r.key());
        assert_eq!(restored.epoch(), 1234, "the monotonic guard reads the same epoch back");
    }

    /// A device signs its own address, and the record self-verifies against the key inside it.
    /// Tampering with ANY covered field must break it — that is the whole integrity story, since there is no whole-file hash maintained across updates.
    #[test]
    fn address_record_self_verifies_and_detects_tampering() {
        let dev = sk(1);
        let hp = [5u8; 32];
        let mut r = Record::new_device_address(&pk(&dev), &hp, &[1u8; 16], 7953, &[2u8; 16], 42, &[0u8; 64]);
        let sig = sign(&dev, &r.address_signing_bytes());
        r = Record::new_device_address(&pk(&dev), &hp, &[1u8; 16], 7953, &[2u8; 16], 42, &sig);
        assert!(r.verify_address(), "a correctly signed address must verify");

        // Every covered field: flip it, the signature must fail.
        let bad_ip = Record::new_device_address(&pk(&dev), &hp, &[9u8; 16], 7953, &[2u8; 16], 42, &sig);
        assert!(!bad_ip.verify_address(), "a redirected IP must not verify");
        let bad_port = Record::new_device_address(&pk(&dev), &hp, &[1u8; 16], 1, &[2u8; 16], 42, &sig);
        assert!(!bad_port.verify_address(), "a changed port must not verify");
        let bad_ts = Record::new_device_address(&pk(&dev), &hp, &[1u8; 16], 7953, &[2u8; 16], 43, &sig);
        assert!(!bad_ts.verify_address(), "a replayed timestamp must not verify");
        let bad_hp = Record::new_device_address(&pk(&dev), &[6u8; 32], &[1u8; 16], 7953, &[2u8; 16], 42, &sig);
        assert!(!bad_hp.verify_address(), "planting the device under another identity must not verify");

        // Another device cannot sign this device's row.
        let attacker = sk(2);
        let forged = sign(&attacker, &r.address_signing_bytes());
        let bad_key = Record::new_device_address(&pk(&dev), &hp, &[1u8; 16], 7953, &[2u8; 16], 42, &forged);
        assert!(!bad_key.verify_address(), "a signature by another key must not verify");
    }

    /// A placement verifies against the placer named in it — but that is only WHO, never WHETHER they were entitled.
    /// A departed member's signature stays valid forever, so the caller must check current membership separately; this test pins that the check is genuinely absent here.
    #[test]
    fn placement_verifies_signer_but_not_membership() {
        let placer = sk(3);
        let hp = [1u8; 32];
        let base = Record::new_device_pointer(&hp, 2, &[7u8; 32], 10, &pk(&placer), &[0u8; 64]);
        let sig = sign(&placer, &base.placement_signing_bytes());
        let r = Record::new_device_pointer(&hp, 2, &[7u8; 32], 10, &pk(&placer), &sig);
        assert!(r.verify_placement());

        // Same signature, different index → different signing bytes → fails.
        // This is target (b) of the shuffle attack, closed cryptographically rather than by convention.
        let moved = Record::new_device_pointer(&hp, 3, &[7u8; 32], 10, &pk(&placer), &sig);
        assert!(!moved.verify_placement(), "a placement cannot be replayed at another index");

        // A stranger's placement verifies as THEIRS — proving the caller must gate on membership.
        let stranger = sk(9);
        let sbase = Record::new_device_pointer(&hp, 2, &[7u8; 32], 11, &pk(&stranger), &[0u8; 64]);
        let ssig = sign(&stranger, &sbase.placement_signing_bytes());
        let srec = Record::new_device_pointer(&hp, 2, &[7u8; 32], 11, &pk(&stranger), &ssig);
        assert!(srec.verify_placement(), "signature is valid — membership is the CALLER's check");
    }

    /// Consent-only removal: the departing device's own signature is required, and an unsigned or wrongly-signed departure is not consent.
    /// An add has nothing to prove.
    #[test]
    fn departure_requires_the_leavers_own_signature() {
        let leaver = sk(4);
        let witness = sk(5);
        let hp = [1u8; 32];

        let add = Record::new_identity_count(&hp, 3, 10, &pk(&witness), &[0u8; 64], None);
        assert!(add.verify_departure(), "an add has no departure to prove");

        let msg = Record::departure_signing_bytes(&hp, &pk(&leaver), 11);
        let good = Record::new_identity_count(&hp, 2, 11, &pk(&witness), &[0u8; 64], Some((&pk(&leaver), &sign(&leaver, &msg))));
        assert!(good.verify_departure(), "the leaver's own signature is consent");

        let forged = sign(&witness, &msg); // a member signing on the leaver's behalf
        let bad = Record::new_identity_count(&hp, 2, 11, &pk(&witness), &[0u8; 64], Some((&pk(&leaver), &forged)));
        assert!(!bad.verify_departure(), "no device removes another — a member cannot sign for the leaver");

        let wrong_epoch = Record::new_identity_count(&hp, 2, 12, &pk(&witness), &[0u8; 64], Some((&pk(&leaver), &sign(&leaver, &msg))));
        assert!(!wrong_epoch.verify_departure(), "the departure is bound to its epoch");
    }

    /// The witness attests the count AND which device departed, so it cannot be replayed against a different removal.
    #[test]
    fn count_witness_commits_to_the_departure() {
        let witness = sk(6);
        let hp = [1u8; 32];
        let leaver = [7u8; 32];
        let base = Record::new_identity_count(&hp, 2, 11, &pk(&witness), &[0u8; 64], Some((&leaver, &[0u8; 64])));
        let sig = sign(&witness, &base.count_signing_bytes());
        let r = Record::new_identity_count(&hp, 2, 11, &pk(&witness), &sig, Some((&leaver, &[0u8; 64])));
        assert!(r.verify_count());

        let other_leaver = Record::new_identity_count(&hp, 2, 11, &pk(&witness), &sig, Some((&[8u8; 32], &[0u8; 64])));
        assert!(!other_leaver.verify_count(), "the witness names WHICH device departed");
        let other_count = Record::new_identity_count(&hp, 5, 11, &pk(&witness), &sig, Some((&leaver, &[0u8; 64])));
        assert!(!other_count.verify_count(), "the witness attests a specific count");
    }

    // ── transport ──

    /// A slice ships as a COMPLETE VSF file: header, provenance hash, geometry, and the raw fixed-stride body as an unboxed section.
    /// Round-trip must preserve every record and both invariants, and the geometry must come from the document rather than the caller.
    #[test]
    fn slice_round_trips_through_a_vsf_document() {
        let (s, made) = populate(1500);
        let doc = s.to_document().expect("build document");
        assert!(doc.starts_with(b"R\xc3\x85<"), "must carry the R\u{c5}< magic");
        let (header, _) = vsf::verification::read_verified(&doc, None).expect("verified read");
        assert!(matches!(header.provenance_hash, vsf::VsfType::hp(ref h) if h.len() == 32),
            "a slice in transit carries a provenance hash so a torn transfer is detectable");

        let back = Slice::from_document(&doc).expect("read back");
        assert_eq!(back.slice_bits(), s.slice_bits(), "geometry comes from the document");
        assert_eq!(back.slice_id(), s.slice_id());
        assert_eq!(back.fill(), made.len());
        back.check_invariants().expect("invariants survive transport");
        for r in &made {
            assert!(back.lookup(&r.key().unwrap()).is_some());
        }
    }

    /// A corrupted document must be refused before any record is trusted.
    #[test]
    fn corrupt_document_is_rejected() {
        let (s, _) = populate(200);
        let mut doc = s.to_document().expect("build");
        let n = doc.len();
        doc[n / 2] ^= 0xFF;
        assert!(Slice::from_document(&doc).is_err(), "a tampered body must not load");
        assert!(Slice::from_document(b"not a vsf document").is_err());
    }

    /// Every layout must fit the stride with reserve left over — the reserve is the migration budget, and a field that overflows 256 is a flag day rather than a free addition.
    #[test]
    fn layouts_fit_the_stride_with_reserve() {
        assert_eq!(STRIDE, 256);
        assert_eq!(SLICE_SLOTS * STRIDE, 1024 * 1024, "one slice is 1 MiB");
        assert_eq!(STRIDE * 16, 4096, "16 records per 4 KiB block");
        assert!(IC_DEPART_SIG + 64 <= STRIDE, "IdentityCount overflows");
        assert!(DP_PLACE_SIG + 64 <= STRIDE, "DevicePointer overflows");
        assert!(DA_SIG + 64 <= STRIDE, "DeviceAddress overflows");
    }

    /// Test-side registry storage: apply a plan's records the way per-key storage would (count replaces, a pointer lands at its index), then trim to the attested extent.
    fn apply_plan(view: &mut RegistryView, plan: &[Record]) {
        for r in plan {
            match r.kind() {
                RecordKind::IdentityCount => view.count = Some(*r),
                RecordKind::DevicePointer => {
                    let i = r.index() as usize;
                    while view.pointers.len() <= i {
                        view.pointers.push(Record::empty());
                    }
                    view.pointers[i] = *r;
                }
                _ => panic!("a plan only emits count + pointer records"),
            }
        }
        let n = view.count.as_ref().map(|c| c.count() as usize).unwrap_or(0);
        view.pointers.truncate(n);
    }

    #[test]
    fn plan_converges_from_empty_then_goes_quiet() {
        let member = sk(1);
        let hp = [9u8; 32];
        let fold = [pk(&sk(1)), pk(&sk(2))];
        let mut view = RegistryView::default();
        let plan = registry_plan(&member, &hp, &fold, &view, 100, None);
        assert_eq!(plan.len(), 3, "two pointers + the count");
        apply_plan(&mut view, &plan);
        assert!(view.verify(&hp), "a plan minted by one member must verify for any reader");
        assert_eq!(view.devices(), fold.to_vec());
        // In sync → the next plan is empty, so racing siblings settle instead of ping-ponging writes.
        assert!(registry_plan(&member, &hp, &fold, &view, 101, None).is_empty());
    }

    #[test]
    fn plan_appends_without_touching_stored_slots() {
        let member = sk(1);
        let hp = [9u8; 32];
        let mut view = RegistryView::default();
        let plan0 = registry_plan(&member, &hp, &[pk(&sk(1)), pk(&sk(2))], &view, 100, None);
        apply_plan(&mut view, &plan0);
        let stored_first = view.pointers[0];
        let fold3 = [pk(&sk(1)), pk(&sk(2)), pk(&sk(3))];
        let plan = registry_plan(&member, &hp, &fold3, &view, 200, None);
        assert_eq!(plan.len(), 2, "one new pointer + the count — stored slots stay untouched");
        apply_plan(&mut view, &plan);
        assert!(view.verify(&hp));
        assert_eq!(view.devices(), fold3.to_vec());
        assert_eq!(view.pointers[0].0, stored_first.0, "an untouched slot keeps its record (and epoch) exactly as stored");
    }

    #[test]
    fn plan_removes_by_pop_and_swap_with_consent() {
        let member = sk(1);
        let hp = [9u8; 32];
        let leaver = sk(2);
        let mut view = RegistryView::default();
        let fold3 = [pk(&sk(1)), pk(&leaver), pk(&sk(3))];
        let plan0 = registry_plan(&member, &hp, &fold3, &view, 100, None);
        apply_plan(&mut view, &plan0);
        // The leaver consents with its OWN key over the departure bytes at the new epoch.
        let fold2 = [pk(&sk(1)), pk(&sk(3))];
        let leaver_pk = pk(&leaver);
        let consent = {
            use ed25519_dalek::Signer;
            leaver.sign(&Record::departure_signing_bytes(&hp, &leaver_pk, 200)).to_bytes()
        };
        let plan = registry_plan(&member, &hp, &fold2, &view, 200, Some((&leaver_pk, &consent)));
        assert_eq!(plan.len(), 2, "the relocated tail pointer + the count");
        apply_plan(&mut view, &plan);
        assert!(view.verify(&hp), "verify covers the departure consent riding the count");
        assert_eq!(view.devices(), vec![pk(&sk(1)), pk(&sk(3))], "the tail popped into the hole — indices stay dense");
        let count = view.count.unwrap();
        assert_eq!(count.departing().unwrap().0, leaver_pk);
        assert!(count.verify_departure());
    }

    #[test]
    fn view_verify_rejects_tampering() {
        let member = sk(1);
        let hp = [9u8; 32];
        let mut view = RegistryView::default();
        let plan0 = registry_plan(&member, &hp, &[pk(&sk(1)), pk(&sk(2))], &view, 100, None);
        apply_plan(&mut view, &plan0);
        assert!(view.verify(&hp));
        // A pointer moved to the wrong slot fails (index is inside the placement signature).
        view.pointers.swap(0, 1);
        assert!(!view.verify(&hp), "a shuffled pointer run must not verify");
        view.pointers.swap(0, 1);
        // A count that disagrees with the pointer run fails.
        view.pointers.pop();
        assert!(!view.verify(&hp), "count and pointer extent must agree");
    }
}
