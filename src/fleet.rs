//! Fleet membership blob — the network-held, signed, authenticated log of the devices that constitute one identity (the user's fleet).
//! This is the v1 keyring: a list of device public keys you can add to and remove from, where **every change is signed by a device that was valid in the previous state**, chained by hash so the whole history is tamper-evident and replayable.
//! Peers verify a friend's fleet by folding the chain; FGTW gates updates by the same rule.
//! (Supersedes the v0 Merkle-root keyring: count-hiding is deferred to a future modulus accumulator, which layers over this set without changing membership logic.)
//!
//! ## One source of truth for signer and verifier
//!
//! This module is shared verbatim by the FGTW worker (verify-only: parse a posted chain and fold it) and by clients (fetch-then-sign builders).
//! `signing_bytes`, `chain_hash`, `verify_sigs`, `fold`, and the VSF op layout are the same code on both sides, so a chain a device signs always folds where the worker checks it.
//! The `known_answer_vector_for_worker_parity` test pins a fixed blob's fold — the drift guard from when signer and verifier were two hand-mirrored copies.
//!
//! ## Model (decided 2026-06-30)
//!
//! - Devices are **blind, stateless signing oracles** — each knows only its own private key.
//!   The blob lives wholly on the network; a device fetches it, finds its own pubkey, signs an op, done.
//!   No local fleet state.
//! - **Authorisation = signature from a prior-valid member.**
//!   No shared secret (the handle is disclosable; the only real secret is the per-device key), so "an authorised device approved this" can only be a signature from a key that was in the set before this op.
//! - **Genesis is first-come, self-signed** (the first device claims the handle, like the handle itself).
//!
//! ## Signatures — Ed25519 now, egg-list shaped
//!
//! Each op carries a LIST of `(scheme, sig)` eggs and the rule is **every listed egg must verify**.
//! v1 lists only Ed25519 (the device's existing identity key); adding Falcon-512 / SPHINCS+ later is appending an egg, gated by a credential-format version bump — not a reshape.
//! A forger then has to break *every* family.
//!
//! ## Sovereign records (2026-07-13, docs/pairing-v2.md)
//!
//! The subject signs; others verify or withhold.
//! - **Add is bilateral**: the sponsor's egg authorises, and the op carries the added device's own consent — its binding-request signature ([`bindreq_signing_bytes`]) as `consent_sig`. An op without valid consent does not fold, so conscription (and the virgin-pubkey ownership squat it enabled) is structurally impossible.
//! - **Remove is self-signed departure ONLY**: `signer == device`, no exceptions. Nobody can be expelled; eviction is withholding (re-key around the device), never erasure.
//! - Consent freshness: `|eagle_time − consent_t| ≤` [`CONSENT_WINDOW_OSC`], so a departed device's ancient consent can't be replayed to re-add it.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use vsf::VsfType;

/// Signature-scheme tag (the egg label). Wire-stable: append, never renumber.
pub mod scheme {
    /// Elliptic-curve family (ECDLP). The device key itself, so EVERY device can always produce this one.
    pub const ED25519: u8 = 0;
    /// Lattice family (NTRU/SIS). 897 B key, 666 B signature.
    pub const FALCON512: u8 = 1;
    /// Hash family (preimage resistance) — the backstop if curves and lattices both fall. 32 B key, 7856 B signature.
    pub const SPHINCS_PLUS: u8 = 2;

    /// A set of schemes as a bitmask, bit N = scheme N. The currency of the fleet's capability floor.
    pub type Mask = u16;

    /// The mask every device satisfies unconditionally — its device key IS an Ed25519 key, so a member that has declared nothing still honestly has this much.
    pub const MASK_BASE: Mask = 1 << ED25519;

    /// All three families. What a fully-upgraded fleet reaches.
    pub const MASK_ALL: Mask = (1 << ED25519) | (1 << FALCON512) | (1 << SPHINCS_PLUS);

    /// `true` if `mask` contains every scheme in `required`.
    pub fn covers(mask: Mask, required: Mask) -> bool {
        mask & required == required
    }

    /// Schemes this build knows how to verify. An op demanding anything outside this is rejected rather than skipped — a verifier must never silently treat an unknown scheme as satisfied.
    pub const MASK_KNOWN: Mask = MASK_ALL;
}

/// One signature egg: which scheme, and the signature bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct Egg {
    pub scheme: u8,
    pub sig: Vec<u8>,
}

/// What a fleet op does. `u8` discriminant is the on-wire `kind`; wire-stable.
/// Checkpoint (2026-08-12) is the fleet-plane epoch spine (photon docs/braid.md §14.4): a chain-format flag-day — pre-checkpoint builds hard-fail the parse on kind 3, which is the approved atomic-update behaviour, never a tolerated fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Genesis = 0,
    Add = 1,
    Remove = 2,
    Checkpoint = 3,
    /// A member publishes its own key bundle, raising what it can sign with. Self-signed only — you may declare your keys and nobody else's. The transition instrument: existing members declare to lift the fleet's floor, while devices joining afterwards carry their bundle on the Add itself.
    Declare = 4,
}

impl OpKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(OpKind::Genesis),
            1 => Some(OpKind::Add),
            2 => Some(OpKind::Remove),
            3 => Some(OpKind::Checkpoint),
            4 => Some(OpKind::Declare),
            _ => None,
        }
    }
}

/// One link in the fleet chain: an authorised change to the device set.
#[derive(Clone, Debug, PartialEq)]
pub struct FleetOp {
    /// The identity (public network id) this op's chain belongs to — bound into every op's signature so a valid chain can't be transplanted under a different (e.g. unclaimed) handle_proof to brick it.
    pub handle_proof: [u8; 32],
    /// Hash of the previous op (`chain_hash`), linking the chain. `[0; 32]` for genesis.
    pub prev_hash: [u8; 32],
    pub kind: OpKind,
    /// The device being added/removed (for genesis: the founding device).
    pub device_pubkey: [u8; 32],
    /// Eagle-time the op was made (ordering / display; not load-bearing for auth).
    pub eagle_time: i64,
    /// The device that SIGNED this op — must have been a member in the previous state (genesis: == device; remove: == device, self-departure only).
    pub signer_pubkey: [u8; 32],
    /// GENESIS ONLY: the identity public key `Ed25519(identity_seed)` — the key only the holder of the handle's secret seed can produce, co-signing the genesis so the fleet is provably founded by the identity owner (not just whoever scraped the public `handle_proof`).
    /// `[0; 32]` on add/remove ops.
    pub identity_pubkey: [u8; 32],
    /// GENESIS ONLY: signature over [`FleetOp::signing_bytes`] by `identity_pubkey`. Empty on add/remove ops.
    pub identity_sig: Vec<u8>,
    /// ADD ONLY: the eagle-time stamp of the binding request whose signature rides `consent_sig`. 0 elsewhere.
    pub consent_t: i64,
    /// ADD and consented REMOVE: the subject device's OWN eggs over [`bindreq_signing_bytes`] / [`departreq_signing_bytes`] — the subject consenting to its membership or its exit (bilateral; the sovereign-records rule). NOT signatures over this op's signing bytes, so they are data the sponsor's egg commits to. On an Add the consent must cover every scheme in the joiner's bundle: this is where a joiner PROVES the keys it declares, since the Add itself is signed by the sponsor. Empty on genesis/checkpoint/declare and on a legacy self-departure. v1 ops carry exactly one Ed25519 egg.
    pub consent: Vec<Egg>,
    /// CHECKPOINT ONLY: the monotonic checkpoint sequence number, strictly prev+1 starting at 1 — the epoch index `k` the fleet's key schedule advances on. 0 elsewhere.
    pub ckpt_k: u64,
    /// CHECKPOINT ONLY: blake3 commitment to the SECRET settled-root (the merkle root over the fleet's settled message rows) — the chain carries only this preimage-hiding commitment, never the root. `[0; 32]` elsewhere.
    pub ckpt_commit: [u8; 32],
    /// CHECKPOINT ONLY: the fan-out fleet-key epoch this checkpoint folds into its derivation, so a catching-up sibling knows WHICH fleet key enters `epoch_k`. Already-public information (the fan-out slot shows its epoch). 0 elsewhere.
    pub ckpt_fanout_epoch: u64,
    /// Signature eggs over [`FleetOp::signing_bytes`]; every listed egg must verify (the egg-list rule).
    pub sigs: Vec<Egg>,
    /// Which preimage rule this op's signatures were made under — see [`OpVersion`]. Absent on the wire for every op written before the egg work, which decodes as `V1` and is what keeps existing chains folding.
    pub version: OpVersion,
    /// ADD and DECLARE only: the subject device's full public-key bundle. Carried in the chain — not just committed — because the worker holds nothing else and must be able to verify the PQ eggs on every later op by this device. `None` on every other kind, and on an Add whose device has declared nothing yet. Outside the chain the bundle is named by [`KeyBundle::commit`](crate::pq::KeyBundle::commit).
    pub bundle: Option<crate::pq::KeyBundle>,
}

/// Domain tag so a fleet-op signature can never be confused with any other signature in the system. v1 = the sovereign-records break (consent egg on Add, self-departure-only Remove).
const SIGNING_DOMAIN_V1: &[u8] = b"PHOTON_FLEET_OP_v1";

/// v2 = LENGTH-FRAMED preimages (see [`frame_into`]), the prerequisite for eggs of differing lengths.
const SIGNING_DOMAIN_V2: &[u8] = b"PHOTON_FLEET_OP_v2";

/// Which preimage rule an op's signatures were made under. A PER-OP property, never a global one.
///
/// The genesis op's [`FleetOp::chain_hash`] is the fleet's generation id, and every friend TOFU-pins it (docs/lifecycle.md — "free must not mean inheritable"). Recomputing it under a new rule changes that hash, so every friend would see a stranger and refuse the fold. Gating per op keeps v1 ops byte-identical forever: the genesis hash a friend pinned still equals what today's code computes, and the chain extends rather than restarts.
///
/// This mirrors the rule the checkpoint fields already follow in [`FleetOp::signing_bytes`] — kind-gated precisely so pre-checkpoint ops keep byte-identical signing bytes. An unconditional change breaks every deployed fleet's signatures at once.
///
/// Safe to trust off the wire: the version is the FIRST thing in the preimage, so relabelling an op changes its preimage and the signature simply fails to verify. Forging a downgrade needs the signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum OpVersion {
    /// Unframed preimages, Ed25519-only. Every op written before the egg work. The default when an op carries no version field, which is how existing chains keep folding.
    #[default]
    V1 = 1,
    /// Length-framed preimages; the shape eggs of differing lengths require.
    V2 = 2,
}

impl OpVersion {
    fn domain(self) -> &'static [u8] {
        match self {
            OpVersion::V1 => SIGNING_DOMAIN_V1,
            OpVersion::V2 => SIGNING_DOMAIN_V2,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(OpVersion::V1),
            2 => Some(OpVersion::V2),
            _ => None,
        }
    }
}

/// Append a variable-length element to a preimage as `u32 LE length ‖ bytes`.
///
/// EVERY variable-length element in a signature or chain-hash preimage must go through this. Unframed concatenation is injective only while every element has one fixed width — true while Ed25519 was the only scheme, since a run of `scheme ‖ 64-byte sig` parses back apart unambiguously. With a second scheme of a different length it is not: one Falcon egg (666 B) is byte-identical to a crafted run of shorter eggs, so two DIFFERENT signature sets can produce the same [`FleetOp::chain_hash`] — and that hash is `prev_hash`, the generation id, and `head()`. The same hazard applies to the trailing `consent_sig` in [`FleetOp::signing_bytes`].
fn frame_into(v: &mut Vec<u8>, bytes: &[u8]) {
    v.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(bytes);
}

/// [`frame_into`] for a hasher — same framing rule, same reason.
fn frame_hash(h: &mut blake3::Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u32).to_le_bytes());
    h.update(bytes);
}

/// The exact bytes a binding request signs: the device attests "I consent to join fleet `handle_proof`" at time `t`. Signed TWICE at the registry (device key + `Ed25519(identity_seed)` — the write gate), and the device signature is re-verified forever after as the Add op's `consent_sig` (the fold gate). Lives here rather than `pair` because the worker folds chains without the `fanout` feature.
pub fn bindreq_signing_bytes(handle_proof: &[u8; 32], device_pubkey: &[u8; 32], t: i64) -> Vec<u8> {
    let mut v = Vec::with_capacity(18 + 64 + 8);
    v.extend_from_slice(b"PHOTON_BINDREQ_v1");
    v.extend_from_slice(handle_proof);
    v.extend_from_slice(device_pubkey);
    v.extend_from_slice(&t.to_le_bytes());
    v
}

/// The exact bytes a departure request signs: the device attests "I request removal from fleet `handle_proof`" at time `t`. Signed by the LEAVING device; the signature becomes the Remove op's `consent_sig`, countersigned (egg) by a surviving member — the exact mirror of Add's bilateral shape. Why bilateral: a unilateral self-remove lets whoever briefly holds one unlocked device sign it out — forcing a fleet-wide key rotation AND laundering the hardware into a clean re-attestable device for their own handle.
pub fn departreq_signing_bytes(handle_proof: &[u8; 32], device_pubkey: &[u8; 32], t: i64) -> Vec<u8> {
    let mut v = Vec::with_capacity(19 + 64 + 8);
    v.extend_from_slice(b"PHOTON_DEPARTREQ_v1");
    v.extend_from_slice(handle_proof);
    v.extend_from_slice(device_pubkey);
    v.extend_from_slice(&t.to_le_bytes());
    v
}

/// How far an Add's `eagle_time` may sit from its consent stamp: 1 hour — generous for a live ceremony (the request re-posts every ~3.5 min anyway), fatal for replaying a departed device's ancient consent.
pub const CONSENT_WINDOW_OSC: i64 = 3600 * vsf::OSCILLATIONS_PER_SECOND as i64;

/// Binding requests older than this are lapsed (worker refuses at put, skips at list; clients skip too). The author refreshes at ~3.5 min while its ceremony screen is up; an abandoned ceremony self-cleans by expiry — the worker NEVER consumes a request (no third-party deletion, per the sovereign-records rule).
pub const BINDREQ_FRESH_OSC: i64 = 300 * vsf::OSCILLATIONS_PER_SECOND as i64;

/// A binding request: a device's signed, identity-co-signed ask to join a fleet — the registry entry the old device's matcher screens candidates from, and the source of the Add op's consent egg.
#[derive(Clone, Debug, PartialEq)]
pub struct BindRequest {
    pub device_pubkey: [u8; 32],
    /// Eagle-time stamp — freshness at the registry, and the `consent_t` the Add op carries.
    pub t: i64,
    /// The device's eggs over [`bindreq_signing_bytes`] — the consent (becomes the Add op's `consent`). One per scheme in `bundle`, so posting a request IS proving possession of every key it declares.
    pub device_sig: Vec<Egg>,
    /// The joiner's public-key bundle, if it has one beyond Ed25519. Rides the registry so the sponsor can put it on the Add (`add_declared`) and so the worker can verify the PQ consent eggs at the door. `None` = Ed25519 alone, which a promoted fleet will refuse as `BelowFloor` at bind time.
    pub bundle: Option<crate::pq::KeyBundle>,
    /// `Ed25519(identity_seed)`'s signature over the same bytes — an ANTI-SPAM gate on the pending-request slot: posting requires knowing the handle STRING, which `handle_proof` (public, it is the slot key) does not. NOTE: this is NOT "only the owner can enter the set" — `identity_seed = BLAKE3(handle)` is public-derivable, and entering the member set still requires a member sponsor's Add. Checked against the chain's genesis identity pubkey; never enters the chain itself. See docs/fleet-identity-remediation.md.
    pub identity_sig: Vec<u8>,
    /// NFC instant-add commitment: `pair::nfc_secret_hash(S, device_pubkey, t)` where `S` is the 32-byte random secret the joiner serves over the NFC tap. All-zero = no NFC offered. DELIBERATELY OUTSIDE `bindreq_signing_bytes` — those bytes are the chain's consent verification forever (every future fold re-checks consent_sig against them), so a new field there is a protocol-wide flag-day; the binding lives inside the keyed hash instead (recomputed per candidate with ITS pubkey+t), so a tampered/transplanted hash simply never matches — fail-closed, never wrong-device.
    pub nfc_hash: [u8; 32],
}

impl BindRequest {
    /// Verify both signatures: the device's own consent, and the identity co-signature under `identity_pubkey`. NOTE: the identity co-signature is a handle-knowledge ANTI-SPAM gate, NOT an ownership/membership gate (see the `identity_sig` field doc and docs/fleet-identity-remediation.md). The worker screens writes with this; the old device re-checks at list time. Actual membership still requires a member sponsor's Add.
    pub fn verify(&self, handle_proof: &[u8; 32], identity_pubkey: &[u8; 32]) -> bool {
        let msg = bindreq_signing_bytes(handle_proof, &self.device_pubkey, self.t);
        let subject = self.bundle.clone().unwrap_or_else(|| crate::pq::KeyBundle::ed25519_only(&self.device_pubkey));
        // The bundle must be this device's, and the consent must cover every scheme in it — declaring a key is proving it.
        subject.ed25519() == self.device_pubkey
            && crate::pq::verify_eggs(&self.device_sig, &subject, &msg, subject.mask())
            && verify_ed25519(identity_pubkey, &msg, &self.identity_sig)
    }
}

impl FleetOp {
    /// The exact bytes every egg signs: domain + all content fields, fixed-width and deterministic.
    /// Excludes the sigs themselves (you can't sign the signature) — but INCLUDES `consent_sig`, which is a signature over DIFFERENT bytes (the binding request), so the sponsor's egg commits to the exact consent it saw.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let domain = self.version.domain();
        let mut b = Vec::with_capacity(domain.len() + 32 + 32 + 1 + 32 + 8 + 32 + 32 + 8 + 4 + self.consent.iter().map(|e| 5 + e.sig.len()).sum::<usize>());
        b.extend_from_slice(domain);
        b.extend_from_slice(&self.handle_proof);
        b.extend_from_slice(&self.prev_hash);
        b.push(self.kind as u8);
        b.extend_from_slice(&self.device_pubkey);
        b.extend_from_slice(&self.eagle_time.to_le_bytes());
        b.extend_from_slice(&self.signer_pubkey);
        b.extend_from_slice(&self.identity_pubkey); // bound in so the device sig also commits to the identity key (it can't be swapped)
        b.extend_from_slice(&self.consent_t.to_le_bytes());
        // Bound in so the consent can't be swapped under the sponsor's egg. v1 appends the single Ed25519 signature bare, so v1 preimages stay byte-identical; v2 frames the egg-list blob (see `frame_into`).
        match self.version {
            OpVersion::V1 => b.extend_from_slice(self.consent.first().map(|e| e.sig.as_slice()).unwrap_or(&[])),
            OpVersion::V2 => frame_into(&mut b, &crate::pq::eggs_to_bytes(&self.consent)),
        }
        // Checkpoint fields append KIND-GATED: every pre-checkpoint op kind keeps byte-identical signing bytes, so chains signed by pre-2026-08-12 builds still verify — an unconditional append would break every deployed fleet's signatures at once.
        if self.kind == OpKind::Checkpoint {
            b.extend_from_slice(&self.ckpt_k.to_le_bytes());
            b.extend_from_slice(&self.ckpt_commit);
            b.extend_from_slice(&self.ckpt_fanout_epoch.to_le_bytes());
        }
        // The key bundle, bound in so a device's advertised capability can't be edited under its own signature. Kind-gated like the checkpoint triple, v2-only because no v1 op ever carried it, and ALWAYS framed — an absent bundle frames as zero bytes, so "no bundle" and "some bundle" can never share a preimage.
        if self.version == OpVersion::V2 && matches!(self.kind, OpKind::Add | OpKind::Declare) {
            let bytes = self.bundle.as_ref().map(|k| k.to_bytes()).unwrap_or_default();
            frame_into(&mut b, &bytes);
        }
        b
    }

    /// The chain link for the NEXT op's `prev_hash`: a hash over the signed content AND every signature, so the whole op (including who signed it and how) is immutable once chained.
    ///
    /// From v2 the egg count is committed before the eggs themselves and each signature is length-framed. Without both, a chain hash does not uniquely determine the signature set it covers once schemes of differing lengths exist — see [`frame_into`]. v1 keeps the bare concatenation, which is unambiguous there because Ed25519 is its only scheme, and which MUST NOT change: this hash is the generation id every friend pinned.
    pub fn chain_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.signing_bytes());
        match self.version {
            OpVersion::V1 => {
                for egg in &self.sigs {
                    h.update(&[egg.scheme]);
                    h.update(&egg.sig);
                }
                h.update(&self.identity_sig);
            }
            OpVersion::V2 => {
                h.update(&(self.sigs.len() as u32).to_le_bytes());
                for egg in &self.sigs {
                    h.update(&[egg.scheme]);
                    frame_hash(&mut h, &egg.sig);
                }
                frame_hash(&mut h, &self.identity_sig);
            }
        }
        *h.finalize().as_bytes()
    }

    /// Verify the GENESIS identity binding: `identity_sig` is a valid signature over [`FleetOp::signing_bytes`] by `identity_pubkey`.
    /// NOTE: `identity_seed = BLAKE3(handle)` is a PUBLIC function of the handle, so this binding proves only that the signer KNEW the handle string — NOT that they own it (anyone who knows the handle reproduces `Ed25519(identity_seed)`). It is not an ownership proof. Real identity assurance is the TOFU genesis-hash pin plus device-secret-gated membership; see docs/fleet-identity-remediation.md.
    fn verify_identity_binding(&self) -> bool {
        self.identity_pubkey != [0u8; 32]
            && self.identity_sig.len() == 64
            && verify_ed25519(&self.identity_pubkey, &self.signing_bytes(), &self.identity_sig)
    }

    /// Verify the ADD consent binding: `consent_sig` is the ADDED device's own signature over its binding request — the subject signing its own membership. Forging it requires the device's private key, which is what makes conscription (and the ownership squat) impossible.
    fn verify_consent(&self, subject: &crate::pq::KeyBundle, required: scheme::Mask) -> bool {
        let msg = bindreq_signing_bytes(&self.handle_proof, &self.device_pubkey, self.consent_t);
        crate::pq::verify_eggs(&self.consent, subject, &msg, required)
    }

    /// Verify the REMOVE consent binding: `consent_sig` is the LEAVING device's own signature over its departure request — the subject signing its own exit, countersigned by the approver's egg. The mirror of [`FleetOp::verify_consent`].
    fn verify_depart_consent(&self, subject: &crate::pq::KeyBundle, required: scheme::Mask) -> bool {
        let msg = departreq_signing_bytes(&self.handle_proof, &self.device_pubkey, self.consent_t);
        crate::pq::verify_eggs(&self.consent, subject, &msg, required)
    }

    /// Verify every signature egg against `signer_pubkey`.
    /// v1 understands Ed25519; an op carrying an egg whose scheme this build doesn't implement is REJECTED (fail-closed — never silently accept an unverifiable op, the no-fork rule).
    /// An empty egg list is invalid.
    /// `bundle` holds the signer's public keys, one per scheme. An egg for a scheme the bundle lacks — or one this build cannot verify — fails closed. The Ed25519 entry is always checked against `signer_pubkey` itself, never the bundle, so the chain's own naming of the device is what anchors everything else.
    pub fn verify_sigs(&self, bundle: &crate::pq::KeyBundle) -> bool {
        if self.sigs.is_empty() {
            return false;
        }
        let msg = self.signing_bytes();
        for egg in &self.sigs {
            let ok = match egg.scheme {
                scheme::ED25519 => verify_ed25519(&self.signer_pubkey, &msg, &egg.sig),
                other => match bundle.pubkey(other) {
                    Some(pk) => crate::pq::verify_egg(other, pk, &msg, &egg.sig),
                    None => false,
                },
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

/// Pure Ed25519 verify.
fn verify_ed25519(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(&sig_arr)).is_ok()
}

/// Why a blob failed to fold. Surfaced so the UI/logs can say *what* was wrong, not just "invalid".
#[derive(Debug, PartialEq)]
pub enum FoldError {
    Empty,
    NotGenesisFirst,
    GenesisNotSelfSigned,
    /// Genesis lacks a valid identity-key co-signature (not founded by the handle owner).
    BadIdentityBinding,
    /// A non-genesis op carries identity-binding fields it has no business carrying.
    StrayIdentityBinding { index: usize },
    /// An Add lacks a valid consent signature from the device being added (conscription attempt, or a forged/absent binding-request signature).
    BadConsent { index: usize },
    /// An Add's consent stamp sits outside [`CONSENT_WINDOW_OSC`] of the op — a replayed ancient consent.
    ConsentStale { index: usize },
    /// A non-Add op carries consent fields it has no business carrying.
    StrayConsent { index: usize },
    /// A non-Checkpoint op carries checkpoint fields it has no business carrying.
    StrayCheckpoint { index: usize },
    /// A Checkpoint with `k == 0` or an all-zero commit — structurally void.
    CheckpointMalformed { index: usize },
    /// A Checkpoint whose `k` is not exactly the previous checkpoint's `k + 1` (first is 1) — a skipped or replayed epoch index.
    CheckpointOutOfSequence { index: usize },
    /// Bundle fields on an op kind that never carries them — only Add and Declare do.
    StrayBundle { index: usize },
    /// A declared scheme mask that is internally impossible: missing Ed25519 (every device has it), naming a scheme this build cannot verify, or claiming schemes with no commitment to the keys behind them.
    BadBundle { index: usize },
    /// A Declare signed by somebody other than its subject. A device may raise its OWN capability and nobody else's.
    DeclareNotSelfSigned { index: usize },
    /// A Declare that drops a scheme the device had already proved. Capability is monotonic per device, or renouncing would be a way to lower the fleet floor without adding anyone.
    CapabilityRegression { index: usize },
    /// An Add whose device cannot sign with everything the fleet already requires. THE RATCHET: admitting it would lower the floor, so it does not fold at all.
    BelowFloor { index: usize },
    /// A Declare whose eggs do not cover every scheme in its own bundle. Declaring a key you cannot sign with would let a device raise the floor on paper only; possession is proved on the spot or the op does not fold.
    DeclareUnproven { index: usize },
    /// An op signed with fewer schemes than the fleet floor demanded at that point in the chain. The floor is the required set, read from the chain itself — it cannot be stripped from the payload.
    InsufficientEggs { index: usize },
    /// A bundle whose Ed25519 entry is not the op's `device_pubkey`. The bundle must belong to the device the chain already names.
    BundleMismatch { index: usize },
    /// A Remove signed by anyone but the departing device itself — expulsion doesn't exist (self-signed departure only).
    RemoveNotSelfSigned { index: usize },
    /// A consented Remove whose approver egg is the leaving device's own — the countersignature must come from a DIFFERENT surviving member (two devices, two signatures).
    RemoveApproverIsLeaver { index: usize },
    /// An op carries a different `handle_proof` than the genesis — a spliced/transplanted chain.
    InconsistentHandleProof { index: usize },
    BrokenChain { index: usize },
    BadSignature { index: usize },
    SignerNotMember { index: usize },
    AddExistingMember { index: usize },
    RemoveNonMember { index: usize },
}

/// The fleet membership blob: the ordered op chain.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MembershipBlob {
    pub ops: Vec<FleetOp>,
}

impl MembershipBlob {
    /// The GENERATION ID: the genesis op's chain-hash — a blake3 over the signed genesis content INCLUDING its signatures and eagle time, so it is unique per claim and unforgeable by a later claimant of the same (freed) handle. Friends pin this at first-met; a chain whose genesis hash differs from the pin is a SUCCESSOR holding a re-claimed name — a stranger — never the pinned identity. `None` only on an empty blob. (Callers wanting a VERIFIED generation id fold first; this accessor is cheap and does no validation itself.)
    pub fn genesis_hash(&self) -> Option<[u8; 32]> {
        self.ops.first().map(|op| op.chain_hash())
    }

    /// Fold the chain to the CURRENT member set, validating every rule along the way.
    /// This is the heart of the design and the part FGTW must mirror exactly: each op must (1) link to the prior op by hash, (2) carry valid signature(s), and (3) be signed by a device that was a member *before* this op (genesis excepted — it's self-signed into an empty set).
    /// Returns the live device pubkeys in insertion order, or the first rule it violated.
    pub fn fold(&self) -> Result<Vec<[u8; 32]>, FoldError> {
        self.fold_inner().map(|(members, _, _)| members)
    }

    /// The single chain walk behind [`fold`](MembershipBlob::fold) and [`scheme_floor`](MembershipBlob::scheme_floor) — one traversal, both answers, so the two can never disagree about the same chain.
    fn fold_inner(&self) -> Result<(Vec<[u8; 32]>, scheme::Mask, Vec<([u8; 32], crate::pq::KeyBundle)>), FoldError> {
        if self.ops.is_empty() {
            return Err(FoldError::Empty);
        }
        let mut members: Vec<[u8; 32]> = Vec::new();
        // What each member has declared it can sign with — the full public bundle, so later ops by that device can be verified against it. Absent = Ed25519 alone: no special "undeclared" state, because every device genuinely holds an Ed25519 key.
        let mut bundles: Vec<([u8; 32], crate::pq::KeyBundle)> = Vec::new();
        // The fleet's capability floor, RATCHETED. It only ever rises, so a device joining with less cannot drag the fleet back to single-egg — that op simply does not fold.
        let mut floor: scheme::Mask = scheme::MASK_BASE;
        let mut expected_prev = [0u8; 32];
        let mut last_ckpt_k = 0u64;
        let identity = self.ops[0].handle_proof;

        for (i, op) in self.ops.iter().enumerate() {
            if op.handle_proof != identity {
                return Err(FoldError::InconsistentHandleProof { index: i });
            }
            if op.prev_hash != expected_prev {
                return Err(FoldError::BrokenChain { index: i });
            }
            // Structural checks before the sig check: only genesis carries an identity binding, only Add carries consent, only Checkpoint carries the epoch triple (all are in signing_bytes, so a stray one would otherwise surface as a confusing BadSignature).
            if op.kind != OpKind::Genesis && (op.identity_pubkey != [0u8; 32] || !op.identity_sig.is_empty()) {
                return Err(FoldError::StrayIdentityBinding { index: i });
            }
            // Consent rides Add (join request) AND Remove (departure request) — the two bilateral membership ops. Genesis/Checkpoint never carry it; a Remove carries BOTH halves or NEITHER (a lone stamp or lone sig is malformed).
            if !matches!(op.kind, OpKind::Add | OpKind::Remove)
                && (op.consent_t != 0 || !op.consent.is_empty())
            {
                return Err(FoldError::StrayConsent { index: i });
            }
            if op.kind == OpKind::Remove && (op.consent_t != 0) != (!op.consent.is_empty()) {
                return Err(FoldError::StrayConsent { index: i });
            }
            if op.kind != OpKind::Checkpoint && (op.ckpt_k != 0 || op.ckpt_commit != [0u8; 32] || op.ckpt_fanout_epoch != 0) {
                return Err(FoldError::StrayCheckpoint { index: i });
            }
            if !matches!(op.kind, OpKind::Add | OpKind::Declare) && op.bundle.is_some() {
                return Err(FoldError::StrayBundle { index: i });
            }
            // A carried bundle must belong to the op's subject: its Ed25519 entry IS the device key the chain names. (Well-formedness — known schemes, right lengths, Ed25519 present — was enforced at parse by `KeyBundle::from_bytes`.)
            if let Some(b) = &op.bundle {
                if b.ed25519() != op.device_pubkey {
                    return Err(FoldError::BundleMismatch { index: i });
                }
            }
            // THE FLOOR AS THE REQUIRED SET. Before checking any signature, the op must CARRY every scheme the fleet had reached by the previous op. Read off the chain the verifier is already folding, so unlike a version pin in the payload it cannot be stripped — dropping the Falcon egg from a post-promotion op leaves it short, and it does not fold.
            if !scheme::covers(crate::pq::egg_mask(&op.sigs), floor) {
                return Err(FoldError::InsufficientEggs { index: i });
            }
            // Which public keys verify this op's eggs: a Declare is verified against the bundle it carries (self-certifying, anchored by the Ed25519 egg under the device key the chain already knows); every other op against what its signer last declared, or Ed25519 alone if nothing.
            let verify_with: crate::pq::KeyBundle = match (op.kind, &op.bundle) {
                (OpKind::Declare, Some(b)) => b.clone(),
                _ => bundles
                    .iter()
                    .find(|(d, _)| *d == op.signer_pubkey)
                    .map(|(_, b)| b.clone())
                    .unwrap_or_else(|| crate::pq::KeyBundle::ed25519_only(&op.signer_pubkey)),
            };
            if !op.verify_sigs(&verify_with) {
                return Err(FoldError::BadSignature { index: i });
            }
            match op.kind {
                OpKind::Genesis => {
                    if i != 0 || !members.is_empty() {
                        return Err(FoldError::NotGenesisFirst);
                    }
                    if op.signer_pubkey != op.device_pubkey {
                        return Err(FoldError::GenesisNotSelfSigned);
                    }
                    // Genesis must carry an identity_pubkey (both v1 and v2 set it — the bindreq anti-spam gate keys off it).
                    if op.identity_pubkey == [0u8; 32] {
                        return Err(FoldError::BadIdentityBinding);
                    }
                    // v1 genesis carries the identity self-cosignature; verify it WHEN PRESENT. v2 genesis (docs/identity-succession.md) omits it (empty identity_sig) and is accepted — the binding only ever proved handle-string knowledge, never ownership (docs/fleet-identity-remediation.md). A non-empty but INVALID sig stays a hard reject (a corrupt v1 op).
                    if !op.identity_sig.is_empty() && !op.verify_identity_binding() {
                        return Err(FoldError::BadIdentityBinding);
                    }
                    members.push(op.device_pubkey);
                }
                OpKind::Declare => {
                    // Self-declaration only: a device may raise what IT can sign with, never what another device claims.
                    if op.signer_pubkey != op.device_pubkey {
                        return Err(FoldError::DeclareNotSelfSigned { index: i });
                    }
                    if !members.contains(&op.device_pubkey) {
                        return Err(FoldError::SignerNotMember { index: i });
                    }
                    let Some(bundle) = &op.bundle else {
                        return Err(FoldError::BadBundle { index: i });
                    };
                    // Possession, proved on the spot: the Declare is signed with EVERY scheme it declares, so a bundle can never raise the floor on the strength of a key nobody has shown they hold.
                    if !scheme::covers(crate::pq::egg_mask(&op.sigs), bundle.mask()) {
                        return Err(FoldError::DeclareUnproven { index: i });
                    }
                    // Capability is monotonic per device too — a device cannot quietly renounce a scheme it already proved, which would otherwise be the way to drag the floor down without adding anybody.
                    if let Some(slot) = bundles.iter_mut().find(|(d, _)| *d == op.device_pubkey) {
                        if !scheme::covers(bundle.mask(), slot.1.mask()) {
                            return Err(FoldError::CapabilityRegression { index: i });
                        }
                        slot.1 = bundle.clone();
                    } else {
                        bundles.push((op.device_pubkey, bundle.clone()));
                    }
                }
                OpKind::Add => {
                    if !members.contains(&op.signer_pubkey) {
                        return Err(FoldError::SignerNotMember { index: i });
                    }
                    if members.contains(&op.device_pubkey) {
                        return Err(FoldError::AddExistingMember { index: i });
                    }
                    // THE RATCHET. A device joining below the fleet's established floor would lower it, so it is refused outright rather than admitted and tolerated. This is what stops a single-egg device silently undoing a completed upgrade.
                    let joined = op.bundle.clone().unwrap_or_else(|| crate::pq::KeyBundle::ed25519_only(&op.device_pubkey));
                    if !scheme::covers(joined.mask(), floor) {
                        return Err(FoldError::BelowFloor { index: i });
                    }
                    // Bilateral, and the joiner's proof of possession: the added device consented with its OWN keys — every scheme in the bundle it is being added with, plus whatever the floor demands. The Add op itself is the sponsor's signature, so this consent is the only place the joiner signs, which makes it the only place its declared PQ keys can be proved. A bundle nobody can sign for never enters the chain.
                    if !op.verify_consent(&joined, joined.mask() | floor) {
                        return Err(FoldError::BadConsent { index: i });
                    }
                    // The consent must be from THIS ceremony, not a departed device's replayed past.
                    if (op.eagle_time - op.consent_t).abs() > CONSENT_WINDOW_OSC {
                        return Err(FoldError::ConsentStale { index: i });
                    }
                    members.push(op.device_pubkey);
                    bundles.push((op.device_pubkey, joined));
                }
                OpKind::Remove => {
                    if !members.contains(&op.signer_pubkey) {
                        return Err(FoldError::SignerNotMember { index: i });
                    }
                    if op.consent.is_empty() {
                        // LEGACY self-signed departure (pre-consent chains keep folding). New bare departures are refused at the worker's publish gate — a unilateral sign-out lets a device thief launder the hardware into their own fleet.
                        if op.signer_pubkey != op.device_pubkey {
                            return Err(FoldError::RemoveNotSelfSigned { index: i });
                        }
                    } else {
                        // CONSENTED removal — the mirror of Add: the leaving device signed its departure request with its own eggs (at least the floor's schemes, against the bundle it declared), a DIFFERENT surviving member's egg authorises it. Expulsion still doesn't exist: without the leaving device's request signature the op can't fold.
                        if op.signer_pubkey == op.device_pubkey {
                            return Err(FoldError::RemoveApproverIsLeaver { index: i });
                        }
                        let leaver = bundles
                            .iter()
                            .find(|(d, _)| *d == op.device_pubkey)
                            .map(|(_, b)| b.clone())
                            .unwrap_or_else(|| crate::pq::KeyBundle::ed25519_only(&op.device_pubkey));
                        if !op.verify_depart_consent(&leaver, floor) {
                            return Err(FoldError::BadConsent { index: i });
                        }
                        if (op.eagle_time - op.consent_t).abs() > CONSENT_WINDOW_OSC {
                            return Err(FoldError::ConsentStale { index: i });
                        }
                    }
                    let before = members.len();
                    members.retain(|m| m != &op.device_pubkey);
                    if members.len() == before {
                        return Err(FoldError::RemoveNonMember { index: i });
                    }
                }
                OpKind::Checkpoint => {
                    // Membership is untouched; the op only pins the epoch spine, so the gates are: a current member signed it, the fields are non-void, and k advances by exactly one.
                    if !members.contains(&op.signer_pubkey) {
                        return Err(FoldError::SignerNotMember { index: i });
                    }
                    if op.ckpt_k == 0 || op.ckpt_commit == [0u8; 32] || op.device_pubkey != op.signer_pubkey {
                        return Err(FoldError::CheckpointMalformed { index: i });
                    }
                    if op.ckpt_k != last_ckpt_k + 1 {
                        return Err(FoldError::CheckpointOutOfSequence { index: i });
                    }
                    last_ckpt_k = op.ckpt_k;
                }
            }
            // Recompute the floor from the CURRENT membership after every op, then ratchet: the AND across members is what the whole fleet can do, and `max` with the running value is what stops a departure or a fresh fold from lowering it.
            let live = members
                .iter()
                .map(|m| bundles.iter().find(|(d, _)| d == m).map(|(_, b)| b.mask()).unwrap_or(scheme::MASK_BASE))
                .fold(scheme::MASK_ALL, |a, b| a & b);
            floor |= live;
            expected_prev = op.chain_hash();
        }
        Ok((members, floor, bundles))
    }

    /// The public-key bundle the chain holds for `device` — what any consent, vouch or handshake from that device is verified against. `None` if it has never declared, which means Ed25519 alone (the device key the chain already names).
    pub fn declared_bundle(&self, device: &[u8; 32]) -> Option<crate::pq::KeyBundle> {
        self.fold_inner()
            .ok()
            .and_then(|(_, _, bundles)| bundles.into_iter().find(|(d, _)| d == device).map(|(_, b)| b))
    }

    /// Which schemes the chain knows `device` can sign with — its declared bundle's mask, or Ed25519 alone if it has never declared. What a builder signs the device's next op under. Falls back to Ed25519 on a chain that does not fold, which then fails at the fold anyway.
    pub fn declared_mask(&self, device: &[u8; 32]) -> scheme::Mask {
        self.fold_inner()
            .ok()
            .and_then(|(_, _, bundles)| bundles.into_iter().find(|(d, _)| d == device).map(|(_, b)| b.mask()))
            .unwrap_or(scheme::MASK_BASE)
    }

    /// The fleet's signature-capability FLOOR: the schemes every current member has proved it can sign with.
    ///
    /// Derived, never stored. Two devices reaching the same conclusion at the same moment is not a race, a truncated chain cannot understate it any more than it can understate membership (the same tip monotonicity guards both), and there is no flag to forge — lifting the floor means producing a [`OpKind::Declare`] op, which needs the device key.
    ///
    /// This is the automatic promotion: when the LAST member declares a scheme, the AND across members gains that bit and the whole fleet is at the higher floor with nothing published to announce it. Ratcheted inside [`MembershipBlob::fold`], so it never falls.
    pub fn scheme_floor(&self) -> Result<scheme::Mask, FoldError> {
        self.fold_full().map(|(_, floor)| floor)
    }

    /// [`MembershipBlob::fold`] plus the ratcheted [`scheme_floor`](MembershipBlob::scheme_floor), for callers that want both without folding twice.
    pub fn fold_full(&self) -> Result<(Vec<[u8; 32]>, scheme::Mask), FoldError> {
        self.fold_inner().map(|(members, floor, _)| (members, floor))
    }

    /// Fold to the current member set AND return the tip op's eagle time (the timestamp of the last applied op). `(members, tip_et)`. The freshness signal a consumer uses to never regress to a stale (pre-removal) view of someone's membership: a fold with an older tip than one already adopted is ignored. `tip_et` is 0 only for the impossible empty-but-Ok case (fold errors on empty).
    pub fn fold_with_ts(&self) -> Result<(Vec<[u8; 32]>, i64), FoldError> {
        let members = self.fold()?;
        let tip = self.ops.last().map(|op| op.eagle_time).unwrap_or(0);
        Ok((members, tip))
    }

    /// Convenience: is `device_pubkey` a current member? (`fold` + membership test.)
    pub fn is_member(&self, device_pubkey: &[u8; 32]) -> bool {
        self.fold().map(|m| m.contains(device_pubkey)).unwrap_or(false)
    }

    /// The hash the NEXT op must reference as `prev_hash` (the tail link, or `[0;32]` if empty).
    pub fn head(&self) -> [u8; 32] {
        self.ops.last().map(|op| op.chain_hash()).unwrap_or([0u8; 32])
    }

    /// The identity this chain belongs to (the genesis op's handle_proof), or `None` if empty.
    pub fn handle_proof(&self) -> Option<[u8; 32]> {
        self.ops.first().map(|op| op.handle_proof)
    }

    /// Is `prior` an exact prefix of this chain? FGTW uses this to accept only forward extensions of the stored chain (optimistic concurrency: a writer who appended to a stale head fails this and re-fetches).
    pub fn extends(&self, prior: &MembershipBlob) -> bool {
        prior.ops.len() <= self.ops.len() && self.ops[..prior.ops.len()] == prior.ops[..]
    }

    /// Does the genesis identity key equal `Ed25519(identity_seed)`, the canonical key derived from the handle?
    /// NOTE: since `identity_seed = BLAKE3(handle)` is public, a squatter who knows the handle uses the SAME canonical key and passes this too — so it is NOT proof against a squatted fleet, only a check that the founder used the canonical derivation (a weak integrity signal). Retained as a utility; production trust decisions use `genesis_handle_proof` + the TOFU genesis-hash pin instead. See docs/fleet-identity-remediation.md.
    pub fn genesis_identity_matches(&self, identity_seed: &[u8; 32]) -> bool {
        let expect = ed25519_dalek::SigningKey::from_bytes(identity_seed).verifying_key().to_bytes();
        self.ops.first().map(|op| op.identity_pubkey == expect).unwrap_or(false)
    }

    /// The genesis identity pubkey (the key `identity_sig`s verify under) — what the worker checks a binding request's identity co-signature against.
    pub fn genesis_identity_pubkey(&self) -> Option<[u8; 32]> {
        self.ops.first().map(|op| op.identity_pubkey)
    }

    /// The genesis op's `handle_proof` — the slot this chain claims. A caller that fetched by a known `handle_proof` compares against this to reject a relay that swapped in a structurally-valid chain from a DIFFERENT slot (the probe-time TOCTOU). `handle_proof` is public (it IS the slot key), so this is a slot-consistency check, NOT an ownership proof.
    pub fn genesis_handle_proof(&self) -> Option<[u8; 32]> {
        self.ops.first().map(|op| op.handle_proof)
    }

    // ── builders (sign with the local device key; the device is the only thing that can authorise) ──

    /// Start a brand-new fleet: the founding device self-signs itself in, bound to `handle_proof`, and the identity key `Ed25519(identity_seed)` co-signs. NOTE: `identity_seed = BLAKE3(handle)` is public, so the co-signature proves only knowledge of the handle string, NOT ownership (see docs/fleet-identity-remediation.md); it is retained for wire compatibility. The real binding is the device self-signature over `handle_proof`, and founding already requires producing the memory-hard `handle_proof`. Genesis needs no separate consent: the founding device is both the subject and the sole authoriser.
    pub fn genesis(
        device_key: &impl crate::pq::FleetSigner,
        handle_proof: [u8; 32],
        identity_seed: &[u8; 32],
        eagle_time: i64,
    ) -> Self {
        let sign_with: scheme::Mask = scheme::MASK_BASE;
        let pk = device_key.keypair().public.to_bytes();
        let identity_key = ed25519_dalek::SigningKey::from_bytes(identity_seed);
        let op = sign_op(
            device_key,
            handle_proof,
            [0u8; 32],
            OpKind::Genesis,
            pk,
            eagle_time,
            pk,
            identity_key.verifying_key().to_bytes(),
            Some(&identity_key),
            None,
            None,
            None,
            sign_with,
        );
        MembershipBlob { ops: vec![op] }
    }

    /// Add `new_device` carrying its public key bundle — the join a promoted fleet requires, since `add` (no bundle) is refused as `BelowFloor` once the floor has risen. The `consent` must be signed with every scheme in `bundle`: that is the joiner proving it holds the keys the sponsor is adding it with.
    pub fn add_declared(&mut self, device_key: &impl crate::pq::FleetSigner, new_device: [u8; 32], eagle_time: i64, consent_t: i64, consent: Vec<Egg>, bundle: crate::pq::KeyBundle) {
        let sign_with: scheme::Mask = self.declared_mask(&device_key.keypair().public.to_bytes());
        let hp = self.handle_proof().unwrap_or([0u8; 32]);
        let op = sign_op(
            device_key,
            hp,
            self.head(),
            OpKind::Add,
            new_device,
            eagle_time,
            device_key.keypair().public.to_bytes(),
            [0u8; 32],
            None,
            Some((consent_t, consent)),
            None,
            Some(bundle),
            sign_with,
        );
        self.ops.push(op);
    }

    /// A member publishes its own key bundle, raising what it can sign with.
    ///
    /// Self-signed by construction: `sign_op` is handed the declaring device's key as both signer and subject, so a device can only ever raise its OWN capability. When the last member declares a scheme, [`scheme_floor`](MembershipBlob::scheme_floor) gains that bit on its own — that is the whole promotion, with nothing published to announce it.
    pub fn declare(&mut self, device_key: &impl crate::pq::FleetSigner, eagle_time: i64) {
        let hp = self.ops[0].handle_proof;
        let pk = device_key.keypair().public.to_bytes();
        // A signer with nothing beyond Ed25519 declares the Ed25519-only bundle — legal, and a no-op for the floor.
        let bundle = device_key.bundle().unwrap_or_else(|| crate::pq::KeyBundle::ed25519_only(&pk));
        let sign_with: scheme::Mask = bundle.mask();
        let op = sign_op(
            device_key,
            hp,
            self.head(),
            OpKind::Declare,
            pk,
            eagle_time,
            pk,
            [0u8; 32],
            None,
            None,
            None,
            Some(bundle),
            sign_with,
        );
        self.ops.push(op);
    }

    /// Start a brand-new **v2** fleet (docs/identity-succession.md): identical to [`genesis`] except the genesis carries NO `identity_sig` — only the `identity_pubkey` the bindreq anti-spam gate keys off. The inert self-cosignature (which proved only handle-string knowledge, never ownership — docs/fleet-identity-remediation.md) is gone from the wire. `signing_bytes` is unchanged (the device egg still commits to `identity_pubkey`), and `chain_hash` naturally excludes the now-empty `identity_sig` (blake3 over zero bytes is a no-op), so a v2 genesis links exactly like a v1 one minus that field. `fold` accepts it. This is what new fleets found under.
    pub fn genesis_v2(
        device_key: &impl crate::pq::FleetSigner,
        handle_proof: [u8; 32],
        identity_seed: &[u8; 32],
        eagle_time: i64,
    ) -> Self {
        let sign_with: scheme::Mask = scheme::MASK_BASE;
        let pk = device_key.keypair().public.to_bytes();
        let identity_pubkey =
            ed25519_dalek::SigningKey::from_bytes(identity_seed).verifying_key().to_bytes();
        let op = sign_op(
            device_key,
            handle_proof,
            [0u8; 32],
            OpKind::Genesis,
            pk,
            eagle_time,
            pk,
            identity_pubkey,
            None, // v2: embed the pubkey, do NOT sign the inert identity_sig
            None,
            None,
            None,
            sign_with,
        );
        MembershipBlob { ops: vec![op] }
    }

    /// Append an Add: the sponsor `device_key` (a current member) signs, carrying the added device's consent — `(consent_t, consent_sig)` straight off its binding request. Without valid consent the result won't fold.
    pub fn add(&mut self, device_key: &impl crate::pq::FleetSigner, new_device: [u8; 32], eagle_time: i64, consent_t: i64, consent: Vec<Egg>) {
        let sign_with: scheme::Mask = self.declared_mask(&device_key.keypair().public.to_bytes());
        let hp = self.handle_proof().unwrap_or([0u8; 32]);
        let op = sign_op(
            device_key,
            hp,
            self.head(),
            OpKind::Add,
            new_device,
            eagle_time,
            device_key.keypair().public.to_bytes(),
            [0u8; 32],
            None,
            Some((consent_t, consent)),
            None,
            None,
            sign_with,
        );
        self.ops.push(op);
    }

    /// Append this device's own departure — the ONLY remove the fold accepts (`signer == device`). Expelling another device is not a chain verb; eviction is withholding at the key layer.
    pub fn depart(&mut self, device_key: &impl crate::pq::FleetSigner, eagle_time: i64) {
        let sign_with: scheme::Mask = self.declared_mask(&device_key.keypair().public.to_bytes());
        let hp = self.handle_proof().unwrap_or([0u8; 32]);
        let pk = device_key.keypair().public.to_bytes();
        let op = sign_op(
            device_key,
            hp,
            self.head(),
            OpKind::Remove,
            pk,
            eagle_time,
            pk,
            [0u8; 32],
            None,
            None,
            None,
            None,
            sign_with,
        );
        self.ops.push(op);
    }

    /// Append a CONSENTED removal: the approver `device_key` (a surviving member, never the leaver) signs, carrying the leaving device's departure-request signature — `(consent_t, consent_sig)` over [`departreq_signing_bytes`]. The exact mirror of [`MembershipBlob::add`]. Without valid consent the result won't fold; with `approver == leaving` it won't fold either.
    pub fn remove_consented(&mut self, approver_key: &impl crate::pq::FleetSigner, leaving: [u8; 32], eagle_time: i64, consent_t: i64, consent: Vec<Egg>) {
        let sign_with: scheme::Mask = self.declared_mask(&approver_key.keypair().public.to_bytes());
        let hp = self.handle_proof().unwrap_or([0u8; 32]);
        let op = sign_op(
            approver_key,
            hp,
            self.head(),
            OpKind::Remove,
            leaving,
            eagle_time,
            approver_key.keypair().public.to_bytes(),
            [0u8; 32],
            None,
            Some((consent_t, consent)),
            None,
            None,
            sign_with,
        );
        self.ops.push(op);
    }

    /// Append a Checkpoint: any current member pins epoch `k` with the settled-root commitment and the fan-out epoch it folds. Single winner per k by the same `extends()` forward-only discipline every append rides — a loser's push fails the extension check and it re-derives against the winner.
    pub fn checkpoint(&mut self, device_key: &impl crate::pq::FleetSigner, eagle_time: i64, k: u64, commit: [u8; 32], fanout_epoch: u64) {
        let sign_with: scheme::Mask = self.declared_mask(&device_key.keypair().public.to_bytes());
        let hp = self.handle_proof().unwrap_or([0u8; 32]);
        let pk = device_key.keypair().public.to_bytes();
        let op = sign_op(
            device_key,
            hp,
            self.head(),
            OpKind::Checkpoint,
            pk,
            eagle_time,
            pk,
            [0u8; 32],
            None,
            None,
            Some((k, commit, fanout_epoch)),
            None,
            sign_with,
        );
        self.ops.push(op);
    }

    /// The newest checkpoint's `(k, commit, fanout_epoch)`, or `None` if the chain has no checkpoint yet. Does no validation itself — callers fold first, which enforces sequencing and signatures.
    pub fn latest_checkpoint(&self) -> Option<(u64, [u8; 32], u64)> {
        self.ops.iter().rev().find(|op| op.kind == OpKind::Checkpoint).map(|op| (op.ckpt_k, op.ckpt_commit, op.ckpt_fanout_epoch))
    }

    // ── VSF wire form: section "fleet" with one repeated "op" multi-value field per op (same shape as PhonebookResponse's "peer" fields, so the FGTW worker mirrors the parse with the existing pattern).
    //    Positional op layout: hP(handle_proof) hb(prev) u(kind) ke(device) e6(time) ke(signer), then GENESIS-ONLY ke(identity_pubkey) ge(identity_sig), then ADD-ONLY e6(consent_t) ge(consent_sig), then CHECKPOINT-ONLY u(k) hb(commit) u(fanout_epoch), then (u scheme, ge sig) egg pairs to the end.
    //    The identity/consent/checkpoint groups are gated by kind (known at value index 2) and mutually exclusive, so no op carries waste and the egg tail stays unambiguous. Appending a PQ egg = two more trailing values; nothing before them moves. ──

    /// Encode to a complete VSF file (header + provenance + the "fleet" section). Network/disk transport.
    pub fn to_vsf_bytes(&self) -> Result<Vec<u8>, String> {
        let mut section = vsf::VsfSection::new("fleet");
        for op in &self.ops {
            section.add_field_multi("op", op_field_values(op));
        }
        // Default build carries hp + hb — a provenance-only doc is unverifiable under read_verified, and from_vsf_bytes below refuses to parse one.
        vsf::VsfBuilder::new()
            .creation_time_oscillations(vsf::eagle_time_oscillations())
            .add_section_direct(section)
            .build()
            .map_err(|e| format!("fleet to_vsf: {e}"))
    }

    /// Parse from a complete VSF file.
    /// The document must verify (hp + hb | signature) before any op is read; op-level signatures are then validated by [`fold`].
    /// A malformed op aborts the whole parse (the chain is only meaningful intact); returns the blob for [`fold`] to then validate cryptographically.
    pub fn from_vsf_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (header, header_end) = vsf::verification::read_verified(bytes, None)
            .map_err(|e| format!("fleet chain verification: {e}"))?;
        // primary_section: name resolution + header-only tolerance live in the vsf crate (an empty chain would encode header-only; fold still rejects it as Empty).
        let section = header
            .primary_section(bytes, header_end)
            .map_err(|e| format!("fleet section: {e}"))?;

        let mut ops = Vec::new();
        for field in section.get_fields("op") {
            ops.push(parse_op(&field.values)?);
        }
        Ok(MembershipBlob { ops })
    }
}

// ───────────────────────────── Identity succession ─────────────────────────────
// docs/identity-succession.md. A re-founded identity proves continuity with its predecessor so a contact who pinned the OLD genesis auto-migrates the pin — no delete-and-re-add. The trust anchor is a DEVICE KEY of the old chain (a fingerprint-oracle secret, never handle-derived), so it is unforgeable by anyone who merely knows the (public) handle.

/// Domain tag so a continuity signature can never be confused with a fleet-op or bindreq signature.
pub const SUCCESSION_DOMAIN: &[u8] = b"PHOTON_SUCCESSION_v1";

/// The exact bytes a continuity egg signs: "the chain at `handle_proof` moves from `old_genesis_hash`
/// to `new_genesis_hash`". `handle_proof` is stable across a re-found (same handle → same proof).
pub fn succession_signing_bytes(
    handle_proof: &[u8; 32],
    old_genesis_hash: &[u8; 32],
    new_genesis_hash: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(SUCCESSION_DOMAIN.len() + 96);
    v.extend_from_slice(SUCCESSION_DOMAIN);
    v.extend_from_slice(handle_proof);
    v.extend_from_slice(old_genesis_hash);
    v.extend_from_slice(new_genesis_hash);
    v
}

/// One re-founding device's signature vouching for the successor. `device_pubkey` must be a member of the PREDECESSOR chain — that is what the verifier checks it against.
#[derive(Clone, Debug, PartialEq)]
pub struct ContinuityEgg {
    pub device_pubkey: [u8; 32],
    pub scheme: u8,
    pub sig: Vec<u8>,
}

/// A self-contained proof that the new chain (`new_genesis_hash`) succeeds the embedded `predecessor`,
/// vouched by one or more predecessor-member devices. Published once per re-found; a contact holding the predecessor's genesis-hash pin verifies it and migrates the pin. See docs/identity-succession.md.
#[derive(Clone, Debug, PartialEq)]
pub struct SuccessorRecord {
    pub handle_proof: [u8; 32],
    pub new_genesis_hash: [u8; 32],
    pub predecessor: MembershipBlob,
    pub continuity_eggs: Vec<ContinuityEgg>,
}

impl SuccessorRecord {
    /// Build a successor: each device in `signers` (members of BOTH the old and new chains) signs a continuity egg over `(handle_proof, predecessor.genesis_hash, new_genesis_hash)`. Signing with every current device maximises the chance a contact matches one against the predecessor set.
    pub fn new<S: crate::pq::FleetSigner>(
        predecessor: MembershipBlob,
        new_genesis_hash: [u8; 32],
        handle_proof: [u8; 32],
        signers: &[&S],
    ) -> Result<Self, String> {
        let old_gh = predecessor.genesis_hash().ok_or("predecessor has no genesis")?;
        let msg = succession_signing_bytes(&handle_proof, &old_gh, &new_genesis_hash);
        // Each voucher signs with what the PREDECESSOR chain knows it holds — that is what a contact verifies against, and it is what makes a vouch as strong as the old fleet's floor rather than as weak as Ed25519 alone.
        let mut continuity_eggs = Vec::new();
        for s in signers {
            let pk = s.keypair().public.to_bytes();
            let mask = predecessor.declared_mask(&pk);
            for egg in s.eggs(&msg, mask) {
                continuity_eggs.push(ContinuityEgg { device_pubkey: pk, scheme: egg.scheme, sig: egg.sig });
            }
        }
        Ok(Self { handle_proof, new_genesis_hash, predecessor, continuity_eggs })
    }

    /// Contact-side verification. `pinned_genesis` is the genesis hash the contact currently trusts for this identity. On `Ok`, the caller migrates its pin to `new_genesis_hash` (adopting the new chain's fold, fetched separately, after confirming its genesis hash equals `new_genesis_hash`).
    ///
    /// Proves: (1) the predecessor folds, (2) it hashes to the CURRENT pin (monotonic — succeed only
    /// FROM where the contact is, so a replay can't walk them backward), (3) it is for this
    /// `handle_proof`, and (4) at least one continuity egg is signed by a PREDECESSOR MEMBER over the exact transition. (4) is load-bearing: only a holder of an old-chain device secret can produce it, so a handle-only attacker cannot forge a re-pin.
    pub fn verify_for_pin(&self, pinned_genesis: &[u8; 32]) -> Result<(), String> {
        let (pred_members, pred_floor, pred_bundles) = self
            .predecessor
            .fold_inner()
            .map_err(|e| format!("successor predecessor invalid: {e:?}"))?;
        let old_gh = self.predecessor.genesis_hash().ok_or("successor predecessor has no genesis")?;
        if &old_gh != pinned_genesis {
            return Err("successor predecessor does not match the pinned genesis".into());
        }
        if self.predecessor.genesis_handle_proof() != Some(self.handle_proof) {
            return Err("successor handle_proof does not match its predecessor".into());
        }
        let msg = succession_signing_bytes(&self.handle_proof, &old_gh, &self.new_genesis_hash);
        // An egg naming a scheme this build cannot verify is a hard reject, never a skip. Succession re-founds the identity; silently ignoring what cannot be checked is exactly the gap a forged vouch would walk through.
        if self.continuity_eggs.iter().any(|e| !scheme::covers(scheme::MASK_KNOWN, 1 << e.scheme.min(15))) {
            return Err("continuity egg names an unknown scheme".into());
        }
        // ANY predecessor member may vouch, but a device's vouch is ALL of its eggs: they verify against the bundle the old chain holds for it and cover the old fleet's floor. A single Ed25519 vouch from a fleet that had reached three schemes is not a vouch — it is what a curve break would let an attacker forge.
        let mut devices: Vec<[u8; 32]> = self.continuity_eggs.iter().map(|e| e.device_pubkey).collect();
        devices.sort();
        devices.dedup();
        let vouched = devices.iter().any(|d| {
            if !pred_members.contains(d) {
                return false;
            }
            let bundle = pred_bundles
                .iter()
                .find(|(p, _)| p == d)
                .map(|(_, b)| b.clone())
                .unwrap_or_else(|| crate::pq::KeyBundle::ed25519_only(d));
            let eggs: Vec<Egg> = self
                .continuity_eggs
                .iter()
                .filter(|e| e.device_pubkey == *d)
                .map(|e| Egg { scheme: e.scheme, sig: e.sig.clone() })
                .collect();
            crate::pq::verify_eggs(&eggs, &bundle, &msg, pred_floor)
        });
        if !vouched {
            return Err("no valid continuity vouch from a predecessor member at the predecessor's floor".into());
        }
        Ok(())
    }

    /// The "succession" section: `hp`, `new`, the predecessor's `op` fields verbatim (reusing the fleet op codec), and one `cegg` field `[ke device, u scheme, ge sig]` per egg. Exposed so the member-gated publish can wrap it in a device-signed envelope.
    pub fn to_section(&self) -> vsf::VsfSection {
        let mut section = vsf::VsfSection::new("succession");
        section.add_field("hp", VsfType::hP(self.handle_proof.to_vec()));
        section.add_field("new", VsfType::hb(self.new_genesis_hash.to_vec()));
        for op in &self.predecessor.ops {
            section.add_field_multi("op", op_field_values(op));
        }
        for egg in &self.continuity_eggs {
            section.add_field_multi(
                "cegg",
                vec![
                    VsfType::ke(egg.device_pubkey.to_vec()),
                    VsfType::u(egg.scheme as usize, false),
                    VsfType::ge(egg.sig.clone()),
                ],
            );
        }
        section
    }

    /// Encode to a complete (unsigned) VSF file — the form served from the succession slot and re-parsed by a contact.
    pub fn to_vsf_bytes(&self) -> Result<Vec<u8>, String> {
        vsf::VsfBuilder::new()
            .creation_time_oscillations(vsf::eagle_time_oscillations())
            .add_section_direct(self.to_section())
            .build()
            .map_err(|e| format!("succession to_vsf: {e}"))
    }

    /// Parse from a complete VSF file. Structural only — [`verify_for_pin`] does the cryptographic checks.
    pub fn from_vsf_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (header, header_end) = vsf::verification::read_verified(bytes, None)
            .map_err(|e| format!("succession verification: {e}"))?;
        let section = header
            .primary_section(bytes, header_end)
            .map_err(|e| format!("succession section: {e}"))?;
        let handle_proof = take_hp32(
            section.get_field("hp").and_then(|f| f.values.first()).ok_or("succession: missing hp")?,
            "hp",
        )?;
        let new_genesis_hash = take_hb32(
            section.get_field("new").and_then(|f| f.values.first()).ok_or("succession: missing new")?,
            "new",
        )?;
        let mut predecessor = MembershipBlob::default();
        for field in section.get_fields("op") {
            predecessor.ops.push(parse_op(&field.values)?);
        }
        let mut continuity_eggs = Vec::new();
        for field in section.get_fields("cegg") {
            let v = &field.values;
            let device_pubkey = take_ke32(v.first().ok_or("cegg: missing device")?, "cegg device")?;
            // Same fallback as the egg-tail scheme decode: the codec may round-trip a small `u` as a narrower type, so accept `u(_, false)` OR anything `u8::from_vsf_type` can read.
            let scheme = match v.get(1) {
                Some(VsfType::u(s, false)) => *s as u8,
                Some(other) => {
                    use vsf::schema::FromVsfType;
                    u8::from_vsf_type(other).map_err(|_| "cegg: bad scheme".to_string())?
                }
                None => return Err("cegg: missing scheme".into()),
            };
            let sig = match v.get(2) {
                Some(VsfType::ge(s)) => s.clone(),
                _ => return Err("cegg: bad sig".into()),
            };
            continuity_eggs.push(ContinuityEgg { device_pubkey, scheme, sig });
        }
        Ok(Self { handle_proof, new_genesis_hash, predecessor, continuity_eggs })
    }
}

/// Build + sign one op. Each enabled scheme contributes an egg over the op's signing bytes; v1 = Ed25519. `consent` = the added device's `(t, binding-request signature)`, Add only. `checkpoint` = `(k, commit, fanout_epoch)`, Checkpoint only.
#[allow(clippy::too_many_arguments)]
fn sign_op(
    signer: &impl crate::pq::FleetSigner,
    handle_proof: [u8; 32],
    prev_hash: [u8; 32],
    kind: OpKind,
    device_pubkey: [u8; 32],
    eagle_time: i64,
    signer_pubkey: [u8; 32],
    // GENESIS identity binding: `identity_pubkey` is the canonical `Ed25519(identity_seed)` embedded in the op (and in signing_bytes, so the device egg commits to it — the bindreq anti-spam gate keys off it). `identity_signer` is Some ONLY for a v1 genesis, where it also produces the `identity_sig` self-cosignature; a v2 genesis passes the pubkey with `None` (empty identity_sig, docs/identity-succession.md); non-genesis ops pass `[0;32]` + `None`.
    identity_pubkey: [u8; 32],
    identity_signer: Option<&ed25519_dalek::SigningKey>,
    consent: Option<(i64, Vec<Egg>)>,
    checkpoint: Option<(u64, [u8; 32], u64)>,
    // `bundle`: ADD / DECLARE carry the subject's public-key bundle. None everywhere else, and on an Add whose device has declared nothing yet.
    bundle: Option<crate::pq::KeyBundle>,
    // `sign_with`: which schemes to sign under — what the chain knows the signer holds (see `FleetSigner::eggs`). Builders derive it from the chain; a Declare uses its own bundle's mask.
    sign_with: scheme::Mask,
) -> FleetOp {
    use ed25519_dalek::Signer;
    let (consent_t, consent) = consent.unwrap_or((0, Vec::new()));
    let (ckpt_k, ckpt_commit, ckpt_fanout_epoch) = checkpoint.unwrap_or((0, [0u8; 32], 0));
    let mut op = FleetOp {
        // Newly minted ops are v2 — framed preimages, the shape multi-scheme eggs need. Existing ops keep whatever version they were written under.
        version: OpVersion::V2,
        bundle,
        handle_proof,
        prev_hash,
        kind,
        device_pubkey,
        eagle_time,
        signer_pubkey,
        identity_pubkey,
        identity_sig: Vec::new(),
        consent_t,
        consent,
        ckpt_k,
        ckpt_commit,
        ckpt_fanout_epoch,
        sigs: Vec::new(),
    };
    let msg = op.signing_bytes();
    op.sigs = signer.eggs(&msg, sign_with);
    if let Some(idk) = identity_signer {
        op.identity_sig = idk.sign(&msg).to_bytes().to_vec();
    }
    op
}

/// The consent as it rides the wire: a v1 op carries its single Ed25519 signature bare (so existing bytes are untouched); a v2 op carries the framed egg-list blob.
fn consent_to_wire(op: &FleetOp) -> Vec<u8> {
    match op.version {
        OpVersion::V1 => op.consent.first().map(|e| e.sig.clone()).unwrap_or_default(),
        OpVersion::V2 => crate::pq::eggs_to_bytes(&op.consent),
    }
}

/// Inverse of [`consent_to_wire`], keyed on the op's version.
fn consent_from_wire(version: OpVersion, bytes: &[u8]) -> Result<Vec<Egg>, String> {
    match version {
        OpVersion::V1 => Ok(vec![Egg { scheme: scheme::ED25519, sig: bytes.to_vec() }]),
        OpVersion::V2 => crate::pq::eggs_from_bytes(bytes).map_err(|e| format!("fleet op: consent {e}")),
    }
}

/// Encode one op to its positional "op" field values (the exact layout [`parse_op`] reads). Shared by the fleet chain codec and the succession record (which embeds a predecessor chain's ops verbatim).
fn op_field_values(op: &FleetOp) -> Vec<VsfType> {
    let mut values = Vec::new();
    // A v1 op begins with `hP(handle_proof)`; every later version begins with `u(version)`. The TYPE at position 0 is what tells them apart, so a v1 op's bytes stay exactly as they were written and its chain_hash — the generation id every friend pinned — never moves.
    if op.version != OpVersion::V1 {
        values.push(VsfType::u(op.version as usize, false));
    }
    values.extend([
        VsfType::hP(op.handle_proof.to_vec()),
        VsfType::hb(op.prev_hash.to_vec()),
        VsfType::u(op.kind as usize, false),
        VsfType::ke(op.device_pubkey.to_vec()),
        VsfType::e(vsf::types::EtType::e6(op.eagle_time)),
        VsfType::ke(op.signer_pubkey.to_vec()),
    ]);
    if op.kind == OpKind::Genesis {
        values.push(VsfType::ke(op.identity_pubkey.to_vec()));
        // v1 carries the identity self-cosignature; v2 (docs/identity-succession.md) OMITS it. The `ge` type stores `len-1`, so a zero-length value is unrepresentable — we don't emit it. The egg tail always begins with a `u` scheme (never a `ge`), so the parser discriminates the two layouts by type at this position.
        if !op.identity_sig.is_empty() {
            values.push(VsfType::ge(op.identity_sig.clone()));
        }
    }
    if op.kind == OpKind::Add {
        values.push(VsfType::e(vsf::types::EtType::e6(op.consent_t)));
        values.push(VsfType::ge(consent_to_wire(op)));
    }
    // Consented Remove appends the same (e6 t, ge sig) pair; legacy self-departure appends nothing. The parser discriminates by TYPE at position 6 (the egg tail always begins with a `u` scheme, never an `e`), same trick as the genesis v1/v2 split.
    if op.kind == OpKind::Remove && !op.consent.is_empty() {
        values.push(VsfType::e(vsf::types::EtType::e6(op.consent_t)));
        values.push(VsfType::ge(consent_to_wire(op)));
    }
    if op.kind == OpKind::Checkpoint {
        values.push(VsfType::u(op.ckpt_k as usize, false));
        values.push(VsfType::hb(op.ckpt_commit.to_vec()));
        values.push(VsfType::u(op.ckpt_fanout_epoch as usize, false));
    }
    // ADD / DECLARE: the key bundle as one opaque `ge`. It never appears at this position otherwise — the egg tail always starts with a `u` scheme — so type discriminates it, the same trick the genesis and consented-remove splits use. Omitted when there is no bundle, so an Add from an undeclared device encodes byte-identically to before.
    if let (OpKind::Add | OpKind::Declare, Some(bundle)) = (op.kind, &op.bundle) {
        values.push(VsfType::ge(bundle.to_bytes()));
    }
    for egg in &op.sigs {
        values.push(VsfType::u(egg.scheme as usize, false));
        values.push(VsfType::ge(egg.sig.clone()));
    }
    values
}

/// Decode one positional "op" field's values back into a [`FleetOp`].
fn parse_op(all: &[VsfType]) -> Result<FleetOp, String> {
    if all.is_empty() {
        return Err("fleet op: no values".into());
    }
    // Mirror of `op_field_values`: `hP` at position 0 means a v1 op written before the version field existed, anything else is the version itself. Defaulting to v1 rather than rejecting is what lets every chain already in the field keep folding.
    let (version, base) = match &all[0] {
        VsfType::hP(_) => (OpVersion::V1, 0usize),
        other => {
            use vsf::schema::FromVsfType;
            let v = u8::from_vsf_type(other).map_err(|_| "fleet op: bad version type".to_string())?;
            let ver = OpVersion::from_byte(v).ok_or_else(|| format!("fleet op: unknown version {v}"))?;
            (ver, 1usize)
        }
    };
    let values = &all[base..];
    if values.len() < 6 {
        return Err(format!("fleet op: need >=6 values, got {}", values.len()));
    }
    let handle_proof = take_hp32(&values[0], "hp")?;
    let prev_hash = take_hb32(&values[1], "prev")?;
    let kind = match &values[2] {
        VsfType::u(v, false) => OpKind::from_u8(*v as u8).ok_or_else(|| format!("bad kind {v}"))?,
        other => {
            use vsf::schema::FromVsfType;
            let v = u8::from_vsf_type(other).map_err(|_| "fleet op: bad kind type".to_string())?;
            OpKind::from_u8(v).ok_or_else(|| format!("bad kind {v}"))?
        }
    };
    let device_pubkey = take_ke32(&values[3], "device")?;
    let eagle_time = match &values[4] {
        VsfType::e(et) => et_to_osc(et),
        _ => return Err("fleet op: bad time".into()),
    };
    let signer_pubkey = take_ke32(&values[5], "signer")?;

    // GENESIS carries the identity binding (ke pubkey, ge sig), ADD carries the consent (e6 t, ge sig), CHECKPOINT carries the epoch triple (u k, hb commit, u fanout_epoch), each before the egg pairs; the groups are kind-gated and mutually exclusive.
    let mut i = 6;
    let mut identity_pubkey = [0u8; 32];
    let mut identity_sig = Vec::new();
    let mut consent_t = 0i64;
    let mut consent: Vec<Egg> = Vec::new();
    let mut ckpt_k = 0u64;
    let mut ckpt_commit = [0u8; 32];
    let mut ckpt_fanout_epoch = 0u64;
    if kind == OpKind::Genesis {
        identity_pubkey = take_ke32(values.get(6).ok_or("fleet op: genesis missing identity pubkey")?, "identity")?;
        // v1 genesis carries a `ge(identity_sig)` at position 7; v2 (docs/identity-succession.md) omits it. Discriminate by TYPE: a `ge` here is the v1 sig (egg tail begins at 8); anything else is the egg tail itself (v2, identity_sig empty, tail begins at 7). The egg tail always starts with a `u` scheme, never a `ge`, so this is unambiguous, and a genesis always carries at least the device egg so position 7 is never past the end.
        match values.get(7) {
            Some(VsfType::ge(s)) => {
                identity_sig = s.clone();
                i = 8;
            }
            _ => {
                i = 7;
            }
        }
    }
    if kind == OpKind::Add {
        consent_t = match values.get(6) {
            Some(VsfType::e(et)) => et_to_osc(et),
            _ => return Err("fleet op: add missing consent time".into()),
        };
        consent = match values.get(7) {
            Some(VsfType::ge(s)) => consent_from_wire(version, s)?,
            _ => return Err("fleet op: add missing consent sig".into()),
        };
        i = 8;
    }
    if kind == OpKind::Remove {
        // Consented form carries (e6 consent_t, ge consent_sig) before the egg tail; legacy self-departure goes straight to eggs. Type-discriminated: an `e` at 6 is the consent stamp, a `u` is the first egg's scheme.
        if let Some(VsfType::e(et)) = values.get(6) {
            consent_t = et_to_osc(et);
            consent = match values.get(7) {
                Some(VsfType::ge(s)) => consent_from_wire(version, s)?,
                _ => return Err("fleet op: consented remove missing consent sig".into()),
            };
            i = 8;
        }
    }
    if kind == OpKind::Checkpoint {
        ckpt_k = take_u64(values.get(6).ok_or("fleet op: checkpoint missing k")?, "k")?;
        ckpt_commit = take_hb32(values.get(7).ok_or("fleet op: checkpoint missing commit")?, "commit")?;
        ckpt_fanout_epoch = take_u64(values.get(8).ok_or("fleet op: checkpoint missing fanout epoch")?, "fanout epoch")?;
        i = 9;
    }

    // ADD / DECLARE may carry the bundle here, discriminated by `ge` against the egg tail's leading `u`. A bundle that does not parse is a malformed op, not an absent bundle.
    let mut bundle = None;
    if matches!(kind, OpKind::Add | OpKind::Declare) {
        if let Some(VsfType::ge(b)) = values.get(i) {
            bundle = Some(crate::pq::KeyBundle::from_bytes(b).map_err(|e| format!("fleet op: {e}"))?);
            i += 1;
        }
    }

    // Remaining values are (scheme:u, sig:ge) egg pairs.
    let mut sigs = Vec::new();
    while i + 1 < values.len() {
        let scheme = match &values[i] {
            VsfType::u(v, false) => *v as u8,
            other => {
                use vsf::schema::FromVsfType;
                u8::from_vsf_type(other).map_err(|_| "fleet egg: bad scheme".to_string())?
            }
        };
        let sig = match &values[i + 1] {
            VsfType::ge(s) => s.clone(),
            _ => return Err("fleet egg: bad sig".into()),
        };
        sigs.push(Egg { scheme, sig });
        i += 2;
    }
    Ok(FleetOp {
        version,
        bundle,
        handle_proof,
        prev_hash,
        kind,
        device_pubkey,
        eagle_time,
        signer_pubkey,
        identity_pubkey,
        identity_sig,
        consent_t,
        consent,
        ckpt_k,
        ckpt_commit,
        ckpt_fanout_epoch,
        sigs,
    })
}

fn take_u64(v: &VsfType, what: &str) -> Result<u64, String> {
    match v {
        VsfType::u(n, false) => Ok(*n as u64),
        other => {
            use vsf::schema::FromVsfType;
            u64::from_vsf_type(other).map_err(|_| format!("fleet op: bad {what} (u)"))
        }
    }
}

fn take_hp32(v: &VsfType, what: &str) -> Result<[u8; 32], String> {
    match v {
        VsfType::hP(b) if b.len() == 32 => Ok(b.as_slice().try_into().unwrap()),
        _ => Err(format!("fleet op: bad {what} (hP32)")),
    }
}
fn take_hb32(v: &VsfType, what: &str) -> Result<[u8; 32], String> {
    match v {
        VsfType::hb(b) if b.len() == 32 => Ok(b.as_slice().try_into().unwrap()),
        _ => Err(format!("fleet op: bad {what} (hb32)")),
    }
}
fn take_ke32(v: &VsfType, what: &str) -> Result<[u8; 32], String> {
    match v {
        VsfType::ke(b) if b.len() == 32 => Ok(b.as_slice().try_into().unwrap()),
        _ => Err(format!("fleet op: bad {what} (ke32)")),
    }
}

/// Decode a VSF eagle-time value to oscillations. Public so the FGTW client (pairing/fan-out parse) can reuse the exact same conversion.
pub fn et_to_osc(et: &vsf::types::EtType) -> i64 {
    use vsf::types::EtType;
    match et {
        EtType::e5(o) => *o as i64,
        EtType::e6(o) => *o,
        EtType::e7(o) => *o as i64,
        _ => 0, // deprecated float forms; we only ever emit e6
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;
    use crate::pq::{FleetSigner, KeyBundle, SigningBundle};

    const HP: [u8; 32] = [0xab; 32];
    const SEED: [u8; 32] = [0xcd; 32]; // stand-in identity_seed for the founder

    fn key(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }
    fn pk(k: &Keypair) -> [u8; 32] {
        k.public.to_bytes()
    }
    /// The added device signs its own binding request — the consent every Add must carry.
    /// A joiner's consent: its eggs over the bindreq bytes, with every scheme it holds — so a `SigningBundle` consents three-deep and proves its bundle, and a bare `Keypair` consents with Ed25519 alone.
    fn consent_for(device: &impl FleetSigner, t: i64) -> (i64, Vec<Egg>) {
        let pk = device.keypair().public.to_bytes();
        let mask = device.bundle().map(|b| b.mask()).unwrap_or(scheme::MASK_BASE);
        (t, device.eggs(&bindreq_signing_bytes(&HP, &pk, t), mask))
    }

    /// A leaver's consent over its departure request, Ed25519 alone (the departure tests use bare keypairs).
    fn depart_consent(device: &Keypair, t: i64) -> Vec<Egg> {
        device.eggs(&departreq_signing_bytes(&HP, &device.public.to_bytes(), t), scheme::MASK_BASE)
    }

    #[test]
    fn genesis_then_adds_then_departure_folds_to_live_set() {
        let a = key(1);
        let b = key(2);
        let c = key(3);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        assert_eq!(blob.fold().unwrap(), vec![pk(&a)]);
        assert_eq!(blob.handle_proof(), Some(HP));

        let (t1, s1) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t1, s1); // a sponsors b, b consents
        let (t2, s2) = consent_for(&c, 290);
        blob.add(&b, pk(&c), 300, t2, s2); // b (now a member) sponsors c
        assert_eq!(blob.fold().unwrap(), vec![pk(&a), pk(&b), pk(&c)]);

        blob.depart(&a, 400); // a resigns — the only remove that exists
        assert_eq!(blob.fold().unwrap(), vec![pk(&b), pk(&c)]);
        assert!(!blob.is_member(&pk(&a)));
        assert!(blob.is_member(&pk(&c)));
    }

    #[test]
    fn consented_removal_folds_and_round_trips() {
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t1, s1) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t1, s1);
        // b requests removal (signs its departure request); a countersigns and appends.
        let dt = 390i64;
        let dsig = depart_consent(&b, dt);
        blob.remove_consented(&a, pk(&b), 400, dt, dsig);
        assert_eq!(blob.fold().unwrap(), vec![pk(&a)]);
        // Wire round-trip keeps the consent group intact.
        let bytes = blob.to_vsf_bytes().unwrap();
        let back = MembershipBlob::from_vsf_bytes(&bytes).unwrap();
        assert_eq!(back.fold().unwrap(), vec![pk(&a)]);
    }

    #[test]
    fn consented_removal_rejects_self_approval_and_forged_request() {
        let a = key(1);
        let b = key(2);
        let mk = |a: &Keypair, b: &Keypair| {
            let mut blob = MembershipBlob::genesis(a, HP, &SEED, 100);
            let (t1, s1) = consent_for(b, 190);
            blob.add(a, pk(b), 200, t1, s1);
            blob
        };
        // The leaver approving its own consented removal — two signatures must be two devices.
        let mut blob = mk(&a, &b);
        let dt = 390i64;
        let dsig = depart_consent(&b, dt);
        blob.remove_consented(&b, pk(&b), 400, dt, dsig);
        assert_eq!(blob.fold(), Err(FoldError::RemoveApproverIsLeaver { index: 2 }));
        // The approver forging the leaver's request signature — expulsion attempt.
        let mut blob = mk(&a, &b);
        let forged = depart_consent(&a, dt);
        blob.remove_consented(&a, pk(&b), 400, dt, forged);
        assert_eq!(blob.fold(), Err(FoldError::BadConsent { index: 2 }));
        // A stale request replayed past the window.
        let mut blob = mk(&a, &b);
        let dsig = depart_consent(&b, dt);
        blob.remove_consented(&a, pk(&b), dt + CONSENT_WINDOW_OSC + 1, dt, dsig);
        assert_eq!(blob.fold(), Err(FoldError::ConsentStale { index: 2 }));
    }

    #[test]
    fn op_signed_by_non_member_is_rejected() {
        let a = key(1);
        let stranger = key(9);
        let victim = key(5);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        // A stranger (not in the fleet) tries to sponsor an add — even WITH the victim's valid consent, the sponsor gate fails first.
        let (t, s) = consent_for(&victim, 190);
        blob.add(&stranger, pk(&victim), 200, t, s);
        assert_eq!(blob.fold(), Err(FoldError::SignerNotMember { index: 1 }));
    }

    #[test]
    fn add_without_valid_consent_is_conscription_and_rejected() {
        let a = key(1);
        let victim = key(5);
        // No consent at all.
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.add(&a, pk(&victim), 200, 0, Vec::new());
        assert_eq!(blob.fold(), Err(FoldError::BadConsent { index: 1 }));
        // Consent signed by the WRONG key (the sponsor forging on the victim's behalf).
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let forged = a.eggs(&bindreq_signing_bytes(&HP, &pk(&victim), 190), scheme::MASK_BASE);
        blob.add(&a, pk(&victim), 200, 190, forged);
        assert_eq!(blob.fold(), Err(FoldError::BadConsent { index: 1 }));
    }

    #[test]
    fn replayed_ancient_consent_is_rejected() {
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        // b consented long ago (departed since, say); re-adding with the old consent must fail the window.
        let (t, s) = consent_for(&b, 200);
        blob.add(&a, pk(&b), 200 + CONSENT_WINDOW_OSC + 1, t, s);
        assert_eq!(blob.fold(), Err(FoldError::ConsentStale { index: 1 }));
    }

    #[test]
    fn remove_must_be_self_signed() {
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        // a tries to expel b — expulsion doesn't exist.
        let expel = sign_op(&a, HP, blob.head(), OpKind::Remove, pk(&b), 300, pk(&a), [0u8; 32], None, None, None, None, scheme::MASK_BASE);
        blob.ops.push(expel);
        assert_eq!(blob.fold(), Err(FoldError::RemoveNotSelfSigned { index: 2 }));
    }

    #[test]
    fn genesis_must_be_self_signed_and_first() {
        let a = key(1);
        let b = key(2);
        // A genesis whose signer != device is forged.
        let forged = sign_op(&a, HP, [0u8; 32], OpKind::Genesis, pk(&b), 100, pk(&a), [0u8; 32], None, None, None, None, scheme::MASK_BASE);
        let blob = MembershipBlob { ops: vec![forged] };
        assert_eq!(blob.fold(), Err(FoldError::GenesisNotSelfSigned));
    }

    #[test]
    fn tampering_breaks_the_chain_or_signature() {
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        assert!(blob.fold().is_ok());

        // Tamper with the add op's device pubkey AFTER signing → signature no longer covers it.
        blob.ops[1].device_pubkey = pk(&key(7));
        assert_eq!(blob.fold(), Err(FoldError::BadSignature { index: 1 }));

        // Re-sign the tampered op correctly but leave its prev_hash stale → chain breaks instead.
        let a2 = key(1);
        let (t7, s7) = consent_for(&key(7), 190);
        blob.ops[1] = sign_op(&a2, HP, [1u8; 32], OpKind::Add, pk(&key(7)), 200, pk(&a2), [0u8; 32], None, Some((t7, s7)), None, None, scheme::MASK_BASE);
        assert_eq!(blob.fold(), Err(FoldError::BrokenChain { index: 1 }));

        // Swap the consent under the sponsor's egg — consent is in signing_bytes, so the egg breaks.
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        let (t2, s2) = consent_for(&b, 195);
        blob.ops[1].consent_t = t2;
        blob.ops[1].consent = s2;
        assert_eq!(blob.fold(), Err(FoldError::BadSignature { index: 1 }));
    }

    #[test]
    fn transplanted_chain_under_wrong_identity_is_rejected() {
        // A valid chain whose later op was re-stamped with a different handle_proof must fail. (Genuine transplant — re-keying ops[1].handle_proof without re-signing — trips the consistency check.)
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        blob.ops[1].handle_proof = [0x11; 32];
        assert_eq!(blob.fold(), Err(FoldError::InconsistentHandleProof { index: 1 }));
    }

    #[test]
    fn extends_accepts_forward_only() {
        let a = key(1);
        let b = key(2);
        let base = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let mut grown = base.clone();
        let (t, s) = consent_for(&b, 190);
        grown.add(&a, pk(&b), 200, t, s);
        assert!(grown.extends(&base)); // forward extension
        assert!(!base.extends(&grown)); // shorter can't extend longer

        // A divergent branch (different op at the same height) is NOT an extension.
        let mut fork = base.clone();
        let (t8, s8) = consent_for(&key(8), 190);
        fork.add(&a, pk(&key(8)), 200, t8, s8);
        assert!(!fork.extends(&grown) && !grown.extends(&fork));
    }

    #[test]
    fn vsf_round_trips_and_still_folds() {
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        blob.depart(&b, 300);
        let bytes = blob.to_vsf_bytes().unwrap();
        let parsed = MembershipBlob::from_vsf_bytes(&bytes).unwrap();
        assert_eq!(parsed, blob);
        assert_eq!(parsed.fold().unwrap(), vec![pk(&a)]);
    }

    /// A real chain written by the PRE-egg build (2026-08-12): genesis a, add b, b departs. Carries no version field, so it parses as v1 and must fold under v1 rules forever. Shared by the two tests that guard the migration.
    const PINNED_HEX: &str = "52c3853c7a330979330962337e6c3404136536237edeb2824c5c006870331f4d0baa0b8e1566fe11128f43a2a4e9483f82a5af4acd27a94e6df043bdc6a37f6862331f4f3f5a57908e2951a9b7d385510994b16ae44ba669157fc37af6b0d700a4f93b6e330128643305666c6565743a6f337e2c623403952c6e3303293e5b286433026f703a6850331fabababababababababababababababababababababababababababababababab2c6862331f00000000000000000000000000000000000000000000000000000000000000002c7533002c6b65331f8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c2c653600000000000000642c6b65331f8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c2c6b65331ffc947730f49eb01427a66e050733294d9e520e545c7a27125a780634e0860a272c6765333f39148ed5a51baf7f765600b277f8ac2fddf445b55ed8c261d3a8eca449a7286614d00939188337bd07f1248654b86bc5c6659f14f9d504ce0fc5fded4b3d30092c7533002c6765333feb2b722e7d441cec833a63f76026ae7aadb29316d0164bfb61d4c2f34866bf3a4e53c5c6d628f12f32613316cabece5e32a53c4b4ff3bb147ccecfd9cc2e580b29286433026f703a6850331fabababababababababababababababababababababababababababababababab2c6862331f934c5a5c68855e63a020b9a8da384f37b3cb0ccf7d6a090c56130cbad4a90d912c7533012c6b65331f8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3942c653600000000000000c82c6b65331f8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c2c653600000000000000be2c6765333f0d5b6753187a455f5f2ae54016ecbc96b082e5d58f2bc768ebe6686baf21f18ad5527b359610eeda8ac917e04f4d92ddc242ed26bbd7bf4cb0f210e7ea292b082c7533002c6765333f1aa37898dea850c91e4c57c133fa3ef49f648f62b96d55b768adba460a463db2a031e1d92e1b923c2490e61ff237490227cc795ce61ae1969f7ee9a3047f240e29286433026f703a6850331fabababababababababababababababababababababababababababababababab2c6862331fbb1daf28635b791d0c66592c912d78bd71ade425974d947601464709b16c65712c7533022c6b65331f8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3942c6536000000000000012c2c6b65331f8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3942c7533002c6765333f75b772ee48e506047eca02a0db47b81d9bb708caa6478172a001eb5cbb8f3cee45de3fcc818477127f87142ced6f4c89fa008d3ca19aa4e4923347a3e7699b09295d";

    /// Two real three-scheme devices. Derivation is deterministic, so these are stable across runs.
    fn bundles() -> (SigningBundle, SigningBundle) {
        (SigningBundle::derive(b"test-machine-A"), SigningBundle::derive(b"test-machine-B"))
    }

    /// The promotion is automatic: the floor rises the moment the LAST member declares, with nothing published to announce it.
    #[test]
    fn floor_rises_when_the_last_member_declares() {
        let (a, b) = bundles();
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, sig) = consent_for(b.keypair(), 190);
        blob.add(&a, pk(b.keypair()), 200, t, sig);

        // Nobody has declared: every device honestly holds an Ed25519 key and nothing more is proved.
        assert_eq!(blob.scheme_floor().unwrap(), scheme::MASK_BASE);

        // One of two declares — the fleet is NOT promoted, because the other member still cannot sign that way.
        blob.declare(&a, 300);
        assert_eq!(blob.scheme_floor().unwrap(), scheme::MASK_BASE, "a partial upgrade must not promote the fleet");

        // The last one declares, and the floor rises by itself — to all three families.
        blob.declare(&b, 400);
        assert_eq!(blob.scheme_floor().unwrap(), scheme::MASK_ALL, "the floor is the AND across members");
        // And it survives the wire: bundles and PQ eggs round-trip, and the parsed chain reaches the same floor.
        let round = MembershipBlob::from_vsf_bytes(&blob.to_vsf_bytes().unwrap()).unwrap();
        assert_eq!(round, blob);
        assert_eq!(round.scheme_floor().unwrap(), scheme::MASK_ALL);
    }

    /// The floor IS the required set: once promoted, an op carrying fewer schemes does not fold, whoever signed it.
    #[test]
    fn floor_is_the_required_set() {
        let (a, b) = bundles();
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, sig) = consent_for(b.keypair(), 190);
        blob.add(&a, pk(b.keypair()), 200, t, sig);
        blob.declare(&a, 300);
        blob.declare(&b, 400);
        assert_eq!(blob.scheme_floor().unwrap(), scheme::MASK_ALL);

        // The same device, signing with only its Ed25519 key: short of the floor, refused.
        let mut short = blob.clone();
        short.checkpoint(a.keypair(), 500, 1, [0x11; 32], 1);
        assert_eq!(short.fold(), Err(FoldError::InsufficientEggs { index: 4 }));

        // Signing with everything it declared: folds.
        blob.checkpoint(&a, 500, 1, [0x11; 32], 1);
        assert_eq!(blob.fold().unwrap(), vec![pk(a.keypair()), pk(b.keypair())]);
    }

    /// The ratchet: once promoted, a fleet cannot be dragged back to single-egg by admitting a device that cannot keep up — and CAN admit one that can.
    #[test]
    fn a_device_below_the_floor_cannot_join_but_a_declared_one_can() {
        let (a, b) = bundles();
        let c = key(3);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.declare(&a, 200);
        assert_eq!(blob.scheme_floor().unwrap(), scheme::MASK_ALL);

        // c joins declaring nothing — it would lower the floor, so the op does not fold at all.
        let mut bare = blob.clone();
        let (t, sig) = consent_for(&c, 290);
        bare.add(&a, pk(&c), 300, t, sig);
        assert_eq!(bare.fold(), Err(FoldError::BelowFloor { index: 2 }));

        // b joins WITH its bundle and a consent signed by all three of its keys: admitted, and the floor holds.
        let (t, sig) = consent_for(&b, 290);
        blob.add_declared(&a, pk(b.keypair()), 300, t, sig, b.public());
        assert_eq!(blob.fold().unwrap(), vec![pk(a.keypair()), pk(b.keypair())]);
        assert_eq!(blob.scheme_floor().unwrap(), scheme::MASK_ALL);
    }

    /// A member cannot renounce a scheme it already proved — the other route to lowering the floor.
    ///
    /// A second, undeclared member keeps the floor at Ed25519, so the renouncing op is not short of the floor and reaches the regression check. (A sole member at the full floor could never get this far — `InsufficientEggs` fires first, which is the stricter and correct outcome.)
    #[test]
    fn capability_cannot_regress() {
        let (a, b) = bundles();
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, sig) = consent_for(b.keypair(), 190);
        blob.add(&a, pk(b.keypair()), 200, t, sig);
        blob.declare(&a, 300);
        assert_eq!(blob.scheme_floor().unwrap(), scheme::MASK_BASE, "b holds the floor down");
        let smaller = KeyBundle::ed25519_only(&pk(a.keypair()));
        let renounce = sign_op(&a, HP, blob.head(), OpKind::Declare, pk(a.keypair()), 400, pk(a.keypair()), [0u8; 32], None, None, None, Some(smaller.clone()), smaller.mask());
        blob.ops.push(renounce);
        assert_eq!(blob.fold(), Err(FoldError::CapabilityRegression { index: 3 }));
    }

    /// Declaring is proving: a bundle signed with fewer schemes than it names does not fold.
    #[test]
    fn declare_must_prove_possession() {
        let (a, _) = bundles();
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        // Full bundle, Ed25519-only eggs — the claim outruns the proof.
        let unproven = sign_op(a.keypair(), HP, blob.head(), OpKind::Declare, pk(a.keypair()), 200, pk(a.keypair()), [0u8; 32], None, None, None, Some(a.public()), scheme::MASK_BASE);
        blob.ops.push(unproven);
        assert_eq!(blob.fold(), Err(FoldError::DeclareUnproven { index: 1 }));
    }

    /// A device may raise its own capability and nobody else's.
    #[test]
    fn declare_must_be_self_signed() {
        let (a, b) = bundles();
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, sig) = consent_for(b.keypair(), 190);
        blob.add(&a, pk(b.keypair()), 200, t, sig);
        // a signs a declaration whose SUBJECT is b, carrying b's real bundle — vouching for capability b never proved.
        let forged = sign_op(a.keypair(), HP, blob.head(), OpKind::Declare, pk(b.keypair()), 300, pk(a.keypair()), [0u8; 32], None, None, None, Some(b.public()), scheme::MASK_BASE);
        blob.ops.push(forged);
        assert_eq!(blob.fold(), Err(FoldError::DeclareNotSelfSigned { index: 2 }));
    }

    /// A Declare without a bundle, or carrying a bundle that belongs to a different device, is malformed.
    #[test]
    fn declare_needs_its_own_bundle() {
        let (a, b) = bundles();
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let none = sign_op(&a, HP, blob.head(), OpKind::Declare, pk(a.keypair()), 200, pk(a.keypair()), [0u8; 32], None, None, None, None, scheme::MASK_BASE);
        blob.ops.push(none);
        assert_eq!(blob.fold(), Err(FoldError::BadBundle { index: 1 }));

        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let theirs = sign_op(&a, HP, blob.head(), OpKind::Declare, pk(a.keypair()), 200, pk(a.keypair()), [0u8; 32], None, None, None, Some(b.public()), scheme::MASK_BASE);
        blob.ops.push(theirs);
        assert_eq!(blob.fold(), Err(FoldError::BundleMismatch { index: 1 }));
    }

    /// A PQ egg is really checked: flip one byte of the Falcon signature and the op is rejected.
    #[test]
    fn tampered_pq_egg_is_rejected() {
        let (a, _) = bundles();
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.declare(&a, 200);
        blob.checkpoint(&a, 300, 1, [0x11; 32], 1);
        assert!(blob.fold().is_ok());
        let falcon = blob.ops[2].sigs.iter_mut().find(|e| e.scheme == scheme::FALCON512).unwrap();
        falcon.sig[10] ^= 0x01;
        assert_eq!(blob.fold(), Err(FoldError::BadSignature { index: 2 }));
    }

    /// Declaring on an Add is proving: a consent that does not cover the bundle the joiner is added with does not fold.
    #[test]
    fn add_consent_must_prove_the_declared_bundle() {
        let (a, b) = bundles();
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        // b's full bundle on the Add, but b consented with Ed25519 only — the claim outruns the proof.
        let (t, sig) = consent_for(b.keypair(), 190);
        blob.add_declared(&a, pk(b.keypair()), 200, t, sig, b.public());
        assert_eq!(blob.fold(), Err(FoldError::BadConsent { index: 1 }));
    }

    /// A departure from a promoted fleet is consented at the floor: the leaver signs with everything it declared.
    #[test]
    fn departure_consent_is_held_to_the_floor() {
        let (a, b) = bundles();
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, sig) = consent_for(&b, 190);
        blob.add_declared(&a, pk(b.keypair()), 200, t, sig, b.public());
        blob.declare(&a, 300);
        assert_eq!(blob.scheme_floor().unwrap(), scheme::MASK_ALL);
        let msg = departreq_signing_bytes(&HP, &pk(b.keypair()), 390);
        // Ed25519-only departure consent on a three-scheme fleet: refused.
        let mut short = blob.clone();
        short.remove_consented(&a, pk(b.keypair()), 400, 390, b.keypair().eggs(&msg, scheme::MASK_BASE));
        assert_eq!(short.fold(), Err(FoldError::BadConsent { index: 3 }));
        // Full consent: b leaves, a remains.
        blob.remove_consented(&a, pk(b.keypair()), 400, 390, b.eggs(&msg, scheme::MASK_ALL));
        assert_eq!(blob.fold().unwrap(), vec![pk(a.keypair())]);
    }

    /// Succession is a re-founding, so a vouch is held to the predecessor's floor: from a three-scheme fleet, an Ed25519-only vouch is exactly what a curve break would let an attacker forge, and it is refused.
    #[test]
    fn succession_vouch_is_held_to_the_predecessor_floor() {
        let (a, b) = bundles();
        let mut pred = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, sig) = consent_for(&b, 190);
        pred.add_declared(&a, pk(b.keypair()), 200, t, sig, b.public());
        pred.declare(&a, 300);
        assert_eq!(pred.scheme_floor().unwrap(), scheme::MASK_ALL);
        let pinned = pred.genesis_hash().unwrap();
        let new = MembershipBlob::genesis_v2(&a, HP, &SEED, 1000);
        let new_gh = new.genesis_hash().unwrap();

        // Vouched with everything a declared: accepted.
        let good = SuccessorRecord::new(pred.clone(), new_gh, HP, &[&a]).unwrap();
        assert!(good.verify_for_pin(&pinned).is_ok());
        // Same device, Ed25519 alone: below the predecessor's floor, refused.
        let weak = SuccessorRecord::new(pred.clone(), new_gh, HP, &[a.keypair()]).unwrap();
        assert!(weak.verify_for_pin(&pinned).is_err());
        // An egg naming a scheme this build cannot verify is a hard reject, not a skip.
        let mut unknown = good.clone();
        unknown.continuity_eggs.push(ContinuityEgg { device_pubkey: pk(a.keypair()), scheme: 200, sig: vec![0u8; 64] });
        assert!(unknown.verify_for_pin(&pinned).is_err());
    }

    /// The migration itself: a v1 chain EXTENDS with v2 ops rather than being replaced.
    ///
    /// This is the property that removes the wipe. The genesis hash is the fleet's generation id and every friend TOFU-pins it, so it must survive the egg work byte-for-byte while new ops still get the framed preimages multi-scheme eggs need. Both halves are asserted here: the pinned pre-egg genesis keeps its exact hash, and an op appended today folds on top of it.
    #[test]
    fn v1_chain_extends_with_v2_ops_and_keeps_its_genesis() {
        let bytes: Vec<u8> = (0..PINNED_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&PINNED_HEX[i..i + 2], 16).unwrap())
            .collect();
        let mut blob = MembershipBlob::from_vsf_bytes(&bytes).expect("v1 chain must parse");
        assert_eq!(blob.ops[0].version, OpVersion::V1, "a chain with no version field is v1");
        assert_eq!(blob.scheme_floor().unwrap(), scheme::MASK_BASE, "a v1 chain has declared nothing");
        let genesis_before = blob.genesis_hash();

        // Append under today's rules — sign_op mints v2.
        let a = key(1);
        let c = key(3);
        let (t, s) = consent_for(&c, 390);
        blob.add(&a, pk(&c), 400, t, s);
        assert_eq!(blob.ops.last().unwrap().version, OpVersion::V2, "new ops are framed");

        assert_eq!(blob.genesis_hash(), genesis_before, "the pinned generation id must not move");
        assert_eq!(blob.fold().expect("mixed-version chain must fold"), vec![pk(&a), pk(&c)]);

        // And it survives the wire in both directions.
        let round = MembershipBlob::from_vsf_bytes(&blob.to_vsf_bytes().unwrap()).unwrap();
        assert_eq!(round, blob);
        assert_eq!(round.genesis_hash(), genesis_before);
    }

    /// The preimages must stay injective once signatures of differing lengths exist.
    ///
    /// Before framing, `chain_hash` appended `scheme ‖ sig` with no length, so a single long egg hashed identically to a crafted run of shorter ones — two different signature SETS, one chain hash, and that hash is `prev_hash`. Splitting one egg's payload across two eggs is the cheapest witness: unframed, both spellings feed the hasher the same bytes.
    #[test]
    fn chain_hash_distinguishes_egg_boundaries() {
        let a = key(1);
        let base = MembershipBlob::genesis(&a, HP, &SEED, 100);

        let mut one_long = base.clone();
        one_long.ops[0].sigs.push(Egg { scheme: 7, sig: vec![0xAB; 64] });

        let mut two_short = base.clone();
        two_short.ops[0].sigs.push(Egg { scheme: 7, sig: vec![0xAB; 32] });
        two_short.ops[0].sigs.push(Egg { scheme: 0xAB, sig: vec![0xAB; 31] });

        assert_ne!(
            one_long.ops[0].chain_hash(),
            two_short.ops[0].chain_hash(),
            "one long egg must not hash the same as a run of shorter eggs"
        );
    }

    /// Same property for `signing_bytes`, whose trailing `consent_sig` is the other variable-length tail. A shorter consent plus attacker-chosen trailing content must not reproduce a longer consent's preimage.
    #[test]
    fn signing_bytes_frames_the_consent_tail() {
        let a = key(1);
        let mut short = MembershipBlob::genesis(&a, HP, &SEED, 100).ops[0].clone();
        let mut long = short.clone();
        short.consent = vec![Egg { scheme: scheme::ED25519, sig: vec![0xCD; 32] }];
        long.consent = vec![Egg { scheme: scheme::ED25519, sig: vec![0xCD; 64] }];
        assert_ne!(short.signing_bytes(), long.signing_bytes());
        // And the framed length is what separates them, not just the byte count.
        assert_ne!(
            short.signing_bytes().len(),
            long.signing_bytes().len(),
            "framing must carry the length explicitly"
        );
    }

    #[test]
    fn unknown_scheme_egg_fails_closed() {
        let a = key(1);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        // Inject an extra egg with an unimplemented scheme — "every egg must verify" → reject.
        blob.ops[0].sigs.push(Egg { scheme: 250, sig: vec![0u8; 64] });
        assert_eq!(blob.fold(), Err(FoldError::BadSignature { index: 0 }));
    }

    /// Cross-crate drift guard: a fixed blob's bytes must fold to a fixed device set. Historically the FGTW worker carried a hand-mirrored copy of this module and this vector guarded their parity; now that both sides share this crate the vector is a belt-and-suspenders determinism check (signing_bytes / chain_hash / parse). Seeds + handle_proof are fixed and timestamps are constants, so the encoded bytes are deterministic.
    #[test]
    fn known_answer_vector_for_worker_parity() {
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        let members = blob.fold().unwrap();
        assert_eq!(members, vec![pk(&a), pk(&b)]);
        // Re-parsing the wire form yields the identical member set (what the worker computes from the POST).
        let parsed = MembershipBlob::from_vsf_bytes(&blob.to_vsf_bytes().unwrap()).unwrap();
        assert_eq!(parsed.fold().unwrap(), members);
    }

    #[test]
    fn genesis_identity_binding_holds_and_matches_seed() {
        let a = key(1);
        let blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        assert!(blob.fold().is_ok());
        // A contact who knows the handle (→ SEED) can confirm the founder is the real owner...
        assert!(blob.genesis_identity_matches(&SEED));
        // ...and a different seed (different handle) does not match.
        assert!(!blob.genesis_identity_matches(&[0x99; 32]));
        // The binding survives the VSF round-trip.
        let parsed = MembershipBlob::from_vsf_bytes(&blob.to_vsf_bytes().unwrap()).unwrap();
        assert!(parsed.fold().is_ok() && parsed.genesis_identity_matches(&SEED));
    }

    #[test]
    fn genesis_handle_proof_returns_the_claimed_slot() {
        // The accessor the anti-swap check (`current_members_verified`) reads: a chain's genesis handle_proof IS the slot it claims. A fetch-by-HP compares against this to reject a relay serving a chain from a different slot.
        let a = key(1);
        let blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        assert_eq!(blob.genesis_handle_proof(), Some(HP));
        // A chain founded at a DIFFERENT slot reports that different proof → the `!= Some(queried)` check fires.
        let other_hp = [0x55u8; 32];
        let foreign = MembershipBlob::genesis(&a, other_hp, &SEED, 100);
        assert_eq!(foreign.genesis_handle_proof(), Some(other_hp));
        assert_ne!(foreign.genesis_handle_proof(), Some(HP));
        // Empty blob claims no slot.
        assert_eq!(MembershipBlob::default().genesis_handle_proof(), None);
        // Survives the VSF round-trip.
        let parsed = MembershipBlob::from_vsf_bytes(&blob.to_vsf_bytes().unwrap()).unwrap();
        assert_eq!(parsed.genesis_handle_proof(), Some(HP));
    }

    #[test]
    fn v2_genesis_folds_omits_sig_keeps_pubkey() {
        let a = key(1);
        let blob = MembershipBlob::genesis_v2(&a, HP, &SEED, 100);
        // Folds like any genesis.
        assert_eq!(blob.fold().unwrap(), vec![pk(&a)]);
        // The inert self-cosignature is gone from the wire…
        assert!(blob.ops[0].identity_sig.is_empty(), "v2 genesis carries no identity_sig");
        // …but the pubkey the bindreq gate keys off is still there (canonical Ed25519(seed)).
        let expect = ed25519_dalek::SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
        assert_eq!(blob.ops[0].identity_pubkey, expect);
        assert_eq!(blob.genesis_identity_pubkey(), Some(expect));
    }

    #[test]
    fn v2_genesis_round_trips_through_vsf() {
        // The load-bearing serialization check: an EMPTY `ge(identity_sig)` must survive encode→parse at its position, or the egg tail would misalign. If this passes, the empty-value discriminant holds.
        let a = key(1);
        let blob = MembershipBlob::genesis_v2(&a, HP, &SEED, 100);
        let parsed = MembershipBlob::from_vsf_bytes(&blob.to_vsf_bytes().unwrap()).unwrap();
        assert_eq!(parsed.fold().unwrap(), vec![pk(&a)]);
        assert!(parsed.ops[0].identity_sig.is_empty(), "empty identity_sig round-trips as empty");
        assert_eq!(parsed.ops[0].identity_pubkey, blob.ops[0].identity_pubkey);
        // The parsed op equals the original field-for-field ⇒ the egg tail parsed at the right offset.
        // (Raw bytes differ only by the non-deterministic document creation timestamp, so compare the op.)
        assert_eq!(parsed.ops[0], blob.ops[0]);
    }

    #[test]
    fn v2_genesis_then_adds_fold_and_link() {
        // Chain linkage THROUGH a v2 genesis: prev_hash chains off the v2 genesis's chain_hash,
        // so if the v2 hash computation were wrong the Adds wouldn't link.
        let a = key(1);
        let b = key(2);
        let c = key(3);
        let mut blob = MembershipBlob::genesis_v2(&a, HP, &SEED, 100);
        let (t1, s1) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t1, s1);
        let (t2, s2) = consent_for(&c, 290);
        blob.add(&b, pk(&c), 300, t2, s2);
        assert_eq!(blob.fold().unwrap(), vec![pk(&a), pk(&b), pk(&c)]);
        // And the whole multi-op v2 chain survives the codec.
        let parsed = MembershipBlob::from_vsf_bytes(&blob.to_vsf_bytes().unwrap()).unwrap();
        assert_eq!(parsed.fold().unwrap(), vec![pk(&a), pk(&b), pk(&c)]);
    }

    #[test]
    fn genesis_without_identity_pubkey_is_rejected() {
        // A genesis validly device-signed but carrying NO identity_pubkey (degenerate) — the bindreq gate would have no key, so fold refuses it. Built via sign_op directly (no public builder makes one).
        let a = key(1);
        let op = sign_op(&a, HP, [0u8; 32], OpKind::Genesis, pk(&a), 100, pk(&a), [0u8; 32], None, None, None, None, scheme::MASK_BASE);
        let blob = MembershipBlob { ops: vec![op] };
        assert_eq!(blob.fold(), Err(FoldError::BadIdentityBinding));
    }

    // ── Identity succession ──

    /// A predecessor (v1) chain, a new v2 chain (re-found), and a successor vouched by an old-chain device.
    fn succession_fixture() -> (MembershipBlob, [u8; 32], SuccessorRecord, Keypair) {
        let a = key(1); // a device of the OLD fleet (the continuity signer)
        let predecessor = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let old_gh = predecessor.genesis_hash().unwrap();
        let new_device = key(9);
        let new_chain = MembershipBlob::genesis_v2(&new_device, HP, &SEED, 500);
        let new_gh = new_chain.genesis_hash().unwrap();
        let record = SuccessorRecord::new(predecessor.clone(), new_gh, HP, &[&a]).unwrap();
        (predecessor, old_gh, record, a)
    }

    #[test]
    fn succession_round_trips_through_vsf() {
        let (_pred, _old_gh, record, _a) = succession_fixture();
        let parsed = SuccessorRecord::from_vsf_bytes(&record.to_vsf_bytes().unwrap()).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn contact_auto_repins_on_valid_succession() {
        let (_pred, old_gh, record, _a) = succession_fixture();
        // The contact pins old_gh; the successor is vouched by a predecessor member → migrate ok.
        assert!(record.verify_for_pin(&old_gh).is_ok());
        // Survives the codec too (what a contact actually fetches).
        let parsed = SuccessorRecord::from_vsf_bytes(&record.to_vsf_bytes().unwrap()).unwrap();
        assert!(parsed.verify_for_pin(&old_gh).is_ok());
    }

    #[test]
    fn succession_rejected_without_old_member_egg() {
        // The attacker case: a successor whose continuity egg is signed by a device NOT in the predecessor's member set. Knowing the (public) handle does not grant an old device secret.
        let a = key(1);
        let predecessor = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let old_gh = predecessor.genesis_hash().unwrap();
        let new_gh = MembershipBlob::genesis_v2(&key(9), HP, &SEED, 500).genesis_hash().unwrap();
        let stranger = key(42); // not a member of `predecessor`
        let forged = SuccessorRecord::new(predecessor, new_gh, HP, &[&stranger]).unwrap();
        assert!(forged.verify_for_pin(&old_gh).is_err());
    }

    #[test]
    fn succession_predecessor_must_match_pin() {
        let (_pred, _old_gh, record, _a) = succession_fixture();
        // A contact pinned to a DIFFERENT genesis must not be re-pinned by this successor.
        assert!(record.verify_for_pin(&[0x77; 32]).is_err());
    }

    #[test]
    fn succession_handle_proof_must_match_predecessor() {
        let (_pred, old_gh, mut record, _a) = succession_fixture();
        record.handle_proof = [0x55; 32]; // predecessor is for HP, not this
        assert!(record.verify_for_pin(&old_gh).is_err());
    }

    #[test]
    fn succession_is_monotonic() {
        let (_pred, _old_gh, record, _a) = succession_fixture();
        // Once the contact has migrated to new_genesis_hash, replaying the same record (whose predecessor is the OLD chain) can't walk them back — its predecessor ≠ the new pin.
        assert!(record.verify_for_pin(&record.new_genesis_hash).is_err());
    }

    #[test]
    fn genesis_with_bad_identity_sig_is_rejected() {
        let a = key(1);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        // Corrupt ONLY the identity signature — the device egg still covers signing_bytes (which excludes it), so this isolates the identity check.
        blob.ops[0].identity_sig = vec![0u8; 64];
        assert_eq!(blob.fold(), Err(FoldError::BadIdentityBinding));
    }

    #[test]
    fn swapping_identity_pubkey_breaks_the_device_sig() {
        let a = key(1);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        // identity_pubkey is folded into signing_bytes, so swapping it invalidates the device self-signature.
        blob.ops[0].identity_pubkey =
            ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]).verifying_key().to_bytes();
        assert_eq!(blob.fold(), Err(FoldError::BadSignature { index: 0 }));
    }

    #[test]
    fn stray_bindings_are_rejected() {
        let a = key(1);
        let b = key(2);
        // Identity binding on an Add — only genesis may carry one.
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        blob.ops[1].identity_pubkey = [0x77; 32];
        assert_eq!(blob.fold(), Err(FoldError::StrayIdentityBinding { index: 1 }));
        // Consent fields on a Remove — only Add may carry them.
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        blob.depart(&b, 300);
        blob.ops[2].consent_t = 42;
        assert_eq!(blob.fold(), Err(FoldError::StrayConsent { index: 2 }));
    }

    /// The signature-stability guard, now doing double duty. These bytes were generated by the PRE-checkpoint build (2026-08-12, before kind 3 existed) and carry NO version field, so they parse as `OpVersion::V1` and must fold under v1 rules — unframed preimages, bare `consent_sig` tail, Ed25519 only.
    ///
    /// This is the test that proves the egg work did not strand the field. A fleet's genesis `chain_hash` is its generation id and every friend TOFU-pins it; if framing were applied unconditionally that hash would move and every friendship would render as a stranger. Folding this vector unchanged is what says it did not.
    #[test]
    fn pinned_pre_checkpoint_chain_still_parses_and_folds() {
        let bytes: Vec<u8> = (0..PINNED_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&PINNED_HEX[i..i + 2], 16).unwrap())
            .collect();
        let blob = MembershipBlob::from_vsf_bytes(&bytes).expect("pre-checkpoint chain must parse");
        // genesis a, add b, b departs → the live set is a alone, and the genesis identity binding still verifies.
        let a = key(1);
        assert_eq!(blob.fold().expect("pre-checkpoint chain must fold"), vec![pk(&a)]);
        assert!(blob.genesis_identity_matches(&SEED));
        assert_eq!(blob.latest_checkpoint(), None);
    }

    #[test]
    fn checkpoint_folds_and_leaves_membership_untouched() {
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        blob.checkpoint(&b, 300, 1, [0x11; 32], 4);
        blob.checkpoint(&a, 400, 2, [0x22; 32], 4);
        assert_eq!(blob.fold().unwrap(), vec![pk(&a), pk(&b)]);
        assert_eq!(blob.latest_checkpoint(), Some((2, [0x22; 32], 4)));
        // Membership ops keep working after a checkpoint — the spine interleaves, never blocks.
        blob.depart(&b, 500);
        assert_eq!(blob.fold().unwrap(), vec![pk(&a)]);
    }

    #[test]
    fn checkpoint_by_non_member_is_rejected() {
        let a = key(1);
        let stranger = key(9);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.checkpoint(&stranger, 200, 1, [0x11; 32], 1);
        assert_eq!(blob.fold(), Err(FoldError::SignerNotMember { index: 1 }));
    }

    #[test]
    fn checkpoint_sequence_must_advance_by_one() {
        let a = key(1);
        // First checkpoint must be k=1.
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.checkpoint(&a, 200, 2, [0x11; 32], 1);
        assert_eq!(blob.fold(), Err(FoldError::CheckpointOutOfSequence { index: 1 }));
        // A skip after a valid one fails too.
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.checkpoint(&a, 200, 1, [0x11; 32], 1);
        blob.checkpoint(&a, 300, 3, [0x22; 32], 1);
        assert_eq!(blob.fold(), Err(FoldError::CheckpointOutOfSequence { index: 2 }));
        // As does a replayed index.
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.checkpoint(&a, 200, 1, [0x11; 32], 1);
        blob.checkpoint(&a, 300, 1, [0x22; 32], 1);
        assert_eq!(blob.fold(), Err(FoldError::CheckpointOutOfSequence { index: 2 }));
    }

    #[test]
    fn void_or_misattributed_checkpoint_is_rejected() {
        let a = key(1);
        // Zero commit is structurally void.
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.checkpoint(&a, 200, 1, [0u8; 32], 1);
        assert_eq!(blob.fold(), Err(FoldError::CheckpointMalformed { index: 1 }));
        // A checkpoint whose device field names someone other than its signer is void (the minter speaks for itself only).
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let op = sign_op(&a, HP, blob.head(), OpKind::Checkpoint, pk(&key(7)), 200, pk(&a), [0u8; 32], None, None, Some((1, [0x11; 32], 1)), None, scheme::MASK_BASE);
        blob.ops.push(op);
        assert_eq!(blob.fold(), Err(FoldError::CheckpointMalformed { index: 1 }));
    }

    #[test]
    fn stray_checkpoint_fields_are_rejected() {
        // The checkpoint triple is kind-gated OUT of Add signing bytes (signature stability), so a bolted-on triple wouldn't break the egg — the structural gate is what rejects it.
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        blob.ops[1].ckpt_k = 1;
        assert_eq!(blob.fold(), Err(FoldError::StrayCheckpoint { index: 1 }));
    }

    #[test]
    fn checkpoint_round_trips_thru_vsf() {
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        blob.checkpoint(&b, 300, 1, [0x33; 32], 9);
        let parsed = MembershipBlob::from_vsf_bytes(&blob.to_vsf_bytes().unwrap()).unwrap();
        assert_eq!(parsed, blob);
        assert_eq!(parsed.fold().unwrap(), vec![pk(&a), pk(&b)]);
        assert_eq!(parsed.latest_checkpoint(), Some((1, [0x33; 32], 9)));
    }

    /// The registry door applies the same rule as the fold: a request that declares a bundle must consent with every scheme in it. This is what lets the worker refuse an unprovable bundle before a sponsor ever sees it.
    #[test]
    fn bindreq_with_a_bundle_must_consent_with_every_declared_scheme() {
        let (b, _) = bundles();
        let identity_key = ed25519_dalek::SigningKey::from_bytes(&SEED);
        let identity_pubkey = identity_key.verifying_key().to_bytes();
        let t = 12345i64;
        let msg = bindreq_signing_bytes(&HP, &pk(b.keypair()), t);
        use ed25519_dalek::Signer;
        let full = BindRequest {
            device_pubkey: pk(b.keypair()),
            t,
            device_sig: b.eggs(&msg, scheme::MASK_ALL),
            identity_sig: identity_key.sign(&msg).to_bytes().to_vec(),
            nfc_hash: [0u8; 32],
            bundle: Some(b.public()),
        };
        assert!(full.verify(&HP, &identity_pubkey), "three eggs over a three-scheme bundle");
        // Same bundle, Ed25519-only consent: the claim outruns the proof.
        let mut short = full.clone();
        short.device_sig = b.keypair().eggs(&msg, scheme::MASK_BASE);
        assert!(!short.verify(&HP, &identity_pubkey));
        // Somebody else's bundle under this device's key: refused before any signature is checked.
        let (_, other) = bundles();
        let mut theirs = full.clone();
        theirs.bundle = Some(other.public());
        assert!(!theirs.verify(&HP, &identity_pubkey));
    }

    #[test]
    fn bindreq_verifies_both_signatures() {
        let device = key(6);
        let identity_key = ed25519_dalek::SigningKey::from_bytes(&SEED);
        let identity_pubkey = identity_key.verifying_key().to_bytes();
        let t = 12345i64;
        let msg = bindreq_signing_bytes(&HP, &pk(&device), t);
        use ed25519_dalek::Signer;
        let req = BindRequest {
            device_pubkey: pk(&device),
            t,
            device_sig: device.eggs(&msg, scheme::MASK_BASE),
            identity_sig: identity_key.sign(&msg).to_bytes().to_vec(),
            nfc_hash: [0u8; 32],
            bundle: None,
        };
        assert!(req.verify(&HP, &identity_pubkey));
        // Wrong fleet, wrong identity key, tampered stamp — each leg fails.
        assert!(!req.verify(&[0x11; 32], &identity_pubkey));
        assert!(!req.verify(&HP, &pk(&key(9))));
        let mut stale = req.clone();
        stale.t += 1;
        assert!(!stale.verify(&HP, &identity_pubkey));
    }
}


