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

use crate::keys::Keypair;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use vsf::VsfType;

/// Signature-scheme tag (the egg label). Wire-stable: append, never renumber.
pub mod scheme {
    pub const ED25519: u8 = 0;
    // Reserved for the additive PQ eggs:
    // pub const FALCON512: u8 = 1;
    // pub const SPHINCS_PLUS: u8 = 2;
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
}

impl OpKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(OpKind::Genesis),
            1 => Some(OpKind::Add),
            2 => Some(OpKind::Remove),
            3 => Some(OpKind::Checkpoint),
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
    /// ADD ONLY: the added device's OWN signature over [`bindreq_signing_bytes`]`(handle_proof, device_pubkey, consent_t)` — the subject consenting to its membership (bilateral add; the sovereign-records rule). NOT a signature over this op's signing bytes, so it's data the sponsor's egg commits to, like the genesis identity binding. Empty on genesis/remove ops.
    pub consent_sig: Vec<u8>,
    /// CHECKPOINT ONLY: the monotonic checkpoint sequence number, strictly prev+1 starting at 1 — the epoch index `k` the fleet's key schedule advances on. 0 elsewhere.
    pub ckpt_k: u64,
    /// CHECKPOINT ONLY: blake3 commitment to the SECRET settled-root (the merkle root over the fleet's settled message rows) — the chain carries only this preimage-hiding commitment, never the root. `[0; 32]` elsewhere.
    pub ckpt_commit: [u8; 32],
    /// CHECKPOINT ONLY: the fan-out fleet-key epoch this checkpoint folds into its derivation, so a catching-up sibling knows WHICH fleet key enters `epoch_k`. Already-public information (the fan-out slot shows its epoch). 0 elsewhere.
    pub ckpt_fanout_epoch: u64,
    /// Signature eggs over [`FleetOp::signing_bytes`]; every listed egg must verify (the egg-list rule).
    pub sigs: Vec<Egg>,
}

/// Domain tag so a fleet-op signature can never be confused with any other signature in the system. v1 = the sovereign-records break (consent egg on Add, self-departure-only Remove) — flag-day, v0 chains don't fold.
const SIGNING_DOMAIN: &[u8] = b"PHOTON_FLEET_OP_v1";

/// The exact bytes a binding request signs: the device attests "I consent to join fleet `handle_proof`" at time `t`. Signed TWICE at the registry (device key + `Ed25519(identity_seed)` — the write gate), and the device signature is re-verified forever after as the Add op's `consent_sig` (the fold gate). Lives here rather than `pair` because the worker folds chains without the `fanout` feature.
pub fn bindreq_signing_bytes(handle_proof: &[u8; 32], device_pubkey: &[u8; 32], t: i64) -> Vec<u8> {
    let mut v = Vec::with_capacity(18 + 64 + 8);
    v.extend_from_slice(b"PHOTON_BINDREQ_v1");
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
    /// The device key's signature over [`bindreq_signing_bytes`] — the consent (becomes `consent_sig`).
    pub device_sig: Vec<u8>,
    /// `Ed25519(identity_seed)`'s signature over the same bytes — the registry write gate (only the handle's owner can enter the set). Checked against the chain's genesis identity pubkey; never enters the chain itself.
    pub identity_sig: Vec<u8>,
    /// NFC instant-add commitment: `pair::nfc_secret_hash(S, device_pubkey, t)` where `S` is the 32-byte random secret the joiner serves over the NFC tap. All-zero = no NFC offered. DELIBERATELY OUTSIDE `bindreq_signing_bytes` — those bytes are the chain's consent verification forever (every future fold re-checks consent_sig against them), so a new field there is a protocol-wide flag-day; the binding lives inside the keyed hash instead (recomputed per candidate with ITS pubkey+t), so a tampered/transplanted hash simply never matches — fail-closed, never wrong-device.
    pub nfc_hash: [u8; 32],
}

impl BindRequest {
    /// Verify both signatures against this fleet: the device's own consent, and the identity co-signature under `identity_pubkey` (the genesis key). The worker gates writes with this; the old device re-checks at list time.
    pub fn verify(&self, handle_proof: &[u8; 32], identity_pubkey: &[u8; 32]) -> bool {
        let msg = bindreq_signing_bytes(handle_proof, &self.device_pubkey, self.t);
        verify_ed25519(&self.device_pubkey, &msg, &self.device_sig)
            && verify_ed25519(identity_pubkey, &msg, &self.identity_sig)
    }
}

impl FleetOp {
    /// The exact bytes every egg signs: domain + all content fields, fixed-width and deterministic.
    /// Excludes the sigs themselves (you can't sign the signature) — but INCLUDES `consent_sig`, which is a signature over DIFFERENT bytes (the binding request), so the sponsor's egg commits to the exact consent it saw.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(SIGNING_DOMAIN.len() + 32 + 32 + 1 + 32 + 8 + 32 + 32 + 8 + self.consent_sig.len());
        b.extend_from_slice(SIGNING_DOMAIN);
        b.extend_from_slice(&self.handle_proof);
        b.extend_from_slice(&self.prev_hash);
        b.push(self.kind as u8);
        b.extend_from_slice(&self.device_pubkey);
        b.extend_from_slice(&self.eagle_time.to_le_bytes());
        b.extend_from_slice(&self.signer_pubkey);
        b.extend_from_slice(&self.identity_pubkey); // bound in so the device sig also commits to the identity key (it can't be swapped)
        b.extend_from_slice(&self.consent_t.to_le_bytes());
        b.extend_from_slice(&self.consent_sig); // bound in so the consent can't be swapped under the sponsor's egg
        // Checkpoint fields append KIND-GATED: every pre-checkpoint op kind keeps byte-identical signing bytes, so chains signed by pre-2026-08-12 builds still verify — an unconditional append would break every deployed fleet's signatures at once.
        if self.kind == OpKind::Checkpoint {
            b.extend_from_slice(&self.ckpt_k.to_le_bytes());
            b.extend_from_slice(&self.ckpt_commit);
            b.extend_from_slice(&self.ckpt_fanout_epoch.to_le_bytes());
        }
        b
    }

    /// The chain link for the NEXT op's `prev_hash`: a hash over the signed content AND every signature, so the whole op (including who signed it and how) is immutable once chained.
    pub fn chain_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.signing_bytes());
        for egg in &self.sigs {
            h.update(&[egg.scheme]);
            h.update(&egg.sig);
        }
        h.update(&self.identity_sig);
        *h.finalize().as_bytes()
    }

    /// Verify the GENESIS identity binding: `identity_sig` is a valid signature over [`FleetOp::signing_bytes`] by `identity_pubkey`.
    /// This proves the founder held `identity_seed` (the handle's secret preimage); a peer who knows the handle additionally checks `identity_pubkey == Ed25519(identity_seed)` via [`MembershipBlob::genesis_identity_matches`].
    fn verify_identity_binding(&self) -> bool {
        self.identity_pubkey != [0u8; 32]
            && self.identity_sig.len() == 64
            && verify_ed25519(&self.identity_pubkey, &self.signing_bytes(), &self.identity_sig)
    }

    /// Verify the ADD consent binding: `consent_sig` is the ADDED device's own signature over its binding request — the subject signing its own membership. Forging it requires the device's private key, which is what makes conscription (and the ownership squat) impossible.
    fn verify_consent(&self) -> bool {
        self.consent_sig.len() == 64
            && verify_ed25519(
                &self.device_pubkey,
                &bindreq_signing_bytes(&self.handle_proof, &self.device_pubkey, self.consent_t),
                &self.consent_sig,
            )
    }

    /// Verify every signature egg against `signer_pubkey`.
    /// v1 understands Ed25519; an op carrying an egg whose scheme this build doesn't implement is REJECTED (fail-closed — never silently accept an unverifiable op, the no-fork rule).
    /// An empty egg list is invalid.
    pub fn verify_sigs(&self) -> bool {
        if self.sigs.is_empty() {
            return false;
        }
        let msg = self.signing_bytes();
        for egg in &self.sigs {
            let ok = match egg.scheme {
                scheme::ED25519 => verify_ed25519(&self.signer_pubkey, &msg, &egg.sig),
                _ => false, // unknown scheme → fail closed
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
    /// A Remove signed by anyone but the departing device itself — expulsion doesn't exist (self-signed departure only).
    RemoveNotSelfSigned { index: usize },
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
        if self.ops.is_empty() {
            return Err(FoldError::Empty);
        }
        let mut members: Vec<[u8; 32]> = Vec::new();
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
            if op.kind != OpKind::Add && (op.consent_t != 0 || !op.consent_sig.is_empty()) {
                return Err(FoldError::StrayConsent { index: i });
            }
            if op.kind != OpKind::Checkpoint && (op.ckpt_k != 0 || op.ckpt_commit != [0u8; 32] || op.ckpt_fanout_epoch != 0) {
                return Err(FoldError::StrayCheckpoint { index: i });
            }
            if !op.verify_sigs() {
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
                    // The genesis MUST be co-signed by the identity key — this is the link that closes the chain onto the handle's owner.
                    if !op.verify_identity_binding() {
                        return Err(FoldError::BadIdentityBinding);
                    }
                    members.push(op.device_pubkey);
                }
                OpKind::Add => {
                    if !members.contains(&op.signer_pubkey) {
                        return Err(FoldError::SignerNotMember { index: i });
                    }
                    if members.contains(&op.device_pubkey) {
                        return Err(FoldError::AddExistingMember { index: i });
                    }
                    // Bilateral: the added device must have consented with its own key (the subject signs — sovereign records).
                    if !op.verify_consent() {
                        return Err(FoldError::BadConsent { index: i });
                    }
                    // The consent must be from THIS ceremony, not a departed device's replayed past.
                    if (op.eagle_time - op.consent_t).abs() > CONSENT_WINDOW_OSC {
                        return Err(FoldError::ConsentStale { index: i });
                    }
                    members.push(op.device_pubkey);
                }
                OpKind::Remove => {
                    if !members.contains(&op.signer_pubkey) {
                        return Err(FoldError::SignerNotMember { index: i });
                    }
                    // Self-signed departure ONLY — expulsion is not a verb this chain has; eviction lives at the key/provision layer.
                    if op.signer_pubkey != op.device_pubkey {
                        return Err(FoldError::RemoveNotSelfSigned { index: i });
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
            expected_prev = op.chain_hash();
        }
        Ok(members)
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

    /// Peer check: does the genesis identity key match `Ed25519(identity_seed)` — the key a contact derives from the handle?
    /// `fold()` already proves the genesis is self-consistently identity-signed; this additionally proves it's THIS handle's owner, so a contact who knows your handle can't be fooled by a squatted fleet under your `handle_proof`.
    pub fn genesis_identity_matches(&self, identity_seed: &[u8; 32]) -> bool {
        let expect = ed25519_dalek::SigningKey::from_bytes(identity_seed).verifying_key().to_bytes();
        self.ops.first().map(|op| op.identity_pubkey == expect).unwrap_or(false)
    }

    /// The genesis identity pubkey (the key `identity_sig`s verify under) — what the worker checks a binding request's identity co-signature against.
    pub fn genesis_identity_pubkey(&self) -> Option<[u8; 32]> {
        self.ops.first().map(|op| op.identity_pubkey)
    }

    // ── builders (sign with the local device key; the device is the only thing that can authorise) ──

    /// Start a brand-new fleet: the founding device self-signs itself in, bound to `handle_proof`, and the identity key `Ed25519(identity_seed)` co-signs to prove the founder owns the handle. Both ownerships are already present, so genesis needs no separate consent.
    pub fn genesis(
        device_key: &Keypair,
        handle_proof: [u8; 32],
        identity_seed: &[u8; 32],
        eagle_time: i64,
    ) -> Self {
        let pk = device_key.public.to_bytes();
        let identity_key = ed25519_dalek::SigningKey::from_bytes(identity_seed);
        let op = sign_op(
            device_key,
            handle_proof,
            [0u8; 32],
            OpKind::Genesis,
            pk,
            eagle_time,
            pk,
            Some(&identity_key),
            None,
            None,
        );
        MembershipBlob { ops: vec![op] }
    }

    /// Append an Add: the sponsor `device_key` (a current member) signs, carrying the added device's consent — `(consent_t, consent_sig)` straight off its binding request. Without valid consent the result won't fold.
    pub fn add(&mut self, device_key: &Keypair, new_device: [u8; 32], eagle_time: i64, consent_t: i64, consent_sig: Vec<u8>) {
        let hp = self.handle_proof().unwrap_or([0u8; 32]);
        let op = sign_op(
            device_key,
            hp,
            self.head(),
            OpKind::Add,
            new_device,
            eagle_time,
            device_key.public.to_bytes(),
            None,
            Some((consent_t, consent_sig)),
            None,
        );
        self.ops.push(op);
    }

    /// Append this device's own departure — the ONLY remove the fold accepts (`signer == device`). Expelling another device is not a chain verb; eviction is withholding at the key layer.
    pub fn depart(&mut self, device_key: &Keypair, eagle_time: i64) {
        let hp = self.handle_proof().unwrap_or([0u8; 32]);
        let pk = device_key.public.to_bytes();
        let op = sign_op(
            device_key,
            hp,
            self.head(),
            OpKind::Remove,
            pk,
            eagle_time,
            pk,
            None,
            None,
            None,
        );
        self.ops.push(op);
    }

    /// Append a Checkpoint: any current member pins epoch `k` with the settled-root commitment and the fan-out epoch it folds. Single winner per k by the same `extends()` forward-only discipline every append rides — a loser's push fails the extension check and it re-derives against the winner.
    pub fn checkpoint(&mut self, device_key: &Keypair, eagle_time: i64, k: u64, commit: [u8; 32], fanout_epoch: u64) {
        let hp = self.handle_proof().unwrap_or([0u8; 32]);
        let pk = device_key.public.to_bytes();
        let op = sign_op(
            device_key,
            hp,
            self.head(),
            OpKind::Checkpoint,
            pk,
            eagle_time,
            pk,
            None,
            None,
            Some((k, commit, fanout_epoch)),
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
            let mut values = vec![
                VsfType::hP(op.handle_proof.to_vec()),
                VsfType::hb(op.prev_hash.to_vec()),
                VsfType::u(op.kind as usize, false),
                VsfType::ke(op.device_pubkey.to_vec()),
                VsfType::e(vsf::types::EtType::e6(op.eagle_time)),
                VsfType::ke(op.signer_pubkey.to_vec()),
            ];
            if op.kind == OpKind::Genesis {
                values.push(VsfType::ke(op.identity_pubkey.to_vec()));
                values.push(VsfType::ge(op.identity_sig.clone()));
            }
            if op.kind == OpKind::Add {
                values.push(VsfType::e(vsf::types::EtType::e6(op.consent_t)));
                values.push(VsfType::ge(op.consent_sig.clone()));
            }
            if op.kind == OpKind::Checkpoint {
                values.push(VsfType::u(op.ckpt_k as usize, false));
                values.push(VsfType::hb(op.ckpt_commit.to_vec()));
                values.push(VsfType::u(op.ckpt_fanout_epoch as usize, false));
            }
            for egg in &op.sigs {
                values.push(VsfType::u(egg.scheme as usize, false));
                values.push(VsfType::ge(egg.sig.clone()));
            }
            section.add_field_multi("op", values);
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

/// Build + sign one op. Each enabled scheme contributes an egg over the op's signing bytes; v1 = Ed25519. `consent` = the added device's `(t, binding-request signature)`, Add only. `checkpoint` = `(k, commit, fanout_epoch)`, Checkpoint only.
#[allow(clippy::too_many_arguments)]
fn sign_op(
    device_key: &Keypair,
    handle_proof: [u8; 32],
    prev_hash: [u8; 32],
    kind: OpKind,
    device_pubkey: [u8; 32],
    eagle_time: i64,
    signer_pubkey: [u8; 32],
    identity: Option<&ed25519_dalek::SigningKey>,
    consent: Option<(i64, Vec<u8>)>,
    checkpoint: Option<(u64, [u8; 32], u64)>,
) -> FleetOp {
    use ed25519_dalek::Signer;
    let identity_pubkey = identity.map(|k| k.verifying_key().to_bytes()).unwrap_or([0u8; 32]);
    let (consent_t, consent_sig) = consent.unwrap_or((0, Vec::new()));
    let (ckpt_k, ckpt_commit, ckpt_fanout_epoch) = checkpoint.unwrap_or((0, [0u8; 32], 0));
    let mut op = FleetOp {
        handle_proof,
        prev_hash,
        kind,
        device_pubkey,
        eagle_time,
        signer_pubkey,
        identity_pubkey,
        identity_sig: Vec::new(),
        consent_t,
        consent_sig,
        ckpt_k,
        ckpt_commit,
        ckpt_fanout_epoch,
        sigs: Vec::new(),
    };
    let msg = op.signing_bytes();
    op.sigs.push(Egg {
        scheme: scheme::ED25519,
        sig: device_key.secret.sign(&msg).to_bytes().to_vec(),
    });
    if let Some(idk) = identity {
        op.identity_sig = idk.sign(&msg).to_bytes().to_vec();
    }
    op
}

/// Decode one positional "op" field's values back into a [`FleetOp`].
fn parse_op(values: &[VsfType]) -> Result<FleetOp, String> {
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
    let mut consent_sig = Vec::new();
    let mut ckpt_k = 0u64;
    let mut ckpt_commit = [0u8; 32];
    let mut ckpt_fanout_epoch = 0u64;
    if kind == OpKind::Genesis {
        identity_pubkey = take_ke32(values.get(6).ok_or("fleet op: genesis missing identity pubkey")?, "identity")?;
        identity_sig = match values.get(7) {
            Some(VsfType::ge(s)) => s.clone(),
            _ => return Err("fleet op: genesis missing identity sig".into()),
        };
        i = 8;
    }
    if kind == OpKind::Add {
        consent_t = match values.get(6) {
            Some(VsfType::e(et)) => et_to_osc(et),
            _ => return Err("fleet op: add missing consent time".into()),
        };
        consent_sig = match values.get(7) {
            Some(VsfType::ge(s)) => s.clone(),
            _ => return Err("fleet op: add missing consent sig".into()),
        };
        i = 8;
    }
    if kind == OpKind::Checkpoint {
        ckpt_k = take_u64(values.get(6).ok_or("fleet op: checkpoint missing k")?, "k")?;
        ckpt_commit = take_hb32(values.get(7).ok_or("fleet op: checkpoint missing commit")?, "commit")?;
        ckpt_fanout_epoch = take_u64(values.get(8).ok_or("fleet op: checkpoint missing fanout epoch")?, "fanout epoch")?;
        i = 9;
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
        handle_proof,
        prev_hash,
        kind,
        device_pubkey,
        eagle_time,
        signer_pubkey,
        identity_pubkey,
        identity_sig,
        consent_t,
        consent_sig,
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

    const HP: [u8; 32] = [0xab; 32];
    const SEED: [u8; 32] = [0xcd; 32]; // stand-in identity_seed for the founder

    fn key(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }
    fn pk(k: &Keypair) -> [u8; 32] {
        k.public.to_bytes()
    }
    /// The added device signs its own binding request — the consent every Add must carry.
    fn consent_for(device: &Keypair, t: i64) -> (i64, Vec<u8>) {
        (t, device.sign(&bindreq_signing_bytes(&HP, &device.public.to_bytes(), t)).to_bytes().to_vec())
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
        let forged = a.sign(&bindreq_signing_bytes(&HP, &pk(&victim), 190)).to_bytes().to_vec();
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
        let expel = sign_op(&a, HP, blob.head(), OpKind::Remove, pk(&b), 300, pk(&a), None, None, None);
        blob.ops.push(expel);
        assert_eq!(blob.fold(), Err(FoldError::RemoveNotSelfSigned { index: 2 }));
    }

    #[test]
    fn genesis_must_be_self_signed_and_first() {
        let a = key(1);
        let b = key(2);
        // A genesis whose signer != device is forged.
        let forged = sign_op(&a, HP, [0u8; 32], OpKind::Genesis, pk(&b), 100, pk(&a), None, None, None);
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
        blob.ops[1] = sign_op(&a2, HP, [1u8; 32], OpKind::Add, pk(&key(7)), 200, pk(&a2), None, Some((t7, s7)), None);
        assert_eq!(blob.fold(), Err(FoldError::BrokenChain { index: 1 }));

        // Swap the consent under the sponsor's egg — consent is in signing_bytes, so the egg breaks.
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let (t, s) = consent_for(&b, 190);
        blob.add(&a, pk(&b), 200, t, s);
        let (t2, s2) = consent_for(&b, 195);
        blob.ops[1].consent_t = t2;
        blob.ops[1].consent_sig = s2;
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

    /// The signature-stability guard for the Checkpoint flag-day: these bytes were generated by the PRE-checkpoint build (2026-08-12, before kind 3 existed). Genesis/Add/Remove signing bytes are kind-gated to exclude the checkpoint fields precisely so this chain — and every fleet chain deployed in the field — keeps verifying. If this test fails, deployed fleets brick on update.
    #[test]
    fn pinned_pre_checkpoint_chain_still_parses_and_folds() {
        const PINNED_HEX: &str = "52c3853c7a330979330962337e6c3404136536237edeb2824c5c006870331f4d0baa0b8e1566fe11128f43a2a4e9483f82a5af4acd27a94e6df043bdc6a37f6862331f4f3f5a57908e2951a9b7d385510994b16ae44ba669157fc37af6b0d700a4f93b6e330128643305666c6565743a6f337e2c623403952c6e3303293e5b286433026f703a6850331fabababababababababababababababababababababababababababababababab2c6862331f00000000000000000000000000000000000000000000000000000000000000002c7533002c6b65331f8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c2c653600000000000000642c6b65331f8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c2c6b65331ffc947730f49eb01427a66e050733294d9e520e545c7a27125a780634e0860a272c6765333f39148ed5a51baf7f765600b277f8ac2fddf445b55ed8c261d3a8eca449a7286614d00939188337bd07f1248654b86bc5c6659f14f9d504ce0fc5fded4b3d30092c7533002c6765333feb2b722e7d441cec833a63f76026ae7aadb29316d0164bfb61d4c2f34866bf3a4e53c5c6d628f12f32613316cabece5e32a53c4b4ff3bb147ccecfd9cc2e580b29286433026f703a6850331fabababababababababababababababababababababababababababababababab2c6862331f934c5a5c68855e63a020b9a8da384f37b3cb0ccf7d6a090c56130cbad4a90d912c7533012c6b65331f8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3942c653600000000000000c82c6b65331f8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c2c653600000000000000be2c6765333f0d5b6753187a455f5f2ae54016ecbc96b082e5d58f2bc768ebe6686baf21f18ad5527b359610eeda8ac917e04f4d92ddc242ed26bbd7bf4cb0f210e7ea292b082c7533002c6765333f1aa37898dea850c91e4c57c133fa3ef49f648f62b96d55b768adba460a463db2a031e1d92e1b923c2490e61ff237490227cc795ce61ae1969f7ee9a3047f240e29286433026f703a6850331fabababababababababababababababababababababababababababababababab2c6862331fbb1daf28635b791d0c66592c912d78bd71ade425974d947601464709b16c65712c7533022c6b65331f8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3942c6536000000000000012c2c6b65331f8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3942c7533002c6765333f75b772ee48e506047eca02a0db47b81d9bb708caa6478172a001eb5cbb8f3cee45de3fcc818477127f87142ced6f4c89fa008d3ca19aa4e4923347a3e7699b09295d";
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
        let op = sign_op(&a, HP, blob.head(), OpKind::Checkpoint, pk(&key(7)), 200, pk(&a), None, None, Some((1, [0x11; 32], 1)));
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
            device_sig: device.sign(&msg).to_bytes().to_vec(),
            identity_sig: identity_key.sign(&msg).to_bytes().to_vec(),
            nfc_hash: [0u8; 32],
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

