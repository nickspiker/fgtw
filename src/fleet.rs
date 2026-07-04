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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Genesis = 0,
    Add = 1,
    Remove = 2,
}

impl OpKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(OpKind::Genesis),
            1 => Some(OpKind::Add),
            2 => Some(OpKind::Remove),
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
    /// The device that SIGNED this op — must have been a member in the previous state (genesis: == device).
    pub signer_pubkey: [u8; 32],
    /// GENESIS ONLY: the identity public key `Ed25519(identity_seed)` — the key only the holder of the handle's secret seed can produce, co-signing the genesis so the fleet is provably founded by the identity owner (not just whoever scraped the public `handle_proof`).
    /// `[0; 32]` on add/remove ops.
    pub identity_pubkey: [u8; 32],
    /// GENESIS ONLY: signature over [`FleetOp::signing_bytes`] by `identity_pubkey`. Empty on add/remove ops.
    pub identity_sig: Vec<u8>,
    /// Signature eggs over [`FleetOp::signing_bytes`]; every listed egg must verify (the egg-list rule).
    pub sigs: Vec<Egg>,
}

/// Domain tag so a fleet-op signature can never be confused with any other signature in the system.
const SIGNING_DOMAIN: &[u8] = b"PHOTON_FLEET_OP_v0";

impl FleetOp {
    /// The exact bytes every egg signs: domain + all content fields, fixed-width and deterministic.
    /// Excludes the sigs themselves (you can't sign the signature).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(SIGNING_DOMAIN.len() + 32 + 32 + 1 + 32 + 8 + 32);
        b.extend_from_slice(SIGNING_DOMAIN);
        b.extend_from_slice(&self.handle_proof);
        b.extend_from_slice(&self.prev_hash);
        b.push(self.kind as u8);
        b.extend_from_slice(&self.device_pubkey);
        b.extend_from_slice(&self.eagle_time.to_le_bytes());
        b.extend_from_slice(&self.signer_pubkey);
        b.extend_from_slice(&self.identity_pubkey); // bound in so the device sig also commits to the identity key (it can't be swapped)
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
    /// Fold the chain to the CURRENT member set, validating every rule along the way.
    /// This is the heart of the design and the part FGTW must mirror exactly: each op must (1) link to the prior op by hash, (2) carry valid signature(s), and (3) be signed by a device that was a member *before* this op (genesis excepted — it's self-signed into an empty set).
    /// Returns the live device pubkeys in insertion order, or the first rule it violated.
    pub fn fold(&self) -> Result<Vec<[u8; 32]>, FoldError> {
        if self.ops.is_empty() {
            return Err(FoldError::Empty);
        }
        let mut members: Vec<[u8; 32]> = Vec::new();
        let mut expected_prev = [0u8; 32];
        let identity = self.ops[0].handle_proof;

        for (i, op) in self.ops.iter().enumerate() {
            if op.handle_proof != identity {
                return Err(FoldError::InconsistentHandleProof { index: i });
            }
            if op.prev_hash != expected_prev {
                return Err(FoldError::BrokenChain { index: i });
            }
            // Structural check before the sig check: only genesis carries an identity binding (and identity_pubkey is in signing_bytes, so a stray one would otherwise surface as a confusing BadSignature).
            if op.kind != OpKind::Genesis && (op.identity_pubkey != [0u8; 32] || !op.identity_sig.is_empty()) {
                return Err(FoldError::StrayIdentityBinding { index: i });
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
                    members.push(op.device_pubkey);
                }
                OpKind::Remove => {
                    if !members.contains(&op.signer_pubkey) {
                        return Err(FoldError::SignerNotMember { index: i });
                    }
                    let before = members.len();
                    members.retain(|m| m != &op.device_pubkey);
                    if members.len() == before {
                        return Err(FoldError::RemoveNonMember { index: i });
                    }
                }
            }
            expected_prev = op.chain_hash();
        }
        Ok(members)
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

    // ── builders (sign with the local device key; the device is the only thing that can authorise) ──

    /// Start a brand-new fleet: the founding device self-signs itself in, bound to `handle_proof`, and the identity key `Ed25519(identity_seed)` co-signs to prove the founder owns the handle.
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
        );
        MembershipBlob { ops: vec![op] }
    }

    /// Append an Add, signed by `device_key` (which must be a current member for the result to fold).
    pub fn add(&mut self, device_key: &Keypair, new_device: [u8; 32], eagle_time: i64) {
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
        );
        self.ops.push(op);
    }

    /// Append a Remove, signed by `device_key` (a current member). A device may remove itself or any other.
    pub fn remove(&mut self, device_key: &Keypair, target_device: [u8; 32], eagle_time: i64) {
        let hp = self.handle_proof().unwrap_or([0u8; 32]);
        let op = sign_op(
            device_key,
            hp,
            self.head(),
            OpKind::Remove,
            target_device,
            eagle_time,
            device_key.public.to_bytes(),
            None,
        );
        self.ops.push(op);
    }

    // ── VSF wire form: section "fleet" with one repeated "op" multi-value field per op (same shape as PhonebookResponse's "peer" fields, so the FGTW worker mirrors the parse with the existing pattern).
    //    Positional op layout: hP(handle_proof) hb(prev) u(kind) ke(device) e6(time) ke(signer), then GENESIS-ONLY ke(identity_pubkey) ge(identity_sig), then (u scheme, ge sig) egg pairs to the end.
    //    The identity pair is gated by kind (known at value index 2), so non-genesis ops carry no waste and the egg tail stays unambiguous. Appending a PQ egg = two more trailing values; nothing before them moves. ──

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
            for egg in &op.sigs {
                values.push(VsfType::u(egg.scheme as usize, false));
                values.push(VsfType::ge(egg.sig.clone()));
            }
            section.add_field_multi("op", values);
        }
        vsf::VsfBuilder::new()
            .creation_time_oscillations(vsf::eagle_time_oscillations())
            .provenance_only()
            .add_section_direct(section)
            .build()
            .map_err(|e| format!("fleet to_vsf: {e}"))
    }

    /// Parse from a complete VSF file.
    /// A malformed op aborts the whole parse (the chain is only meaningful intact); returns the blob for [`fold`] to then validate cryptographically.
    pub fn from_vsf_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (_, header_end) =
            vsf::VsfHeader::decode(bytes).map_err(|e| format!("fleet header: {e}"))?;
        // VsfSection::parse reads from the FULL buffer starting at the header's end offset.
        let mut ptr = header_end;
        let section =
            vsf::VsfSection::parse(bytes, &mut ptr).map_err(|e| format!("fleet section: {e}"))?;

        let mut ops = Vec::new();
        for field in section.get_fields("op") {
            ops.push(parse_op(&field.values)?);
        }
        Ok(MembershipBlob { ops })
    }
}

/// Build + sign one op. Each enabled scheme contributes an egg over the op's signing bytes; v1 = Ed25519.
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
) -> FleetOp {
    use ed25519_dalek::Signer;
    let identity_pubkey = identity.map(|k| k.verifying_key().to_bytes()).unwrap_or([0u8; 32]);
    let mut op = FleetOp {
        handle_proof,
        prev_hash,
        kind,
        device_pubkey,
        eagle_time,
        signer_pubkey,
        identity_pubkey,
        identity_sig: Vec::new(),
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

    // GENESIS carries the identity binding (ke pubkey, ge sig) before the egg pairs; other kinds don't.
    let mut i = 6;
    let mut identity_pubkey = [0u8; 32];
    let mut identity_sig = Vec::new();
    if kind == OpKind::Genesis {
        identity_pubkey = take_ke32(values.get(6).ok_or("fleet op: genesis missing identity pubkey")?, "identity")?;
        identity_sig = match values.get(7) {
            Some(VsfType::ge(s)) => s.clone(),
            _ => return Err("fleet op: genesis missing identity sig".into()),
        };
        i = 8;
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
        sigs,
    })
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

    #[test]
    fn genesis_then_adds_then_remove_folds_to_live_set() {
        let a = key(1);
        let b = key(2);
        let c = key(3);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        assert_eq!(blob.fold().unwrap(), vec![pk(&a)]);
        assert_eq!(blob.handle_proof(), Some(HP));

        blob.add(&a, pk(&b), 200); // a (a member) adds b
        blob.add(&b, pk(&c), 300); // b (now a member) adds c
        assert_eq!(blob.fold().unwrap(), vec![pk(&a), pk(&b), pk(&c)]);

        blob.remove(&c, pk(&a), 400); // c removes a (any member may remove any)
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
        // A stranger (not in the fleet) tries to add a device — must fail at fold.
        blob.add(&stranger, pk(&victim), 200);
        assert_eq!(blob.fold(), Err(FoldError::SignerNotMember { index: 1 }));
    }

    #[test]
    fn genesis_must_be_self_signed_and_first() {
        let a = key(1);
        let b = key(2);
        // A genesis whose signer != device is forged.
        let forged = sign_op(&a, HP, [0u8; 32], OpKind::Genesis, pk(&b), 100, pk(&a), None);
        let blob = MembershipBlob { ops: vec![forged] };
        assert_eq!(blob.fold(), Err(FoldError::GenesisNotSelfSigned));
    }

    #[test]
    fn tampering_breaks_the_chain_or_signature() {
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.add(&a, pk(&b), 200);
        assert!(blob.fold().is_ok());

        // Tamper with the add op's device pubkey AFTER signing → signature no longer covers it.
        blob.ops[1].device_pubkey = pk(&key(7));
        assert_eq!(blob.fold(), Err(FoldError::BadSignature { index: 1 }));

        // Re-sign the tampered op correctly but leave its prev_hash stale → chain breaks instead.
        let a2 = key(1);
        blob.ops[1] = sign_op(&a2, HP, [1u8; 32], OpKind::Add, pk(&key(7)), 200, pk(&a2), None);
        assert_eq!(blob.fold(), Err(FoldError::BrokenChain { index: 1 }));
    }

    #[test]
    fn transplanted_chain_under_wrong_identity_is_rejected() {
        // A valid chain whose later op was re-stamped with a different handle_proof must fail. (Genuine transplant — re-keying ops[1].handle_proof without re-signing — trips the consistency check.)
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.add(&a, pk(&b), 200);
        blob.ops[1].handle_proof = [0x11; 32];
        assert_eq!(blob.fold(), Err(FoldError::InconsistentHandleProof { index: 1 }));
    }

    #[test]
    fn extends_accepts_forward_only() {
        let a = key(1);
        let b = key(2);
        let base = MembershipBlob::genesis(&a, HP, &SEED, 100);
        let mut grown = base.clone();
        grown.add(&a, pk(&b), 200);
        assert!(grown.extends(&base)); // forward extension
        assert!(!base.extends(&grown)); // shorter can't extend longer

        // A divergent branch (different op at the same height) is NOT an extension.
        let mut fork = base.clone();
        fork.add(&a, pk(&key(8)), 200);
        assert!(!fork.extends(&grown) && !grown.extends(&fork));
    }

    #[test]
    fn vsf_round_trips_and_still_folds() {
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.add(&a, pk(&b), 200);
        let bytes = blob.to_vsf_bytes().unwrap();
        let parsed = MembershipBlob::from_vsf_bytes(&bytes).unwrap();
        assert_eq!(parsed, blob);
        assert_eq!(parsed.fold().unwrap(), vec![pk(&a), pk(&b)]);
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
        blob.add(&a, pk(&b), 200);
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
    fn add_op_carrying_identity_fields_is_rejected() {
        let a = key(1);
        let b = key(2);
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        blob.add(&a, pk(&b), 200);
        // Stuff an identity binding onto the add op — only genesis may carry one.
        blob.ops[1].identity_pubkey = [0x77; 32];
        assert_eq!(blob.fold(), Err(FoldError::StrayIdentityBinding { index: 1 }));
    }
}
