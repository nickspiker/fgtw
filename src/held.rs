//! The chains and fan-outs a device HOLDS (photon docs/peers-are-fgtw.md: peers first, the seed last; Nick 2026-10-26: "not sure why we have to rely on this fgtw.org unless everyone on our list does not respond").
//!
//! Every membership chain a device has seen that FOLDS (its own fleet's and every contact's) is kept by the handle proof its genesis claims, and so is the newest fan-out it sealed or was handed. The seed (fgtw.org) is asked first by every call here, but a copy in hand answers when it does not, and a copy a PEER hands over (`fleet_resp`) is adopted by the same rule a seed copy is. Nothing here trusts bytes: a caller adopts only what folds and claims the slot it asked for.
//!
//! Where the held set lives is the embedding's: Photon keeps it in a process-wide mutex and its vault, a ferros service in its own state. Both implement [`ChainHold`] / [`FanoutHold`] over the plain [`HeldChains`] / [`HeldFanouts`] sets, so the rule that picks between two copies is written once.
//!
//! Moved from photon src/network/fgtw/fleet.rs (2026-11-08), behaviour unchanged.

use crate::client::{self, FgtwTransport};
use crate::fleet::MembershipBlob;
use crate::keys::Keypair;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// A key's first four bytes in hex: the fingerprint the logs use, never a whole key.
pub fn fp(k: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in &k[..4] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Should `new` replace `old` as the held copy of one fleet's chain? Both must have folded already.
/// An extension wins over its prefix; between forks (two members appended at once with no seed to serialise them) the longer valid chain wins, then the newer tip, then the lower head hash: deterministic, so every holder converges on the same head without a server.
pub fn prefer(new: &MembershipBlob, old: &MembershipBlob) -> bool {
    if new.extends(old) {
        return new.ops.len() > old.ops.len();
    }
    if old.extends(new) {
        return false;
    }
    let (nt, ot) = (new.ops.last().map(|o| o.eagle_time).unwrap_or(0), old.ops.last().map(|o| o.eagle_time).unwrap_or(0));
    (new.ops.len(), nt, core::cmp::Reverse(new.head())) > (old.ops.len(), ot, core::cmp::Reverse(old.head()))
}

/// The chains a device holds, by the handle proof each genesis claims. A linear list: a device holds its own fleet's chain and its contacts', a few dozen at most, and every lookup is one pass.
#[derive(Default, Clone)]
pub struct HeldChains(Vec<([u8; 32], MembershipBlob)>);

impl HeldChains {
    pub const fn new() -> Self {
        HeldChains(Vec::new())
    }

    /// The chain held for `handle_proof`, if any.
    pub fn get(&self, handle_proof: &[u8; 32]) -> Option<&MembershipBlob> {
        self.0.iter().find(|(hp, _)| hp == handle_proof).map(|(_, b)| b)
    }

    /// Keep `blob` as the held copy of its fleet's chain if it is preferred over what is held (or nothing is). Returns whether the held copy changed. The caller has folded it.
    pub fn hold(&mut self, blob: &MembershipBlob) -> bool {
        let Some(hp) = blob.genesis_handle_proof() else { return false };
        match self.0.iter_mut().find(|(h, _)| *h == hp) {
            Some((_, old)) => {
                if prefer(blob, old) {
                    *old = blob.clone();
                    true
                } else {
                    false
                }
            }
            None => {
                self.0.push((hp, blob.clone()));
                true
            }
        }
    }
}

/// The embedding's held chains: read one, offer one. `&self` so a process-wide mutex (Photon) and a single-threaded cell (a ferros service) both implement it.
pub trait ChainHold {
    fn held(&self, handle_proof: &[u8; 32]) -> Option<MembershipBlob>;
    /// Offer `blob` (folded already) as the held copy of its fleet's chain; whether the held copy changed.
    fn hold(&self, blob: &MembershipBlob) -> bool;
}

impl ChainHold for core::cell::RefCell<HeldChains> {
    fn held(&self, handle_proof: &[u8; 32]) -> Option<MembershipBlob> {
        self.borrow().get(handle_proof).cloned()
    }
    fn hold(&self, blob: &MembershipBlob) -> bool {
        self.borrow_mut().hold(blob)
    }
}

#[cfg(feature = "std")]
impl ChainHold for std::sync::Mutex<HeldChains> {
    fn held(&self, handle_proof: &[u8; 32]) -> Option<MembershipBlob> {
        self.lock().ok()?.get(handle_proof).cloned()
    }
    fn hold(&self, blob: &MembershipBlob) -> bool {
        self.lock().map(|mut h| h.hold(blob)).unwrap_or(false)
    }
}

/// A chain handed over by a PEER (a `fleet_resp` frame, or the embedding's own vault copy at attest): parse, fold, require it to claim the slot `handle_proof`, hold it if preferred. Returns the fold facts (the chain, members, tip eagle time, genesis hash) or why it was refused. Who sent it does not matter: the chain is self-verifying (every op signed by a member, consent eggs inside).
pub fn adopt_chain_bytes(h: &impl ChainHold, handle_proof: &[u8; 32], bytes: &[u8]) -> Result<(MembershipBlob, Vec<[u8; 32]>, i64, [u8; 32]), String> {
    let blob = MembershipBlob::from_vsf_bytes(bytes)?;
    if blob.genesis_handle_proof() != Some(*handle_proof) {
        return Err("chain claims a different handle".into());
    }
    let (members, tip) = blob.fold_with_ts().map_err(|e| format!("chain does not fold: {e:?}"))?;
    h.hold(&blob);
    let genesis = blob.genesis_hash().unwrap_or([0u8; 32]);
    Ok((blob, members, tip, genesis))
}

/// The identity's fleet chain: the seed's copy when it answers, else the copy held; `None` only when neither exists. A seed copy that folds is held; where the two differ, [`prefer`] picks (a local extension the seed never received outranks the seed's prefix). Parsed but not trusted until `fold()`: a caller that trusts the result folds it.
pub fn fetch<T: FgtwTransport>(t: &T, h: &impl ChainHold, handle_proof: &[u8; 32]) -> Result<Option<MembershipBlob>, String> {
    let held = h.held(handle_proof);
    match client::fetch(t, handle_proof) {
        Ok(Some(seed)) => {
            if seed.fold().is_ok() {
                h.hold(&seed);
            }
            Ok(Some(match held {
                Some(hc) if hc.fold().is_ok() && !prefer(&seed, &hc) => hc,
                _ => seed,
            }))
        }
        // The seed holds nothing: a verdict only when nothing is held either; a seed that lost a record is not an identity's death while a device still carries the chain.
        Ok(None) => Ok(held),
        Err(e) => match held {
            Some(hc) => {
                crate::log(&format!("FLEET: seed unreachable ({}) — serving the held chain for {}", e, fp(handle_proof)));
                Ok(Some(hc))
            }
            None => Err(e),
        },
    }
}

/// Publish a new (or extended) chain to the seed (`stale` reason → `"fleet: stale"` for the retry loop). The blob is held first, whatever the seed says: the chain is the fleet's, the seed mirrors it.
pub fn publish<T: FgtwTransport>(t: &T, h: &impl ChainHold, blob: &MembershipBlob) -> Result<(), String> {
    h.hold(blob);
    client::publish(t, blob)
}

/// Whether `me` folds as a current member of the chain held for `handle_proof`.
pub fn held_member(h: &impl ChainHold, handle_proof: &[u8; 32], me: &[u8; 32]) -> bool {
    h.held(handle_proof).and_then(|c| c.fold().ok()).is_some_and(|m| m.contains(me))
}

/// The fan-out blobs a device holds, by handle: (handle proof, revision, blob bytes), the newest grow or mint it sealed or was handed. A revision floor for the next grow when the seed is unreachable, and the copy a sibling's `fanout_resp` is compared against.
#[derive(Default, Clone)]
pub struct HeldFanouts(Vec<([u8; 32], u64, Vec<u8>)>);

impl HeldFanouts {
    pub const fn new() -> Self {
        HeldFanouts(Vec::new())
    }

    /// Keep a fan-out blob as the held copy for `handle_proof` if its revision is at least the held one's.
    pub fn hold(&mut self, handle_proof: &[u8; 32], revision: u64, blob: &[u8]) {
        match self.0.iter_mut().find(|(h, _, _)| h == handle_proof) {
            Some(e) => {
                if revision >= e.1 {
                    e.1 = revision;
                    e.2 = blob.to_vec();
                }
            }
            None => self.0.push((*handle_proof, revision, blob.to_vec())),
        }
    }

    /// The held fan-out's revision for `handle_proof` (0 = none held).
    pub fn revision(&self, handle_proof: &[u8; 32]) -> u64 {
        self.0.iter().find(|(hp, _, _)| hp == handle_proof).map(|e| e.1).unwrap_or(0)
    }

    /// The held fan-out blob for `handle_proof`, if any.
    pub fn blob(&self, handle_proof: &[u8; 32]) -> Option<&[u8]> {
        self.0.iter().find(|(hp, _, _)| hp == handle_proof).map(|e| e.2.as_slice())
    }
}

/// The embedding's held fan-outs.
pub trait FanoutHold {
    fn held_revision(&self, handle_proof: &[u8; 32]) -> u64;
    fn hold_fanout(&self, handle_proof: &[u8; 32], revision: u64, blob: &[u8]);
}

impl FanoutHold for core::cell::RefCell<HeldFanouts> {
    fn held_revision(&self, handle_proof: &[u8; 32]) -> u64 {
        self.borrow().revision(handle_proof)
    }
    fn hold_fanout(&self, handle_proof: &[u8; 32], revision: u64, blob: &[u8]) {
        self.borrow_mut().hold(handle_proof, revision, blob)
    }
}

#[cfg(feature = "std")]
impl FanoutHold for std::sync::Mutex<HeldFanouts> {
    fn held_revision(&self, handle_proof: &[u8; 32]) -> u64 {
        self.lock().map(|h| h.revision(handle_proof)).unwrap_or(0)
    }
    fn hold_fanout(&self, handle_proof: &[u8; 32], revision: u64, blob: &[u8]) {
        if let Ok(mut h) = self.lock() {
            h.hold(handle_proof, revision, blob)
        }
    }
}

/// GROW the fan-out HELD-FIRST: seal the current key to `members` at the next revision (the seed's revision + 1 when it answers, else the held one + 1), hold the blob, mirror it to the seed as a best effort, and return (revision, blob) for the caller to hand to the newcomer and the siblings as a `fanout_resp`. Never a mint. A seed that holds a DIFFERENT key fingerprint is a rotation this device missed: the grow is refused, since sealing a stale key to the newcomer would hand it a dead key.
pub fn fanout_grow_held<T: FgtwTransport>(
    t: &T,
    fh: &impl FanoutHold,
    handle_proof: &[u8; 32],
    signer: &impl crate::pq::FleetSigner,
    held_key: &[u8; 32],
    members: &[[u8; 32]],
    identity_seed: &[u8; 32],
) -> Result<(u64, Vec<u8>), String> {
    let kfp = crate::fanout::fleet_key_fingerprint(held_key);
    let seed = match client::fetch_fanout(t, handle_proof) {
        Ok(Some((revision, seed_kfp, _, _))) => {
            if seed_kfp != kfp {
                return Err("fanout: held key is not the published key — grow refused (a rotation this device missed)".into());
            }
            Some(revision)
        }
        Ok(None) => None,
        Err(e) => {
            crate::log(&format!("FANOUT: seed unreachable for the grow ({}) — growing from the held revision", e));
            None
        }
    };
    // WHY the max: the next revision must pass both the seed's monotonic guard and every holder's, so it steps past the higher of the two.
    let revision = seed.unwrap_or(0).max(fh.held_revision(handle_proof)) + 1;
    let wraps = crate::fanout::fanout_seal(handle_proof, held_key, members, identity_seed)?;
    let me = signer.keypair().public.to_bytes();
    let epoch_pub = crate::pq::epoch_bundle(held_key).public();
    let blob = crate::fanout::fanout_to_bytes(revision, &kfp, &me, &epoch_pub, &wraps);
    fh.hold_fanout(handle_proof, revision, &blob);
    match client::post_fanout(t, handle_proof, signer, revision, held_key, &wraps) {
        Ok(()) => crate::log(&format!("FANOUT: grew to revision {} ({} ira(s) wrapped) — held and mirrored to the seed", revision, members.len())),
        Err(e) => crate::log(&format!("FANOUT: grew to revision {} ({} ira(s) wrapped) — held; the seed mirror failed ({}), the fan-out reaches the fleet over the mesh", revision, members.len(), e)),
    }
    Ok((revision, blob))
}

/// Open a fan-out blob handed over (a `fanout_resp`) with this device's ira keypair and the identity seed: `Ok(Some((revision, key)))` when it holds a wrap for us and its header's epoch bundle is the one the key derives (a header we cannot reproduce is refused), `Ok(None)` when no wrap is ours, `Err` when the blob does not parse. A blob that opens is held.
pub fn fanout_open_blob(fh: &impl FanoutHold, handle_proof: &[u8; 32], blob: &[u8], device_key: &Keypair, identity_seed: &[u8; 32]) -> Result<Option<(u64, [u8; 32])>, String> {
    let f = crate::fanout::fanout_from_bytes_full(blob)?;
    let Some(k) = crate::fanout::fanout_open(handle_proof, &f.kfp, &f.wraps, device_key, identity_seed) else { return Ok(None) };
    if crate::pq::epoch_bundle(&k).public() != f.epoch_pub {
        return Err("fanout: header epoch bundle does not match the fleet key — tampered header".into());
    }
    fh.hold_fanout(handle_proof, f.revision, blob);
    Ok(Some((f.revision, k)))
}
