//! The attest verdict — after the handle's roots are derived, decide whether this device RESUMES, JOINS an existing fleet, may MINT a new identity, or must wait (docs/pairing-v2.md, docs/peers-are-fgtw.md).
//!
//! One pure function, so every client decides identically: Photon on the desktop, Android and macOS, and ferros's bare-metal Photon (2026-10-28: an attest screen that minted "a new identity" for a handle that already had a fleet, because it never looked the identity up).
//! The inputs are every chain this device can see — the one it holds, the ones LAN peers answered with (`fleet_req` / `fleet_resp`), and the seed's answer — and the output never claims more than they prove.
//!
//! The lamps (pairing v2): [`AttestVerdict::Member`] is GREEN; [`AttestVerdict::JoinOurs`] is RED, waiting on a sponsor; [`AttestVerdict::WrongFleet`] is RED, wrong fleet; [`AttestVerdict::Unreachable`] and [`AttestVerdict::Unverifiable`] are GREY, never a verdict; [`AttestVerdict::Fresh`] is the mint path (the permanence warning, then the retype).

use crate::fleet::{FoldError, MembershipBlob};

/// What the seed (fgtw.org) said when asked for the identity's chain.
pub enum SeedAnswer<'a> {
    /// It holds a chain (not yet trusted — the verdict folds it).
    Chain(&'a MembershipBlob),
    /// It holds no chain for this handle: the only answer that can make a handle fresh.
    NotFound,
    /// It could not be asked (offline, refused, timed out) — silence, never absence.
    Unreachable,
}

/// The decision, from the chains this device could see.
#[derive(Debug, PartialEq)]
pub enum AttestVerdict {
    /// No chain anywhere and the seed answered `NotFound`: a genuine fresh claim — mint, after the permanence warning and the retype.
    Fresh,
    /// The most advanced verified chain at this handle's slot lists this device: resume.
    Member,
    /// A verified chain at this handle's slot exists and this device is not in it: join (pairing words → a sponsor's bind) — never mint over it.
    JoinOurs,
    /// The only verified chains claim a different slot than the handle's — a relay or peer answered with another fleet.
    WrongFleet,
    /// No chain was seen and the seed could not be asked: nothing is known, so nothing is decided (claiming needs the lookup).
    Unreachable,
    /// A chain was seen but failed verification (corrupt, partial, a read lag): indeterminate — retry, never brand the handle taken or fresh.
    Unverifiable(FoldError),
}

/// Decide the attest branch for `handle_proof` and this `device` (its Ed25519 public key).
/// `held` is the chain this device keeps on disk, `peers` the chains LAN peers answered with, `seed` the seed's answer — every chain is folded (verified) here, none is trusted as given.
/// "Ours" is the slot: a chain whose genesis claims `handle_proof`. Identity is handle-derived, so a chain cannot be proven owned beyond that (docs/fleet-identity-remediation.md); the slot match is the honest signal, exactly as Photon's probe decided before this moved here.
/// Among our chains the most advanced decides (the most ops; a stale held chain loses to a longer one that removed this device), and a tie goes to the seed's.
pub fn attest_verdict(handle_proof: &[u8; 32], device: &[u8; 32], held: Option<&MembershipBlob>, peers: &[MembershipBlob], seed: SeedAnswer) -> AttestVerdict {
    let seed_chain = match seed {
        SeedAnswer::Chain(c) => Some(c),
        _ => None,
    };
    // The seed's chain first, so a tie in length keeps it.
    let candidates = seed_chain.into_iter().chain(held).chain(peers.iter());
    // The most advanced verified chain at our slot: (its op count, whether this device is a member).
    let mut ours: Option<(usize, bool)> = None;
    let mut wrong_slot = false;
    let mut unverifiable: Option<FoldError> = None;
    for chain in candidates {
        match chain.fold() {
            Ok(members) => {
                if chain.genesis_handle_proof() == Some(*handle_proof) {
                    let len = chain.ops.len();
                    if ours.map_or(true, |(best, _)| len > best) {
                        ours = Some((len, members.contains(device)));
                    }
                } else {
                    wrong_slot = true;
                }
            }
            // A chain with no ops is no claim: the slot was allocated but never written (a wipe), the same as no chain.
            Err(FoldError::Empty) => {}
            Err(e) => {
                if unverifiable.is_none() {
                    unverifiable = Some(e);
                }
            }
        }
    }
    if let Some((_, member)) = ours {
        return if member { AttestVerdict::Member } else { AttestVerdict::JoinOurs };
    }
    if wrong_slot {
        return AttestVerdict::WrongFleet;
    }
    if let Some(e) = unverifiable {
        return AttestVerdict::Unverifiable(e);
    }
    match seed {
        // The seed's chain folded to Empty: no one holds the handle.
        SeedAnswer::NotFound | SeedAnswer::Chain(_) => AttestVerdict::Fresh,
        SeedAnswer::Unreachable => AttestVerdict::Unreachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::{bindreq_signing_bytes, scheme};
    use crate::keys::Keypair;
    use crate::pq::FleetSigner;

    const HP: [u8; 32] = [0xab; 32];
    const OTHER_HP: [u8; 32] = [0x5a; 32];
    const SEED: [u8; 32] = [0xcd; 32];

    fn key(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }
    fn pk(k: &Keypair) -> [u8; 32] {
        k.public.to_bytes()
    }
    /// A chain at `hp` founded by `a`, with `b` added when given.
    fn chain(hp: [u8; 32], a: &Keypair, b: Option<&Keypair>) -> MembershipBlob {
        let mut blob = MembershipBlob::genesis_v2(a, hp, &SEED, 100);
        if let Some(b) = b {
            let consent = b.eggs(&bindreq_signing_bytes(&hp, &pk(b), 190), scheme::MASK_BASE);
            blob.add(a, pk(b), 200, 190, consent);
        }
        blob
    }

    #[test]
    fn only_the_seeds_not_found_makes_a_handle_fresh() {
        let me = pk(&key(1));
        assert_eq!(attest_verdict(&HP, &me, None, &[], SeedAnswer::NotFound), AttestVerdict::Fresh);
        // Silence is not absence: an unreachable seed with nothing seen decides nothing — the ferros screen minted here.
        assert_eq!(attest_verdict(&HP, &me, None, &[], SeedAnswer::Unreachable), AttestVerdict::Unreachable);
    }

    #[test]
    fn a_chain_listing_this_device_resumes_and_one_without_it_joins() {
        let (a, b) = (key(1), key(2));
        let with_b = chain(HP, &a, Some(&b));
        let founder_only = chain(HP, &a, None);
        assert_eq!(attest_verdict(&HP, &pk(&b), None, &[], SeedAnswer::Chain(&with_b)), AttestVerdict::Member);
        assert_eq!(attest_verdict(&HP, &pk(&b), None, &[], SeedAnswer::Chain(&founder_only)), AttestVerdict::JoinOurs);
    }

    #[test]
    fn a_peers_chain_joins_even_when_the_seed_is_unreachable() {
        let (a, b) = (key(1), key(2));
        let peer = chain(HP, &a, None);
        assert_eq!(attest_verdict(&HP, &pk(&b), None, core::slice::from_ref(&peer), SeedAnswer::Unreachable), AttestVerdict::JoinOurs);
        // …and the held chain resumes offline.
        let held = chain(HP, &a, Some(&b));
        assert_eq!(attest_verdict(&HP, &pk(&b), Some(&held), &[], SeedAnswer::Unreachable), AttestVerdict::Member);
    }

    #[test]
    fn the_most_advanced_chain_decides() {
        let (a, b) = (key(1), key(2));
        // A held founder-only chain is stale beside the seed's, which added this device.
        let stale = chain(HP, &a, None);
        let current = chain(HP, &a, Some(&b));
        assert_eq!(attest_verdict(&HP, &pk(&b), Some(&stale), &[], SeedAnswer::Chain(&current)), AttestVerdict::Member);
    }

    #[test]
    fn a_chain_at_another_slot_is_the_wrong_fleet() {
        let (a, b) = (key(1), key(2));
        let elsewhere = chain(OTHER_HP, &a, None);
        assert_eq!(attest_verdict(&HP, &pk(&b), None, &[], SeedAnswer::Chain(&elsewhere)), AttestVerdict::WrongFleet);
        // …but our own slot's chain outranks it.
        let ours = chain(HP, &a, None);
        assert_eq!(attest_verdict(&HP, &pk(&b), Some(&ours), &[], SeedAnswer::Chain(&elsewhere)), AttestVerdict::JoinOurs);
    }

    #[test]
    fn an_empty_chain_is_no_claim() {
        let empty = MembershipBlob::default();
        assert_eq!(attest_verdict(&HP, &pk(&key(1)), None, &[], SeedAnswer::Chain(&empty)), AttestVerdict::Fresh);
    }
}
