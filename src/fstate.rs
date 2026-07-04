//! Fleet shared state — the contact roster codec.
//!
//! The roster is the "who are my friends" half of a fleet's private state.
//! It rides the fleet key: encrypted with it, pushed to a membership-gated slot, pulled + CRDT-merged by every device.
//! A new device that joins pulls the roster and re-CLUTCHes each friend on its own device key (conversation HISTORY + per-device ratchets are a later phase — this phase is the roster only).
//!
//! This module is the data model + codec + merge; the seal-and-push / pull-and-open transport (which needs the fleet key and the network) is the client's job.

/// One syncable friend. The minimal identity a device needs to reconstruct a contact and re-CLUTCH: who they are (handle + proof + hash) plus CRDT bookkeeping (`updated` for last-writer-wins, `tombstone` for removals that must stick across a merge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    pub handle_proof: [u8; 32],
    pub handle_hash: [u8; 32],
    /// Last-known friend device pubkey (a hint; the joining device re-discovers current devices by handle_proof). Zero if unknown.
    pub public_identity: [u8; 32],
    pub handle: String,
    pub added: i64,
    /// Logical clock for this entry — the newest write across the fleet wins the merge.
    pub updated: i64,
    /// A removed contact stays as a tombstone so a stale device re-adding it can't resurrect it.
    pub tombstone: bool,
}

const ROSTER_TAG: &[u8; 5] = b"PRST0";

/// Serialize the roster to the plaintext that gets sealed under the fleet key. Not VSF: this is opaque AEAD-payload bytes, so a compact fixed-layout encoding is simpler and just as forensic (the wire envelope around the ciphertext is VSF).
pub fn roster_to_bytes(entries: &[RosterEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ROSTER_TAG);
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for e in entries {
        out.extend_from_slice(&e.handle_proof);
        out.extend_from_slice(&e.handle_hash);
        out.extend_from_slice(&e.public_identity);
        out.extend_from_slice(&e.added.to_be_bytes());
        out.extend_from_slice(&e.updated.to_be_bytes());
        out.push(e.tombstone as u8);
        let hb = e.handle.as_bytes();
        out.extend_from_slice(&(hb.len() as u32).to_be_bytes());
        out.extend_from_slice(hb);
    }
    out
}

/// Parse the roster plaintext back. Bounds-checked throughout — a truncated or corrupt blob fails rather than panicking.
pub fn roster_from_bytes(bytes: &[u8]) -> Result<Vec<RosterEntry>, String> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], String> {
        if *p + n > bytes.len() {
            return Err("roster: truncated".into());
        }
        let s = &bytes[*p..*p + n];
        *p += n;
        Ok(s)
    };
    if take(&mut p, 5)? != ROSTER_TAG {
        return Err("roster: bad tag".into());
    }
    let count = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let handle_proof: [u8; 32] = take(&mut p, 32)?.try_into().unwrap();
        let handle_hash: [u8; 32] = take(&mut p, 32)?.try_into().unwrap();
        let public_identity: [u8; 32] = take(&mut p, 32)?.try_into().unwrap();
        let added = i64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
        let updated = i64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
        let tombstone = take(&mut p, 1)?[0] != 0;
        let hlen = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
        let handle = String::from_utf8(take(&mut p, hlen)?.to_vec())
            .map_err(|_| "roster: handle not utf8".to_string())?;
        out.push(RosterEntry {
            handle_proof,
            handle_hash,
            public_identity,
            handle,
            added,
            updated,
            tombstone,
        });
    }
    Ok(out)
}

/// CRDT merge: union by handle_proof, per-entry last-writer-wins on `updated`. Deterministic and order-independent (commutative/idempotent). A tombstone wins an `updated` tie so a concurrent remove beats a concurrent re-add — deletes are conservative.
pub fn merge_rosters(a: Vec<RosterEntry>, b: Vec<RosterEntry>) -> Vec<RosterEntry> {
    use std::collections::HashMap;
    let mut by: HashMap<[u8; 32], RosterEntry> = HashMap::new();
    for e in a.into_iter().chain(b.into_iter()) {
        let replace = match by.get(&e.handle_proof) {
            None => true,
            Some(cur) => {
                e.updated > cur.updated
                    || (e.updated == cur.updated && e.tombstone && !cur.tombstone)
            }
        };
        if replace {
            by.insert(e.handle_proof, e);
        }
    }
    let mut out: Vec<RosterEntry> = by.into_values().collect();
    out.sort_by(|x, y| x.handle_proof.cmp(&y.handle_proof));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roster_entry(hp: u8, updated: i64, tombstone: bool) -> RosterEntry {
        RosterEntry {
            handle_proof: [hp; 32],
            handle_hash: [hp ^ 0xff; 32],
            public_identity: [hp.wrapping_add(1); 32],
            handle: format!("friend{hp}"),
            added: 100,
            updated,
            tombstone,
        }
    }

    #[test]
    fn roster_serialize_round_trips() {
        let entries = vec![roster_entry(1, 200, false), roster_entry(2, 300, true)];
        let bytes = roster_to_bytes(&entries);
        assert_eq!(roster_from_bytes(&bytes).unwrap(), entries);
        // A truncated blob fails rather than panicking.
        assert!(roster_from_bytes(&bytes[..bytes.len() - 3]).is_err());
        assert!(roster_from_bytes(b"nope").is_err());
    }

    #[test]
    fn roster_merge_is_commutative_lww_with_sticky_tombstones() {
        let old = roster_entry(1, 100, false);
        let newer = roster_entry(1, 200, false);
        // Last-writer-wins on `updated`, regardless of merge order.
        let ab = merge_rosters(vec![old.clone()], vec![newer.clone()]);
        let ba = merge_rosters(vec![newer.clone()], vec![old.clone()]);
        assert_eq!(ab, ba);
        assert_eq!(ab[0].updated, 200);
        // A tombstone wins an `updated` tie (delete beats concurrent re-add).
        let alive = roster_entry(1, 200, false);
        let dead = roster_entry(1, 200, true);
        assert!(merge_rosters(vec![alive.clone()], vec![dead.clone()])[0].tombstone);
        assert!(merge_rosters(vec![dead], vec![alive])[0].tombstone);
        // Distinct contacts union together, sorted by handle_proof.
        let two = merge_rosters(vec![roster_entry(2, 1, false)], vec![roster_entry(1, 1, false)]);
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].handle_proof, [1; 32]);
    }
}
