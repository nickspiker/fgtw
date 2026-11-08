//! The person's identity space: the small set of facts that belong to a person rather than to any one device of theirs (owner, 2026-11-08: "when I attest, the key matches, it syncs with my fleet, pulls a kist roster … and throws it on my home screen in the same exact spot and rotation it was before I factory reset this thing").
//!
//! What goes in is the embedding's (ferros: the kists the person installed and their answers, their permission defaults, the arrangement of their home screen, the view, each device's "sync this device's home screen" switch). This module only keeps facts, merges copies, seals them under the fleet key and reconciles a device's own copy with them; it never knows what a kind means.
//!
//! - **An entry** is one fact: a `kind` (the embedding's code), an `id` (typed VSF values naming which one: a developer key and option, a right, a device), a `value` (typed VSF values), when it was written (Eagle oscillations), which device wrote it (its Ed25519 key) and whether it is gone (a tombstone, so a removal sticks across a merge).
//! - **The merge** keeps, per (kind, id), the entry that is greatest by (written, device, gone, value bytes): a total order, so a merge is commutative, associative and idempotent, and every device that has seen the same entries holds the same space, whatever order they arrived in.
//! - **The document** is a complete VSF file (header, creation time, provenance hash): a section `space` (`version`), then a section `entry` per entry, every field typed and named. Nothing positional, nothing in text but the embedding's own words.
//! - **Sealed** (feature `fanout`): XChaCha20-Poly1305 under a key derived from the fleet key, a fresh 24-byte nonce, the identity's handle proof and the key's fingerprint as associated data, so a sealed space opens only under its own fleet and key. Fleet devices hand it to each other (`protocol::space_push`); fgtw.org keeps one copy (`space_put`), the backup a total loss recovers from.
//! - **Reconcile** joins a device's own copy (the files its programs read and write, which carry no stamps) to the space with a baseline: what the device's copy held when it last agreed with the space. A local value that moved from its baseline is the person's change on this device and goes into the space, stamped newer than anything this device has seen; one that did not move takes the space's value. A value with no baseline (a fresh device, a new install) takes the space's when the space has one, unless the fact carries its own later stamp.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use vsf::file_format::{VsfHeader, VsfSection};
use vsf::types::EtType;
use vsf::{VsfBuilder, VsfType};

/// The document's version (`space.version`). A reader takes only its own.
pub const VERSION: u64 = 0;

/// One fact of the person's space.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// What the fact is, in the embedding's vocabulary.
    pub kind: u8,
    /// Which one: typed values (a developer key and option, a right, a device key …), compared by their bytes.
    pub id: Vec<VsfType>,
    /// The fact itself: typed values. Empty for a tombstone.
    pub value: Vec<VsfType>,
    /// When it was written, Eagle oscillations.
    pub updated: i64,
    /// The device that wrote it (its Ed25519 key): the tie-break between two writes stamped alike.
    pub by: [u8; 32],
    /// Removed: kept so that a copy that still holds the fact cannot bring it back.
    pub gone: bool,
}

/// The bytes a list of typed values flattens to: what ids and values are compared and hashed by.
pub fn bytes_of(values: &[VsfType]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in values {
        out.extend_from_slice(&v.flatten());
    }
    out
}

/// An entry's place in the space: its kind, then its id's bytes.
pub fn key_of(kind: u8, id: &[VsfType]) -> Vec<u8> {
    let mut k = alloc::vec![kind];
    k.extend_from_slice(&bytes_of(id));
    k
}

impl Entry {
    pub fn key(&self) -> Vec<u8> {
        key_of(self.kind, &self.id)
    }

    /// Whether `self` wins over `other` (the same fact, two writes): later written, then the greater device key, then gone over present, then the greater value bytes. Equal on all four is the same write.
    pub fn wins_over(&self, other: &Entry) -> bool {
        (self.updated, self.by, self.gone, bytes_of(&self.value)) > (other.updated, other.by, other.gone, bytes_of(&other.value))
    }
}

/// The person's space: its entries, one per (kind, id), kept in key order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Space {
    entries: Vec<Entry>,
}

impl Space {
    pub fn new() -> Space {
        Space { entries: Vec::new() }
    }

    /// Every entry, tombstones included, in key order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The live entries of one kind.
    pub fn live(&self, kind: u8) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(move |e| e.kind == kind && !e.gone)
    }

    /// The entry for (kind, id), live or gone.
    pub fn get(&self, kind: u8, id: &[VsfType]) -> Option<&Entry> {
        let k = key_of(kind, id);
        self.entries.binary_search_by(|e| e.key().cmp(&k)).ok().map(|i| &self.entries[i])
    }

    /// One write merged in: it replaces the entry for its fact only when it wins. True when the space changed.
    pub fn put(&mut self, e: Entry) -> bool {
        let k = e.key();
        match self.entries.binary_search_by(|x| x.key().cmp(&k)) {
            Ok(i) => {
                if e.wins_over(&self.entries[i]) {
                    self.entries[i] = e;
                    true
                } else {
                    false
                }
            }
            Err(i) => {
                self.entries.insert(i, e);
                true
            }
        }
    }

    /// Another copy merged in. True when this copy changed.
    pub fn merge(&mut self, other: Space) -> bool {
        let mut changed = false;
        for e in other.entries {
            changed |= self.put(e);
        }
        changed
    }

    /// The newest stamp in the space (0 for an empty one): a write on this device is stamped past it, so the person's latest change wins even over a sibling whose clock runs ahead.
    pub fn newest(&self) -> i64 {
        self.entries.iter().map(|e| e.updated).max().unwrap_or(0)
    }

    /// A digest of the whole space (blake3 over every entry's bytes in key order): two copies with the same digest hold the same entries, so a device can tell whether a copy it was handed adds anything.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for e in &self.entries {
            for part in [e.key(), bytes_of(&e.value)] {
                h.update(&(part.len() as u64).to_le_bytes());
                h.update(&part);
            }
            h.update(&e.updated.to_le_bytes());
            h.update(&e.by);
            h.update(&[e.gone as u8]);
        }
        *h.finalize().as_bytes()
    }

    /// The space as a complete VSF document stamped `now` (Eagle oscillations).
    pub fn to_doc(&self, now: i64) -> Result<Vec<u8>, String> {
        let mut head = VsfSection::new("space");
        head.add_field("version", VsfType::u(VERSION as usize, false));
        let mut b = VsfBuilder::new().creation_time_oscillations(now).provenance_only().add_section_direct(head);
        for e in &self.entries {
            let mut s = VsfSection::new("entry");
            s.add_field("kind", VsfType::u(e.kind as usize, false));
            s.add_field_multi("id", e.id.clone());
            if !e.value.is_empty() {
                s.add_field_multi("value", e.value.clone());
            }
            s.add_field("updated", VsfType::e(EtType::e6(e.updated)));
            s.add_field("by", VsfType::ke(e.by.to_vec()));
            if e.gone {
                s.add_field("gone", VsfType::u(1, false));
            }
            b = b.add_section_direct(s);
        }
        b.build()
    }

    /// A space from its document. A document of another version, or an entry missing its kind, stamp or writer, refuses the whole document: half a space merged in would read as removals that never happened.
    pub fn from_doc(doc: &[u8]) -> Result<Space, String> {
        let (header, end) = VsfHeader::decode(doc).map_err(|e| alloc::format!("space: {e}"))?;
        let sections = header.sections(doc, end).map_err(|e| alloc::format!("space sections: {e}"))?;
        let mut version = None;
        let mut out = Space::new();
        for s in &sections {
            match s.name.as_str() {
                "space" => version = s.uint("version"),
                "entry" => {
                    let kind = s.uint("kind").and_then(|k| u8::try_from(k).ok()).ok_or("space: an entry without its kind")?;
                    let id = s.get_field("id").map(|f| f.values.clone()).unwrap_or_default();
                    let value = s.get_field("value").map(|f| f.values.clone()).unwrap_or_default();
                    let updated = s.eagle("updated").ok_or("space: an entry without its stamp")?;
                    let by = s.bytes32("by").ok_or("space: an entry without its writer")?;
                    let gone = s.flag("gone");
                    out.put(Entry { kind, id, value, updated, by, gone });
                }
                _ => {}
            }
        }
        if version != Some(VERSION) {
            return Err("space: not a version this reader takes".to_string());
        }
        Ok(out)
    }
}

// ── Reconcile: a device's own copy and the space ──

/// One fact as the device's own copy holds it now: its kind, id and value, and its own stamp when the copy keeps one (a kist answer keeps when it was given; a place on the map keeps none).
#[derive(Clone, Debug, PartialEq)]
pub struct Fact {
    pub kind: u8,
    pub id: Vec<VsfType>,
    pub value: Vec<VsfType>,
    pub stamp: Option<i64>,
}

/// What the device's own copy must do to agree with the space.
#[derive(Clone, Debug, PartialEq)]
pub enum Write {
    /// Write this value for (kind, id); `updated` is the entry's stamp, for a copy that keeps one (a kist answer's when).
    Set { kind: u8, id: Vec<VsfType>, value: Vec<VsfType>, updated: i64 },
    /// Remove (kind, id) from the device's copy.
    Remove { kind: u8, id: Vec<VsfType> },
}

/// What the device's copy held for each fact when it last agreed with the space: blake3 of the fact's key, blake3 of its value. A fact with no baseline has never been reconciled on this device. Device-local: never synced (it describes this device's copy, not the person's facts).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Baseline {
    seen: Vec<([u8; 32], [u8; 32])>,
}

fn hash(b: &[u8]) -> [u8; 32] {
    *blake3::hash(b).as_bytes()
}

impl Baseline {
    fn find(&self, key: &[u8; 32]) -> Result<usize, usize> {
        self.seen.binary_search_by(|s| s.0.cmp(key))
    }

    fn get(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.find(key).ok().map(|i| self.seen[i].1)
    }

    fn set(&mut self, key: [u8; 32], value: Option<[u8; 32]>) {
        match (self.find(&key), value) {
            (Ok(i), Some(v)) => self.seen[i].1 = v,
            (Ok(i), None) => {
                self.seen.remove(i);
            }
            (Err(i), Some(v)) => self.seen.insert(i, (key, v)),
            (Err(_), None) => {}
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// The baseline as a complete VSF document: a section `baseline`, a field `seen` per fact (two `hb`: the key's hash, the value's).
    pub fn to_doc(&self, now: i64) -> Result<Vec<u8>, String> {
        let mut s = VsfSection::new("baseline");
        for (k, v) in &self.seen {
            s.add_field_multi("seen", alloc::vec![VsfType::hb(k.to_vec()), VsfType::hb(v.to_vec())]);
        }
        VsfBuilder::new().creation_time_oscillations(now).provenance_only().add_section_direct(s).build()
    }

    pub fn from_doc(doc: &[u8]) -> Result<Baseline, String> {
        let (header, end) = VsfHeader::decode(doc).map_err(|e| alloc::format!("baseline: {e}"))?;
        let s = header.sections(doc, end).map_err(|e| alloc::format!("baseline sections: {e}"))?.into_iter().find(|s| s.name == "baseline").ok_or("baseline: no section")?;
        let mut out = Baseline::default();
        for f in s.get_fields("seen") {
            let mut two = f.values.iter().filter_map(|v| match v {
                VsfType::hb(b) => <[u8; 32]>::try_from(b.as_slice()).ok(),
                _ => None,
            });
            if let (Some(k), Some(v)) = (two.next(), two.next()) {
                out.set(k, Some(v));
            }
        }
        Ok(out)
    }
}

/// Join the device's own copy to the space.
///
/// - `local`: every fact the device's copy holds now, of the kinds and ids this reconcile manages.
/// - `managed`: which of the space's entries this device's copy is the mirror of (the kinds it keeps, and for a per-device fact, this device's): those the copy lacks are written to it.
/// - `me`, `now`: this device's key and the time, for the entries a local change writes.
///
/// The space gets an entry for every local change (stamped past anything this device has seen); the answer is what the device's copy must write to agree with the space; the baseline is left describing the copy as it will be once those writes are made.
pub fn reconcile(space: &mut Space, base: &mut Baseline, local: &[Fact], managed: impl Fn(u8, &[VsfType]) -> bool, me: [u8; 32], now: i64) -> Vec<Write> {
    let mut writes = Vec::new();
    // Each managed fact once: the local ones, then the space's live or gone ones the copy does not hold. A few dozen facts, so a plain list searched linearly.
    let mut keys: Vec<(u8, Vec<VsfType>)> = Vec::new();
    for f in local {
        keys.push((f.kind, f.id.clone()));
    }
    for e in space.entries() {
        if managed(e.kind, &e.id) && !local.iter().any(|f| f.kind == e.kind && f.id == e.id) {
            keys.push((e.kind, e.id.clone()));
        }
    }
    for (kind, id) in keys {
        let k = hash(&key_of(kind, &id));
        let fact = local.iter().find(|f| f.kind == kind && f.id == id);
        let l = fact.map(|f| hash(&bytes_of(&f.value)));
        let b = base.get(&k);
        let s = space.get(kind, &id).cloned();
        let s_value = s.as_ref().filter(|e| !e.gone).map(|e| hash(&bytes_of(&e.value)));
        // A change on this device: the copy moved from what it last agreed to; or a fact the space does not have (never had, or a copy of the space that lost it: the device's copy puts it back rather than lose it too); or, with no baseline, a fact whose own stamp is later than the space's.
        let moved = match (b, &s) {
            (Some(_), None) => true,
            (Some(b), Some(_)) => l != Some(b),
            (None, None) => l.is_some(),
            (None, Some(e)) => l.is_some() && l != s_value && fact.and_then(|f| f.stamp).is_some_and(|t| t > e.updated),
        };
        if moved && l != s_value {
            // Stamped past everything this device has seen, so the person's latest change here wins: their own stamp when the fact keeps one, else now.
            let floor = space.newest() + 1;
            let stamp = fact.and_then(|f| f.stamp).unwrap_or(now).max(floor);
            let (value, gone) = match fact {
                Some(f) => (f.value.clone(), false),
                None => (Vec::new(), true),
            };
            space.put(Entry { kind, id: id.clone(), value, updated: stamp, by: me, gone });
            base.set(k, l);
            continue;
        }
        if moved {
            // Moved, but to what the space already holds: nothing to write either way.
            base.set(k, l);
            continue;
        }
        // Unchanged here: the copy takes the space's value.
        match &s {
            Some(e) if !e.gone => {
                if l != s_value {
                    writes.push(Write::Set { kind, id: id.clone(), value: e.value.clone(), updated: e.updated });
                }
                base.set(k, s_value);
            }
            _ => {
                // Gone from the space (a tombstone: with no fact in the space at all, a fact held here is a local change above): the copy drops it too, whether or not this device had reconciled it before. A removal sticks.
                if l.is_some() {
                    writes.push(Write::Remove { kind, id: id.clone() });
                }
                base.set(k, None);
            }
        }
    }
    writes
}

// ── Sealed under the fleet key ──

/// The key a space is sealed under: derived from the fleet key for this one use, so the fleet key itself never keys an AEAD here.
#[cfg(feature = "fanout")]
fn space_key(fleet_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("fgtw identity space XChaCha20-Poly1305 2026-11-08", fleet_key)
}

/// A sealed space: the fleet key's fingerprint (`fanout::fleet_key_fingerprint`) and the XChaCha20-Poly1305 wrap, nonce first.
#[cfg(feature = "fanout")]
#[derive(Clone, Debug, PartialEq)]
pub struct Sealed {
    pub kfp: [u8; 32],
    pub wrap: Vec<u8>,
}

/// Seal a space's document for fleet `handle_proof` under `fleet_key`. The nonce is fresh (`crate::random32`: the OS's, or the embedding's registered entropy on bare metal).
#[cfg(feature = "fanout")]
pub fn seal(doc: &[u8], handle_proof: &[u8; 32], fleet_key: &[u8; 32]) -> Result<Sealed, String> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
    let kfp = crate::fanout::fleet_key_fingerprint(fleet_key);
    let r = crate::random32();
    let nonce: [u8; 24] = r[..24].try_into().unwrap();
    let mut aad = handle_proof.to_vec();
    aad.extend_from_slice(&kfp);
    let ct = XChaCha20Poly1305::new((&space_key(fleet_key)).into()).encrypt((&nonce).into(), Payload { msg: doc, aad: &aad }).map_err(|_| "space: seal failed".to_string())?;
    let mut wrap = nonce.to_vec();
    wrap.extend_from_slice(&ct);
    Ok(Sealed { kfp, wrap })
}

/// Open a sealed space for fleet `handle_proof` under `fleet_key`: refused when it was sealed under another key (the fingerprint), for another fleet, or altered.
#[cfg(feature = "fanout")]
pub fn open(sealed: &Sealed, handle_proof: &[u8; 32], fleet_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
    if crate::fanout::fleet_key_fingerprint(fleet_key) != sealed.kfp {
        return Err("space: sealed under another fleet key".to_string());
    }
    // WHY: the wrap comes off the wire or the seed; shorter than a nonce and a tag it is not a wrap, and the split below would panic.
    if sealed.wrap.len() < 24 + 16 {
        return Err("space: a wrap too short to be one".to_string());
    }
    let (nonce, ct) = sealed.wrap.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().unwrap();
    let mut aad = handle_proof.to_vec();
    aad.extend_from_slice(&sealed.kfp);
    XChaCha20Poly1305::new((&space_key(fleet_key)).into()).decrypt((&nonce).into(), Payload { msg: ct, aad: &aad }).map_err(|_| "space: does not open under this fleet's key".to_string())
}

/// The sealed space's two fields in a section (`kf` the fingerprint, `ct` the wrap as `v'X'`, XChaCha20-Poly1305), as the frames and the seed's slot carry it.
#[cfg(feature = "fanout")]
pub fn sealed_fields(section: &mut VsfSection, sealed: &Sealed) {
    section.add_field("kf", VsfType::hb(sealed.kfp.to_vec()));
    section.add_field("ct", VsfType::v(vsf::crypto_algorithms::WRAP_XCHACHA20POLY1305, sealed.wrap.clone()));
}

/// The sealed space read back from a section's `kf` and `ct`.
#[cfg(feature = "fanout")]
pub fn sealed_from(section: &VsfSection) -> Option<Sealed> {
    let kfp = section.bytes32("kf")?;
    let wrap = match section.get_field("ct").and_then(|f| f.values.first())? {
        VsfType::v(w, b) if *w == vsf::crypto_algorithms::WRAP_XCHACHA20POLY1305 => b.clone(),
        _ => return None,
    };
    Some(Sealed { kfp, wrap })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const A: [u8; 32] = [0xA0; 32];
    const B: [u8; 32] = [0xB0; 32];

    fn e(kind: u8, id: u8, value: i64, updated: i64, by: [u8; 32]) -> Entry {
        Entry { kind, id: vec![VsfType::u(id as usize, false)], value: vec![VsfType::i(value as isize)], updated, by, gone: false }
    }

    fn fact(kind: u8, id: u8, value: i64) -> Fact {
        Fact { kind, id: vec![VsfType::u(id as usize, false)], value: vec![VsfType::i(value as isize)], stamp: None }
    }

    fn apply(local: &mut Vec<Fact>, writes: Vec<Write>) {
        for w in writes {
            match w {
                Write::Set { kind, id, value, .. } => {
                    local.retain(|f| !(f.kind == kind && f.id == id));
                    local.push(Fact { kind, id, value, stamp: None });
                }
                Write::Remove { kind, id } => local.retain(|f| !(f.kind == kind && f.id == id)),
            }
        }
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let xs = [e(1, 0, 5, 10, A), e(1, 0, 6, 10, B), e(1, 1, 7, 3, A), e(2, 0, 8, 12, B), e(1, 1, 9, 4, B), Entry { gone: true, value: vec![], ..e(2, 0, 0, 12, B) }];
        let mut reference = None;
        // Every rotation of the arrival order, merged pairwise and in one go: the same space.
        for r in 0..xs.len() {
            let mut s = Space::new();
            for k in 0..xs.len() {
                s.put(xs[(r + k) % xs.len()].clone());
            }
            let again = s.clone();
            assert!(!s.merge(again), "a space merged with itself does not change");
            match &reference {
                None => reference = Some(s),
                Some(r0) => assert_eq!(&s, r0),
            }
        }
        let s = reference.unwrap();
        assert_eq!(s.get(1, &[VsfType::u(0, false)]).unwrap().by, B, "equal stamps: the greater device wins");
        assert_eq!(s.get(1, &[VsfType::u(1, false)]).unwrap().value, vec![VsfType::i(9)], "the later stamp wins");
        assert!(s.get(2, &[VsfType::u(0, false)]).unwrap().gone, "gone over present at an equal stamp and writer");
    }

    #[test]
    fn document_round_trips() {
        let mut s = Space::new();
        s.put(e(1, 0, -5, 10, A));
        s.put(Entry { kind: 3, id: vec![VsfType::ke(B.to_vec()), VsfType::u(6, false)], value: vec![VsfType::u(1, false), VsfType::a("a reason".to_string())], updated: 1 << 40, by: B, gone: false });
        s.put(Entry { gone: true, value: vec![], ..e(2, 7, 0, 11, B) });
        let doc = s.to_doc(99).unwrap();
        let back = Space::from_doc(&doc).unwrap();
        assert_eq!(back.digest(), s.digest());
        assert_eq!(back.to_doc(99).unwrap(), doc, "re-encoding a decoded space gives the same bytes");
    }

    #[test]
    fn baseline_round_trips() {
        let mut b = Baseline::default();
        b.set([3; 32], Some([4; 32]));
        b.set([1; 32], Some([2; 32]));
        assert_eq!(Baseline::from_doc(&b.to_doc(5).unwrap()).unwrap(), b);
    }

    /// Two devices, two copies: device A arranges, device B is fresh (a factory reset); after one exchange B's copy is A's.
    #[test]
    fn a_fresh_device_takes_the_space() {
        let all = |_: u8, _: &[VsfType]| true;
        let (mut sa, mut ba) = (Space::new(), Baseline::default());
        let mut la = vec![fact(1, 0, 100), fact(1, 1, 200), fact(2, 0, 7)];
        assert!(reconcile(&mut sa, &mut ba, &la, all, A, 1000).is_empty());
        assert_eq!(sa.live(1).count(), 2);
        // B: nothing of its own, A's space handed over.
        let (mut sb, mut bb) = (Space::new(), Baseline::default());
        let mut lb: Vec<Fact> = Vec::new();
        sb.merge(sa.clone());
        let w = reconcile(&mut sb, &mut bb, &lb, all, B, 2000);
        apply(&mut lb, w);
        lb.sort_by_key(|f| (f.kind, bytes_of(&f.id)));
        la.sort_by_key(|f| (f.kind, bytes_of(&f.id)));
        assert_eq!(lb, la);
        // Nothing moves on a second pass.
        assert!(reconcile(&mut sb, &mut bb, &lb, all, B, 2001).is_empty());
        assert_eq!(sb.digest(), sa.digest());
    }

    /// A change on one device reaches the other; a removal sticks; the person's latest change wins even against a sibling whose clock ran ahead.
    #[test]
    fn changes_flow_both_ways_and_the_latest_wins() {
        let all = |_: u8, _: &[VsfType]| true;
        let (mut sa, mut ba, mut la) = (Space::new(), Baseline::default(), vec![fact(1, 0, 100), fact(1, 1, 200)]);
        reconcile(&mut sa, &mut ba, &la, all, A, 1000);
        let (mut sb, mut bb, mut lb) = (sa.clone(), Baseline::default(), Vec::new());
        let w = reconcile(&mut sb, &mut bb, &lb, all, B, 1001);
        apply(&mut lb, w);
        // B's clock is far ahead: B moves circle 0.
        lb.retain(|f| f.id != vec![VsfType::u(0, false)]);
        lb.push(fact(1, 0, 111));
        reconcile(&mut sb, &mut bb, &lb, all, B, 1 << 50);
        // A, its clock behind, removes circle 1 and then moves circle 0 again after seeing B's move.
        sa.merge(sb.clone());
        let w = reconcile(&mut sa, &mut ba, &la, all, A, 1010);
        apply(&mut la, w);
        assert!(la.contains(&fact(1, 0, 111)), "A took B's move");
        la.retain(|f| f.id != vec![VsfType::u(1, false)]);
        la.retain(|f| f.id != vec![VsfType::u(0, false)]);
        la.push(fact(1, 0, 122));
        reconcile(&mut sa, &mut ba, &la, all, A, 1020);
        // B takes both.
        sb.merge(sa.clone());
        let w = reconcile(&mut sb, &mut bb, &lb, all, B, (1 << 50) + 1);
        apply(&mut lb, w);
        assert_eq!(lb, vec![fact(1, 0, 122)], "A's later move won though A's clock was behind, and the removal stuck");
        assert_eq!(sb.digest(), sa.digest());
    }

    /// A fact the space has, held differently by a device that never reconciled it: the space wins, unless the fact's own stamp is later.
    #[test]
    fn no_baseline_defers_to_the_space_unless_stamped_later() {
        let all = |_: u8, _: &[VsfType]| true;
        let mut s = Space::new();
        s.put(e(1, 0, 100, 50, A));
        let mut lb = vec![fact(1, 0, 999)];
        let w = reconcile(&mut s.clone(), &mut Baseline::default(), &lb, all, B, 60);
        apply(&mut lb, w);
        assert_eq!(lb, vec![fact(1, 0, 100)]);
        let stamped = vec![Fact { stamp: Some(70), ..fact(1, 0, 999) }];
        let w = reconcile(&mut s, &mut Baseline::default(), &stamped, all, B, 80);
        assert!(w.is_empty());
        assert_eq!(s.get(1, &[VsfType::u(0, false)]).unwrap().value, vec![VsfType::i(999)]);
    }

    /// Facts outside what a device manages (another device's own arrangement) are neither written to its copy nor removed from the space.
    #[test]
    fn unmanaged_entries_are_left_alone() {
        let mut s = Space::new();
        s.put(e(1, 0, 100, 50, A));
        s.put(e(9, 0, 5, 50, A));
        let w = reconcile(&mut s, &mut Baseline::default(), &[], |k, _| k == 1, B, 60);
        assert_eq!(w, vec![Write::Set { kind: 1, id: vec![VsfType::u(0, false)], value: vec![VsfType::i(100)], updated: 50 }]);
        assert!(!s.get(9, &[VsfType::u(0, false)]).unwrap().gone);
    }

    /// A fact the fleet removed, still held by a device that never reconciled it (a restore over an old copy): it goes, and stays gone.
    #[test]
    fn a_tombstone_wins_on_first_sight() {
        let all = |_: u8, _: &[VsfType]| true;
        let mut s = Space::new();
        s.put(Entry { gone: true, value: vec![], ..e(1, 0, 0, 50, A) });
        let mut lb = vec![fact(1, 0, 100)];
        let mut bb = Baseline::default();
        let w = reconcile(&mut s, &mut bb, &lb, all, B, 60);
        apply(&mut lb, w);
        assert!(lb.is_empty());
        assert!(reconcile(&mut s, &mut bb, &lb, all, B, 61).is_empty());
        assert!(bb.is_empty());
    }

    #[cfg(feature = "std")]
    #[test]
    fn sealed_opens_only_under_its_own_fleet_and_key() {
        let mut s = Space::new();
        s.put(e(1, 0, 100, 50, A));
        let doc = s.to_doc(1).unwrap();
        let (hp, key) = ([7u8; 32], [8u8; 32]);
        let sealed = seal(&doc, &hp, &key).unwrap();
        assert_eq!(open(&sealed, &hp, &key).unwrap(), doc);
        assert!(open(&sealed, &[6u8; 32], &key).is_err(), "another fleet");
        assert!(open(&sealed, &hp, &[9u8; 32]).is_err(), "another key");
        let mut bent = sealed.clone();
        let last = bent.wrap.len() - 1;
        bent.wrap[last] ^= 1;
        assert!(open(&bent, &hp, &key).is_err(), "altered");
        let mut sec = VsfSection::new("t");
        sealed_fields(&mut sec, &sealed);
        assert_eq!(sealed_from(&sec).unwrap(), sealed);
    }
}
