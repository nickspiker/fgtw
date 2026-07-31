//! Fleet shared state — the contact roster + linked-settings codec.
//!
//! The roster is the "who are my friends" half of a fleet's private state; settings are the "how do my devices behave" half.
//! Both ride the fleet key: encrypted with it, pushed to a membership-gated slot, pulled + CRDT-merged by every device.
//! A new device that joins pulls the roster and re-CLUTCHes each friend on its own device key (conversation HISTORY + per-device ratchets are a later phase).
//!
//! Settings model (photon docs/global-vault.md "Settings: per-device maps + link-to-global"): every setting is per-device with a link bit; a LINKED setting follows the fleet-wide global value (and adjusting it from any linked device writes the global), an UNLINKED one is set locally on that device.
//! Born linked — the default is always "go with the fleet".
//! Each device is the single writer of its own map, so the only true CRDT surface is the global layer; device maps merge by newest-copy-wins.
//!
//! This module is the data model + codec + merge; the seal-and-push / pull-and-open transport (which needs the fleet key and the network) is the client's job.
//! The sealed plaintext is a COMPLETE VSF document (header, provenance hash, schema'd sections) — not a hand-rolled layout; see photon AGENT.md "VSF Transport Rule".

use vsf::schema::{SectionBuilder, SectionSchema, TypeConstraint};
use vsf::types::EtType;
use vsf::VsfType;

/// One syncable friend. The minimal identity a device needs to reconstruct a contact and re-CLUTCH: the PIN-SET (docs/identity-profile.md — party id, proof, avatar key; NEVER the handle string, which derives the identity seed) plus CRDT bookkeeping (`updated` for last-writer-wins, `tombstone` for removals that must stick across a merge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    pub handle_proof: [u8; 32],
    /// The contact's PARTY ID: their pinned identity PUBKEY — verification-only, no signing power. (The pre-pin-set roster carried the friend's identity SEED here; the v1 version bump orphans those blobs.)
    pub handle_hash: [u8; 32],
    /// Last-known friend device pubkey (a hint; the joining device re-discovers current devices by handle_proof). Zero if unknown.
    pub public_identity: [u8; 32],
    /// The pinned avatar-wall material, derived once at first-met and synced so every fleet device fetches + decrypts this friend's avatar without ever holding the handle: AES key (32) ‖ FGTW lookup hash (32). Zero = not pinned.
    pub avatar_pin: [u8; 64],
    pub added: i64,
    /// Logical clock for this entry — the newest write across the fleet wins the merge.
    pub updated: i64,
    /// A removed contact stays as a tombstone so a stale device re-adding it can't resurrect it.
    pub tombstone: bool,
    /// The ONE fleet device running this friendship's CLUTCH (fleet-sync.md §4.2: exactly one device completes the ceremony) — the adding device claims at add time; siblings park their own rounds while the owner is present; presence-loss enables takeover (another LWW write). Zero = unclaimed (legacy entry / pre-claim).
    pub ceremony_owner: [u8; 32],
    /// The owner's ceremony completed (chain woven). Display truth for parked siblings — "secured on <device>" — NEVER a licence to unlock their own compose (that stays chain-gated until chain state travels, braid.md §14).
    pub woven: bool,
    /// How far this friend is trusted (0 Stranger .. 3 Inner). Rides the entry's LWW clock: a trust decision made on one device is a decision for the identity, not for the hardware it was typed on. Before v3 this was the ONLY field the (device-bound, unreadable-by-siblings) cloud contacts blob carried and the roster did not, so trust silently failed to sync at all.
    pub trust_level: u8,
    /// The friend's own chosen display name, adopted from their pong. Synced like the avatar pin so a fresh sibling shows real names instantly instead of pseudonyms until each friend happens to come online. Zero trust — the pinned key carries the trust; empty renders the keyed pseudonym.
    pub published_name: String,
}

// Version history (the bump is the flag-day: an old blob fails the read, the roster re-syncs from live contacts and the settings re-push — both are resyncable caches, so a bump costs one re-push).
// v0 carried handle strings (and seeds in handle_hash); v2 added ceremony_owner + woven; v3 trust_level; v4 published_name; v5 dropped the never-used petname slot.
// v6 retired the hand-rolled "PRST5"/"PSET0"/"PFST1" byte layouts: the plaintext is now a real VSF document and the version rides the spec's `z` type — no more ASCII digit welded into a magic tag (which also changed the tag's LENGTH at revision ten).
const FSTATE_VERSION: usize = 6;

const ROSTER_SECTION: &str = "fleet_roster";
const GLOBALS_SECTION: &str = "fleet_globals";
const DEVICES_SECTION: &str = "fleet_devices";

fn roster_schema() -> SectionSchema {
    SectionSchema::new(ROSTER_SECTION)
        .field("version", TypeConstraint::Any)
        .field("entry", TypeConstraint::Any) // Mixed types per row — values are matched by marker, not position
}

fn globals_schema() -> SectionSchema {
    SectionSchema::new(GLOBALS_SECTION)
        .field("version", TypeConstraint::Any)
        .field("setting", TypeConstraint::Any)
}

fn devices_schema() -> SectionSchema {
    SectionSchema::new(DEVICES_SECTION)
        .field("version", TypeConstraint::Any)
        .field("row", TypeConstraint::Any)
}

/// True when the section's `z` version is exactly ours. A mismatch reads as "not this format" — the flag-day rule, applied per section.
fn version_matches(section: &SectionBuilder) -> bool {
    section
        .get_fields("version")
        .first()
        .and_then(|f| f.values.first())
        .map(|v| matches!(v, VsfType::z(n) if *n == FSTATE_VERSION))
        .unwrap_or(false)
}

/// Wrap section bodies into one complete VSF document (magic, creation time, provenance hash) — the only form that reaches the seal.
fn document(sections: Vec<(&'static str, Vec<u8>)>) -> Vec<u8> {
    let mut b = vsf::VsfBuilder::new()
        .creation_time_oscillations(vsf::eagle_time_oscillations())
        .provenance_only();
    for (name, bytes) in sections {
        b = b.add_unboxed(name, bytes);
    }
    b.build().expect("fstate document build")
}

/// Parse one named section out of a document. `Ok(None)` = the section is absent (a roster-only push); a present-but-corrupt section or an unverifiable document is `Err`.
fn parse_section(schema: SectionSchema, doc: &[u8]) -> Result<Option<SectionBuilder>, String> {
    match SectionBuilder::parse_document(schema, doc, None) {
        Ok(sec) => Ok(Some(sec)),
        Err(e) => {
            let msg = format!("{e:?}");
            if msg.contains("not found in document TOC") {
                Ok(None)
            } else {
                Err(msg)
            }
        }
    }
}

/// A row datum's label — the TIFF-tag model: every value is preceded by its `d` name, so decode is a label lookup, never a position or an arrival-order count.
fn label(name: &str) -> VsfType {
    VsfType::d(name.to_string())
}

/// Walk a row's values as (label, datum) pairs into a lookup map. A trailing label with no datum is dropped; unlabeled values are ignored (forward compatibility: a future writer can add labeled data an old reader skips by name).
fn labeled_values(values: &[VsfType]) -> std::collections::HashMap<&str, &VsfType> {
    let mut map = std::collections::HashMap::new();
    let mut it = values.iter();
    while let Some(v) = it.next() {
        if let VsfType::d(name) = v {
            if let Some(datum) = it.next() {
                map.insert(name.as_str(), datum);
            }
        }
    }
    map
}

fn get_k32(m: &std::collections::HashMap<&str, &VsfType>, name: &str) -> Option<[u8; 32]> {
    match m.get(name)? {
        VsfType::hP(b) | VsfType::ke(b) if b.len() == 32 => b.as_slice().try_into().ok(),
        _ => None,
    }
}

fn get_k64(m: &std::collections::HashMap<&str, &VsfType>, name: &str) -> Option<[u8; 64]> {
    match m.get(name)? {
        VsfType::ge(b) if b.len() == 64 => b.as_slice().try_into().ok(),
        _ => None,
    }
}

fn get_e6(m: &std::collections::HashMap<&str, &VsfType>, name: &str) -> Option<i64> {
    match m.get(name)? {
        VsfType::e(EtType::e6(o)) => Some(*o),
        _ => None,
    }
}

fn get_u3(m: &std::collections::HashMap<&str, &VsfType>, name: &str) -> Option<u8> {
    match m.get(name)? {
        VsfType::u3(t) => Some(*t),
        _ => None,
    }
}

fn get_text(m: &std::collections::HashMap<&str, &VsfType>, name: &str) -> Option<String> {
    match m.get(name)? {
        VsfType::x(s) => Some(s.clone()),
        _ => None,
    }
}

fn get_key(m: &std::collections::HashMap<&str, &VsfType>, name: &str) -> Option<String> {
    match m.get(name)? {
        VsfType::d(s) => Some(s.clone()),
        _ => None,
    }
}

fn get_raw(m: &std::collections::HashMap<&str, &VsfType>, name: &str) -> Option<Vec<u8>> {
    match m.get(name)? {
        VsfType::v(marker, b) if *marker == b'r' => Some(b.clone()),
        _ => None,
    }
}

fn roster_section_bytes(entries: &[RosterEntry]) -> Vec<u8> {
    let mut b = roster_schema()
        .build()
        .set("version", VsfType::z(FSTATE_VERSION))
        .expect("roster version");
    for e in entries {
        b = b
            .append_multi(
                "entry",
                vec![
                    label("proof"),
                    VsfType::hP(e.handle_proof.to_vec()),
                    label("party"),
                    VsfType::ke(e.handle_hash.to_vec()),
                    label("device"),
                    VsfType::ke(e.public_identity.to_vec()),
                    label("owner"),
                    VsfType::ke(e.ceremony_owner.to_vec()),
                    label("pin"),
                    VsfType::ge(e.avatar_pin.to_vec()),
                    label("added"),
                    VsfType::e(EtType::e6(e.added)),
                    label("updated"),
                    VsfType::e(EtType::e6(e.updated)),
                    label("tombstone"),
                    VsfType::u3(e.tombstone as u8),
                    label("woven"),
                    VsfType::u3(e.woven as u8),
                    label("trust"),
                    VsfType::u3(e.trust_level),
                    label("name"),
                    VsfType::x(e.published_name.clone()),
                ],
            )
            .expect("roster row");
    }
    b.encode().expect("roster section encode")
}

fn decode_roster_section(sec: &SectionBuilder) -> Vec<RosterEntry> {
    let mut out = Vec::new();
    for row in sec.get_fields("entry") {
        let m = labeled_values(&row.values);
        // A row is only an entry if every part is present under its label — a malformed row drops rather than poisoning the parse.
        let (
            Some(handle_proof),
            Some(handle_hash),
            Some(public_identity),
            Some(ceremony_owner),
            Some(avatar_pin),
            Some(added),
            Some(updated),
            Some(tombstone),
            Some(woven),
            Some(trust_level),
            Some(published_name),
        ) = (
            get_k32(&m, "proof"),
            get_k32(&m, "party"),
            get_k32(&m, "device"),
            get_k32(&m, "owner"),
            get_k64(&m, "pin"),
            get_e6(&m, "added"),
            get_e6(&m, "updated"),
            get_u3(&m, "tombstone"),
            get_u3(&m, "woven"),
            get_u3(&m, "trust"),
            get_text(&m, "name"),
        )
        else {
            continue;
        };
        out.push(RosterEntry {
            handle_proof,
            handle_hash,
            public_identity,
            ceremony_owner,
            avatar_pin,
            added,
            updated,
            tombstone: tombstone != 0,
            woven: woven != 0,
            trust_level,
            published_name,
        });
    }
    out
}

/// Serialize the roster alone — the plaintext a roster-only push seals under the fleet key.
pub fn roster_to_bytes(entries: &[RosterEntry]) -> Vec<u8> {
    document(vec![(ROSTER_SECTION, roster_section_bytes(entries))])
}

/// Parse a roster document back. Verified read + version gate — a truncated, tampered, or old-format blob fails rather than parsing on faith.
pub fn roster_from_bytes(bytes: &[u8]) -> Result<Vec<RosterEntry>, String> {
    let sec = SectionBuilder::parse_document(roster_schema(), bytes, None)
        .map_err(|e| format!("roster: {e:?}"))?;
    if !version_matches(&sec) {
        return Err("roster: version mismatch".into());
    }
    Ok(decode_roster_section(&sec))
}

/// One fleet-GLOBAL setting: the value every linked device follows. `value` is a flattened VSF value (opaque to this codec — the app types it at the edges), so any spec type can ride without the codec knowing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingEntry {
    pub key: String,
    pub value: Vec<u8>,
    /// Logical clock — the newest write across the fleet wins the merge.
    pub updated: i64,
    /// A deleted key stays as a tombstone so a stale device can't resurrect it.
    pub tombstone: bool,
}

/// One entry in a DEVICE's own settings map. `linked = true` (the birth default) means the device follows the global value for this key and local `value` is only the fallback; `linked = false` means this device set it locally and the global stops applying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSetting {
    pub key: String,
    pub value: Vec<u8>,
    pub updated: i64,
    pub linked: bool,
}

/// A device's settings map. Authored ONLY by that device (single-writer), so merge is newest-copy-wins on `updated` — no per-key CRDT needed. Membership (the fleet fold) is the authority on which devices exist; a removed device's map is dropped by the app at reconcile, not tombstoned here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSettings {
    pub device_pubkey: [u8; 32],
    /// Stamp of the newest write in this map — the whole-map logical clock for newest-copy-wins.
    pub updated: i64,
    pub entries: Vec<DeviceSetting>,
}

/// The full fleet-shared state: the roster plus the settings layers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FleetState {
    pub roster: Vec<RosterEntry>,
    pub global_settings: Vec<SettingEntry>,
    pub device_settings: Vec<DeviceSettings>,
}

fn globals_section_bytes(global: &[SettingEntry]) -> Vec<u8> {
    let mut b = globals_schema()
        .build()
        .set("version", VsfType::z(FSTATE_VERSION))
        .expect("globals version");
    for e in global {
        b = b
            .append_multi(
                "setting",
                vec![
                    // The setting key is itself an internal label, so its VALUE is `d` too — labeled like everything else, so decode never leans on adjacency beyond one label-datum pair.
                    label("key"),
                    VsfType::d(e.key.clone()),
                    label("value"),
                    VsfType::v(b'r', e.value.clone()),
                    label("updated"),
                    VsfType::e(EtType::e6(e.updated)),
                    label("tombstone"),
                    VsfType::u3(e.tombstone as u8),
                ],
            )
            .expect("globals row");
    }
    b.encode().expect("globals section encode")
}

fn decode_globals_section(sec: &SectionBuilder) -> Vec<SettingEntry> {
    let mut out = Vec::new();
    for row in sec.get_fields("setting") {
        let m = labeled_values(&row.values);
        let (Some(key), Some(value), Some(updated)) =
            (get_key(&m, "key"), get_raw(&m, "value"), get_e6(&m, "updated"))
        else {
            continue;
        };
        let tombstone = get_u3(&m, "tombstone").unwrap_or(0) != 0;
        out.push(SettingEntry { key, value, updated, tombstone });
    }
    out
}

fn devices_section_bytes(devices: &[DeviceSettings]) -> Vec<u8> {
    let mut b = devices_schema()
        .build()
        .set("version", VsfType::z(FSTATE_VERSION))
        .expect("devices version");
    for d in devices {
        // Denormalized: one row per (device, entry), every value labeled. An EMPTY map still needs its clock for newest-copy-wins, so it emits one entry-less row.
        if d.entries.is_empty() {
            b = b
                .append_multi(
                    "row",
                    vec![
                        label("device"),
                        VsfType::ke(d.device_pubkey.to_vec()),
                        label("map_updated"),
                        VsfType::e(EtType::e6(d.updated)),
                    ],
                )
                .expect("device bare row");
        }
        for e in &d.entries {
            b = b
                .append_multi(
                    "row",
                    vec![
                        label("device"),
                        VsfType::ke(d.device_pubkey.to_vec()),
                        label("map_updated"),
                        VsfType::e(EtType::e6(d.updated)),
                        label("key"),
                        VsfType::d(e.key.clone()),
                        label("value"),
                        VsfType::v(b'r', e.value.clone()),
                        label("entry_updated"),
                        VsfType::e(EtType::e6(e.updated)),
                        label("linked"),
                        VsfType::u3(e.linked as u8),
                    ],
                )
                .expect("device entry row");
        }
    }
    b.encode().expect("devices section encode")
}

fn decode_devices_section(sec: &SectionBuilder) -> Vec<DeviceSettings> {
    let mut out: Vec<DeviceSettings> = Vec::new();
    for row in sec.get_fields("row") {
        let m = labeled_values(&row.values);
        let (Some(pk), Some(map_updated)) = (get_k32(&m, "device"), get_e6(&m, "map_updated")) else {
            continue;
        };
        let slot = match out.iter_mut().find(|d| d.device_pubkey == pk) {
            Some(d) => d,
            None => {
                out.push(DeviceSettings { device_pubkey: pk, updated: map_updated, entries: Vec::new() });
                out.last_mut().unwrap()
            }
        };
        slot.updated = slot.updated.max(map_updated);
        if let (Some(key), Some(value), Some(entry_updated)) =
            (get_key(&m, "key"), get_raw(&m, "value"), get_e6(&m, "entry_updated"))
        {
            let linked = get_u3(&m, "linked").unwrap_or(0) != 0;
            slot.entries.push(DeviceSetting { key, value, updated: entry_updated, linked });
        }
    }
    out
}

/// Serialize the settings layers (global + per-device maps) to sealed-payload bytes — a document with the two settings sections.
pub fn settings_to_bytes(global: &[SettingEntry], devices: &[DeviceSettings]) -> Vec<u8> {
    document(vec![
        (GLOBALS_SECTION, globals_section_bytes(global)),
        (DEVICES_SECTION, devices_section_bytes(devices)),
    ])
}

/// Parse the settings layers back. Verified read + version gate per section.
pub fn settings_from_bytes(bytes: &[u8]) -> Result<(Vec<SettingEntry>, Vec<DeviceSettings>), String> {
    let g = parse_section(globals_schema(), bytes)?.ok_or("settings: globals section missing")?;
    let d = parse_section(devices_schema(), bytes)?.ok_or("settings: devices section missing")?;
    if !version_matches(&g) || !version_matches(&d) {
        return Err("settings: version mismatch".into());
    }
    Ok((decode_globals_section(&g), decode_devices_section(&d)))
}

/// Serialize the FULL fleet state (roster + settings) — the one document that rides the fstate slot.
pub fn fstate_to_bytes(state: &FleetState) -> Vec<u8> {
    document(vec![
        (ROSTER_SECTION, roster_section_bytes(&state.roster)),
        (GLOBALS_SECTION, globals_section_bytes(&state.global_settings)),
        (DEVICES_SECTION, devices_section_bytes(&state.device_settings)),
    ])
}

/// Parse a fleet-state document. A roster-only document reads as roster + empty settings — no version fork.
pub fn fstate_from_bytes(bytes: &[u8]) -> Result<FleetState, String> {
    // A KNOWN legacy layout (the pre-v6 hand-rolled tags) is the documented flag-day: it reads as ABSENT — roster re-seeds from live contacts, settings re-push. It must NOT read as an error: push is pull-merge-push and a pull error rightly aborts the push (the PRST2→PRST3 lesson), so error-ing on the old blob would deadlock the slot on its old bytes forever — no v6 device could ever complete the push that re-seeds it.
    if bytes.len() >= 4 {
        let tag = &bytes[..4];
        if tag == b"PRST" || tag == b"PFST" || tag == b"PSET" {
            return Ok(FleetState::default());
        }
    }
    // Anything else non-document is corruption or an unknown future format — a real error, which the push path treats as untouchable.
    vsf::verification::read_verified(bytes, None).map_err(|e| format!("fstate: {e:?}"))?;
    // A roster the reader can't parse is EMPTY, not fatal. The layers share one document but are independent, and a roster version bump is a documented flag-day whose cost is meant to be "one re-push of the roster" — NOT the settings going with it. Propagating the error here made the whole fstate unreadable, and because `push_roster` is pull-merge-push, the failed pull left an empty merge base and the next push DESTROYED the fleet's settings on FGTW (observed on the v2→v3 bump: "state pulled — 8 roster entries, 0 global settings, 0 device maps").
    let roster = match parse_section(roster_schema(), bytes) {
        Ok(Some(sec)) if version_matches(&sec) => decode_roster_section(&sec),
        _ => Vec::new(),
    };
    // Settings stay strict the other way: an ABSENT section is a roster-only push, but a CORRUPT or wrong-version one must fail the pull — defaulting it to empty would hand pull-merge-push an empty base and destroy the fleet's settings on the next push.
    let global_settings = match parse_section(globals_schema(), bytes)? {
        Some(sec) if version_matches(&sec) => decode_globals_section(&sec),
        Some(_) => return Err("fstate: settings version mismatch".into()),
        None => Vec::new(),
    };
    let device_settings = match parse_section(devices_schema(), bytes)? {
        Some(sec) if version_matches(&sec) => decode_devices_section(&sec),
        Some(_) => return Err("fstate: settings version mismatch".into()),
        None => Vec::new(),
    };
    Ok(FleetState { roster, global_settings, device_settings })
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

/// CRDT merge for the GLOBAL settings layer: union by key, last-writer-wins on `updated`. On an exact-tie: a tombstone wins (deletes are conservative, mirroring the roster), then greater value bytes — a strictly deterministic total order, so the merge is commutative even for a same-instant write of different values.
pub fn merge_global_settings(a: Vec<SettingEntry>, b: Vec<SettingEntry>) -> Vec<SettingEntry> {
    use std::collections::HashMap;
    let mut by: HashMap<String, SettingEntry> = HashMap::new();
    for e in a.into_iter().chain(b.into_iter()) {
        let replace = match by.get(&e.key) {
            None => true,
            Some(cur) => {
                e.updated > cur.updated
                    || (e.updated == cur.updated
                        && (e.tombstone && !cur.tombstone
                            || (e.tombstone == cur.tombstone && e.value > cur.value)))
            }
        };
        if replace {
            by.insert(e.key.clone(), e);
        }
    }
    let mut out: Vec<SettingEntry> = by.into_values().collect();
    out.sort_by(|x, y| x.key.cmp(&y.key));
    out
}

/// Canonical ordering key for a device map — entries sorted by field, for the deterministic tie-break below. (This replaced a serialized-bytes comparison: the document codec stamps a creation time, so its bytes are no longer a stable order.)
fn device_map_canon(d: &DeviceSettings) -> Vec<(&str, &[u8], i64, bool)> {
    let mut rows: Vec<_> = d
        .entries
        .iter()
        .map(|e| (e.key.as_str(), e.value.as_slice(), e.updated, e.linked))
        .collect();
    rows.sort();
    rows
}

/// Merge the per-device maps: union by device pubkey, whole-map newest-copy-wins on the map's `updated` (single-writer, so a tie means identical content in practice; the canonical entry ordering breaks it deterministically anyway). A device absent from one side is kept — an offline device's map must survive every merge it isn't present for.
pub fn merge_device_settings(a: Vec<DeviceSettings>, b: Vec<DeviceSettings>) -> Vec<DeviceSettings> {
    use std::collections::HashMap;
    let mut by: HashMap<[u8; 32], DeviceSettings> = HashMap::new();
    for d in a.into_iter().chain(b.into_iter()) {
        let replace = match by.get(&d.device_pubkey) {
            None => true,
            Some(cur) => {
                d.updated > cur.updated
                    || (d.updated == cur.updated && device_map_canon(&d) > device_map_canon(cur))
            }
        };
        if replace {
            by.insert(d.device_pubkey, d);
        }
    }
    let mut out: Vec<DeviceSettings> = by.into_values().collect();
    out.sort_by(|x, y| x.device_pubkey.cmp(&y.device_pubkey));
    out
}

/// Merge two full fleet states — the one call a puller makes: roster LWW + global-settings LWW + device newest-copy-wins.
pub fn merge_fstate(a: FleetState, b: FleetState) -> FleetState {
    FleetState {
        roster: merge_rosters(a.roster, b.roster),
        global_settings: merge_global_settings(a.global_settings, b.global_settings),
        device_settings: merge_device_settings(a.device_settings, b.device_settings),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roster_entry(hp: u8, updated: i64, tombstone: bool) -> RosterEntry {
        RosterEntry {
            handle_proof: [hp; 32],
            handle_hash: [hp ^ 0xff; 32],
            public_identity: [hp.wrapping_add(1); 32],
            published_name: format!("Chosen{hp}"),
            avatar_pin: [hp ^ 0x55; 64],
            added: 100,
            updated,
            tombstone,
            ceremony_owner: [hp.wrapping_add(2); 32],
            woven: hp % 2 == 0,
            trust_level: hp % 4,
        }
    }

    /// The pre-v6 blobs still sitting in live slots must read as ABSENT, not as an error — an error aborts pull-merge-push and no v6 device could ever re-seed the slot.
    #[test]
    fn legacy_tagged_blobs_read_as_absent_fstate() {
        for legacy in [&b"PRST5\x00\x00\x00\x01junk"[..], b"PFST1junk", b"PSET0junk"] {
            let state = fstate_from_bytes(legacy).expect("legacy tags are the flag-day, not corruption");
            assert!(state.roster.is_empty() && state.global_settings.is_empty());
        }
        assert!(fstate_from_bytes(b"XYZWjunk").is_err(), "unknown bytes stay an error");
    }

    #[test]
    fn roster_serialize_round_trips() {
        let entries = vec![roster_entry(1, 200, false), roster_entry(2, 300, true)];
        let bytes = roster_to_bytes(&entries);
        assert_eq!(roster_from_bytes(&bytes).unwrap(), entries);
        // A truncated blob fails the verified read rather than panicking or parsing on faith.
        assert!(roster_from_bytes(&bytes[..bytes.len() - 3]).is_err());
        assert!(roster_from_bytes(b"nope").is_err());
    }

    /// The version rides the document as a `z` field and gates the parse: a wrong version reads as absent, which upstream means "re-sync from live contacts" — the flag-day, without a length-changing ASCII tag.
    #[test]
    fn version_mismatch_reads_as_absent_roster() {
        let sec = roster_schema()
            .build()
            .set("version", VsfType::z(FSTATE_VERSION - 1))
            .unwrap()
            .encode()
            .unwrap();
        let doc = document(vec![(ROSTER_SECTION, sec)]);
        assert!(roster_from_bytes(&doc).is_err(), "an old-version roster must not parse");
        let state = fstate_from_bytes(&doc).expect("the document itself is valid");
        assert!(state.roster.is_empty(), "wrong-version roster reads as absent, not as an error");
    }

    /// trust_level rides the entry's LWW clock: a trust decision belongs to the identity, not to the device it was typed on. Before v3 the roster carried no trust at all, so promoting a friend on one device left every sibling on the old level forever.
    #[test]
    fn trust_level_follows_last_writer_wins() {
        let mut old = roster_entry(7, 100, false);
        old.trust_level = 1; // Known
        let mut newer = roster_entry(7, 200, false);
        newer.trust_level = 3; // Inner — promoted on another device, later

        for merged in [
            merge_rosters(vec![old.clone()], vec![newer.clone()]),
            merge_rosters(vec![newer.clone()], vec![old.clone()]),
        ] {
            assert_eq!(merged.len(), 1);
            assert_eq!(
                merged[0].trust_level, 3,
                "the newer trust decision must win regardless of merge order"
            );
        }

        // And a STALE write must not undo it — an older entry loses even though its trust differs.
        let mut stale = roster_entry(7, 50, false);
        stale.trust_level = 0;
        let merged = merge_rosters(vec![newer.clone()], vec![stale]);
        assert_eq!(merged[0].trust_level, 3, "an older entry must never downgrade trust");
    }

    /// A roster the reader can't parse must not take the SETTINGS with it. The layers share one document but are independent, and a roster version bump is a documented flag-day whose cost is one roster re-push. Propagating the error made the whole fstate unreadable, and because push is pull-merge-push, the failed pull rebased on empty and the next push DESTROYED the fleet's settings on FGTW — observed live on the v2→v3 bump ("8 roster entries, 0 global settings, 0 device maps").
    #[test]
    fn an_unparseable_roster_does_not_destroy_settings() {
        // Hand-build a document whose roster section is garbage bytes but whose settings sections are valid.
        let blob = document(vec![
            (ROSTER_SECTION, b"not a section".to_vec()),
            (
                GLOBALS_SECTION,
                globals_section_bytes(&[SettingEntry {
                    key: "display.theme".into(),
                    value: vec![7],
                    updated: 42,
                    tombstone: false,
                }]),
            ),
            (DEVICES_SECTION, devices_section_bytes(&[])),
        ]);

        let state = fstate_from_bytes(&blob).expect("an unreadable roster must not fail the whole fstate");
        assert!(state.roster.is_empty(), "the unreadable roster reads as absent — it re-syncs from live contacts");
        assert_eq!(state.global_settings.len(), 1, "the settings layer must survive intact");
        assert_eq!(state.global_settings[0].key, "display.theme");
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

    fn setting(key: &str, value: &[u8], updated: i64, tombstone: bool) -> SettingEntry {
        SettingEntry { key: key.to_string(), value: value.to_vec(), updated, tombstone }
    }

    fn device_map(pk: u8, updated: i64, entries: Vec<DeviceSetting>) -> DeviceSettings {
        DeviceSettings { device_pubkey: [pk; 32], updated, entries }
    }

    fn dev_setting(key: &str, value: &[u8], updated: i64, linked: bool) -> DeviceSetting {
        DeviceSetting { key: key.to_string(), value: value.to_vec(), updated, linked }
    }

    #[test]
    fn settings_serialize_round_trips() {
        let global = vec![setting("updates.auto", &[1], 500, false), setting("theme", b"amber", 400, true)];
        let devices = vec![
            device_map(7, 600, vec![dev_setting("display.cal", &[9, 9], 600, false), dev_setting("updates.auto", &[1], 500, true)]),
            device_map(8, 300, vec![]),
        ];
        let bytes = settings_to_bytes(&global, &devices);
        let (g, d) = settings_from_bytes(&bytes).unwrap();
        assert_eq!(g, global);
        assert_eq!(d, devices);
        // Truncated / garbage fails rather than panicking.
        assert!(settings_from_bytes(&bytes[..bytes.len() - 2]).is_err());
        assert!(settings_from_bytes(b"nope").is_err());
    }

    #[test]
    fn fstate_round_trips_and_reads_roster_only_documents() {
        let state = FleetState {
            roster: vec![roster_entry(1, 200, false)],
            global_settings: vec![setting("updates.auto", &[1], 500, false)],
            device_settings: vec![device_map(7, 600, vec![dev_setting("k", &[2], 600, true)])],
        };
        let bytes = fstate_to_bytes(&state);
        assert_eq!(fstate_from_bytes(&bytes).unwrap(), state);
        // A roster-only document parses as roster + empty settings — no version fork.
        let old = roster_to_bytes(&state.roster);
        let parsed = fstate_from_bytes(&old).unwrap();
        assert_eq!(parsed.roster, state.roster);
        assert!(parsed.global_settings.is_empty());
        assert!(parsed.device_settings.is_empty());
        assert!(fstate_from_bytes(b"junk").is_err());
    }

    #[test]
    fn global_settings_merge_is_commutative_lww_with_deterministic_ties() {
        let old = setting("theme", b"green", 100, false);
        let newer = setting("theme", b"amber", 200, false);
        let ab = merge_global_settings(vec![old.clone()], vec![newer.clone()]);
        let ba = merge_global_settings(vec![newer.clone()], vec![old.clone()]);
        assert_eq!(ab, ba);
        assert_eq!(ab[0].value, b"amber");
        // Tombstone wins an exact tie (delete beats concurrent write).
        let alive = setting("k", &[1], 200, false);
        let dead = setting("k", &[1], 200, true);
        assert!(merge_global_settings(vec![alive.clone()], vec![dead.clone()])[0].tombstone);
        assert!(merge_global_settings(vec![dead], vec![alive])[0].tombstone);
        // Same-instant different-value writes resolve identically in either order (greater value bytes).
        let x = setting("k", &[5], 300, false);
        let y = setting("k", &[9], 300, false);
        let xy = merge_global_settings(vec![x.clone()], vec![y.clone()]);
        let yx = merge_global_settings(vec![y], vec![x]);
        assert_eq!(xy, yx);
        assert_eq!(xy[0].value, vec![9]);
    }

    #[test]
    fn device_settings_merge_is_newest_copy_wins_and_keeps_absent_devices() {
        let stale = device_map(7, 100, vec![dev_setting("k", &[1], 100, true)]);
        let fresh = device_map(7, 200, vec![dev_setting("k", &[2], 200, false)]);
        let other = device_map(8, 50, vec![]);
        let ab = merge_device_settings(vec![stale.clone(), other.clone()], vec![fresh.clone()]);
        let ba = merge_device_settings(vec![fresh], vec![stale, other]);
        assert_eq!(ab, ba);
        // Device 7 took the newer whole map (link bit + value together — never a cross-copy mix).
        let seven = ab.iter().find(|d| d.device_pubkey == [7; 32]).unwrap();
        assert_eq!(seven.entries[0].value, vec![2]);
        assert!(!seven.entries[0].linked);
        // Device 8, absent from one side, survives the merge (offline device's map persists).
        assert!(ab.iter().any(|d| d.device_pubkey == [8; 32]));
    }
}
