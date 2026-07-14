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

/// One syncable friend. The minimal identity a device needs to reconstruct a contact and re-CLUTCH: the PIN-SET (docs/identity-profile.md — party id, proof, avatar key, petname; NEVER the handle string, which derives the identity seed) plus CRDT bookkeeping (`updated` for last-writer-wins, `tombstone` for removals that must stick across a merge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    pub handle_proof: [u8; 32],
    /// The contact's PARTY ID: their pinned identity PUBKEY — verification-only, no signing power. (The pre-pin-set roster carried the friend's identity SEED here; the PRST1 tag bump orphans those blobs.)
    pub handle_hash: [u8; 32],
    /// Last-known friend device pubkey (a hint; the joining device re-discovers current devices by handle_proof). Zero if unknown.
    pub public_identity: [u8; 32],
    /// The local petname, synced across OUR OWN fleet under the fleet key — a label we chose, empty = render the keyed pseudonym.
    pub name: String,
    /// The pinned avatar-wall material, derived once at first-met and synced so every fleet device fetches + decrypts this friend's avatar without ever holding the handle: AES key (32) ‖ FGTW lookup hash (32). Zero = not pinned.
    pub avatar_pin: [u8; 64],
    pub added: i64,
    /// Logical clock for this entry — the newest write across the fleet wins the merge.
    pub updated: i64,
    /// A removed contact stays as a tombstone so a stale device re-adding it can't resurrect it.
    pub tombstone: bool,
}

// PRST0 carried handle strings (and seeds in handle_hash) — the tag bump is the flag-day: old blobs read as absent and the roster re-syncs from live contacts.
const ROSTER_TAG: &[u8; 5] = b"PRST1";

/// Serialize the roster to the plaintext that gets sealed under the fleet key. Not VSF: this is opaque AEAD-payload bytes, so a compact fixed-layout encoding is simpler and just as forensic (the wire envelope around the ciphertext is VSF).
pub fn roster_to_bytes(entries: &[RosterEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ROSTER_TAG);
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for e in entries {
        out.extend_from_slice(&e.handle_proof);
        out.extend_from_slice(&e.handle_hash);
        out.extend_from_slice(&e.public_identity);
        out.extend_from_slice(&e.avatar_pin);
        out.extend_from_slice(&e.added.to_be_bytes());
        out.extend_from_slice(&e.updated.to_be_bytes());
        out.push(e.tombstone as u8);
        let nb = e.name.as_bytes();
        out.extend_from_slice(&(nb.len() as u32).to_be_bytes());
        out.extend_from_slice(nb);
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
        let avatar_pin: [u8; 64] = take(&mut p, 64)?.try_into().unwrap();
        let added = i64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
        let updated = i64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
        let tombstone = take(&mut p, 1)?[0] != 0;
        let nlen = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
        let name = String::from_utf8(take(&mut p, nlen)?.to_vec())
            .map_err(|_| "roster: name not utf8".to_string())?;
        out.push(RosterEntry {
            handle_proof,
            handle_hash,
            public_identity,
            name,
            avatar_pin,
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

const SETTINGS_TAG: &[u8; 5] = b"PSET0";
const FSTATE_TAG: &[u8; 5] = b"PFST1";

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// Serialize the settings layers (global + per-device maps) to sealed-payload bytes. Same doctrine as the roster: compact fixed layout, not VSF — the wire envelope around the ciphertext is VSF.
pub fn settings_to_bytes(global: &[SettingEntry], devices: &[DeviceSettings]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SETTINGS_TAG);
    out.extend_from_slice(&(global.len() as u32).to_be_bytes());
    for e in global {
        put_bytes(&mut out, e.key.as_bytes());
        put_bytes(&mut out, &e.value);
        out.extend_from_slice(&e.updated.to_be_bytes());
        out.push(e.tombstone as u8);
    }
    out.extend_from_slice(&(devices.len() as u32).to_be_bytes());
    for d in devices {
        out.extend_from_slice(&d.device_pubkey);
        out.extend_from_slice(&d.updated.to_be_bytes());
        out.extend_from_slice(&(d.entries.len() as u32).to_be_bytes());
        for e in &d.entries {
            put_bytes(&mut out, e.key.as_bytes());
            put_bytes(&mut out, &e.value);
            out.extend_from_slice(&e.updated.to_be_bytes());
            out.push(e.linked as u8);
        }
    }
    out
}

/// Parse the settings payload back. Bounds-checked throughout — truncated/corrupt fails, never panics.
pub fn settings_from_bytes(bytes: &[u8]) -> Result<(Vec<SettingEntry>, Vec<DeviceSettings>), String> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], String> {
        if *p + n > bytes.len() {
            return Err("settings: truncated".into());
        }
        let s = &bytes[*p..*p + n];
        *p += n;
        Ok(s)
    };
    let take_str = |p: &mut usize| -> Result<String, String> {
        let n = u32::from_be_bytes(
            if *p + 4 > bytes.len() { return Err("settings: truncated".into()) } else { let s = &bytes[*p..*p + 4]; *p += 4; s }
                .try_into()
                .unwrap(),
        ) as usize;
        if *p + n > bytes.len() {
            return Err("settings: truncated".into());
        }
        let s = String::from_utf8(bytes[*p..*p + n].to_vec()).map_err(|_| "settings: key not utf8".to_string())?;
        *p += n;
        Ok(s)
    };
    let take_val = |p: &mut usize| -> Result<Vec<u8>, String> {
        let n = u32::from_be_bytes(
            if *p + 4 > bytes.len() { return Err("settings: truncated".into()) } else { let s = &bytes[*p..*p + 4]; *p += 4; s }
                .try_into()
                .unwrap(),
        ) as usize;
        if *p + n > bytes.len() {
            return Err("settings: truncated".into());
        }
        let v = bytes[*p..*p + n].to_vec();
        *p += n;
        Ok(v)
    };
    if take(&mut p, 5)? != SETTINGS_TAG {
        return Err("settings: bad tag".into());
    }
    let gcount = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    let mut global = Vec::with_capacity(gcount.min(4096));
    for _ in 0..gcount {
        let key = take_str(&mut p)?;
        let value = take_val(&mut p)?;
        let updated = i64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
        let tombstone = take(&mut p, 1)?[0] != 0;
        global.push(SettingEntry { key, value, updated, tombstone });
    }
    let dcount = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    let mut devices = Vec::with_capacity(dcount.min(4096));
    for _ in 0..dcount {
        let device_pubkey: [u8; 32] = take(&mut p, 32)?.try_into().unwrap();
        let updated = i64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
        let ecount = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
        let mut entries = Vec::with_capacity(ecount.min(4096));
        for _ in 0..ecount {
            let key = take_str(&mut p)?;
            let value = take_val(&mut p)?;
            let updated = i64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
            let linked = take(&mut p, 1)?[0] != 0;
            entries.push(DeviceSetting { key, value, updated, linked });
        }
        devices.push(DeviceSettings { device_pubkey, updated, entries });
    }
    Ok((global, devices))
}

/// Serialize the FULL fleet state (roster + settings) — the one blob that rides the fstate slot. The roster and settings payloads nest verbatim, so their codecs stay the single source of truth.
pub fn fstate_to_bytes(state: &FleetState) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(FSTATE_TAG);
    put_bytes(&mut out, &roster_to_bytes(&state.roster));
    put_bytes(&mut out, &settings_to_bytes(&state.global_settings, &state.device_settings));
    out
}

/// Parse a fleet-state blob. Accepts BOTH the combined `PFST1` layout AND a bare pre-settings roster blob (`PRST0`) — an old blob simply reads as roster-only with empty settings, so the transition needs no version fork.
pub fn fstate_from_bytes(bytes: &[u8]) -> Result<FleetState, String> {
    if bytes.len() >= 5 && &bytes[..5] == ROSTER_TAG {
        return Ok(FleetState { roster: roster_from_bytes(bytes)?, ..Default::default() });
    }
    if bytes.len() < 5 || &bytes[..5] != FSTATE_TAG {
        return Err("fstate: bad tag".into());
    }
    let mut p = 5usize;
    let take_chunk = |p: &mut usize| -> Result<&[u8], String> {
        if *p + 4 > bytes.len() {
            return Err("fstate: truncated".into());
        }
        let n = u32::from_be_bytes(bytes[*p..*p + 4].try_into().unwrap()) as usize;
        *p += 4;
        if *p + n > bytes.len() {
            return Err("fstate: truncated".into());
        }
        let s = &bytes[*p..*p + n];
        *p += n;
        Ok(s)
    };
    let roster = roster_from_bytes(take_chunk(&mut p)?)?;
    let (global_settings, device_settings) = settings_from_bytes(take_chunk(&mut p)?)?;
    Ok(FleetState { roster, global_settings, device_settings })
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

/// Merge the per-device maps: union by device pubkey, whole-map newest-copy-wins on the map's `updated` (single-writer, so a tie means identical content in practice; greater serialized bytes breaks it deterministically anyway). A device absent from one side is kept — an offline device's map must survive every merge it isn't present for.
pub fn merge_device_settings(a: Vec<DeviceSettings>, b: Vec<DeviceSettings>) -> Vec<DeviceSettings> {
    use std::collections::HashMap;
    let mut by: HashMap<[u8; 32], DeviceSettings> = HashMap::new();
    for d in a.into_iter().chain(b.into_iter()) {
        let replace = match by.get(&d.device_pubkey) {
            None => true,
            Some(cur) => {
                d.updated > cur.updated
                    || (d.updated == cur.updated
                        && settings_to_bytes(&[], std::slice::from_ref(&d))
                            > settings_to_bytes(&[], std::slice::from_ref(cur)))
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
            name: format!("friend{hp}"),
            avatar_pin: [hp ^ 0x55; 64],
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
    fn fstate_round_trips_and_reads_old_roster_only_blobs() {
        let state = FleetState {
            roster: vec![roster_entry(1, 200, false)],
            global_settings: vec![setting("updates.auto", &[1], 500, false)],
            device_settings: vec![device_map(7, 600, vec![dev_setting("k", &[2], 600, true)])],
        };
        let bytes = fstate_to_bytes(&state);
        assert_eq!(fstate_from_bytes(&bytes).unwrap(), state);
        // A pre-settings roster blob parses as roster-only with empty settings — no version fork.
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
