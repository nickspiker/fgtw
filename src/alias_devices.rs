//! The devices a kist's alias vouches for (ferros docs/PHOTON.md "Photon's devices", M3): the alias signs the list of the device keys its kist runs on, one per device of the person's, and a contact takes that kist's traffic from a device in the list.
//! On the desktop and Android a device's key is the device's own fleet member key, so it is in both the chain and the list; on ferros the kist's key is its own, in the list only and never a member of the fleet, so the kist can never sponsor a device into it.
//! The newest revision wins; `complete` says every member of the person's fleet has signed into the list, the cutover (M4): from then a contact takes that person's traffic only from a listed device.
//! The list is signed by the alias with every egg it holds, and checked against the alias's public bundle as the person's binding names it (fgtw `facets`).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vsf::file_format::VsfSection;
use vsf::types::EtType;
use vsf::VsfType;

use crate::pq::{eggs_from_bytes, KeyBundle};

/// A device or identity key.
pub type Key = [u8; 32];

/// The devices an alias vouches for, as the alias signed them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceList {
    /// The person (handle proof) whose alias this is.
    pub handle_proof: Key,
    /// The Eagle time (oscillations) the alias signed this list: the newest wins.
    pub revision: i64,
    /// The kist's device keys, sorted and without repeats.
    pub devices: Vec<Key>,
    /// Every member of the person's fleet has signed into this list (the cutover).
    pub complete: bool,
    /// The alias's eggs over [`DeviceList::signing_bytes`], as an egg-list blob.
    pub sig: Vec<u8>,
}

impl DeviceList {
    /// The bytes the alias signs: a domain, the person, the revision, the cutover mark, the number of devices and each device in order.
    pub fn signing_bytes(handle_proof: &Key, revision: i64, devices: &[Key], complete: bool) -> Vec<u8> {
        let mut m = Vec::with_capacity(64 + devices.len() * 32);
        m.extend_from_slice(b"fgtw.alias.devices.v1");
        m.extend_from_slice(handle_proof);
        m.extend_from_slice(&revision.to_le_bytes());
        m.push(complete as u8);
        m.extend_from_slice(&(devices.len() as u32).to_le_bytes());
        for d in devices {
            m.extend_from_slice(d);
        }
        m
    }

    /// Sign a list with the alias's every egg. The devices are sorted and repeats dropped first, so the same set always signs the same bytes.
    #[cfg(feature = "sign")]
    pub fn sign(alias: &crate::pq::SigningBundle, handle_proof: &Key, revision: i64, mut devices: Vec<Key>, complete: bool) -> Self {
        use crate::pq::FleetSigner;
        devices.sort_unstable();
        devices.dedup();
        let msg = Self::signing_bytes(handle_proof, revision, &devices, complete);
        let mask = alias.bundle().map(|b| b.mask()).unwrap_or(crate::fleet::scheme::MASK_BASE);
        let sig = crate::pq::eggs_to_bytes(&alias.eggs(&msg, mask));
        DeviceList { handle_proof: *handle_proof, revision, devices, complete, sig }
    }

    /// The list with `device` in it, signed by the alias: None when the held list already names it, else the held devices and this one, at a revision past the held one (`now`, or one past the held when the clock is behind it), so the new list wins.
    /// Every Photon of the person's calls this with its own device key on each fetch, so two that add themselves at once converge: the loser of the race finds itself missing in the winner's list and adds itself again.
    #[cfg(feature = "sign")]
    pub fn with_device(held: Option<&DeviceList>, alias: &crate::pq::SigningBundle, handle_proof: &Key, device: Key, now: i64) -> Option<Self> {
        Self::revised(held, alias, handle_proof, &[device], &[], now)
    }

    /// The list with every device of `add` in it and none of `drop`, signed by the alias: None when the held list already says exactly that, else at a revision past the held one (`now`, or one past the held when the clock is behind it), so the new list wins.
    /// A sign-out drops the device itself; a member drops what the chain has locked out.
    #[cfg(feature = "sign")]
    pub fn revised(held: Option<&DeviceList>, alias: &crate::pq::SigningBundle, handle_proof: &Key, add: &[Key], drop: &[Key], now: i64) -> Option<Self> {
        let mut devices = held.map(|l| l.devices.clone()).unwrap_or_default();
        let before = devices.len();
        devices.retain(|d| !drop.contains(d));
        let dropped = devices.len() != before;
        let mut added = false;
        for d in add {
            if !devices.contains(d) && !drop.contains(d) {
                devices.push(*d);
                added = true;
            }
        }
        if !dropped && !added && held.is_some() {
            return None;
        }
        // WHY the max: the revision must pass the held one for the new list to win, and a device's clock may sit behind the one that signed it.
        let revision = held.map_or(now, |l| now.max(l.revision + 1));
        Some(Self::sign(alias, handle_proof, revision, devices, held.is_some_and(|l| l.complete)))
    }

    /// Whether the alias whose public bundle this is signed the list, with every egg that bundle holds (no single eggs), and the list is in its signed form (sorted, no repeats).
    pub fn verify(&self, alias: &KeyBundle) -> bool {
        if self.devices.windows(2).any(|w| w[0] >= w[1]) {
            return false;
        }
        let msg = Self::signing_bytes(&self.handle_proof, self.revision, &self.devices, self.complete);
        eggs_from_bytes(&self.sig).is_ok_and(|eggs| crate::pq::verify_eggs(&eggs, alias, &msg, alias.mask()))
    }

    /// Whether a device is one the alias vouches for.
    pub fn contains(&self, device: &Key) -> bool {
        self.devices.binary_search(device).is_ok()
    }

    /// Newer than `other` for the same person: the later revision, and at an equal revision the larger signature hash, so every holder keeps the same list.
    pub fn newer_than(&self, other: &DeviceList) -> bool {
        self.revision > other.revision || (self.revision == other.revision && blake3::hash(&self.sig).as_bytes() > blake3::hash(&other.sig).as_bytes())
    }

    /// The list as a VSF section; an empty device list is left out (its absence reads back as no devices), never written as an empty field.
    pub fn to_section(&self) -> VsfSection {
        let mut sec = VsfSection::new("alias_devices");
        sec.add_field("handle_proof", VsfType::hP(self.handle_proof.to_vec()));
        sec.add_field("revision", VsfType::e(EtType::e6(self.revision)));
        if !self.devices.is_empty() {
            sec.add_field_multi("devices", self.devices.iter().map(|d| VsfType::ke(d.to_vec())).collect());
        }
        sec.add_field("complete", VsfType::u(self.complete as usize, false));
        sec.add_field("sig", VsfType::ge(self.sig.clone()));
        sec
    }

    /// Read a list back; a field of the wrong type is an error, never defaulted.
    pub fn from_section(sec: &VsfSection) -> Result<Self, String> {
        if sec.name != "alias_devices" {
            return Err("not an alias device list".to_string());
        }
        let first = |name: &str| sec.get_field(name).and_then(|f| f.values.first());
        let handle_proof = match first("handle_proof") {
            Some(VsfType::hP(b)) if b.len() == 32 => b.as_slice().try_into().map_err(|_| "handle proof".to_string())?,
            _ => return Err("alias device list missing its person".to_string()),
        };
        let revision = sec.eagle("revision").ok_or("alias device list missing its revision")?;
        let mut devices = Vec::new();
        if let Some(f) = sec.get_field("devices") {
            for v in &f.values {
                match v {
                    VsfType::ke(b) if b.len() == 32 => devices.push(b.as_slice().try_into().map_err(|_| "device key".to_string())?),
                    _ => return Err("alias device list: a device that is not a 32-byte key".to_string()),
                }
            }
        }
        let complete = match first("complete").and_then(|v| v.as_u64()) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err("alias device list missing its cutover mark".to_string()),
        };
        let sig = match first("sig") {
            Some(VsfType::ge(b)) => b.clone(),
            _ => return Err("alias device list missing its signature".to_string()),
        };
        Ok(DeviceList { handle_proof, revision, devices, complete, sig })
    }
}

/// A device's own word that it left the alias's list (the owner 2026-11-18: "the other needs the device present to sign itself out, thus asserting it wiped its keys"): signed by the leaving device's own key over the person, the device and the list revision it leaves at.
/// The alias is every Photon's of the person, so a list that merely omits a device proves nothing; a reader takes a device out of the list it acts on only when this record, or the chain, backs the omission ([`unbacked_drops`]).
/// It rides the slot document beside the list, carried from revision to revision while the device stays out ([`carried`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignOut {
    /// The person (handle proof) whose list the device leaves.
    pub handle_proof: Key,
    /// The leaving device's key, the one that signed.
    pub device: Key,
    /// The revision of the list the device leaves at: the first one without it.
    pub revision: i64,
    /// The device's eggs over [`SignOut::signing_bytes`], as an egg-list blob: its Ed25519 key, the one every listed device holds.
    pub sig: Vec<u8>,
}

/// The wrap a sign-out rides under in the slot document.
pub const SIGNOUT_WRAP: u8 = b'S';

impl SignOut {
    /// The bytes the leaving device signs: a domain, the person, the device and the revision it leaves at.
    pub fn signing_bytes(handle_proof: &Key, device: &Key, revision: i64) -> Vec<u8> {
        let mut m = Vec::with_capacity(96);
        m.extend_from_slice(b"fgtw.alias.signout.v1");
        m.extend_from_slice(handle_proof);
        m.extend_from_slice(device);
        m.extend_from_slice(&revision.to_le_bytes());
        m
    }

    /// The leaving device signs its own sign-out with its Ed25519 key.
    pub fn sign(device: &impl crate::pq::FleetSigner, handle_proof: &Key, revision: i64) -> Self {
        let me = device.keypair().public.to_bytes();
        let msg = Self::signing_bytes(handle_proof, &me, revision);
        let sig = crate::pq::eggs_to_bytes(&device.eggs(&msg, crate::fleet::scheme::MASK_BASE));
        SignOut { handle_proof: *handle_proof, device: me, revision, sig }
    }

    /// Whether the device it names signed it.
    pub fn verify(&self) -> bool {
        let msg = Self::signing_bytes(&self.handle_proof, &self.device, self.revision);
        eggs_from_bytes(&self.sig).is_ok_and(|eggs| crate::pq::verify_eggs(&eggs, &KeyBundle::ed25519_only(&self.device), &msg, crate::fleet::scheme::MASK_BASE))
    }

    /// The record as a VSF section.
    pub fn to_section(&self) -> VsfSection {
        let mut sec = VsfSection::new("alias_signout");
        sec.add_field("handle_proof", VsfType::hP(self.handle_proof.to_vec()));
        sec.add_field("device", VsfType::ke(self.device.to_vec()));
        sec.add_field("revision", VsfType::e(EtType::e6(self.revision)));
        sec.add_field("sig", VsfType::ge(self.sig.clone()));
        sec
    }

    /// Read a record back; a field of the wrong type is an error, never defaulted.
    pub fn from_section(sec: &VsfSection) -> Result<Self, String> {
        if sec.name != "alias_signout" {
            return Err("not an alias sign-out".to_string());
        }
        let first = |name: &str| sec.get_field(name).and_then(|f| f.values.first());
        let handle_proof = match first("handle_proof") {
            Some(VsfType::hP(b)) if b.len() == 32 => b.as_slice().try_into().map_err(|_| "handle proof".to_string())?,
            _ => return Err("alias sign-out missing its person".to_string()),
        };
        let device = match first("device") {
            Some(VsfType::ke(b)) if b.len() == 32 => b.as_slice().try_into().map_err(|_| "device key".to_string())?,
            _ => return Err("alias sign-out missing its device".to_string()),
        };
        let revision = sec.eagle("revision").ok_or("alias sign-out missing its revision")?;
        let sig = match first("sig") {
            Some(VsfType::ge(b)) => b.clone(),
            _ => return Err("alias sign-out missing its signature".to_string()),
        };
        Ok(SignOut { handle_proof, device, revision, sig })
    }
}

/// The devices the chain itself backs leaving the list: every device it has locked out, and every device that was a member and left (a member's departure is a Remove the leaver signed its own consent to).
pub fn chain_drops(chain: &crate::fleet::MembershipBlob) -> Vec<Key> {
    let mut drops = chain.all_locked().unwrap_or_default();
    let members = chain.fold().unwrap_or_default();
    for op in &chain.ops {
        if matches!(op.kind, crate::fleet::OpKind::Genesis | crate::fleet::OpKind::Add) && !members.contains(&op.device_pubkey) && !drops.contains(&op.device_pubkey) {
            drops.push(op.device_pubkey);
        }
    }
    drops
}

/// Whether `device` signed itself out of `handle_proof`'s list at a revision past `after` (the revision of the newest list known to name it), by a record among `signouts` that verifies.
pub fn signed_out(device: &Key, handle_proof: &Key, after: i64, signouts: &[SignOut]) -> bool {
    signouts.iter().any(|s| s.device == *device && s.handle_proof == *handle_proof && s.revision > after && s.verify())
}

/// The devices `held` names that `next` leaves out with nothing backing their leaving: neither the device's own sign-out past `held`'s revision nor the chain ([`chain_drops`]).
/// Empty when `next` may replace `held` as the list a reader acts on; otherwise the reader keeps the devices (it keeps `held`), and an honest holder publishes them back ([`DeviceList::revised`]).
pub fn unbacked_drops(held: &DeviceList, next: &DeviceList, signouts: &[SignOut], chain: &crate::fleet::MembershipBlob) -> Vec<Key> {
    let backed = chain_drops(chain);
    held.devices
        .iter()
        .filter(|d| !next.contains(d) && !backed.contains(d) && !signed_out(d, &held.handle_proof, held.revision, signouts))
        .copied()
        .collect()
}

/// The sign-outs a slot document carries with `list`: each verified record of a device the list leaves out, the newest per device; a device listed again drops its record (it came back after it).
pub fn carried(signouts: &[SignOut], list: &DeviceList) -> Vec<SignOut> {
    let mut out: Vec<SignOut> = Vec::new();
    for s in signouts.iter().filter(|s| s.handle_proof == list.handle_proof && !list.contains(&s.device) && s.verify()) {
        match out.iter_mut().find(|o| o.device == s.device) {
            Some(o) if s.revision > o.revision => *o = s.clone(),
            Some(_) => {}
            None => out.push(s.clone()),
        }
    }
    out
}

/// The wrap a list rides under inside another document (the slot document, a pong tail), read back by its marker.
pub const WRAP: u8 = b'D';
/// The wrap the binding that names the alias rides under in the slot document.
pub const BINDING_WRAP: u8 = b'B';
/// The slot document's section.
const SLOT_SECTION: &str = "alias_devices_slot";
/// A slot document past this is refused before it is parsed: a binding (about 10 KB with every egg) and a list of 32-byte keys.
const SLOT_BYTES_MAX: usize = 1 << 16;

/// The list and the binding that names its alias, as one complete VSF file: what fgtw.org's `alias_devices` slot holds and every Photon fetches and checks.
pub fn slot_doc(binding: &[u8], list: &DeviceList, now: i64) -> Result<Vec<u8>, String> {
    slot_doc_with(binding, list, &[], now)
}

/// [`slot_doc`] with the sign-outs that back the devices the list leaves out, each its own typed record under [`SIGNOUT_WRAP`]; none is left out, never written as an empty field.
/// A reader built before sign-outs reads the binding and the list by name and passes the rest by.
pub fn slot_doc_with(binding: &[u8], list: &DeviceList, signouts: &[SignOut], now: i64) -> Result<Vec<u8>, String> {
    let mut sec = VsfSection::new(SLOT_SECTION);
    sec.add_field("binding", VsfType::v(BINDING_WRAP, binding.to_vec()));
    sec.add_field("list", VsfType::v(WRAP, list.to_section().encode_far()));
    if !signouts.is_empty() {
        sec.add_field_multi("signout", signouts.iter().map(|s| VsfType::v(SIGNOUT_WRAP, s.to_section().encode_far())).collect());
    }
    vsf::VsfBuilder::new().creation_time_oscillations(now).add_section_direct(sec).build().map_err(|e| format!("alias devices slot: {e}"))
}

/// The sign-outs a slot document carries, as they verify: a record that does not parse, names another person, or was not signed by the device it names is passed by (it backs nothing, and a forged one cannot make the rest of the slot unreadable).
pub fn signouts_from_slot_doc(bytes: &[u8]) -> Result<Vec<SignOut>, String> {
    let (_, list) = from_slot_doc(bytes)?;
    let (header, end) = vsf::verification::read_verified(bytes, None).map_err(|e| format!("alias devices slot verification: {e}"))?;
    let sec = header.primary_section(bytes, end).map_err(|e| format!("alias devices slot section: {e}"))?;
    let mut out = Vec::new();
    if let Some(f) = sec.get_field("signout") {
        for v in &f.values {
            if let VsfType::v(SIGNOUT_WRAP, b) = v {
                let mut ptr = 0;
                if let Ok(s) = VsfSection::parse(b, &mut ptr).and_then(|s| SignOut::from_section(&s)) {
                    if s.handle_proof == list.handle_proof && s.verify() {
                        out.push(s);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Read a slot document back: the file must verify before a field is read; each field is taken by its marker. Only the form is checked here; [`check`] decides whether the list is the person's.
pub fn from_slot_doc(bytes: &[u8]) -> Result<(Vec<u8>, DeviceList), String> {
    // WHY/PROOF: the document comes from fgtw.org or another device; the parse runs over whatever length it claims.
    if bytes.len() > SLOT_BYTES_MAX {
        return Err(format!("alias devices slot: {} bytes is past the {SLOT_BYTES_MAX} it may be", bytes.len()));
    }
    let (header, end) = vsf::verification::read_verified(bytes, None).map_err(|e| format!("alias devices slot verification: {e}"))?;
    let sec = header.primary_section(bytes, end).map_err(|e| format!("alias devices slot section: {e}"))?;
    if sec.name != SLOT_SECTION {
        return Err("not an alias devices slot".to_string());
    }
    let first = |name: &str| sec.get_field(name).and_then(|f| f.values.first());
    let binding = match first("binding") {
        Some(VsfType::v(BINDING_WRAP, b)) => b.clone(),
        _ => return Err("alias devices slot: no binding".to_string()),
    };
    let list = match first("list") {
        Some(VsfType::v(WRAP, b)) => {
            let mut ptr = 0;
            DeviceList::from_section(&VsfSection::parse(b, &mut ptr)?)?
        }
        _ => return Err("alias devices slot: no list".to_string()),
    };
    Ok((binding, list))
}

/// Whether a list is the person's AND names no device the person's chain has locked out: [`check_signed`], then the locks.
/// The alias is every Photon's of the person, a stolen one's too, so the alias's signature alone cannot keep a locked device out of a list; the chain, which only a member can write, does (the owner 2026-11-18, the stolen ferros threat).
/// Returns the binding, so a caller keeps the alias it names beside the pin.
pub fn check(binding: &[u8], list: &DeviceList, chain: &crate::fleet::MembershipBlob) -> Result<crate::binding::Binding, String> {
    let b = check_signed(binding, list, chain)?;
    let named = locked_named(list, chain)?;
    if !named.is_empty() {
        return Err(format!("alias devices: the list names {} device(s) the chain has locked out", named.len()));
    }
    Ok(b)
}

/// The devices in `list` the chain has locked out (members by Lock, the rest by LockListed): what an honest holder drops in its next revision.
pub fn locked_named(list: &DeviceList, chain: &crate::fleet::MembershipBlob) -> Result<Vec<Key>, String> {
    let locked = chain.all_locked().map_err(|e| format!("alias devices: the chain does not fold ({e:?})"))?;
    Ok(list.devices.iter().filter(|d| locked.contains(d)).copied().collect())
}

/// Whether a list is the person's: the binding is taken against the person's chain (a current member signed it with every egg), names the list's person, and the alias it names signed the list with every egg its bundle holds.
/// Says nothing about locks: [`check`] is what a reader trusts; this is for the holder that prunes a list naming a locked device.
pub fn check_signed(binding: &[u8], list: &DeviceList, chain: &crate::fleet::MembershipBlob) -> Result<crate::binding::Binding, String> {
    let b = crate::binding::Binding::from_vsf_bytes(binding)?;
    b.verify(chain).map_err(|e| format!("alias devices: the binding does not hold ({e:?})"))?;
    if b.handle_proof != list.handle_proof {
        return Err("alias devices: the list names another person than its binding".to_string());
    }
    if !list.verify(&b.alias) {
        return Err("alias devices: the alias did not sign this list".to_string());
    }
    Ok(b)
}

#[cfg(all(test, feature = "sign"))]
mod tests {
    use super::*;
    use crate::pq::FleetSigner;

    const HP: Key = [0x48; 32];

    fn alias() -> crate::pq::SigningBundle {
        crate::alias::bundle(&crate::alias::seed(&[1; 32], &[2; 32], &[3; 32]))
    }

    #[test]
    fn the_alias_signs_its_devices_with_every_egg_and_nobody_else_can() {
        let a = alias();
        let pubs = a.bundle().expect("an alias holds every scheme");
        let list = DeviceList::sign(&a, &HP, 100, vec![[9; 32], [4; 32], [9; 32]], false);
        assert_eq!(list.devices, vec![[4; 32], [9; 32]], "sorted, no repeats");
        assert!(list.verify(&pubs));
        assert!(list.contains(&[4; 32]) && !list.contains(&[5; 32]));
        let other = crate::alias::bundle(&crate::alias::seed(&[7; 32], &[2; 32], &[3; 32]));
        assert!(!list.verify(&other.bundle().unwrap()), "another person's alias does not vouch for these devices");
        let mut added = list.clone();
        added.devices.push([0xEE; 32]);
        assert!(!added.verify(&pubs), "a device slipped into the list breaks the signature");
        let mut cut = list.clone();
        cut.complete = true;
        assert!(!cut.verify(&pubs), "the cutover mark is signed too");
    }

    #[test]
    fn the_newest_list_wins_and_round_trips() {
        let a = alias();
        let old = DeviceList::sign(&a, &HP, 100, vec![[4; 32]], false);
        let new = DeviceList::sign(&a, &HP, 101, vec![[4; 32], [9; 32]], true);
        assert!(new.newer_than(&old) && !old.newer_than(&new));
        for l in [old, new, DeviceList::sign(&a, &HP, 102, Vec::new(), false)] {
            let sec = l.to_section();
            if l.devices.is_empty() {
                assert!(sec.get_field("devices").is_none());
            }
            assert_eq!(DeviceList::from_section(&sec).unwrap(), l);
        }
    }

    #[test]
    fn the_slot_holds_a_list_its_binding_vouches_for() {
        use crate::fleet::MembershipBlob;
        let member = crate::pq::SigningBundle::derive(b"device a");
        let mut chain = MembershipBlob::genesis_v2(&member, HP, &[7; 32], 1_000);
        chain.declare(&member, 1_001);
        let a = alias();
        let mask = chain.declared_mask(&member.keypair().public.to_bytes());
        let binding = crate::binding::Binding::sign(&member, mask, &HP, &[2; 32], &[3; 32], a.bundle().unwrap(), 2_000).to_vsf_bytes().unwrap();
        let list = DeviceList::sign(&a, &HP, 2_001, vec![member.keypair().public.to_bytes(), [0x8a; 32]], false);
        let doc = slot_doc(&binding, &list, 2_002).unwrap();
        let (b, l) = from_slot_doc(&doc).unwrap();
        assert_eq!(l, list);
        assert!(check(&b, &l, &chain).is_ok(), "a member vouches for the alias, the alias for the list");
        let other = DeviceList::sign(&crate::alias::bundle(&crate::alias::seed(&[7; 32], &[2; 32], &[3; 32])), &HP, 2_001, vec![[0x8a; 32]], false);
        assert!(check(&b, &other, &chain).is_err(), "a list another alias signed is not this binding's");
        let stranger = MembershipBlob::genesis_v2(&crate::pq::SigningBundle::derive(b"device b"), HP, &[7; 32], 1_000);
        assert!(check(&b, &l, &stranger).is_err(), "a binding by a device outside the chain is refused");
    }

    /// The stolen ferros threat (the owner 2026-11-18): the alias is every Photon's, so a stolen one signs a list naming itself again; a member's LockListed on the chain makes every check refuse it, a member's Lock does the same for a member, and an honest holder's revision without the locked device checks again.
    #[test]
    fn a_list_naming_a_chain_locked_device_is_refused() {
        use crate::fleet::{bindreq_signing_bytes, MembershipBlob};
        let member = crate::pq::SigningBundle::derive(b"device a");
        let other = crate::pq::SigningBundle::derive(b"device b");
        let mut chain = MembershipBlob::genesis_v2(&member, HP, &[7; 32], 1_000);
        chain.declare(&member, 1_001);
        let opk = other.keypair().public.to_bytes();
        let consent = other.eggs(&bindreq_signing_bytes(&HP, &opk, 1_002), other.public().mask());
        chain.add_declared(&member, opk, 1_002, 1_002, consent, other.public());
        let a = alias();
        let mask = chain.declared_mask(&member.keypair().public.to_bytes());
        let binding = crate::binding::Binding::sign(&member, mask, &HP, &[2; 32], &[3; 32], a.bundle().unwrap(), 2_000).to_vsf_bytes().unwrap();
        let mpk = member.keypair().public.to_bytes();
        let ferros = [0x8a; 32];
        let list = DeviceList::sign(&a, &HP, 2_001, vec![mpk, opk, ferros], false);
        assert!(check(&binding, &list, &chain).is_ok());

        chain.lock_listed(&member, ferros, 2_002);
        assert_eq!(chain.listed_locked().unwrap(), vec![ferros]);
        assert_eq!(chain.fold().unwrap().len(), 2, "a device outside the membership is locked without touching it");
        let stolen = DeviceList::sign(&a, &HP, 2_003, vec![mpk, opk, ferros], false);
        assert!(check(&binding, &stolen, &chain).is_err(), "the alias signs, the chain refuses");
        assert!(check_signed(&binding, &stolen, &chain).is_ok(), "the signature itself is the person's");
        assert_eq!(locked_named(&stolen, &chain).unwrap(), vec![ferros]);
        let pruned = DeviceList::revised(Some(&stolen), &a, &HP, &[], &[ferros], 2_004).unwrap();
        assert!(pruned.newer_than(&stolen));
        assert!(check(&binding, &pruned, &chain).is_ok(), "the holder's revision without it checks");

        chain.lock(&member, opk, 2_005);
        assert!(check(&binding, &pruned, &chain).is_err(), "a member locked by Lock is refused in a list as well");
        assert_eq!(locked_named(&pruned, &chain).unwrap(), vec![opk]);
    }

    /// LockListed folds only from a live member, over a device outside the membership, once.
    #[test]
    fn lock_listed_names_a_non_member_once() {
        use crate::fleet::{FoldError, MembershipBlob};
        let member = crate::pq::SigningBundle::derive(b"device a");
        let mut chain = MembershipBlob::genesis_v2(&member, HP, &[7; 32], 1_000);
        let mpk = member.keypair().public.to_bytes();
        let mut bad = chain.clone();
        bad.lock_listed(&member, mpk, 1_001);
        assert!(matches!(bad.fold(), Err(FoldError::LockMalformed { .. })), "a member is locked with Lock, never LockListed");
        chain.lock_listed(&member, [0x8a; 32], 1_001);
        let mut bad = chain.clone();
        bad.lock_listed(&member, [0x8a; 32], 1_002);
        assert!(matches!(bad.fold(), Err(FoldError::LockMalformed { .. })), "twice");
        let stranger = crate::pq::SigningBundle::derive(b"device z");
        let mut bad = chain.clone();
        bad.lock_listed(&stranger, [0x8b; 32], 1_002);
        assert!(matches!(bad.fold(), Err(FoldError::SignerNotMember { .. })), "a non-member cannot lock");
        let bytes = chain.to_vsf_bytes().unwrap();
        let back = MembershipBlob::from_vsf_bytes(&bytes).unwrap();
        assert_eq!(back.listed_locked().unwrap(), vec![[0x8a; 32]], "the wire carries the kind");
        assert_eq!(back.all_locked().unwrap(), vec![[0x8a; 32]]);
    }

    #[test]
    fn a_device_signs_itself_out_of_the_list() {
        let a = alias();
        let list = DeviceList::sign(&a, &HP, 100, vec![[4; 32], [9; 32]], true);
        let out = DeviceList::revised(Some(&list), &a, &HP, &[], &[[9; 32]], 50).unwrap();
        assert_eq!(out.devices, vec![[4; 32]]);
        assert!(out.complete, "the cutover mark is kept");
        assert!(out.newer_than(&list));
        assert!(DeviceList::revised(Some(&out), &a, &HP, &[], &[[9; 32]], 200).is_none(), "already gone: nothing to sign");
    }

    /// The owner's rule for a sign out: only the device itself can sign it, it backs the omission only past the list that last named the device, it rides the slot document, and a list that merely omits a device is no removal; the chain backs a lock or a member's departure.
    #[test]
    fn only_the_device_itself_signs_it_out() {
        use crate::fleet::MembershipBlob;
        let a = alias();
        let member = crate::pq::SigningBundle::derive(b"device a");
        let chain = MembershipBlob::genesis_v2(&member, HP, &[7; 32], 1_000);
        let mpk = member.keypair().public.to_bytes();
        let ferros = crate::keys::Keypair::from_seed(&[0x8a; 32]);
        let fpk = ferros.public.to_bytes();
        let held = DeviceList::sign(&a, &HP, 100, vec![mpk, fpk], false);
        let omitted = DeviceList::revised(Some(&held), &a, &HP, &[], &[fpk], 101).unwrap();
        assert_eq!(unbacked_drops(&held, &omitted, &[], &chain), vec![fpk], "an omission alone is no removal");

        let out = SignOut::sign(&ferros, &HP, omitted.revision);
        assert!(out.verify());
        assert!(unbacked_drops(&held, &omitted, &[out.clone()], &chain).is_empty(), "the device's own sign out backs it");
        let mut forged = out.clone();
        forged.device = mpk;
        assert!(!forged.verify(), "another key cannot sign a device out");
        assert_eq!(unbacked_drops(&held, &omitted, &[forged], &chain), vec![fpk]);
        let old = SignOut::sign(&ferros, &HP, held.revision);
        assert_eq!(unbacked_drops(&held, &omitted, &[old], &chain), vec![fpk], "a sign out from before the list that names it again backs nothing");

        let binding = crate::binding::Binding::sign(&member, chain.declared_mask(&mpk), &HP, &[2; 32], &[3; 32], a.bundle().unwrap(), 2_000).to_vsf_bytes().unwrap();
        let doc = slot_doc_with(&binding, &omitted, &carried(&[out.clone()], &omitted), 2_001).unwrap();
        assert_eq!(signouts_from_slot_doc(&doc).unwrap(), vec![out.clone()], "the record rides the slot");
        assert_eq!(from_slot_doc(&doc).unwrap().1, omitted, "the list reads as before");
        assert!(signouts_from_slot_doc(&slot_doc(&binding, &omitted, 2_001).unwrap()).unwrap().is_empty());
        let back = DeviceList::revised(Some(&omitted), &a, &HP, &[fpk], &[], 2_002).unwrap();
        assert!(carried(&[out], &back).is_empty(), "a device listed again drops its record");

        let mut locked_chain = chain.clone();
        locked_chain.lock_listed(&member, fpk, 1_001);
        assert!(unbacked_drops(&held, &omitted, &[], &locked_chain).is_empty(), "the chain's lock backs it");
    }

    #[test]
    fn a_device_adds_itself_once_and_the_new_list_wins() {
        let a = alias();
        let first = DeviceList::with_device(None, &a, &HP, [4; 32], 100).unwrap();
        assert_eq!(first.devices, vec![[4; 32]]);
        assert!(DeviceList::with_device(Some(&first), &a, &HP, [4; 32], 200).is_none(), "already listed: nothing to sign");
        let second = DeviceList::with_device(Some(&first), &a, &HP, [9; 32], 50).unwrap();
        assert_eq!(second.devices, vec![[4; 32], [9; 32]], "the held devices kept");
        assert!(second.newer_than(&first), "a clock behind the held revision still wins");
        assert!(second.verify(&a.bundle().unwrap()));
    }
}
