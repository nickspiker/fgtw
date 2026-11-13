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
}
