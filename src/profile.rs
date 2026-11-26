//! A person's profile fields (preferred name, avatar pin, later the You page's contact details) as records their owner signs, so every holder can tell which copy is newest (FLOWS.md, "Profile").
//! A record names its identity, its field, its value, the revision its owner gave it, and the device that set it; that device's eggs cover all of it.
//! Newest revision wins per (identity, field), a tie going to the larger value hash, so every holder picks the same copy; a carrier never re-stamps a record.
//! The record verifies itself, so any holder may hand it on: the owner's devices, a friend's, a pong answered by any of the person's devices, the roster, a backup.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vsf::file_format::VsfSection;
use vsf::types::EtType;
use vsf::VsfType;

use crate::fleet::scheme;
use crate::pq::{eggs_from_bytes, eggs_to_bytes, FleetSigner};

/// A device or identity key.
pub type Key = [u8; 32];

/// The wrapped-value marker a record rides under when it is one value inside another document (a pong tail, a contact document, a settings value): VSF's application range, `P` for profile.
pub const WRAP: u8 = b'P';

/// Which profile field a record carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    /// The name its owner chose to be shown by.
    Name,
    /// The pin that finds and opens its owner's avatar.
    AvatarPin,
}

impl Field {
    /// The field's label on the wire, at rest and in the signature (ASCII, a system label: kistcat's convention, ferros 2026-11-13).
    pub fn label(self) -> &'static str {
        match self {
            Field::Name => "name",
            Field::AvatarPin => "avatar_pin",
        }
    }

    /// The field a label names; None for a label this build does not know (a newer field), which a reader skips.
    pub fn from_label(l: &str) -> Option<Field> {
        match l {
            "name" => Some(Field::Name),
            "avatar_pin" => Some(Field::AvatarPin),
            _ => None,
        }
    }
}

/// One profile field as its owner set it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileRecord {
    /// The identity (handle proof) whose field this is.
    pub subject: Key,
    pub field: Field,
    /// The value: a name's UTF-8 bytes, or a pin's bytes. Empty is a real value (a removed avatar, a cleared name), never "unknown".
    pub value: Vec<u8>,
    /// The Eagle time (oscillations) its owner set it: the revision. Never re-stamped by a carrier.
    pub rev: i64,
    /// The device that set it, a member of the identity's fleet then. For an identity-signed record (`identity` set) this is the identity's own key too, kept so the field is never empty.
    pub device: Key,
    /// Set when the record is signed by the SUBJECT'S OWN IDENTITY key (the Ed25519 key whose pubkey is the identity party id, `crypto::clutch::identity_party_id`), not a device: then the signer never changes owners and the record stays valid forever, no fleet-membership check (the owner's rule 2026-11-26: "signed by my identity, not a device that might change owners — signed records ALWAYS stay active"). Absent = the legacy device-signed form, which a carrier only trusts while that device is a current member. An older build drops this unknown field.
    pub identity: Option<Key>,
    /// The signer's eggs over the matching `signing_bytes` (device form) or `signing_bytes_identity` (identity form), as an egg-list blob.
    pub sig: Vec<u8>,
}

/// What offering a record to a held set did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Merged {
    /// It was newer than what was held for its (identity, field), or the first: adopted, to be handed on.
    Adopted,
    /// The held copy is as new or newer: nothing changes, nothing is handed on.
    Kept,
}

impl ProfileRecord {
    /// The bytes a record's eggs cover: a domain, the identity, the field, the revision, the setting device and the value's hash.
    pub fn signing_bytes(subject: &Key, field: Field, value: &[u8], rev: i64, device: &Key) -> Vec<u8> {
        let mut m = Vec::with_capacity(128);
        m.extend_from_slice(b"fgtw.profile.v1");
        m.extend_from_slice(subject);
        m.extend_from_slice(field.label().as_bytes());
        m.push(0);
        m.extend_from_slice(&rev.to_le_bytes());
        m.extend_from_slice(device);
        m.extend_from_slice(blake3::hash(value).as_bytes());
        m
    }

    /// Sign a field this device's owner set at `rev`, with every egg the signer holds.
    pub fn sign(signer: &(impl FleetSigner + ?Sized), subject: &Key, field: Field, value: Vec<u8>, rev: i64) -> Self {
        let device = signer.keypair().public.to_bytes();
        let msg = Self::signing_bytes(subject, field, &value, rev, &device);
        let mask = signer.bundle().map(|b| b.mask()).unwrap_or(scheme::MASK_BASE);
        let sig = eggs_to_bytes(&signer.eggs(&msg, mask));
        ProfileRecord { subject: *subject, field, value, rev, device, identity: None, sig }
    }

    /// What the IDENTITY signs (v2): no device at all, since the signer is the identity itself and does not change across devices. The value rides as its hash, as in the device form.
    pub fn signing_bytes_identity(subject: &Key, field: Field, value: &[u8], rev: i64) -> Vec<u8> {
        let mut m = Vec::with_capacity(128);
        m.extend_from_slice(b"fgtw.profile.v2.identity");
        m.extend_from_slice(subject);
        m.extend_from_slice(field.label().as_bytes());
        m.push(0);
        m.extend_from_slice(&rev.to_le_bytes());
        m.extend_from_slice(blake3::hash(value).as_bytes());
        m
    }

    /// The identity's own signing bundle: the Ed25519 half is `Keypair::from_seed(identity_seed)`, so its pubkey IS the party id every contact pins at first-met (crypto::clutch::identity_party_id derives it the same way), and the Falcon-512 + SPHINCS+ halves are derived from the same seed — the release/developer-key pattern (pq::SigningBundle). One seed, three independent-assumption schemes, so a forever-valid signature does not rest on one curve (the owner, 2026-11-26: a single egg is the one-basket failure the egg system exists to kill). The name is part of the key and never changes.
    pub fn identity_bundle(identity_seed: &Key) -> crate::pq::SigningBundle {
        crate::pq::SigningBundle::developer(identity_seed, "FGTW_IDENTITY")
    }

    /// Sign a profile field with the subject's OWN IDENTITY — the full three-scheme basket of [`identity_bundle`], not one egg. The record then verifies against that pinned identity (its party-id Ed25519 key, and the Falcon/SPHINCS+ pubkeys of the bundle once pinned) forever, through every device rotation and ownership change, with no fleet-membership check. `identity_seed` is the caller's own seed (in RAM at attest); it never leaves.
    pub fn sign_as_identity(identity_seed: &Key, subject: &Key, field: Field, value: Vec<u8>, rev: i64) -> Self {
        let bundle = Self::identity_bundle(identity_seed);
        let identity = bundle.keypair().public.to_bytes();
        let msg = Self::signing_bytes_identity(subject, field, &value, rev);
        let sig = eggs_to_bytes(&bundle.eggs(&msg, scheme::MASK_ALL));
        ProfileRecord { subject: *subject, field, value, rev, device: identity, identity: Some(identity), sig }
    }

    /// Whether the record is its owner's: the setting device's Ed25519 egg verifies, and `member` says that device was in the identity's fleet at the revision (the app's fold check).
    pub fn verify(&self, member: impl Fn(&Key, &Key, i64) -> bool) -> bool {
        // The signer and what it signed depend on the form. Identity-signed: the identity's own key over the v2 bytes — `member` vouches it is the subject's pinned identity (a permanent fact), so the record stays valid through every rotation. Device-signed (legacy): the device key over the v1 bytes — `member` vouches current fleet membership, which is why an old device's record lapses.
        let (key, msg) = match &self.identity {
            Some(id) => (id, Self::signing_bytes_identity(&self.subject, self.field, &self.value, self.rev)),
            None => (&self.device, Self::signing_bytes(&self.subject, self.field, &self.value, self.rev, &self.device)),
        };
        if !member(&self.subject, key, self.rev) {
            return false;
        }
        eggs_from_bytes(&self.sig)
            .ok()
            .and_then(|eggs| eggs.into_iter().find(|e| e.scheme == scheme::ED25519))
            .is_some_and(|e| crate::pq::verify_egg(scheme::ED25519, key, &msg, &e.sig))
    }

    /// Newer than `other` for the same (identity, field): the later revision, and at an equal revision the larger value hash, so every holder picks the same copy.
    pub fn newer_than(&self, other: &ProfileRecord) -> bool {
        self.rev > other.rev || (self.rev == other.rev && blake3::hash(&self.value).as_bytes() > blake3::hash(&other.value).as_bytes())
    }

    /// The name, for a [`Field::Name`] record whose value is text.
    pub fn name(&self) -> Option<&str> {
        (self.field == Field::Name).then(|| core::str::from_utf8(&self.value).ok()).flatten()
    }

    /// The record as a VSF section. An empty value is left out (its absence reads back as empty), never written as an empty length-prefixed field.
    pub fn to_section(&self) -> VsfSection {
        let mut sec = VsfSection::new("profile");
        sec.add_field("subject", VsfType::hP(self.subject.to_vec()));
        sec.add_field("field", VsfType::a(vsf::types::Ascii::lit(self.field.label())));
        if !self.value.is_empty() {
            match self.name() {
                Some(name) => sec.add_field("value", VsfType::x(name.to_string())),
                None => sec.add_field("value", VsfType::ge(self.value.clone())),
            }
        }
        sec.add_field("revision", VsfType::e(EtType::e6(self.rev)));
        sec.add_field("device", VsfType::ke(self.device.to_vec()));
        if let Some(id) = &self.identity {
            sec.add_field("identity", VsfType::ke(id.to_vec()));
        }
        sec.add_field("sig", VsfType::ge(self.sig.clone()));
        sec
    }

    /// Read a record back. A field this build does not know is an error the caller skips (a newer build's field).
    pub fn from_section(sec: &VsfSection) -> Result<Self, String> {
        if sec.name != "profile" {
            return Err("not a profile section".to_string());
        }
        let first = |name: &str| sec.get_field(name).and_then(|f| f.values.first());
        let key = |name: &str| -> Option<Key> {
            first(name).and_then(|v| match v {
                VsfType::hP(b) | VsfType::ke(b) if b.len() == 32 => b.as_slice().try_into().ok(),
                _ => None,
            })
        };
        let subject = key("subject").ok_or("profile record missing its identity")?;
        let device = key("device").ok_or("profile record missing its device")?;
        let label = match first("field") {
            Some(VsfType::a(a)) => a.as_str(),
            Some(_) => return Err("profile record field label of an unexpected type".to_string()),
            None => return Err("profile record missing its field".to_string()),
        };
        let field = Field::from_label(label).ok_or("a profile field this build does not know")?;
        let value = match first("value") {
            None => Vec::new(),
            Some(VsfType::x(s)) => s.as_bytes().to_vec(),
            Some(VsfType::ge(b)) => b.clone(),
            Some(_) => return Err("profile record value of an unexpected type".to_string()),
        };
        let rev = sec.eagle("revision").ok_or("profile record missing its revision")?;
        let sig = match first("sig") {
            Some(VsfType::ge(b)) => b.clone(),
            _ => return Err("profile record missing its signature".to_string()),
        };
        // Absent on a legacy (device-signed) record and on an older build's document; present carries the identity-signed form.
        let identity = key("identity");
        Ok(ProfileRecord { subject, field, value, rev, device, identity, sig })
    }

    /// The record as one VSF value, its section's bytes wrapped under [`WRAP`], so it rides a field of another document (a pong tail, a contact document, a settings value) and is read back by its marker, never by position.
    /// The section is in its self-describing form (name, count and length before the fields), since no header's table of contents names it.
    pub fn to_value(&self) -> VsfType {
        VsfType::v(WRAP, self.to_section().encode_far())
    }

    /// Read a record back from [`ProfileRecord::to_value`]'s form; any other value, or a field this build does not know, is an error the caller skips.
    pub fn from_value(v: &VsfType) -> Result<Self, String> {
        match v {
            VsfType::v(WRAP, bytes) => {
                let mut ptr = 0;
                let sec = VsfSection::parse(bytes, &mut ptr)?;
                Self::from_section(&sec)
            }
            _ => Err("not a wrapped profile record".to_string()),
        }
    }
}

/// Verify a record and offer it to a held set, the one step every carrier takes: None when it does not verify (it is never held), else what merging did.
/// `member` is the app's fold check, as in [`ProfileRecord::verify`].
pub fn accept(held: &mut Vec<ProfileRecord>, rec: ProfileRecord, member: impl Fn(&Key, &Key, i64) -> bool) -> Option<Merged> {
    rec.verify(member).then(|| merge(held, rec))
}

/// Offer a verified record to a held set: adopted when it is the first or newer than what is held for its (identity, field). The caller verifies first.
pub fn merge(held: &mut Vec<ProfileRecord>, rec: ProfileRecord) -> Merged {
    match held.iter_mut().find(|h| h.subject == rec.subject && h.field == rec.field) {
        Some(h) if !rec.newer_than(h) => Merged::Kept,
        Some(h) => {
            *h = rec;
            Merged::Adopted
        }
        None => {
            held.push(rec);
            Merged::Adopted
        }
    }
}

/// The held record for an identity's field.
pub fn current<'a>(held: &'a [ProfileRecord], subject: &Key, field: Field) -> Option<&'a ProfileRecord> {
    held.iter().find(|h| h.subject == *subject && h.field == field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    const HP: Key = [0x51; 32];

    fn member_of(device: Key) -> impl Fn(&Key, &Key, i64) -> bool {
        move |s, d, _| *s == HP && *d == device
    }

    #[test]
    fn a_signed_record_verifies_and_a_tampered_one_does_not() {
        let kp = Keypair::from_seed(&[1; 32]);
        let me = kp.public.to_bytes();
        let rec = ProfileRecord::sign(&kp, &HP, Field::Name, b"Bloom".to_vec(), 100);
        assert!(rec.verify(member_of(me)));
        assert!(!rec.verify(member_of([9; 32])), "a device outside the fleet does not speak for it");
        let mut forged = rec.clone();
        forged.value = b"Weed".to_vec();
        assert!(!forged.verify(member_of(me)));
        let mut restamped = rec.clone();
        restamped.rev = 200;
        assert!(!restamped.verify(member_of(me)), "a carrier cannot re-stamp a record");
    }

    #[test]
    fn an_identity_signed_record_is_the_full_basket_and_needs_no_fleet_membership() {
        // The owner's rule 2026-11-26: a record signed by the identity never lapses (the signer does not change owners), AND it is the full three-scheme basket, not a single egg (one egg is the one-basket failure the egg system exists to kill).
        let seed = [7u8; 32];
        let bundle = ProfileRecord::identity_bundle(&seed);
        let id_pub = bundle.keypair().public.to_bytes();
        let rec = ProfileRecord::sign_as_identity(&seed, &HP, Field::Name, b"Zinnia".to_vec(), 100);
        assert_eq!(rec.identity, Some(id_pub), "the record names the identity (party id) that signed it");

        // NOT a single Ed25519 egg: all three independent-assumption schemes are present.
        let eggs = crate::pq::eggs_from_bytes(&rec.sig).expect("egg list");
        for want in [scheme::ED25519, scheme::FALCON512, scheme::SPHINCS_PLUS] {
            assert!(eggs.iter().any(|e| e.scheme == want), "scheme {want} is in the basket");
        }
        // The whole basket verifies against the identity's PUBLIC bundle — three independent assumptions, not one curve.
        let msg = ProfileRecord::signing_bytes_identity(&HP, Field::Name, &rec.value, rec.rev);
        assert!(crate::pq::verify_eggs(&eggs, &bundle.public(), &msg, scheme::MASK_ALL), "Ed25519 + Falcon + SPHINCS+ all verify");

        // The transitional verify (Ed25519 via the pinned party id) passes with NO device, NO current membership — device churn cannot drop it.
        let is_the_subjects_identity = |subject: &Key, key: &Key, _rev: i64| *subject == HP && *key == id_pub;
        assert!(rec.verify(is_the_subjects_identity), "verifies against the pinned identity with no membership check");

        // Tampering breaks both the basket and the transitional check.
        let mut forged = rec.clone();
        forged.value = b"NotZinnia".to_vec();
        let fmsg = ProfileRecord::signing_bytes_identity(&HP, Field::Name, &forged.value, forged.rev);
        assert!(!crate::pq::verify_eggs(&crate::pq::eggs_from_bytes(&forged.sig).unwrap(), &bundle.public(), &fmsg, scheme::MASK_ALL));
        assert!(!forged.verify(is_the_subjects_identity));

        // A stranger's identity cannot speak for the subject.
        assert!(!rec.verify(|subject: &Key, key: &Key, _| *subject == HP && *key == [9u8; 32]));

        // Round-trips through the section encoding with the identity field intact.
        assert_eq!(ProfileRecord::from_section(&rec.to_section()).expect("round-trips"), rec);

        // Newest-wins is unchanged.
        let newer = ProfileRecord::sign_as_identity(&seed, &HP, Field::Name, b"Zinnia II".to_vec(), 101);
        let mut held = alloc::vec::Vec::new();
        assert_eq!(accept(&mut held, rec.clone(), is_the_subjects_identity), Some(Merged::Adopted));
        assert_eq!(accept(&mut held, newer, is_the_subjects_identity), Some(Merged::Adopted));
        assert_eq!(accept(&mut held, rec, is_the_subjects_identity), Some(Merged::Kept), "an older copy never wins");
        assert_eq!(current(&held, &HP, Field::Name).and_then(|r| r.name()), Some("Zinnia II"));
    }

    #[test]
    fn the_newest_revision_wins_and_a_tie_picks_the_same_copy_everywhere() {
        let kp = Keypair::from_seed(&[1; 32]);
        let old = ProfileRecord::sign(&kp, &HP, Field::AvatarPin, vec![1; 64], 100);
        let new = ProfileRecord::sign(&kp, &HP, Field::AvatarPin, vec![2; 64], 101);
        let mut held = Vec::new();
        assert_eq!(merge(&mut held, old.clone()), Merged::Adopted);
        assert_eq!(merge(&mut held, new.clone()), Merged::Adopted);
        assert_eq!(merge(&mut held, old.clone()), Merged::Kept, "an older copy never wins");
        assert_eq!(current(&held, &HP, Field::AvatarPin).unwrap().value, vec![2; 64]);
        let a = ProfileRecord::sign(&kp, &HP, Field::Name, b"A".to_vec(), 7);
        let b = ProfileRecord::sign(&kp, &HP, Field::Name, b"B".to_vec(), 7);
        let (mut x, mut y) = (Vec::new(), Vec::new());
        merge(&mut x, a.clone());
        merge(&mut x, b.clone());
        merge(&mut y, b);
        merge(&mut y, a);
        assert_eq!(x, y, "the same two copies in either order leave the same one held");
    }

    #[test]
    fn a_record_round_trips_and_an_empty_value_is_left_out() {
        let kp = Keypair::from_seed(&[1; 32]);
        for rec in [
            ProfileRecord::sign(&kp, &HP, Field::Name, "Zoë".as_bytes().to_vec(), 5),
            ProfileRecord::sign(&kp, &HP, Field::AvatarPin, vec![7; 64], 6),
            ProfileRecord::sign(&kp, &HP, Field::AvatarPin, Vec::new(), 7),
        ] {
            let sec = rec.to_section();
            if rec.value.is_empty() {
                assert!(sec.get_field("value").is_none());
            }
            assert_eq!(ProfileRecord::from_section(&sec).unwrap(), rec);
        }
    }

    #[test]
    fn a_record_rides_as_one_wrapped_value_and_nothing_else_reads_as_one() {
        let kp = Keypair::from_seed(&[1; 32]);
        for rec in [
            ProfileRecord::sign(&kp, &HP, Field::Name, "Zoë".as_bytes().to_vec(), 5),
            ProfileRecord::sign(&kp, &HP, Field::AvatarPin, vec![7; 64], 6),
            ProfileRecord::sign(&kp, &HP, Field::AvatarPin, Vec::new(), 7),
        ] {
            let v = rec.to_value();
            assert!(matches!(&v, VsfType::v(WRAP, b) if !b.is_empty()));
            let back = ProfileRecord::from_value(&v).unwrap();
            assert_eq!(back, rec);
            assert!(back.verify(member_of(kp.public.to_bytes())));
            let flat = v.flatten();
            let mut ptr = 0;
            assert_eq!(ProfileRecord::from_value(&vsf::decoding::parse::parse(&flat, &mut ptr).unwrap()).unwrap(), rec, "the value survives its own wire form");
        }
        assert!(ProfileRecord::from_value(&VsfType::v(b'r', vec![1, 2, 3])).is_err());
        assert!(ProfileRecord::from_value(&VsfType::x("Bloom".to_string())).is_err());
    }

    #[test]
    fn accept_holds_only_what_verifies() {
        let kp = Keypair::from_seed(&[1; 32]);
        let me = kp.public.to_bytes();
        let stranger = Keypair::from_seed(&[2; 32]);
        let mut held = Vec::new();
        let forged = ProfileRecord::sign(&stranger, &HP, Field::Name, b"Weed".to_vec(), 900);
        assert_eq!(accept(&mut held, forged, member_of(me)), None);
        assert!(held.is_empty(), "a record from a device outside the fold is never held");
        let rec = ProfileRecord::sign(&kp, &HP, Field::Name, b"Bloom".to_vec(), 100);
        assert_eq!(accept(&mut held, rec.clone(), member_of(me)), Some(Merged::Adopted));
        assert_eq!(accept(&mut held, rec, member_of(me)), Some(Merged::Kept));
    }
}
