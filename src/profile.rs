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
use crate::space::{Entry, Space};

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

/// The kind of the person's OWN profile facts in their identity space ([`crate::space`]): SELF (the owner, 2026-11-26).
/// The preferred name and the avatar pin as the person set them, one copy for the whole person, synced to every device of theirs and sealed under the fleet key, so it outlives every device.
/// Kept by whatever manages the identity (ferros's identity service; Photon's FGTW part on desktop and Android) and readable by every kist, which publishes it to its own contacts as a [`ProfileRecord`] under its own alias, so a friend in one kist learns nothing of the person in another.
/// The code continues ferros_space's table: 0 to 14 are taken, 255 is the person key.
pub const SELF: u8 = 15;

/// The id a field of [`SELF`] is kept under: the fleet's scope and the field's label.
/// One entry per field, so a name set on one device and an avatar set on another in the same minute both stand; one entry holding both would let the later write carry the other field's old value back.
pub fn self_id(field: Field) -> Vec<VsfType> {
    vec![VsfType::ke(crate::prefs::FLEET.to_vec()), VsfType::a(vsf::types::Ascii::lit(field.label()))]
}

/// The person's own value for `field` and the stamp it was written at; None while it was never set.
/// A cleared field (a removed avatar, a cleared name) reads as an empty value, which is published like any other so the clearing reaches friends too.
/// The stamp is the revision a kist signs the record under, so every device of the person's signs the same revision for the same value.
pub fn own(space: &Space, field: Field) -> Option<(Vec<u8>, i64)> {
    let e = space.get(SELF, &self_id(field))?;
    if e.gone {
        return Some((Vec::new(), e.updated));
    }
    // WHY: the value was written by another device of the person's, perhaps a later build.
    // PROOF: a name that is not text or a pin that is not 64 bytes (key ‖ lookup) is nothing a kist can show or sign, so it reads as never set rather than reaching a screen or a signature.
    let value = e.value.iter().find_map(|v| match (field, v) {
        (Field::Name, VsfType::x(s)) => Some(s.as_bytes().to_vec()),
        (Field::AvatarPin, VsfType::ge(b)) if b.len() == 64 => Some(b.clone()),
        _ => None,
    })?;
    Some((value, e.updated))
}

/// The person set `field` on `by`, one of their devices: a name as VSF text (`x`), a pin as its 64 bytes (`ge`), an empty value as a tombstone so the clearing crosses the fleet like a value.
/// Refused (false) for a name that is not UTF-8, a pin that is not 64 bytes, an unchanged value, or clearing a field never set. True when the space changed.
pub fn set_own(space: &mut Space, by: &[u8; 32], field: Field, value: &[u8], now: i64) -> bool {
    // WHY: the value comes from a screen of the person's device.
    // PROOF: a pin of another length has no key and lookup to split, and bytes that are not UTF-8 have no `x` form, so either would be written as a fact no device can read back.
    let typed = match field {
        _ if value.is_empty() => None,
        Field::Name => match core::str::from_utf8(value) {
            Ok(s) => Some(VsfType::x(s.to_string())),
            Err(_) => return false,
        },
        Field::AvatarPin if value.len() == 64 => Some(VsfType::ge(value.to_vec())),
        Field::AvatarPin => return false,
    };
    match own(space, field) {
        Some((held, _)) if held == value => return false,
        None if typed.is_none() => return false,
        _ => {}
    }
    let id = self_id(field);
    // WHY: stamped past the fact's last write rather than at `now` alone.
    // PROOF: a device whose clock runs behind the one that last wrote would stamp its later choice older, and the merge (greatest stamp wins) would throw the person's newest choice away.
    let updated = space.get(SELF, &id).map_or(now, |e| now.max(e.updated + 1));
    let gone = typed.is_none();
    space.put(Entry { kind: SELF, id, value: typed.into_iter().collect(), updated, by: *by, gone })
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

    /// Sign a profile field with the subject's OWN IDENTITY, at the ENVELOPE tier: Ed25519 + Falcon-512 — two independent hardness families (elliptic-curve + lattice), not one egg, and ~730 bytes so it rides a pong (one datagram). SPHINCS+ (hash, ~8 KB a signature) is deliberately left off the wire — it is the archival backstop, carried only in an at-rest full-basket copy if wanted, never on a status ping (pq::ENVELOPE_TIER, the same tier every per-message envelope uses). The record verifies against the subject's pinned identity (its party-id Ed25519 key, and the Falcon pubkey of the published bundle once pinned) forever, through every device rotation and ownership change, with no fleet-membership check. `identity_seed` is the caller's own seed (in RAM at attest); it never leaves.
    pub fn sign_as_identity(identity_seed: &Key, subject: &Key, field: Field, value: Vec<u8>, rev: i64) -> Self {
        Self::sign_by(&Self::identity_bundle(identity_seed), subject, field, value, rev)
    }

    /// Sign a profile field with a bundle that is the subject's own public face in a kist: its alias (fgtw::alias::bundle), whose public bundle the subject's contacts pinned from a rotation ([`crate::binding::Rotation`]). Envelope tier, as [`sign_as_identity`](Self::sign_as_identity): Ed25519 + Falcon-512, small enough for a pong. The alias derives from the person key, which nobody computes from the handle (the owner, 2026-11-26: the identity key it replaces is the handle's, forgeable by anyone who knows it).
    pub fn sign_by(bundle: &crate::pq::SigningBundle, subject: &Key, field: Field, value: Vec<u8>, rev: i64) -> Self {
        let signer = bundle.keypair().public.to_bytes();
        let msg = Self::signing_bytes_identity(subject, field, &value, rev);
        let sig = eggs_to_bytes(&bundle.eggs(&msg, crate::pq::ENVELOPE_TIER));
        ProfileRecord { subject: *subject, field, value, rev, device: signer, identity: Some(signer), sig }
    }

    /// Whether the record is signed by the holder of `bundle`, a pinned public face of the subject (its alias): the record names that key, and BOTH families of the envelope tier verify against the bundle (Ed25519 and Falcon-512), so a forever-valid record never rests on one curve. A bundle without both families is refused, as is a record whose eggs fall short of them.
    pub fn verify_by(&self, bundle: &crate::pq::KeyBundle) -> bool {
        if self.identity != Some(bundle.ed25519()) || !scheme::covers(bundle.mask(), crate::pq::ENVELOPE_TIER) {
            return false;
        }
        let msg = Self::signing_bytes_identity(&self.subject, self.field, &self.value, self.rev);
        eggs_from_bytes(&self.sig).is_ok_and(|eggs| crate::pq::verify_eggs(&eggs, bundle, &msg, crate::pq::ENVELOPE_TIER))
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

/// [`accept`] for a record signed by a pinned public face of its subject: held only when [`ProfileRecord::verify_by`] passes against `bundle` and it names `subject`.
pub fn accept_by(held: &mut Vec<ProfileRecord>, rec: ProfileRecord, subject: &Key, bundle: &crate::pq::KeyBundle) -> Option<Merged> {
    (rec.subject == *subject && rec.verify_by(bundle)).then(|| merge(held, rec))
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
    fn an_identity_signed_record_is_two_family_envelope_and_needs_no_fleet_membership() {
        // The owner's rule 2026-11-26: a record signed by the identity never lapses (the signer does not change owners), AND it is the full three-scheme basket, not a single egg (one egg is the one-basket failure the egg system exists to kill).
        let seed = [7u8; 32];
        let bundle = ProfileRecord::identity_bundle(&seed);
        let id_pub = bundle.keypair().public.to_bytes();
        let rec = ProfileRecord::sign_as_identity(&seed, &HP, Field::Name, b"Zinnia".to_vec(), 100);
        assert_eq!(rec.identity, Some(id_pub), "the record names the identity (party id) that signed it");

        // NOT a single Ed25519 egg: two independent families (curve + lattice) at the envelope tier, and NOT SPHINCS+ (too big for a pong — it is the at-rest backstop only).
        let eggs = crate::pq::eggs_from_bytes(&rec.sig).expect("egg list");
        assert!(eggs.iter().any(|e| e.scheme == scheme::ED25519), "Ed25519 present");
        assert!(eggs.iter().any(|e| e.scheme == scheme::FALCON512), "Falcon present");
        assert!(!eggs.iter().any(|e| e.scheme == scheme::SPHINCS_PLUS), "SPHINCS+ stays off the wire (rides a pong)");
        assert!(crate::pq::eggs_to_bytes(&eggs).len() < 1024, "fits a datagram");
        // The envelope basket verifies against the identity's PUBLIC bundle — two independent assumptions, not one curve.
        let msg = ProfileRecord::signing_bytes_identity(&HP, Field::Name, &rec.value, rec.rev);
        assert!(crate::pq::verify_eggs(&eggs, &bundle.public(), &msg, crate::pq::ENVELOPE_TIER), "Ed25519 + Falcon both verify");

        // The transitional verify (Ed25519 via the pinned party id) passes with NO device, NO current membership — device churn cannot drop it.
        let is_the_subjects_identity = |subject: &Key, key: &Key, _rev: i64| *subject == HP && *key == id_pub;
        assert!(rec.verify(is_the_subjects_identity), "verifies against the pinned identity with no membership check");

        // Tampering breaks both the basket and the transitional check.
        let mut forged = rec.clone();
        forged.value = b"NotZinnia".to_vec();
        let fmsg = ProfileRecord::signing_bytes_identity(&HP, Field::Name, &forged.value, forged.rev);
        assert!(!crate::pq::verify_eggs(&crate::pq::eggs_from_bytes(&forged.sig).unwrap(), &bundle.public(), &fmsg, crate::pq::ENVELOPE_TIER));
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
    fn an_alias_signed_record_needs_both_families_against_the_pinned_bundle() {
        let alias = crate::alias::bundle(&[0x3C; 32]);
        let pinned = alias.public();
        let rec = ProfileRecord::sign_by(&alias, &HP, Field::Name, b"Bloom".to_vec(), 100);
        assert_eq!(rec.identity, Some(pinned.ed25519()));
        assert!(rec.verify_by(&pinned), "Ed25519 and Falcon both verify against the pinned alias");
        assert!(!crate::pq::eggs_from_bytes(&rec.sig).unwrap().iter().any(|e| e.scheme == scheme::SPHINCS_PLUS), "SPHINCS+ stays off the wire");
        assert!(!rec.verify_by(&crate::pq::KeyBundle::ed25519_only(&pinned.ed25519())), "one family is not enough: the Falcon key must be pinned too");
        let mut forged = rec.clone();
        forged.value = b"Weed".to_vec();
        assert!(!forged.verify_by(&pinned));
        let other = crate::alias::bundle(&[0x3D; 32]).public();
        assert!(!rec.verify_by(&other), "another alias does not speak for this one");
        let mut held = Vec::new();
        assert_eq!(accept_by(&mut held, rec.clone(), &[0x45; 32], &pinned), None, "a record naming another subject is not held");
        assert_eq!(accept_by(&mut held, rec.clone(), &HP, &pinned), Some(Merged::Adopted));
        assert_eq!(accept_by(&mut held, rec, &HP, &pinned), Some(Merged::Kept));
    }

    /// A space as another device of the person's holds it after a hand-over: thru its document, as the fleet carries it.
    fn hand_over(s: &Space) -> Space {
        Space::from_doc(&s.to_doc(0).unwrap()).unwrap()
    }

    const PHONE: Key = [1; 32];
    const LAPTOP: Key = [2; 32];

    #[test]
    fn self_crosses_the_fleet_with_its_stamp_as_the_revision() {
        let mut a = Space::new();
        assert_eq!(own(&a, Field::Name), None, "never set");
        assert!(set_own(&mut a, &PHONE, Field::Name, "Zoë".as_bytes(), 2000));
        assert!(!set_own(&mut a, &PHONE, Field::Name, "Zoë".as_bytes(), 2001), "the same name changes nothing");
        let b = hand_over(&a);
        assert_eq!(own(&b, Field::Name), Some(("Zoë".as_bytes().to_vec(), 2000)));
        // Two devices holding the same fact sign the same record: one revision, one value, whichever of them signs.
        let (value, rev) = own(&b, Field::Name).unwrap();
        assert_eq!(own(&a, Field::Name), Some((value, rev)));
    }

    #[test]
    fn a_name_and_an_avatar_set_on_two_devices_both_stand() {
        let mut a = Space::new();
        let mut b = Space::new();
        assert!(set_own(&mut a, &PHONE, Field::Name, b"Bloom", 3000));
        assert!(set_own(&mut b, &LAPTOP, Field::AvatarPin, &[0x5A; 64], 3000));
        a.merge(hand_over(&b));
        b.merge(hand_over(&a));
        for s in [&a, &b] {
            assert_eq!(own(s, Field::Name).map(|(v, _)| v), Some(b"Bloom".to_vec()));
            assert_eq!(own(s, Field::AvatarPin).map(|(v, _)| v), Some(vec![0x5A; 64]));
        }
    }

    #[test]
    fn a_cleared_avatar_crosses_the_fleet_as_an_empty_value() {
        let mut a = Space::new();
        assert!(!set_own(&mut a, &PHONE, Field::AvatarPin, &[], 100), "nothing to clear");
        assert!(set_own(&mut a, &PHONE, Field::AvatarPin, &[7; 64], 200));
        let mut b = hand_over(&a);
        assert!(set_own(&mut b, &LAPTOP, Field::AvatarPin, &[], 300));
        a.merge(hand_over(&b));
        assert_eq!(own(&a, Field::AvatarPin), Some((Vec::new(), 300)), "the clearing is a value to publish, newer than the avatar");
        assert!(!set_own(&mut a, &PHONE, Field::AvatarPin, &[], 400), "already cleared");
        assert!(set_own(&mut a, &PHONE, Field::AvatarPin, &[8; 64], 400), "and an avatar can come back");
        assert_eq!(own(&a, Field::AvatarPin), Some((vec![8; 64], 400)));
    }

    #[test]
    fn self_refuses_what_no_device_could_read_back() {
        let mut a = Space::new();
        assert!(!set_own(&mut a, &PHONE, Field::AvatarPin, &[1; 32], 100), "a pin is 64 bytes");
        assert!(!set_own(&mut a, &PHONE, Field::Name, &[0xFF, 0xFE], 100), "a name is text");
        assert!(a.entries().is_empty());
        // A value another device wrote in a form this build cannot use reads as never set.
        a.put(Entry { kind: SELF, id: self_id(Field::AvatarPin), value: vec![VsfType::ge(vec![1; 32])], updated: 1, by: PHONE, gone: false });
        assert_eq!(own(&a, Field::AvatarPin), None);
    }

    #[test]
    fn the_later_choice_wins_when_its_device_clock_runs_behind() {
        let mut a = Space::new();
        assert!(set_own(&mut a, &PHONE, Field::Name, b"Bloom", 5000));
        let mut b = hand_over(&a);
        assert!(set_own(&mut b, &LAPTOP, Field::Name, b"Blossom", 1000));
        a.merge(hand_over(&b));
        assert_eq!(own(&a, Field::Name), Some((b"Blossom".to_vec(), 5001)));
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
