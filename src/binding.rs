//! Be you: the binding (ferros docs/FACETS.md "Be you"; D3 and D7, decided 2026-11-12 on the owner's delegation).
//! One signed record saying "this alias speaks for the identity at this handle proof, in this kist", made by the person's identity service and signed by a device of their fleet with every egg the chain knows it holds.
//! A verifier fetches the person's chain by the handle proof, as it fetches a contact's chain today, and takes the binding only when its signer folds as a current member of that chain and every egg verifies against the bundle the chain holds for it.
//! It vouches for the alias inside its kist and nothing more: the alias is never a member of the fleet, and the chain never names it, so a binding gives no power over the fleet.
//! No public slot keeps bindings (D7): a binding travels with what its kist sends, so nobody can ask which kists a person uses.
//!
//! The identity service never holds an alias (FACETS.md D1): the kist hands it the alias's public bundle with [`possession`] eggs, the alias's own signatures over [`possession_bytes`], so a binding is only ever made for a key its asker holds.
//! On ferros the kernel also stamps the caller's alias key on every call, and the service binds only that key.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vsf::types::EtType;
use vsf::VsfType;

use crate::fleet::{scheme, MembershipBlob};
use crate::pq::{eggs_from_bytes, eggs_to_bytes, verify_eggs, FleetSigner, KeyBundle};

/// A 32-byte key, proof or hash.
pub type Key = [u8; 32];

/// The domain a binding's eggs sign under. Frozen: every binding ever made verifies against it.
pub const DOMAIN: &[u8] = b"fgtw.binding.v0";

/// The domain an alias signs under to show it holds the keys it names ([`possession_bytes`]). Frozen.
pub const POSSESSION_DOMAIN: &[u8] = b"fgtw.binding.possession.v0";

/// The section a binding document carries.
pub const SECTION: &str = "binding";

/// The largest binding document read (a bundle of three keys and three eggs is about 10 KB): anything past it is refused before it is parsed.
pub const BYTES_MAX: usize = 1 << 15;

/// "This alias speaks for the identity at this handle proof, in this kist."
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The person's handle proof (public: their slot).
    pub handle_proof: Key,
    /// The kist's developer key (Ed25519).
    pub developer: Key,
    /// The kist's option (its `hp`, ORACLE.md §5): with the developer, the kist's identity.
    pub option: Key,
    /// The alias's public bundle (Ed25519, and Falcon-512 and SPHINCS+ when the alias has them).
    pub alias: KeyBundle,
    /// When it was made, Eagle time (oscillations).
    pub when: i64,
    /// The fleet member that signed it.
    pub device: Key,
    /// That member's eggs over [`Binding::signing_bytes`], as an egg list.
    pub sig: Vec<u8>,
}

/// Why a binding was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The chain is for another handle proof (or folds to nothing).
    OtherIdentity,
    /// The signer is not a current member of the chain.
    NotMember,
    /// An egg does not verify, or the eggs fall short of what the chain says the signer holds.
    Eggs,
}

impl Binding {
    /// The bytes a binding's eggs cover: the domain, the handle proof, the kist's identity, the alias bundle's commitment, the time and the signer.
    /// Fixed widths throughout (32-byte fields, an 8-byte time), so no two bindings sign the same bytes.
    pub fn signing_bytes(handle_proof: &Key, developer: &Key, option: &Key, alias: &KeyBundle, when: i64, device: &Key) -> Vec<u8> {
        let mut m = Vec::with_capacity(DOMAIN.len() + 5 * 32 + 8);
        m.extend_from_slice(DOMAIN);
        m.extend_from_slice(handle_proof);
        m.extend_from_slice(developer);
        m.extend_from_slice(option);
        m.extend_from_slice(&alias.commit());
        m.extend_from_slice(&when.to_le_bytes());
        m.extend_from_slice(device);
        m
    }

    /// Make a binding, signed by `signer` with the schemes in `mask`: what the chain knows the signer holds (`MembershipBlob::declared_mask` of its key), so every egg it emits verifies against the chain's bundle for it.
    pub fn sign(signer: &(impl FleetSigner + ?Sized), mask: scheme::Mask, handle_proof: &Key, developer: &Key, option: &Key, alias: KeyBundle, when: i64) -> Self {
        let device = signer.keypair().public.to_bytes();
        let msg = Self::signing_bytes(handle_proof, developer, option, &alias, when, &device);
        let sig = eggs_to_bytes(&signer.eggs(&msg, mask));
        Binding { handle_proof: *handle_proof, developer: *developer, option: *option, alias, when, device, sig }
    }

    /// Take the binding against the person's chain, fetched by the handle proof: the chain is that identity's, the signer folds as a current member, and every egg verifies against the bundle the chain holds for the signer and covers every scheme the chain says it holds.
    pub fn verify(&self, chain: &MembershipBlob) -> Result<(), Refused> {
        if chain.genesis_handle_proof() != Some(self.handle_proof) {
            return Err(Refused::OtherIdentity);
        }
        if !chain.is_member(&self.device) {
            return Err(Refused::NotMember);
        }
        let bundle = chain.declared_bundle(&self.device).unwrap_or_else(|| KeyBundle::ed25519_only(&self.device));
        let msg = Self::signing_bytes(&self.handle_proof, &self.developer, &self.option, &self.alias, self.when, &self.device);
        let ok = eggs_from_bytes(&self.sig).is_ok_and(|eggs| verify_eggs(&eggs, &bundle, &msg, chain.declared_mask(&self.device)));
        if ok { Ok(()) } else { Err(Refused::Eggs) }
    }

    /// The alias's Ed25519 key, the one a kist's peers know it by.
    pub fn alias_key(&self) -> Key {
        self.alias.ed25519()
    }

    /// The binding as a complete VSF file: a header with its provenance, and the section `binding`, each value by its honest type (the handle proof `hP`, the keys `ke`, the option `hp`, the time `e`, the eggs `gm`; the bundle as fgtw carries a bundle everywhere, `ge` of its bytes).
    pub fn to_vsf_bytes(&self) -> Result<Vec<u8>, String> {
        let mut sec = vsf::VsfSection::new(SECTION);
        sec.add_field("handle_proof", VsfType::hP(self.handle_proof.to_vec()));
        sec.add_field("developer", VsfType::ke(self.developer.to_vec()));
        sec.add_field("option", VsfType::hp(self.option.to_vec()));
        sec.add_field("alias", VsfType::ge(self.alias.to_bytes()));
        sec.add_field("when", VsfType::e(EtType::e6(self.when)));
        sec.add_field("device", VsfType::ke(self.device.to_vec()));
        sec.add_field("eggs", VsfType::gm(self.sig.clone()));
        vsf::VsfBuilder::new().creation_time_oscillations(self.when).add_section_direct(sec).build().map_err(|e| format!("binding to_vsf: {e}"))
    }

    /// Read a binding back from [`Binding::to_vsf_bytes`]'s form: the file must verify (its provenance and rolling hash) before a field is read, and each field is taken by its type marker. Only the form is checked here; [`Binding::verify`] decides whether it is the person's.
    pub fn from_vsf_bytes(bytes: &[u8]) -> Result<Self, String> {
        // WHY/PROOF: a binding arrives from another device or another person's kist; the parse below runs over whatever length it claims.
        if bytes.len() > BYTES_MAX {
            return Err(format!("binding: {} bytes is past the {BYTES_MAX} a binding may be", bytes.len()));
        }
        let (header, end) = vsf::verification::read_verified(bytes, None).map_err(|e| format!("binding verification: {e}"))?;
        let sec = header.primary_section(bytes, end).map_err(|e| format!("binding section: {e}"))?;
        if sec.name != SECTION {
            return Err("not a binding".to_string());
        }
        let first = |name: &str| sec.get_field(name).and_then(|f| f.values.first());
        let key = |name: &str| -> Result<Key, String> {
            match first(name) {
                Some(VsfType::hP(b) | VsfType::ke(b) | VsfType::hp(b)) => Key::try_from(b.as_slice()).map_err(|_| format!("binding: {name} is not 32 bytes")),
                _ => Err(format!("binding: no {name}")),
            }
        };
        let alias = match first("alias") {
            Some(VsfType::ge(b)) => KeyBundle::from_bytes(b).map_err(|e| format!("binding alias: {e}"))?,
            _ => return Err("binding: no alias".to_string()),
        };
        let sig = match first("eggs") {
            Some(VsfType::gm(b)) => b.clone(),
            _ => return Err("binding: no eggs".to_string()),
        };
        let when = sec.eagle("when").ok_or("binding: no time")?;
        Ok(Binding { handle_proof: key("handle_proof")?, developer: key("developer")?, option: key("option")?, alias, when, device: key("device")?, sig })
    }
}

/// What an alias signs to show it holds every key its bundle names: the domain and the bundle's commitment.
pub fn possession_bytes(alias: &KeyBundle) -> Vec<u8> {
    let mut m = POSSESSION_DOMAIN.to_vec();
    m.extend_from_slice(&alias.commit());
    m
}

/// The alias's eggs over [`possession_bytes`], with every scheme its bundle has (the kist signs these with its alias's `SigningBundle`).
pub fn possession(signer: &(impl FleetSigner + ?Sized), alias: &KeyBundle) -> Vec<u8> {
    eggs_to_bytes(&signer.eggs(&possession_bytes(alias), alias.mask()))
}

/// Whether `eggs` (an egg list) show the holder of `alias` signed for it, with every scheme the bundle has.
pub fn holds(alias: &KeyBundle, eggs: &[u8]) -> bool {
    eggs_from_bytes(eggs).is_ok_and(|e| verify_eggs(&e, alias, &possession_bytes(alias), alias.mask()))
}

#[cfg(all(test, feature = "sign"))]
mod tests {
    use super::*;
    use crate::pq::SigningBundle;

    const HP: Key = [0x51; 32];
    const DEV: Key = [0x0d; 32];
    const OPT: Key = [0x0e; 32];

    /// A chain founded by `a`, which declares its full bundle, so the chain knows it signs with every scheme.
    fn chain(a: &SigningBundle) -> MembershipBlob {
        let mut c = MembershipBlob::genesis_v2(a, HP, &[7; 32], 1_000);
        c.declare(a, 1_001);
        assert!(c.fold().is_ok());
        c
    }

    fn alias() -> (SigningBundle, KeyBundle) {
        let s = crate::alias::bundle(&crate::alias::seed(&[9; 32], &DEV, &OPT));
        let p = s.public();
        (s, p)
    }

    #[test]
    fn a_member_s_binding_verifies_with_every_egg_and_round_trips() {
        let a = SigningBundle::derive(b"device a");
        let c = chain(&a);
        let me = a.keypair().public.to_bytes();
        let mask = c.declared_mask(&me);
        assert_eq!(mask, scheme::MASK_ALL, "the chain knows the founder holds every scheme");
        let (_, alias) = alias();
        let b = Binding::sign(&a, mask, &HP, &DEV, &OPT, alias.clone(), 2_000);
        assert_eq!(b.verify(&c), Ok(()));
        let eggs = eggs_from_bytes(&b.sig).unwrap();
        assert_eq!(crate::pq::egg_mask(&eggs), scheme::MASK_ALL, "signed with every egg");
        let bytes = b.to_vsf_bytes().unwrap();
        let back = Binding::from_vsf_bytes(&bytes).unwrap();
        assert_eq!(back, b);
        assert_eq!(back.verify(&c), Ok(()));
        assert_eq!(back.alias_key(), alias.ed25519());
    }

    #[test]
    fn every_field_is_covered() {
        let a = SigningBundle::derive(b"device a");
        let c = chain(&a);
        let mask = c.declared_mask(&a.keypair().public.to_bytes());
        let (_, alias) = alias();
        let b = Binding::sign(&a, mask, &HP, &DEV, &OPT, alias, 2_000);
        let mut x = b.clone();
        x.developer[0] ^= 1;
        assert_eq!(x.verify(&c), Err(Refused::Eggs), "another kist");
        let mut x = b.clone();
        x.option[31] ^= 1;
        assert_eq!(x.verify(&c), Err(Refused::Eggs), "another option");
        let mut x = b.clone();
        x.when += 1;
        assert_eq!(x.verify(&c), Err(Refused::Eggs), "restamped");
        let mut x = b.clone();
        x.alias = alias_other();
        assert_eq!(x.verify(&c), Err(Refused::Eggs), "another alias");
        let mut x = b.clone();
        x.handle_proof[0] ^= 1;
        assert_eq!(x.verify(&c), Err(Refused::OtherIdentity), "another person's slot");
    }

    fn alias_other() -> KeyBundle {
        crate::alias::bundle(&crate::alias::seed(&[8; 32], &DEV, &OPT)).public()
    }

    #[test]
    fn a_stranger_or_a_departed_device_does_not_speak_for_the_person() {
        let a = SigningBundle::derive(b"device a");
        let c = chain(&a);
        let (_, alias) = alias();
        let stranger = SigningBundle::derive(b"stranger");
        let b = Binding::sign(&stranger, scheme::MASK_ALL, &HP, &DEV, &OPT, alias.clone(), 2_000);
        assert_eq!(b.verify(&c), Err(Refused::NotMember));
        // A member that left: its binding goes with it (another device makes another).
        let ours = Binding::sign(&a, scheme::MASK_ALL, &HP, &DEV, &OPT, alias, 2_000);
        let mut gone = c.clone();
        gone.depart(&a, 3_000);
        assert_eq!(ours.verify(&gone), Err(Refused::NotMember));
    }

    #[test]
    fn eggs_short_of_what_the_chain_knows_are_refused() {
        let a = SigningBundle::derive(b"device a");
        let c = chain(&a);
        let (_, alias) = alias();
        // Ed25519 alone, from a device the chain knows holds all three.
        let b = Binding::sign(&a, scheme::MASK_BASE, &HP, &DEV, &OPT, alias, 2_000);
        assert_eq!(b.verify(&c), Err(Refused::Eggs));
    }

    #[test]
    fn an_ed25519_only_member_binds_with_its_one_egg() {
        let kp = crate::keys::Keypair::from_seed(&[3; 32]);
        let c = MembershipBlob::genesis_v2(&kp, HP, &[7; 32], 1_000);
        let mask = c.declared_mask(&kp.public.to_bytes());
        assert_eq!(mask, scheme::MASK_BASE);
        let (_, alias) = alias();
        let b = Binding::sign(&kp, mask, &HP, &DEV, &OPT, alias, 2_000);
        assert_eq!(b.verify(&c), Ok(()));
    }

    #[test]
    fn possession_is_the_alias_holder_s_alone() {
        let (s, alias) = alias();
        let eggs = possession(&s, &alias);
        assert!(holds(&alias, &eggs));
        assert!(!holds(&alias_other(), &eggs), "eggs for one alias do not hold another");
        let other = crate::alias::bundle(&crate::alias::seed(&[8; 32], &DEV, &OPT));
        assert!(!holds(&alias, &possession(&other, &alias)), "a key that is not the alias cannot sign for it");
        assert!(!holds(&alias, &[1, 2, 3]));
    }

    #[test]
    fn a_document_that_is_not_a_binding_is_refused() {
        assert!(Binding::from_vsf_bytes(&[0; 64]).is_err());
        let a = SigningBundle::derive(b"device a");
        let c = chain(&a);
        assert!(Binding::from_vsf_bytes(&c.to_vsf_bytes().unwrap()).is_err(), "a chain is no binding");
        let (_, alias) = alias();
        let mut bytes = Binding::sign(&a, scheme::MASK_ALL, &HP, &DEV, &OPT, alias, 2_000).to_vsf_bytes().unwrap();
        let n = bytes.len();
        bytes[n - 40] ^= 1;
        assert!(Binding::from_vsf_bytes(&bytes).is_err(), "a flipped byte fails the file's hash");
    }
}
