//! The person's people (ferros docs/FACETS.md "People"; D5, decided 2026-11-12): who they know, as the identity space keeps them and as a kist granted `people` is handed them.
//! A person is what Photon pins of a contact today (photon docs/identity-profile.md "The pin-set"): their handle proof, the identity key pinned when they were first met, the genesis their chain was pinned at, the fleet that chain folded to, and the name the person gave them.
//! Never their handle: it exists at rest nowhere ("type it once, derive, pin, drop").
//!
//! Two forms, one type:
//! - **In the space** ([`Person::to_value`]): every field, the members included, so each device of the person's knows whom a photon may come from without fetching first.
//! - **To a kist** ([`doc`], a complete VSF file): each person without their fleet (FACETS.md: "Not: their fleet, their devices"); a kist that needs a contact's chain fetches it by the handle proof and checks it against the pinned genesis, as any stranger with the handle proof can.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vsf::file_format::VsfSection;
use vsf::VsfType;

/// A 32-byte key, proof or hash.
pub type Key = [u8; 32];

/// The wrapped-value marker a person rides under as one value inside another document (the space's fact, a kist's people document): VSF's application range, `W` for who.
pub const WRAP: u8 = b'W';

/// The section a kist's people document carries.
pub const SECTION: &str = "people";

/// The largest people document read: 1 MiB, a few thousand people. Past it is refused before it is parsed.
pub const BYTES_MAX: usize = 1 << 20;

/// One person the identity knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    /// Their handle proof: their slot, which finds their chain.
    pub handle_proof: Key,
    /// The identity key pinned when they were first met (Ed25519 of their identity seed): Photon's identifier for a person (PHOTON.md M2).
    pub identity: Key,
    /// The hash of the genesis their chain was pinned at.
    pub genesis: Key,
    /// Their fleet's device keys as the chain folded when it was last checked. Empty in a kist's copy.
    pub members: Vec<Key>,
    /// The name the person gave them (a petname, theirs alone). Empty when they gave none.
    pub name: String,
}

impl Person {
    /// The person as a VSF section, each value by its type: the handle proof `hP`, the identity key `ke`, the genesis `hb`, each member `ke` (left out with `members` false), the name `x` (left out when empty).
    pub fn to_section(&self, members: bool) -> VsfSection {
        let mut sec = VsfSection::new("person");
        sec.add_field("handle_proof", VsfType::hP(self.handle_proof.to_vec()));
        sec.add_field("identity", VsfType::ke(self.identity.to_vec()));
        sec.add_field("genesis", VsfType::hb(self.genesis.to_vec()));
        if members && !self.members.is_empty() {
            sec.add_field_multi("members", self.members.iter().map(|m| VsfType::ke(m.to_vec())).collect());
        }
        if !self.name.is_empty() {
            sec.add_field("name", VsfType::x(self.name.clone()));
        }
        sec
    }

    /// Read a person back: each field by its name and its type marker.
    pub fn from_section(sec: &VsfSection) -> Result<Self, String> {
        if sec.name != "person" {
            return Err("not a person".to_string());
        }
        let key = |name: &str| -> Result<Key, String> {
            match sec.get_field(name).and_then(|f| f.values.first()) {
                Some(VsfType::hP(b)) if name == "handle_proof" => Key::try_from(b.as_slice()).map_err(|_| format!("person: {name} is not 32 bytes")),
                Some(VsfType::ke(b)) if name == "identity" => Key::try_from(b.as_slice()).map_err(|_| format!("person: {name} is not 32 bytes")),
                Some(VsfType::hb(b)) if name == "genesis" => Key::try_from(b.as_slice()).map_err(|_| format!("person: {name} is not 32 bytes")),
                _ => Err(format!("person: no {name}")),
            }
        };
        let mut members = Vec::new();
        if let Some(f) = sec.get_field("members") {
            for v in &f.values {
                match v {
                    VsfType::ke(b) => members.push(Key::try_from(b.as_slice()).map_err(|_| "person: a member is not 32 bytes".to_string())?),
                    _ => return Err("person: a member of an unexpected type".to_string()),
                }
            }
        }
        let name = match sec.get_field("name").and_then(|f| f.values.first()) {
            None => String::new(),
            Some(VsfType::x(s)) => s.clone(),
            Some(_) => return Err("person: a name of an unexpected type".to_string()),
        };
        Ok(Person { handle_proof: key("handle_proof")?, identity: key("identity")?, genesis: key("genesis")?, members, name })
    }

    /// The person as one VSF value, wrapped under [`WRAP`], every field: the identity space's fact.
    pub fn to_value(&self) -> VsfType {
        VsfType::v(WRAP, self.to_section(true).encode_far())
    }

    /// Read a person back from [`Person::to_value`]'s form; any other value is an error the caller skips.
    pub fn from_value(v: &VsfType) -> Result<Self, String> {
        match v {
            VsfType::v(WRAP, bytes) => {
                let mut ptr = 0;
                let sec = VsfSection::parse(bytes, &mut ptr)?;
                Self::from_section(&sec)
            }
            _ => Err("not a wrapped person".to_string()),
        }
    }
}

/// The people a kist is handed, as a complete VSF file: the section `people`, a `person` field per person, each a wrapped person without their fleet.
pub fn doc(people: &[Person], now: i64) -> Result<Vec<u8>, String> {
    let mut sec = VsfSection::new(SECTION);
    for p in people {
        sec.add_field("person", VsfType::v(WRAP, p.to_section(false).encode_far()));
    }
    vsf::VsfBuilder::new().creation_time_oscillations(now).add_section_direct(sec).build().map_err(|e| format!("people to_vsf: {e}"))
}

/// Read a kist's people document back. The file must verify before a person is read; a person this build cannot read is skipped (a newer build's form), the rest kept.
pub fn from_doc(bytes: &[u8]) -> Result<Vec<Person>, String> {
    // WHY/PROOF: the document comes over IPC from another process; the parse runs over whatever length it claims.
    if bytes.len() > BYTES_MAX {
        return Err(format!("people: {} bytes is past the {BYTES_MAX} a document may be", bytes.len()));
    }
    let (header, end) = vsf::verification::read_verified(bytes, None).map_err(|e| format!("people verification: {e}"))?;
    let sec = header.primary_section(bytes, end).map_err(|e| format!("people section: {e}"))?;
    if sec.name != SECTION {
        return Err("not a people document".to_string());
    }
    Ok(sec.get_fields("person").iter().filter_map(|f| f.values.first()).filter_map(|v| Person::from_value(v).ok()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ana() -> Person {
        Person { handle_proof: [1; 32], identity: [2; 32], genesis: [3; 32], members: alloc::vec![[4; 32], [5; 32]], name: "Ana".to_string() }
    }

    #[test]
    fn a_person_round_trips_whole_in_the_space_s_form() {
        for p in [ana(), Person { members: Vec::new(), name: String::new(), ..ana() }] {
            let v = p.to_value();
            assert_eq!(Person::from_value(&v).unwrap(), p);
            let flat = v.flatten();
            let mut ptr = 0;
            assert_eq!(Person::from_value(&vsf::decoding::parse::parse(&flat, &mut ptr).unwrap()).unwrap(), p, "the value survives its own wire form");
        }
        assert!(Person::from_value(&VsfType::v(b'P', alloc::vec![1, 2])).is_err());
    }

    #[test]
    fn a_kist_s_document_carries_no_fleet() {
        let bob = Person { handle_proof: [9; 32], identity: [8; 32], genesis: [7; 32], members: alloc::vec![[6; 32]], name: String::new() };
        let bytes = doc(&[ana(), bob.clone()], 1_000).unwrap();
        let back = from_doc(&bytes).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0], Person { members: Vec::new(), ..ana() });
        assert_eq!(back[1], Person { members: Vec::new(), ..bob });
        assert!(from_doc(&doc(&[], 1).unwrap()).unwrap().is_empty(), "nobody is an empty list, never an error");
        let mut bad = bytes.clone();
        let n = bad.len();
        bad[n - 8] ^= 1;
        assert!(from_doc(&bad).is_err(), "a flipped byte fails the file's hash");
    }
}
