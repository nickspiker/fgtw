//! The person's number base and language as facts of their identity space ([`crate::space`]): one reader and one writer for each, so every device of the person's (ferros's identity service, Photon's FGTW part on desktop and Android) reads exactly what another wrote (2026-11-22; owner: "That's an identity preference, not Photon. Same with language.").
//!
//! - **Whose:** the person's, the same on every device of theirs that follows them. Settings flow identity to device only: a device follows these, and nothing reads a device's own setting back into them.
//! - **The number base** ([`BASE`]): tatau's code as a VSF `u` (10 arabic, 12 DMS, 16 hexadecimal, G#8C DLS; [`BASES`]), read width-agnostic. An app with fewer bases maps them (Photon's one dozenal form takes both 12 and G#8C).
//! - **The language** ([`LANG`]): its ISO 639-3 code as a VSF `wl`, no script or region.
//! - **The id** of both is the fleet's scope ([`FLEET`]): one choice for the person.
//! - **A write** is stamped past the fact's last write, so the later choice wins the merge whatever the clocks say.
//!
//! The kind codes are the ones ferros's identity space has used since it first kept these (ferros_space `kind`): the language since 2026-11-10, the base from 2026-11-22.

use alloc::vec;
use alloc::vec::Vec;
use vsf::VsfType;

use crate::space::{Entry, Space};

/// The person's language.
pub const LANG: u8 = 8;
/// The person's number base.
pub const BASE: u8 = 14;
/// The fleet's scope: the id of a fact that is one choice for the whole person (32 zero bytes, as ferros_space's).
pub const FLEET: [u8; 32] = [0; 32];
/// The number bases a person may choose, tatau's codes (Code/tatau `Base`): arabic, DMS, hexadecimal, DLS.
pub const BASES: [u8; 4] = [10, 12, 16, 0x8C];

/// The id both facts are kept under.
pub fn fleet_id() -> Vec<VsfType> {
    vec![VsfType::ke(FLEET.to_vec())]
}

/// The person's language, its ISO 639-3 code; None until they have chosen one.
pub fn language(space: &Space) -> Option<[u8; 3]> {
    let e = space.get(LANG, &fleet_id()).filter(|e| !e.gone)?;
    e.value.iter().find_map(|v| match v {
        VsfType::wl(l) => Some(l.code()),
        _ => None,
    })
}

/// The person chose their language on `by`, one of their devices: written into the space as a VSF `wl`, stamped past its last write. `code` is three lowercase letters (ISO 639-3); anything else is refused (false). True when the space changed.
pub fn set_language(space: &mut Space, by: &[u8; 32], code: [u8; 3], now: i64) -> bool {
    // WHY: vsf::Language::new panics on anything but a-z, and the code reaches here from a person's device.
    if !code.iter().all(u8::is_ascii_lowercase) || language(space) == Some(code) {
        return false;
    }
    let updated = space.get(LANG, &fleet_id()).map_or(now, |e| now.max(e.updated + 1));
    space.put(Entry { kind: LANG, id: fleet_id(), value: vec![VsfType::wl(vsf::Language::new(code))], updated, by: *by, gone: false })
}

/// The person's number base, tatau's code; None until they have chosen one, or for one this build does not know.
pub fn base(space: &Space) -> Option<u8> {
    let e = space.get(BASE, &fleet_id()).filter(|e| !e.gone)?;
    let code = e.value.iter().find_map(|v| v.as_u64())?;
    // WHY: the value came from another device; a code not among BASES (a later build's base) reads as none rather than reaching a screen.
    u8::try_from(code).ok().filter(|c| BASES.contains(c))
}

/// The person chose their number base on `by`, one of their devices: written into the space as a VSF `u`, stamped past its last write. `code` is one of [`BASES`]; anything else is refused (false). True when the space changed.
pub fn set_base(space: &mut Space, by: &[u8; 32], code: u8, now: i64) -> bool {
    if !BASES.contains(&code) || base(space) == Some(code) {
        return false;
    }
    let updated = space.get(BASE, &fleet_id()).map_or(now, |e| now.max(e.updated + 1));
    space.put(Entry { kind: BASE, id: fleet_id(), value: vec![VsfType::u(code as usize, false)], updated, by: *by, gone: false })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRO: [u8; 32] = [1; 32];
    const OTHER: [u8; 32] = [2; 32];

    /// A space as another device holds it after a hand-over: thru its document, as the fleet carries it.
    fn hand_over(s: &Space) -> Space {
        Space::from_doc(&s.to_doc(0).unwrap()).unwrap()
    }

    #[test]
    fn the_language_crosses_the_fleet_and_the_later_choice_wins() {
        let mut a = Space::new();
        assert_eq!(language(&a), None);
        assert!(set_language(&mut a, &PRO, *b"mri", 2000));
        assert!(!set_language(&mut a, &PRO, *b"mri", 2001), "the same choice changes nothing");
        assert!(!set_language(&mut a, &PRO, *b"MRI", 2002), "not a code");
        let mut b = hand_over(&a);
        assert_eq!(language(&b), Some(*b"mri"));
        // A device whose clock runs behind still writes the later choice.
        assert!(set_language(&mut b, &OTHER, *b"spa", 1500));
        a.merge(hand_over(&b));
        assert_eq!(language(&a), Some(*b"spa"));
    }

    #[test]
    fn the_base_crosses_the_fleet_and_the_later_choice_wins() {
        let mut a = Space::new();
        assert_eq!(base(&a), None);
        assert!(set_base(&mut a, &PRO, 0x8C, 2000));
        assert!(!set_base(&mut a, &PRO, 0x8C, 2001), "the same choice changes nothing");
        assert!(!set_base(&mut a, &PRO, 8, 2002), "not a base");
        let mut b = hand_over(&a);
        assert_eq!(base(&b), Some(0x8C));
        assert!(set_base(&mut b, &OTHER, 16, 1500));
        a.merge(hand_over(&b));
        assert_eq!(base(&a), Some(16));
    }

    #[test]
    fn a_base_this_build_does_not_know_reads_as_none() {
        let mut a = Space::new();
        a.put(Entry { kind: BASE, id: fleet_id(), value: vec![VsfType::u(8, false)], updated: 1, by: PRO, gone: false });
        assert_eq!(base(&a), None);
        // Written by a wider unsigned, still read.
        a.put(Entry { kind: BASE, id: fleet_id(), value: vec![VsfType::u5(10)], updated: 2, by: PRO, gone: false });
        assert_eq!(base(&a), Some(10));
    }
}
