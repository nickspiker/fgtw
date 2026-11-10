//! The words every TOKEN app shows for the fleet and the identity, written once in every language (owner, 2026-11-10: every wording change to the fleet flows was being made twice, once in Photon and once in ferros).
//!
//! Done as Photon does its own text (photon docs/languages.md): every message is a `Msg`, whole, with holes for what changes (a device's name, a word typed, a count), and each language is one exhaustive match over them (text/en.rs the reference), so adding a message fails every language's build until its arm exists.
//!
//! - **The one language list.** `Lang` is the sixteen languages in Photon's storage order (`Lang::index`, which never moves; new languages append), their autonyms, Photon's picker order (`Lang::ALL`), their ISO 639-3 codes as vsf keeps a language (`wl`), and Photon's short codes. An app's own text (Photon's chat, ferros's settings) stays the app's, keyed by this `Lang`.
//! - **Line breaks.** A `\n` in a message is a forced line break and assumes a wrapping draw (a toast, flowed settings text, an error band); the drawer still wraps a long line at its spaces. Each variant's doc says which it is: one-line (a pill, a button, a status row: never wrapped, punctuation only, no `\n`) or wrapping (a sentence, laid out to the width it gets).
//! - **Holes.** Names (a device's two-word name) and words a person typed are never translated. A count arrives both as its value (for a language whose words agree with the number) and written already in the person's base (Photon's dozenal, ferros's choice), and the message prints the written one.
//! - **Wording.** Two sources, each variant saying which. Photon's: its fleet and identity messages as committed at photon 9a93f16c (2026-11-10, the em-dash rewrite), its names kept, every language's text Photon's. ferros's: the lines ferros's Fleet page and attest screen show that Photon has no message for, in ferros's lower-case voice. From now on this module is where either changes.
//! - **Māori** (text/mi.rs) still wants a native speaker's review, Photon's arms and ferros's alike.
//!
//! no_std, no alloc: `tr` writes into any `core::fmt::Write`.

use core::fmt::{self, Write};

mod de;
mod en;
mod es;
mod fil;
mod fr;
mod hi;
mod id;
mod it;
mod mi;
mod pl;
mod pt;
mod ru;
mod sw;
// Turkish's code is `tr`, which reads like the translate function below; Rust keeps modules and functions apart, so `tr::text` is the module and `tr(..)` the call, and the file stays named for its code like every other language.
mod tr;
mod uk;
mod vi;

/// A language. Variants in Photon's ADDITION order, which `index` follows: the index is what an app stores, so a shipped index never moves and new languages append.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    En,
    Es,
    Mi,
    Pt,
    Fr,
    Id,
    De,
    Sw,
    Vi,
    Tr,
    Ru,
    Hi,
    Uk,
    It,
    Pl,
    Fil,
}

/// How many languages there are.
pub const COUNT: u8 = 16;

impl Lang {
    /// STORAGE order. Never re-sorted.
    pub const fn index(self) -> u8 {
        self as u8
    }

    /// The language for a stored index; anything past the list is English.
    pub const fn from_index(i: u8) -> Lang {
        match i {
            1 => Lang::Es,
            2 => Lang::Mi,
            3 => Lang::Pt,
            4 => Lang::Fr,
            5 => Lang::Id,
            6 => Lang::De,
            7 => Lang::Sw,
            8 => Lang::Vi,
            9 => Lang::Tr,
            10 => Lang::Ru,
            11 => Lang::Hi,
            12 => Lang::Uk,
            13 => Lang::It,
            14 => Lang::Pl,
            15 => Lang::Fil,
            _ => Lang::En,
        }
    }

    /// The ISO 639-3 code, as vsf keeps a language (`wl`). Swahili is the macrolanguage `swa`, as Photon's `sw` is.
    pub const fn iso(self) -> [u8; 3] {
        match self {
            Lang::En => *b"eng",
            Lang::Es => *b"spa",
            Lang::Mi => *b"mri",
            Lang::Pt => *b"por",
            Lang::Fr => *b"fra",
            Lang::Id => *b"ind",
            Lang::De => *b"deu",
            Lang::Sw => *b"swa",
            Lang::Vi => *b"vie",
            Lang::Tr => *b"tur",
            Lang::Ru => *b"rus",
            Lang::Hi => *b"hin",
            Lang::Uk => *b"ukr",
            Lang::It => *b"ita",
            Lang::Pl => *b"pol",
            Lang::Fil => *b"fil",
        }
    }

    /// The language for an ISO 639-3 code, if it is one of these (`swh`, Swahili proper, reads as the macrolanguage; `tgl`, Tagalog, as Filipino, as Photon reads `tl`).
    pub fn from_iso(code: [u8; 3]) -> Option<Lang> {
        match &code {
            b"swh" => return Some(Lang::Sw),
            b"tgl" => return Some(Lang::Fil),
            _ => {}
        }
        (0..COUNT).map(Lang::from_index).find(|l| l.iso() == code)
    }

    /// The language as vsf keeps one (`wl`): its ISO 639-3 code, no script or region.
    pub const fn language(self) -> vsf::Language {
        vsf::Language::new(self.iso())
    }

    /// The language a vsf `wl` names, if it is one of these (its script and region are not read).
    pub fn from_language(l: &vsf::Language) -> Option<Lang> {
        Lang::from_iso(l.code())
    }

    /// Photon's short code (its `display.lang`).
    pub const fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Es => "es",
            Lang::Mi => "mi",
            Lang::Pt => "pt",
            Lang::Fr => "fr",
            Lang::Id => "id",
            Lang::De => "de",
            Lang::Sw => "sw",
            Lang::Vi => "vi",
            Lang::Tr => "tr",
            Lang::Ru => "ru",
            Lang::Hi => "hi",
            Lang::Uk => "uk",
            Lang::It => "it",
            Lang::Pl => "pl",
            Lang::Fil => "fil",
        }
    }

    /// The language for Photon's short code (`fil` and Tagalog's older `tl` both Filipino, as Photon reads them).
    pub fn from_code(c: &str) -> Option<Lang> {
        if c == "tl" {
            return Some(Lang::Fil);
        }
        (0..COUNT).map(Lang::from_index).find(|l| l.code() == c)
    }

    /// The language named in itself, as Photon's picker names it (bare names, parallel form; Tiếng Việt and Bahasa Indonesia keep their language word: Photon, Nick 2026-09-03 and 2026-09-15). Invariant across languages: a person lost in a language they cannot read finds their own by its name.
    pub const fn autonym(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Es => "Espa\u{f1}ol",
            Lang::Mi => "M\u{101}ori",
            Lang::Pt => "Portugu\u{EA}s",
            Lang::Fr => "Fran\u{E7}ais",
            Lang::Id => "Bahasa Indonesia",
            Lang::De => "Deutsch",
            Lang::Sw => "Kiswahili",
            Lang::Vi => "Ti\u{1EBF}ng Vi\u{1EC7}t",
            Lang::Tr => "T\u{FC}rk\u{E7}e",
            Lang::Ru => "\u{420}\u{443}\u{441}\u{441}\u{43A}\u{438}\u{439}",
            Lang::Hi => "\u{939}\u{93F}\u{928}\u{94D}\u{926}\u{940}",
            Lang::Uk => "\u{423}\u{43A}\u{440}\u{430}\u{457}\u{43D}\u{441}\u{44C}\u{43A}\u{430}",
            Lang::It => "Italiano",
            Lang::Pl => "Polski",
            Lang::Fil => "Filipino",
        }
    }

    /// DISPLAY order, Photon's picker's: sorted by autonym (Latin names first, then Cyrillic and Devanagari, by code point). Free to re-sort: a pick resolves thru this array, never thru `index`.
    pub const ALL: [Lang; COUNT as usize] = [
        Lang::Id,
        Lang::De,
        Lang::En,
        Lang::Es,
        Lang::Fil,
        Lang::Fr,
        Lang::It,
        Lang::Sw,
        Lang::Mi,
        Lang::Pl,
        Lang::Pt,
        Lang::Vi,
        Lang::Tr,
        Lang::Ru,
        Lang::Uk,
        Lang::Hi,
    ];
}

/// A fleet or identity message. Each variant's doc says whose wording it is (Photon's, from photon 9a93f16c, or ferros's) and whether it is one-line or wrapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Msg<'a> {
    // ---- adding a device: the member's side (Photon's "add device / pairing") ----
    /// Photon's. One-line. The add screen's title.
    AddDeviceTitle,
    /// Photon's. Wrapping. Over the nearby devices asking to join.
    TapNearby,
    /// Photon's. One-line. A nearby device asking to join, by name.
    AddDeviceNearby(&'a str),
    /// Photon's. Wrapping. Type the words the new device shows.
    TypeWords,
    /// Photon's. Wrapping. A typed word that is not a pairing word (the word stays as typed).
    InvalidWord(&'a str),
    /// Photon's. Wrapping. Waiting for the new device to ask.
    WaitingForDevice,
    /// Photon's. Wrapping. `count` devices (two or more) ask at once; `shown` is the count written in the person's base.
    DevicesAskingToJoin { count: u64, shown: &'a str },
    /// Photon's. Wrapping. No device asking has this word.
    NoMatchingDevice(&'a str),
    /// Photon's. One-line. The words typed so far match one device, named.
    MatchingDevice(&'a str),
    /// Photon's. One-line. The words typed match `count` devices (two or more); `shown` is the count written in the person's base.
    MatchingMultiple { count: u64, shown: &'a str },
    /// Photon's. One-line.
    Preparing,
    /// Photon's. Wrapping. This device cannot add one yet.
    NoFleetKey,
    /// Photon's. Wrapping.
    NoDeviceKey,
    /// Photon's. One-line. Adding the named device.
    AddingDevice(&'a str),
    /// Photon's. One-line.
    DeviceAdded,
    /// Photon's. Wrapping. More than one device asks to join at once.
    JoinContended,
    /// Photon's. Wrapping. On a device not yet in a fleet: add it from one that is.
    AddFromSignedIn,
    /// Photon's. One-line. The button that starts adding a device.
    AddDevicePill,
    /// Photon's. One-line. The device selected to add.
    SelectedDevice(&'a str),
    /// Photon's. Wrapping. The question under a selected device: it lit green when selected. Yes adds it, No goes back to the list.
    IsNewDeviceGreen,
    /// Photon's. One-line. Its answers.
    YesPill,
    NoPill,
    /// Photon's. One-line. The add screen's opt-in to fgtw.org's binding requests (devices that are not nearby), and its state after the tap.
    AddLookFgtw,
    AddLookingFgtw,
    // ---- adding a device: the member's side (ferros's Fleet page) ----
    /// ferros's. Wrapping. A device on this network asks to join (under the add button).
    DeviceAsksToJoin,
    /// ferros's. One-line. The add flow's status rows: listing, a device selected, binding it, handing it the key, done, failed.
    AddAsking,
    AddSelected,
    AddingToFleet,
    HandingKey,
    Added,
    AddingFailed,
    /// ferros's. One-line. A device asking to join, by name: added already; heard here (a tap selects it); known only from fgtw.org (matched by its words).
    CandAdded(&'a str),
    CandNearby(&'a str),
    CandNotNearby(&'a str),
    /// ferros's. Wrapping. No device asks yet: where to start on the new one.
    OpenPhotonJoin,
    /// ferros's. One-line. The button that opens the words to type.
    TypeItsWordsPill,
    /// ferros's. Wrapping. Under it: the other way to add.
    HoldTogether,
    /// ferros's. One-line. Closing the add flow once a device is added, and before.
    DonePill,
    ClosePill,
    // ---- adding a device: the joining device's side ----
    /// Photon's. One-line. A device of the fleet selected this one.
    SelectedBy(&'a str),
    /// Photon's. One-line. The joiner's cue that it was selected, and where to finish.
    JoinerSelected,
    /// Photon's. Wrapping.
    JoinerConfirmOther,
    /// Photon's. Wrapping. On the joining device's words screen.
    LaunchJoinConfirmNote,
    /// Photon's. One-line. The joining device's opt-in to the bootstrap mailbox (its binding request goes to fgtw.org only on this tap), and its state after.
    JoinAskFgtw,
    JoinAskedFgtw,
    /// Photon's. Wrapping. Minting: the handle typed again differs from the first.
    HandlesDontMatch,
    /// Photon's. Wrapping. Attest refused: the hardware is still registered to another fleet.
    DeviceBrandedHint,
    /// ferros's. Wrapping. The joining device's step: bind it from a device of the fleet.
    UseExistingDevice,
    /// ferros's. Wrapping. After `SelectedBy` on the attest screen: the keys follow.
    WaitingFleetKeys,
    /// ferros's. Wrapping. Bound, the fleet's keys on their way.
    BoundWaitingKeys,
    /// ferros's. Wrapping. Joining refused: the device is in another identity's fleet.
    DeniedBoundOther,
    /// ferros's. Wrapping. The device belongs to another identity: only that fleet can release it.
    OwnedByOther,
    // ---- the fleet's devices ----
    /// Photon's. One-line.
    ThisDevice,
    /// Photon's. One-line. A device with no name given.
    ADevice,
    /// ferros's. One-line. The selected device, with no name given.
    TheDevice,
    /// ferros's. One-line. A device of the fleet, its name missing.
    OneOfYourDevices,
    /// ferros's. One-line. A member of the fleet, and it is this device; one heard on this network.
    MemberThisDevice(&'a str),
    MemberNearby(&'a str),
    /// ferros's. One-line. Where this device stands with the identity and its fleet.
    NoIdentityHere,
    JoiningConfirm,
    InFleetWaitingKey,
    InFleet,
    LeavingFleet,
    NewIdentityNoFleet,
    HandleHasOtherFleet,
    NoVerdict,
    LookingUp,
    // ---- leaving: a member asking to leave, on the other devices ----
    /// Photon's. Wrapping. A notification: a member asks to leave, and where to approve it.
    DepartureApproval(&'a str),
    /// Photon's. Wrapping. The request on the Fleet page.
    DepartRequestLine(&'a str),
    /// Photon's. Wrapping. What approving does when the leaver asked to have its hardware freed for any fleet.
    DepartFreesHardware,
    /// Photon's. Wrapping. What approving does when the leaver asked to keep its hardware with this fleet.
    DepartKeepsHardware,
    /// Photon's. One-line. The request's buttons.
    DepartApprovePill,
    DepartDenyPill,
    /// Photon's. Wrapping. Denied here: it stays.
    DepartDeniedHere(&'a str),
    /// Photon's. Wrapping. A departure approved here went thru, the hardware freed.
    DepartComplete(&'a str),
    /// Photon's. Wrapping. A device left the fleet (a departure approved here went thru, whatever became of its hardware).
    FleetSignedOut(&'a str),
    /// Photon's. Wrapping. It left, but its hardware was not freed.
    DepartReleasePending(&'a str),
    /// Photon's. Wrapping. A device released: it can join any fleet.
    DeviceReleased(&'a str),
    /// ferros's. Wrapping. What denying does.
    DepartDenyKeeps,
    /// ferros's. One-line. Approve after the last approval did not go out.
    DepartApproveAgainPill,
    /// ferros's. One-line. Approving, and approved.
    DepartApproving,
    DepartApproved,
    // ---- leaving: this device ----
    /// Photon's. Wrapping. This device's request waits on the others.
    DepartWaitingLine,
    /// Photon's. Wrapping. A device of the fleet denied this device's request.
    DepartDenied,
    /// ferros's. One-line. The button that removes this device from the fleet; `armed` after its first tap.
    RemovePill { armed: bool },
    /// ferros's. One-line. This device asks the fleet to let it go; the request on its way.
    DepartAsking,
    DepartSending,
    /// ferros's. Wrapping. Where else to answer it: tap a device to this one.
    DepartTapHint,
    /// ferros's. Wrapping. What follows, and how to give up.
    DepartThen,
    /// ferros's. Wrapping. This device's departure was denied on that device.
    DepartDeniedOn(&'a str),
    /// ferros's. One-line. The request did not go out.
    DepartNotStarted,
}

/// Message `m` in language `l`, written into `o`.
pub fn tr(l: Lang, m: Msg, o: &mut dyn Write) -> fmt::Result {
    match l {
        Lang::En => en::text(m, o),
        Lang::Es => es::text(m, o),
        Lang::Mi => mi::text(m, o),
        Lang::Pt => pt::text(m, o),
        Lang::Fr => fr::text(m, o),
        Lang::Id => id::text(m, o),
        Lang::De => de::text(m, o),
        Lang::Sw => sw::text(m, o),
        Lang::Vi => vi::text(m, o),
        Lang::Tr => tr::text(m, o),
        Lang::Ru => ru::text(m, o),
        Lang::Hi => hi::text(m, o),
        Lang::Uk => uk::text(m, o),
        Lang::It => it::text(m, o),
        Lang::Pl => pl::text(m, o),
        Lang::Fil => fil::text(m, o),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::String;
    use std::vec::Vec;

    /// A hole's mark: a name, a typed word or a written count the test can find again.
    const H: &str = "\u{27e6}H\u{27e7}";

    /// One of every message (counts at one, a few and many, for the languages that agree with them), its holes marked; with how many marks each must carry and whether it must stay on one line.
    fn every() -> Vec<(Msg<'static>, usize, bool)> {
        let mut v = vec![];
        let mut add = |m, holes, one_line| v.push((m, holes, one_line));
        add(Msg::AddDeviceTitle, 0, true);
        add(Msg::TapNearby, 0, false);
        add(Msg::AddDeviceNearby(H), 1, true);
        add(Msg::TypeWords, 0, false);
        add(Msg::InvalidWord(H), 1, false);
        add(Msg::WaitingForDevice, 0, false);
        for count in [2, 5, 21, 112] {
            add(Msg::DevicesAskingToJoin { count, shown: H }, 1, false);
            add(Msg::MatchingMultiple { count, shown: H }, 1, true);
        }
        add(Msg::NoMatchingDevice(H), 1, false);
        add(Msg::MatchingDevice(H), 1, true);
        add(Msg::Preparing, 0, true);
        add(Msg::NoFleetKey, 0, false);
        add(Msg::NoDeviceKey, 0, false);
        add(Msg::AddingDevice(H), 1, true);
        add(Msg::DeviceAdded, 0, true);
        add(Msg::JoinContended, 0, false);
        add(Msg::AddFromSignedIn, 0, false);
        add(Msg::AddDevicePill, 0, true);
        add(Msg::SelectedDevice(H), 1, true);
        add(Msg::IsNewDeviceGreen, 0, false);
        add(Msg::YesPill, 0, true);
        add(Msg::NoPill, 0, true);
        add(Msg::AddLookFgtw, 0, true);
        add(Msg::AddLookingFgtw, 0, true);
        add(Msg::DeviceAsksToJoin, 0, false);
        add(Msg::AddAsking, 0, true);
        add(Msg::AddSelected, 0, true);
        add(Msg::AddingToFleet, 0, true);
        add(Msg::HandingKey, 0, true);
        add(Msg::Added, 0, true);
        add(Msg::AddingFailed, 0, true);
        add(Msg::CandAdded(H), 1, true);
        add(Msg::CandNearby(H), 1, true);
        add(Msg::CandNotNearby(H), 1, true);
        add(Msg::OpenPhotonJoin, 0, false);
        add(Msg::TypeItsWordsPill, 0, true);
        add(Msg::HoldTogether, 0, false);
        add(Msg::DonePill, 0, true);
        add(Msg::ClosePill, 0, true);
        add(Msg::SelectedBy(H), 1, true);
        add(Msg::JoinerSelected, 0, true);
        add(Msg::JoinerConfirmOther, 0, false);
        add(Msg::LaunchJoinConfirmNote, 0, false);
        add(Msg::JoinAskFgtw, 0, true);
        add(Msg::JoinAskedFgtw, 0, true);
        add(Msg::HandlesDontMatch, 0, false);
        add(Msg::DeviceBrandedHint, 0, false);
        add(Msg::UseExistingDevice, 0, false);
        add(Msg::WaitingFleetKeys, 0, false);
        add(Msg::BoundWaitingKeys, 0, false);
        add(Msg::DeniedBoundOther, 0, false);
        add(Msg::OwnedByOther, 0, false);
        add(Msg::ThisDevice, 0, true);
        add(Msg::ADevice, 0, true);
        add(Msg::TheDevice, 0, true);
        add(Msg::OneOfYourDevices, 0, true);
        add(Msg::MemberThisDevice(H), 1, true);
        add(Msg::MemberNearby(H), 1, true);
        add(Msg::NoIdentityHere, 0, true);
        add(Msg::JoiningConfirm, 0, true);
        add(Msg::InFleetWaitingKey, 0, true);
        add(Msg::InFleet, 0, true);
        add(Msg::LeavingFleet, 0, true);
        add(Msg::NewIdentityNoFleet, 0, true);
        add(Msg::HandleHasOtherFleet, 0, true);
        add(Msg::NoVerdict, 0, true);
        add(Msg::LookingUp, 0, true);
        add(Msg::DepartureApproval(H), 1, false);
        add(Msg::DepartRequestLine(H), 1, false);
        add(Msg::DepartFreesHardware, 0, false);
        add(Msg::DepartKeepsHardware, 0, false);
        add(Msg::DepartApprovePill, 0, true);
        add(Msg::DepartDenyPill, 0, true);
        add(Msg::DepartDeniedHere(H), 1, false);
        add(Msg::DepartComplete(H), 1, false);
        add(Msg::FleetSignedOut(H), 1, false);
        add(Msg::DepartReleasePending(H), 1, false);
        add(Msg::DeviceReleased(H), 1, false);
        add(Msg::DepartDenyKeeps, 0, false);
        add(Msg::DepartApproveAgainPill, 0, true);
        add(Msg::DepartApproving, 0, true);
        add(Msg::DepartApproved, 0, true);
        add(Msg::DepartWaitingLine, 0, false);
        add(Msg::DepartDenied, 0, false);
        add(Msg::RemovePill { armed: false }, 0, true);
        add(Msg::RemovePill { armed: true }, 0, true);
        add(Msg::DepartAsking, 0, true);
        add(Msg::DepartSending, 0, true);
        add(Msg::DepartTapHint, 0, false);
        add(Msg::DepartThen, 0, false);
        add(Msg::DepartDeniedOn(H), 1, false);
        add(Msg::DepartNotStarted, 0, true);
        v
    }

    /// Every message in every language: written, its holes there exactly as many times as given, no em dash, a one-line message with no forced break, and a wrapping one's forced breaks as many as the English's (the drawers lay the lines out).
    #[test]
    fn every_message_in_every_language() {
        for (m, holes, one_line) in every() {
            let mut english = String::new();
            tr(Lang::En, m, &mut english).unwrap();
            for i in 0..COUNT {
                let l = Lang::from_index(i);
                let mut s = String::new();
                tr(l, m, &mut s).unwrap();
                assert!(!s.trim().is_empty(), "{l:?} {m:?} is empty");
                assert_eq!(s.matches(H).count(), holes, "{l:?} {m:?}: {s}");
                assert!(!s.contains('\u{2014}'), "{l:?} {m:?} has an em dash: {s}");
                if one_line {
                    assert!(!s.contains('\n'), "{l:?} {m:?} is one-line: {s}");
                } else {
                    assert_eq!(s.matches('\n').count(), english.matches('\n').count(), "{l:?} {m:?}: {s}");
                }
            }
        }
    }

    #[test]
    fn index_round_trips_and_codes_are_unique() {
        for i in 0..COUNT {
            let l = Lang::from_index(i);
            assert_eq!(l.index(), i);
            assert_eq!(Lang::from_iso(l.iso()), Some(l));
            assert_eq!(Lang::from_language(&l.language()), Some(l));
            assert_eq!(Lang::from_code(l.code()), Some(l));
        }
        assert_eq!(Lang::from_index(COUNT), Lang::En);
    }

    #[test]
    fn the_picker_holds_every_language_once() {
        for i in 0..COUNT {
            assert_eq!(Lang::ALL.iter().filter(|l| l.index() == i).count(), 1);
        }
    }
}
