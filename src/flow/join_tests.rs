//! The Join machine against the owner's rules of 2026-11-22: nothing out before the yes, the words only on asking, fgtw.org only on the last-rung edge.

use alloc::vec::Vec;

use super::join::{Do, Join, JoinNote, Phase, Refusal, REMINT_OSC, UNHEARD_OSC};
use super::{Event, Key, UserOp, Wake};

const SEED: [u8; 32] = [7; 32];
const ME: Key = [1; 32];
const FLEET: Key = [2; 32];
const NFC: [u8; 32] = [3; 32];
const NOW: i64 = 1 << 44;
const FRAME: &[u8] = b"bind_req";

/// Anything that reaches past this device: a request, a beacon, a radio, the registry, or the words.
fn sends(a: &[Do]) -> bool {
    a.iter().any(|d| matches!(d, Do::Mint | Do::Hand { .. } | Do::LanBeacon | Do::Ble(Some(_)) | Do::Nfc(Some(_)) | Do::PostRegistry | Do::Watch { .. }))
}

fn posts(a: &[Do]) -> bool {
    a.contains(&Do::PostRegistry)
}

/// A join whose look-up found the identity's fleet, this device unbound: at the question.
fn at_confirm() -> Join {
    let mut j = Join::new(ME, SEED);
    let s = j.step(Event::Looked { has_fleet: true, member: false, busy: false }, NOW);
    assert_eq!(s.actions, vec![Do::Note(JoinNote::Confirm)]);
    assert_eq!(j.phase(), Phase::Confirm);
    j
}

/// Past the yes, its request minted at NOW.
fn asking() -> Join {
    let mut j = at_confirm();
    j.step(Event::User(UserOp::Confirm { nfc_secret: NFC }), NOW);
    j.step(Event::Minted { t: NOW, result: Ok(FRAME) }, NOW);
    j
}

#[test]
fn nothing_leaves_the_device_before_the_yes() {
    let mut j = Join::new(ME, SEED);
    let mut all: Vec<Do> = Vec::new();
    let evs = [
        Event::LanHeard { device: FLEET },
        Event::LinkUp,
        Event::Wake { reason: Wake::Unheard },
        Event::Wake { reason: Wake::Remint },
        Event::User(UserOp::ShowWords),
        Event::Minted { t: NOW, result: Ok(FRAME) },
        Event::Picked { by: FLEET },
        Event::InFleet,
    ];
    // While looking, then at the question: neither phase sends, beacons, serves or shows anything.
    for ev in evs {
        all.extend(j.step(ev, NOW + UNHEARD_OSC).actions);
    }
    all.extend(j.step(Event::Looked { has_fleet: true, member: false, busy: false }, NOW).actions);
    for ev in evs {
        all.extend(j.step(ev, NOW + UNHEARD_OSC).actions);
    }
    assert!(!sends(&all), "{all:?}");
    assert_eq!(j.phase(), Phase::Confirm);
    assert_eq!(j.view().words, None);
    assert_eq!(j.step(Event::Looked { has_fleet: true, member: false, busy: false }, NOW).wake, None, "no deadline before the yes");
}

#[test]
fn a_busy_device_is_refused_and_never_asked() {
    let mut j = Join::new(ME, SEED);
    let s = j.step(Event::Looked { has_fleet: true, member: false, busy: true }, NOW);
    assert_eq!(s.actions, vec![Do::Note(JoinNote::Busy)]);
    assert_eq!(j.phase(), Phase::Refused(Refusal::Busy));
    let s = j.step(Event::User(UserOp::Confirm { nfc_secret: NFC }), NOW);
    assert!(!sends(&s.actions), "a yes on a busy device sends nothing");
}

#[test]
fn a_fresh_handle_or_a_member_is_no_join() {
    let mut j = Join::new(ME, SEED);
    assert!(j.step(Event::Looked { has_fleet: false, member: false, busy: false }, NOW).actions.is_empty());
    assert_eq!(j.phase(), Phase::NotJoining);
    let mut j = Join::new(ME, SEED);
    assert!(j.step(Event::Looked { has_fleet: true, member: true, busy: false }, NOW).actions.is_empty());
    assert_eq!(j.phase(), Phase::NotJoining);
}

#[test]
fn the_yes_goes_to_the_persons_devices_first() {
    let mut j = at_confirm();
    let s = j.step(Event::User(UserOp::Confirm { nfc_secret: NFC }), NOW);
    assert_eq!(s.actions, vec![Do::Nfc(Some(NFC)), Do::Mint, Do::LanBeacon, Do::Watch { registry: false }, Do::Note(JoinNote::Asking)]);
    assert_eq!(s.wake, Some((NOW + UNHEARD_OSC, Wake::Unheard)));
    // A fleet device answering before the mint is handed the request when it is minted.
    assert!(j.step(Event::LanHeard { device: FLEET }, NOW).actions.is_empty());
    let s = j.step(Event::Minted { t: NOW, result: Ok(FRAME) }, NOW);
    assert!(s.actions.contains(&Do::Ble(Some(NOW))));
    assert!(s.actions.contains(&Do::Hand { to: FLEET, frame: FRAME.to_vec() }));
    assert!(!posts(&s.actions));
    // Heard once, handed once per stamp.
    assert!(j.step(Event::LanHeard { device: FLEET }, NOW).actions.is_empty());
}

#[test]
fn no_words_before_show_words() {
    let mut j = asking();
    assert_eq!(j.view().words, None);
    let s = j.step(Event::User(UserOp::ShowWords), NOW);
    assert_eq!(j.view().words, Some(crate::pair::masked_device_words(&ME, &SEED)));
    // The explicit edge: the registry at once.
    assert!(posts(&s.actions));
}

#[test]
fn show_words_before_the_mint_posts_once_it_is_minted() {
    let mut j = at_confirm();
    j.step(Event::User(UserOp::Confirm { nfc_secret: NFC }), NOW);
    let s = j.step(Event::User(UserOp::ShowWords), NOW);
    assert!(!posts(&s.actions), "nothing minted to post yet");
    let s = j.step(Event::Minted { t: NOW, result: Ok(FRAME) }, NOW);
    assert!(posts(&s.actions));
}

#[test]
fn fgtw_org_only_on_the_unheard_edge() {
    let mut j = asking();
    // Early: the window is still open.
    let s = j.step(Event::Wake { reason: Wake::Unheard }, NOW + UNHEARD_OSC - 1);
    assert!(!posts(&s.actions));
    let s = j.step(Event::Wake { reason: Wake::Unheard }, NOW + UNHEARD_OSC);
    assert!(posts(&s.actions));
    assert!(s.actions.contains(&Do::Note(JoinNote::Unheard)));
    let s = j.step(Event::Posted { result: Ok(()) }, NOW + UNHEARD_OSC);
    assert_eq!(s.actions, vec![Do::Watch { registry: true }]);
    assert!(j.view().posted);
}

#[test]
fn a_fleet_device_heard_keeps_fgtw_org_out() {
    let mut j = asking();
    j.step(Event::LanHeard { device: FLEET }, NOW);
    let s = j.step(Event::Wake { reason: Wake::Unheard }, NOW + UNHEARD_OSC);
    assert!(!posts(&s.actions));
    assert!(!j.view().posted);
    assert_eq!(s.wake, Some((NOW + REMINT_OSC, Wake::Remint)), "the only deadline left is the request's freshness");
}

#[test]
fn the_one_owner_verdict_refuses_and_stops_the_radios() {
    let mut j = asking();
    j.step(Event::User(UserOp::ShowWords), NOW);
    let s = j.step(Event::Posted { result: Err("device_owned: another identity's fleet") }, NOW);
    assert!(s.actions.contains(&Do::Nfc(None)) && s.actions.contains(&Do::Ble(None)));
    assert!(!s.actions.contains(&Do::Withdraw), "nothing was taken to withdraw");
    assert_eq!(j.phase(), Phase::Refused(Refusal::Owned));
    // A failed post that is no verdict leaves the join asking.
    let mut j = asking();
    j.step(Event::User(UserOp::ShowWords), NOW);
    let s = j.step(Event::Posted { result: Err("network down") }, NOW);
    assert_eq!(s.actions, vec![Do::Note(JoinNote::PostFailed("network down".into()))]);
    assert_eq!(j.phase(), Phase::Asking);
}

#[test]
fn back_withdraws_and_asks_again() {
    let mut j = asking();
    j.step(Event::User(UserOp::ShowWords), NOW);
    j.step(Event::Posted { result: Ok(()) }, NOW);
    let s = j.step(Event::User(UserOp::Back), NOW);
    for d in [Do::Nfc(None), Do::Ble(None), Do::Unwatch, Do::Withdraw, Do::Note(JoinNote::Withdrawn)] {
        assert!(s.actions.contains(&d), "{d:?} in {:?}", s.actions);
    }
    assert_eq!(j.phase(), Phase::Confirm);
    assert_eq!(j.view().words, None);
}

#[test]
fn the_request_is_minted_again_before_it_lapses_and_handed_again() {
    let mut j = asking();
    j.step(Event::LanHeard { device: FLEET }, NOW);
    let at = NOW + REMINT_OSC;
    assert!(j.step(Event::Wake { reason: Wake::Remint }, at - 1).actions.is_empty());
    assert_eq!(j.step(Event::Wake { reason: Wake::Remint }, at).actions, vec![Do::Mint]);
    let s = j.step(Event::Minted { t: at, result: Ok(b"bind_req again") }, at);
    assert!(s.actions.contains(&Do::Ble(Some(at))));
    assert!(s.actions.contains(&Do::LanBeacon), "a fresh stamp is announced again");
    assert!(s.actions.contains(&Do::Hand { to: FLEET, frame: b"bind_req again".to_vec() }));
}

#[test]
fn a_pick_turns_green_and_the_fold_ends_the_join() {
    let mut j = asking();
    assert_eq!(j.step(Event::Picked { by: FLEET }, NOW).actions, vec![Do::Note(JoinNote::Selected { by: FLEET })]);
    assert_eq!(j.view().selected_by, Some(FLEET));
    let s = j.step(Event::InFleet, NOW);
    assert!(s.actions.contains(&Do::Nfc(None)) && s.actions.contains(&Do::Ble(None)) && s.actions.contains(&Do::Unwatch));
    assert!(s.actions.contains(&Do::Note(JoinNote::Joined)));
    assert_eq!(j.phase(), Phase::Joined);
    assert_eq!(s.wake, None);
}

#[test]
fn a_mint_that_fails_goes_back_to_the_question() {
    let mut j = at_confirm();
    j.step(Event::User(UserOp::Confirm { nfc_secret: NFC }), NOW);
    let s = j.step(Event::Minted { t: NOW, result: Err("no device key") }, NOW);
    assert!(s.actions.contains(&Do::Note(JoinNote::MintFailed("no device key".into()))));
    assert!(s.actions.contains(&Do::Nfc(None)));
    assert_eq!(j.phase(), Phase::Confirm);
}
