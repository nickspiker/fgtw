//! The Add machine against real signed binding requests.

use alloc::vec::Vec;

use super::add::{Add, Phase};
use super::{Action, Event, Frame, Job, Key, Note, To, UserOp, Wake};
use crate::fleet::BindRequest;
use crate::keys::Keypair;

const SEED: [u8; 32] = [7; 32];
const HP: Key = [9; 32];
const NOW: i64 = 1 << 44;

struct Rig {
    m: Add,
    me: Keypair,
    members: Vec<Key>,
    locked: Vec<Key>,
}

impl Rig {
    /// A sponsor in a fleet of itself and `others` more devices, holding the fleet key, its Fleet page shown.
    fn new(others: u8) -> Rig {
        let me = Keypair::from_seed(&[1; 32]);
        let mut members = vec![me.public.to_bytes()];
        for i in 0..others {
            members.push(Keypair::from_seed(&[0x40 + i; 32]).public.to_bytes());
        }
        let mut rig = Rig { m: Add::new(HP, SEED, me.public.to_bytes(), true), me, members, locked: Vec::new() };
        rig.tell_members();
        rig.step(Event::FleetKey { held: true });
        rig
    }

    fn tell_members(&mut self) {
        let (m, l) = (self.members.clone(), self.locked.clone());
        self.step(Event::Members { members: &m, locked: &l });
    }

    fn step(&mut self, ev: Event) -> Vec<Action> {
        self.m.step(ev, NOW).actions
    }

    fn open(&mut self) -> Vec<Action> {
        self.step(Event::Page { shown: true })
    }

    /// A joiner's request heard on the LAN.
    fn hear(&mut self, joiner: &Keypair, req: &BindRequest) -> Vec<Action> {
        let frame = crate::protocol::bind_req(req, &HP, joiner, NOW).unwrap();
        self.step(Event::Frame { bytes: &frame, from: None })
    }
}

fn joiner(n: u8) -> Keypair {
    Keypair::from_seed(&[0x80 + n; 32])
}

fn request(j: &Keypair, nfc: &[u8; 32]) -> BindRequest {
    crate::protocol::bind_request(j, &SEED, &HP, NOW, nfc)
}

fn has_note(a: &[Action], n: Note) -> bool {
    a.contains(&Action::Note(n))
}

fn binds(a: &[Action]) -> bool {
    a.iter().any(|x| matches!(x, Action::Job(Job::Bind { .. })))
}

#[test]
fn a_device_without_the_fleet_key_does_not_open_the_flow() {
    let mut rig = Rig::new(1);
    rig.step(Event::FleetKey { held: false });
    let a = rig.open();
    assert!(has_note(&a, Note::AddNoFleetKey));
    assert!(a.contains(&Action::Radios { ble_scan: false, nfc_reader: false }));
    assert_eq!(rig.m.view().phase, Phase::Closed);
}

#[test]
fn a_lan_request_while_the_page_is_closed_notifies_once() {
    let mut rig = Rig::new(1);
    let j = joiner(0);
    let r = request(&j, &[0; 32]);
    assert!(has_note(&rig.hear(&j, &r), Note::AsksToJoin { device: j.public.to_bytes() }));
    assert!(!rig.hear(&j, &r).iter().any(|a| matches!(a, Action::Note(_))), "the same request again says nothing");
}

#[test]
fn a_touch_picks_without_binding_and_no_drops_the_pick() {
    let mut rig = Rig::new(1);
    assert!(rig.open().contains(&Action::Radios { ble_scan: true, nfc_reader: true }));
    let j = joiner(0);
    let dev = j.public.to_bytes();
    rig.hear(&j, &request(&j, &[0; 32]));
    let a = rig.step(Event::User(UserOp::Touch { device: dev }));
    assert!(a.contains(&Action::PushChain { to: dev }));
    assert!(a.iter().any(|x| matches!(x, Action::Build { frame: Frame::BindSelect { joiner, .. }, .. } if *joiner == dev)));
    assert!(!binds(&a), "a pick binds nothing");
    assert_eq!(rig.m.view().phase, Phase::Selected);
    assert!(rig.m.view().selected.is_some_and(|(d, _, words)| d == dev && !words.is_empty()));
    rig.step(Event::User(UserOp::No));
    assert_eq!(rig.m.view().phase, Phase::Open);
}

#[test]
fn yes_binds_then_grows_without_the_locked_device_then_hands_the_key_out() {
    let mut rig = Rig::new(2);
    let locked = rig.members[2];
    rig.locked.push(locked);
    rig.tell_members();
    rig.open();
    let j = joiner(0);
    let dev = j.public.to_bytes();
    rig.hear(&j, &request(&j, &[0; 32]));
    rig.step(Event::User(UserOp::Touch { device: dev }));
    let a = rig.step(Event::User(UserOp::Yes));
    assert!(binds(&a));
    assert!(has_note(&a, Note::Adding { device: dev }));
    let a = rig.step(Event::Bound { device: dev, result: Ok(()) });
    assert!(a.contains(&Action::ChainNews { extra: Some(dev) }));
    let grow = a.iter().find_map(|x| match x {
        Action::Job(Job::Grow { members, .. }) => Some(members.clone()),
        _ => None,
    });
    let grow = grow.expect("the grow follows the bind");
    assert!(grow.contains(&dev) && grow.contains(&rig.me.public.to_bytes()));
    assert!(!grow.contains(&locked), "a locked device never gets the key");
    let a = rig.step(Event::Grown { device: dev, result: Ok(&[1, 2, 3]) });
    let id = a.iter().find_map(|x| match x {
        Action::Build { id, frame: Frame::FanoutResp { .. } } => Some(*id),
        _ => None,
    });
    let a = rig.step(Event::Built { id: id.expect("the grown fan-out is signed"), result: Ok(&[4, 5, 6]) });
    let sent: Vec<Key> = a
        .iter()
        .filter_map(|x| match x {
            Action::Send { to: To::Device(k), .. } => Some(*k),
            _ => None,
        })
        .collect();
    assert!(sent.contains(&dev) && sent.contains(&rig.members[1]) && !sent.contains(&locked));
    assert!(has_note(&a, Note::Added { device: dev }));
    assert_eq!(rig.m.view().phase, Phase::Open);
}

#[test]
fn an_nfc_tap_adds_at_once() {
    let mut rig = Rig::new(1);
    rig.open();
    let j = joiner(0);
    let secret = [0x33; 32];
    rig.hear(&j, &request(&j, &secret));
    assert!(binds(&rig.step(Event::NfcRead { secret })));
}

#[test]
fn typed_words_add_at_once_and_unknown_words_read_fgtw_org_once() {
    let mut rig = Rig::new(1);
    rig.open();
    let a = rig.step(Event::Words { text: "zzzz " });
    assert!(a.contains(&Action::Job(Job::ListRequests)), "no candidate yet: ask fgtw.org");
    assert!(!rig.step(Event::Words { text: "zzzz y" }).contains(&Action::Job(Job::ListRequests)), "one read at a time");
    let j = joiner(0);
    let r = request(&j, &[0; 32]);
    rig.step(Event::Listed { reqs: core::slice::from_ref(&r), owned_elsewhere: &[] });
    let words = crate::pair::masked_device_words(&j.public.to_bytes(), &SEED);
    assert!(binds(&rig.step(Event::Words { text: &words })));
}

#[test]
fn contention_leaves_only_bluetooth_picks() {
    let mut rig = Rig::new(1);
    rig.open();
    let (a, b) = (joiner(0), joiner(1));
    rig.hear(&a, &request(&a, &[0; 32]));
    rig.hear(&b, &request(&b, &[0; 32]));
    assert!(rig.m.view().contended);
    assert!(!rig.step(Event::User(UserOp::Touch { device: a.public.to_bytes() })).iter().any(|x| matches!(x, Action::PushChain { .. })), "a LAN-only pick is shut");
    rig.step(Event::BeaconHeard { id: crate::pair::beacon_id(&HP, &a.public.to_bytes(), NOW) });
    assert!(rig.step(Event::User(UserOp::Touch { device: a.public.to_bytes() })).contains(&Action::PushChain { to: a.public.to_bytes() }));
}

#[test]
fn a_locked_out_plate_and_a_device_owned_elsewhere_are_refused() {
    let mut rig = Rig::new(1);
    rig.open();
    let j = joiner(0);
    let plate = [0x55; 32];
    let r = crate::protocol::bind_request_plated(&j, &SEED, &HP, NOW, &[0; 32], Some(plate), 1);
    rig.step(Event::LockedPlates { plates: &[plate] });
    rig.hear(&j, &r);
    assert!(has_note(&rig.step(Event::User(UserOp::Touch { device: j.public.to_bytes() })), Note::AddLockedOut { device: j.public.to_bytes() }));
    let k = joiner(1);
    let rk = request(&k, &[0; 32]);
    rig.step(Event::Listed { reqs: core::slice::from_ref(&rk), owned_elsewhere: &[k.public.to_bytes()] });
    rig.step(Event::BeaconHeard { id: crate::pair::beacon_id(&HP, &k.public.to_bytes(), NOW) });
    assert!(rig.m.view().rows.iter().any(|r| r.device == k.public.to_bytes() && r.owned_elsewhere));
    assert!(has_note(&rig.step(Event::User(UserOp::Touch { device: k.public.to_bytes() })), Note::AddOwnedElsewhere { device: k.public.to_bytes() }));
}

#[test]
fn a_grow_cut_short_by_a_restart_is_asked_for_again() {
    let mut rig = Rig::new(1);
    rig.open();
    let j = joiner(0);
    let dev = j.public.to_bytes();
    rig.hear(&j, &request(&j, &[0; 32]));
    rig.step(Event::NfcRead { secret: [0; 32] });
    rig.step(Event::User(UserOp::Touch { device: dev }));
    rig.step(Event::User(UserOp::Yes));
    rig.step(Event::Bound { device: dev, result: Ok(()) });
    let doc = rig.m.to_vsf(NOW).unwrap();
    assert!(!doc.windows(32).any(|w| w == HP || w == SEED), "no root in the saved state");
    rig.m = Add::from_vsf(&doc, HP, SEED, true).unwrap();
    rig.members.push(dev);
    rig.tell_members();
    let s = rig.m.resume();
    assert!(s.actions.iter().any(|x| matches!(x, Action::Job(Job::Grow { device, .. }) if *device == dev)));
}

#[test]
fn a_bind_cut_short_by_a_restart_is_reported_to_do_again() {
    let mut rig = Rig::new(1);
    rig.open();
    let j = joiner(0);
    let dev = j.public.to_bytes();
    rig.hear(&j, &request(&j, &[0; 32]));
    rig.step(Event::User(UserOp::Touch { device: dev }));
    rig.step(Event::User(UserOp::Yes));
    let doc = rig.m.to_vsf(NOW).unwrap();
    rig.m = Add::from_vsf(&doc, HP, SEED, true).unwrap();
    rig.tell_members();
    let s = rig.m.resume();
    assert!(s.actions.iter().any(|x| matches!(x, Action::Note(Note::AddFailed { device, .. }) if *device == dev)));
}

#[test]
fn the_screen_asks_to_be_woken_when_a_nearby_device_lapses() {
    let mut rig = Rig::new(1);
    rig.open();
    let j = joiner(0);
    let frame = crate::protocol::bind_req(&request(&j, &[0; 32]), &HP, &j, NOW).unwrap();
    let s = rig.m.step(Event::Frame { bytes: &frame, from: None }, NOW);
    assert_eq!(s.wake, Some((NOW + super::add::NEARBY_OSC, Wake::Lapse)));
}
