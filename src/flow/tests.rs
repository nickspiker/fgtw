//! The flows against each other in memory: real keys, real frames, sends that fail on demand.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::depart::Depart;
use super::{build, Action, Event, Job, Key, Note, To, UserOp};
use crate::keys::Keypair;
use crate::sponsor::Approved;

const HP: Key = [0x11; 32];

/// What the harness hands a machine next.
enum Q {
    Frame(Vec<u8>),
    Sent(Key, bool),
    Built(u32, Result<Vec<u8>, String>),
    Approved(Key, Result<Approved, String>),
    Members,
    Reachable(Key),
    User(UserOp),
    Nfc([u8; 32]),
}

struct Dev {
    kp: Keypair,
    m: Depart,
}

struct Net {
    devs: Vec<Dev>,
    members: Vec<Key>,
    locked: Vec<Key>,
    /// Sends to these devices give up.
    down: Vec<Key>,
    /// Sends to these devices vanish with no word back (a send the app cannot map to a key).
    silent: Vec<Key>,
    queue: Vec<(usize, Q)>,
    notes: Vec<(Key, Note)>,
    wiped: Vec<Key>,
    recorded_denied: Vec<Key>,
    serving: Vec<(Key, Option<[u8; 32]>)>,
    pushed_chain: Vec<Key>,
    /// What the approve job answers.
    approve_fails: bool,
    now: i64,
}

impl Net {
    fn new(n: u8) -> Net {
        Net::with(n, true)
    }

    /// `reports_sent`: whether the app reports every send's outcome.
    fn with(n: u8, reports_sent: bool) -> Net {
        let devs: Vec<Dev> = (0..n)
            .map(|i| {
                let kp = Keypair::from_seed(&[i + 1; 32]);
                let me = kp.public.to_bytes();
                Dev { kp, m: Depart::new(HP, me, reports_sent) }
            })
            .collect();
        let members = devs.iter().map(|d| d.kp.public.to_bytes()).collect();
        let mut net = Net { devs, members, locked: Vec::new(), down: Vec::new(), silent: Vec::new(), queue: Vec::new(), notes: Vec::new(), wiped: Vec::new(), recorded_denied: Vec::new(), serving: Vec::new(), pushed_chain: Vec::new(), approve_fails: false, now: 1 << 40 };
        for i in 0..net.devs.len() {
            net.queue.push((i, Q::Members));
        }
        net.run();
        net
    }

    fn key(&self, i: usize) -> Key {
        self.devs[i].kp.public.to_bytes()
    }

    fn index(&self, k: &Key) -> Option<usize> {
        self.devs.iter().position(|d| d.kp.public.to_bytes() == *k)
    }

    fn user(&mut self, i: usize, op: UserOp) {
        self.queue.push((i, Q::User(op)));
        self.run();
    }

    fn tell_members(&mut self) {
        for i in 0..self.devs.len() {
            self.queue.push((i, Q::Members));
        }
        self.run();
    }

    fn run(&mut self) {
        while !self.queue.is_empty() {
            let (i, q) = self.queue.remove(0);
            let (members, locked) = (self.members.clone(), self.locked.clone());
            let step = match &q {
                Q::Frame(b) => self.devs[i].m.step(Event::Frame { bytes: b, from: None }, self.now),
                Q::Sent(k, ok) => self.devs[i].m.step(Event::Sent { to: *k, ok: *ok }, self.now),
                Q::Built(id, r) => self.devs[i].m.step(Event::Built { id: *id, result: r.as_deref().map_err(|e| e.as_str()) }, self.now),
                Q::Approved(l, r) => self.devs[i].m.step(Event::Approved { leaver: *l, result: r.as_ref().map_err(|e| e.as_str()) }, self.now),
                Q::Members => self.devs[i].m.step(Event::Members { members: &members, locked: &locked }, self.now),
                Q::Reachable(k) => self.devs[i].m.step(Event::Reachable { from: *k }, self.now),
                Q::User(op) => self.devs[i].m.step(Event::User(*op), self.now),
                Q::Nfc(s) => self.devs[i].m.step(Event::NfcRead { secret: *s }, self.now),
            };
            self.carry(i, step.actions);
        }
    }

    fn carry(&mut self, i: usize, actions: Vec<Action>) {
        let me = self.key(i);
        for a in actions {
            match a {
                Action::Send { to: To::Device(k), frame } => {
                    if self.silent.contains(&k) {
                        continue;
                    }
                    let ok = !self.down.contains(&k);
                    if ok {
                        if let Some(j) = self.index(&k) {
                            self.queue.push((j, Q::Frame(frame)));
                        }
                    }
                    self.queue.push((i, Q::Sent(k, ok)));
                }
                Action::Send { to: To::Addr(_), .. } => panic!("depart sends to devices only"),
                Action::Build { id, frame } => {
                    let r = build(&frame, &self.devs[i].kp, self.now);
                    self.queue.push((i, Q::Built(id, r)));
                }
                Action::Job(Job::Approve { leaver, .. }) => {
                    if self.approve_fails {
                        self.queue.push((i, Q::Approved(leaver, Err("the publish failed".to_string()))));
                    } else {
                        self.members.retain(|k| *k != leaver);
                        self.queue.push((i, Q::Approved(leaver, Ok(Approved::BrandKept))));
                        for j in 0..self.devs.len() {
                            self.queue.push((j, Q::Members));
                        }
                    }
                }
                Action::NfcServe(s) => self.serving.push((me, s)),
                Action::Seen { .. } => {}
                Action::RecordDenied { .. } => self.recorded_denied.push(me),
                Action::Note(n) => self.notes.push((me, n)),
                Action::Wipe => self.wiped.push(me),
                Action::PushChain { to } => self.pushed_chain.push(to),
                Action::Persist | Action::RecordReleased { .. } | Action::RefreshChain => {}
                Action::ChainNews { .. } | Action::Radios { .. } | Action::Job(Job::ListRequests | Job::Bind { .. } | Job::Grow { .. }) => panic!("depart runs none of the add flow's actions"),
            }
        }
    }

    fn noted(&self, i: usize, f: impl Fn(&Note) -> bool) -> bool {
        let k = self.key(i);
        self.notes.iter().any(|(d, n)| *d == k && f(n))
    }
}

const SALT: [u8; 32] = [0x5a; 32];
const LEAVE: UserOp = UserOp::Leave { intent: 1, salt: SALT };

#[test]
fn the_last_device_cannot_ask_to_leave() {
    let mut net = Net::new(1);
    net.user(0, LEAVE);
    assert!(net.noted(0, |n| *n == Note::LastDevice));
    assert!(!net.devs[0].m.asking());
}

#[test]
fn a_fleet_not_known_yet_is_treated_as_one_device() {
    let kp = Keypair::from_seed(&[9; 32]);
    let mut m = Depart::new(HP, kp.public.to_bytes(), true);
    let s = m.step(Event::User(LEAVE), 1);
    assert_eq!(s.actions, vec![Action::Note(Note::LastDevice)]);
}

#[test]
fn approve_on_one_device_removes_the_leaver_and_it_wipes() {
    let mut net = Net::new(3);
    let leaver = net.key(0);
    net.user(0, LEAVE);
    assert!(net.noted(0, |n| *n == Note::DepartAsking));
    assert!(net.noted(1, |n| *n == Note::DepartAsked { leaver }));
    assert!(net.noted(2, |n| *n == Note::DepartAsked { leaver }));
    assert!(net.serving.contains(&(leaver, Some(SALT))), "the leaver serves its salt by NFC while it asks");
    net.user(1, UserOp::Approve);
    assert!(net.noted(1, |n| matches!(n, Note::DepartApproved { leaver: l, outcome: Approved::BrandKept } if *l == leaver)));
    assert!(net.wiped.contains(&leaver), "the leaver wipes once the fold no longer lists it");
    assert!(net.noted(2, |n| *n == Note::DepartSettled { leaver }), "the other approver's request clears");
    assert_eq!(net.devs[2].m.asked(), None);
}

#[test]
fn deny_tells_the_leaver_and_every_device_refuses_that_salt() {
    let mut net = Net::new(3);
    let (leaver, denier) = (net.key(0), net.key(1));
    net.user(0, LEAVE);
    let frame = {
        // The request as the fleet received it, to replay after the deny.
        let o = net.devs[0].m.to_section();
        match o.get_field("own_frame").and_then(|f| f.values.first()) {
            Some(vsf::VsfType::v(b'r', b)) => b.clone(),
            _ => panic!("the built request is kept"),
        }
    };
    net.user(1, UserOp::Deny);
    assert!(net.noted(0, |n| *n == Note::DepartDenied { by: denier }));
    assert!(!net.devs[0].m.asking());
    assert!(net.serving.contains(&(leaver, None)), "the NFC serve stops");
    assert!(net.noted(2, |n| *n == Note::DepartDeniedElsewhere { leaver, by: denier }));
    assert!(net.recorded_denied.contains(&denier), "the deny goes into the fleet-shared settings");
    // The same request again is refused on every device; a new one (new salt) is asked anew.
    net.queue.push((2, Q::Frame(frame)));
    net.run();
    assert_eq!(net.devs[2].m.asked(), None);
    // A real second request is stamped later; a denied consent stamp is refused like a denied salt.
    net.now += 1;
    net.user(0, UserOp::Leave { intent: 1, salt: [0x6b; 32] });
    assert_eq!(net.devs[2].m.asked(), Some((leaver, 1, [0x6b; 32])));
}

#[test]
fn a_request_lost_to_a_failed_send_is_handed_again_when_the_device_is_reachable() {
    let mut net = Net::new(3);
    let (leaver, far) = (net.key(0), net.key(2));
    net.down.push(far);
    net.user(0, LEAVE);
    assert_eq!(net.devs[2].m.asked(), None, "the send gave up");
    net.down.clear();
    net.queue.push((0, Q::Reachable(far)));
    net.run();
    assert_eq!(net.devs[2].m.asked(), Some((leaver, 1, SALT)), "handed again when it answered a ping");
}

#[test]
fn a_locked_member_is_not_asked_and_cannot_deny() {
    let mut net = Net::new(3);
    let (leaver, locked) = (net.key(0), net.key(2));
    net.locked.push(locked);
    net.tell_members();
    net.user(0, LEAVE);
    assert_eq!(net.devs[2].m.asked(), None);
    // A deny signed by the locked device changes nothing.
    let deny = build(&super::Frame::DepartDeny { hp: HP, leaver, salt: SALT, t: net.now }, &net.devs[2].kp, net.now).unwrap();
    net.queue.push((0, Q::Frame(deny)));
    net.run();
    assert!(net.devs[0].m.asking());
}

#[test]
fn a_tap_of_the_leaving_device_approves() {
    let mut net = Net::new(2);
    let leaver = net.key(0);
    net.user(0, LEAVE);
    net.queue.push((1, Q::Nfc(SALT)));
    net.run();
    assert!(net.wiped.contains(&leaver));
}

#[test]
fn a_failed_approval_keeps_the_request_for_another_try() {
    let mut net = Net::new(2);
    let leaver = net.key(0);
    net.approve_fails = true;
    net.user(0, LEAVE);
    net.user(1, UserOp::Approve);
    assert!(net.noted(1, |n| matches!(n, Note::DepartApproveFailed { leaver: l, .. } if *l == leaver)));
    assert_eq!(net.devs[1].m.asked(), Some((leaver, 1, SALT)));
    net.approve_fails = false;
    net.user(1, UserOp::Approve);
    assert!(net.wiped.contains(&leaver));
}

#[test]
fn the_state_survives_a_restart_and_the_request_goes_out_again() {
    let mut net = Net::new(3);
    let (leaver, far) = (net.key(0), net.key(2));
    net.down.push(far);
    net.user(0, LEAVE);
    let doc = net.devs[0].m.to_vsf(net.now).unwrap();
    let back = Depart::from_vsf(&doc, HP, net.key(0), true).unwrap();
    net.devs[0].m = back;
    net.down.clear();
    net.queue.push((0, Q::Members));
    net.run();
    let s = net.devs[0].m.resume();
    net.carry(0, s.actions);
    net.run();
    assert_eq!(net.devs[2].m.asked(), Some((leaver, 1, SALT)), "the restarted leaver hands its saved request to the member that missed it");
    // The approver side survives too.
    let sec = net.devs[2].m.to_section();
    let mut back = Depart::from_section(&sec, HP, net.key(2), true).unwrap();
    assert_eq!(back.asked(), Some((leaver, 1, SALT)));
    let s = back.resume();
    assert_eq!(s.actions, vec![Action::Note(Note::DepartAsked { leaver })]);
}

#[test]
fn a_member_never_reached_is_handed_the_request_when_it_shows_up() {
    // An app that reports no send outcomes (Photon today): a send with no word back is handed again when the device shows up.
    let mut net = Net::with(3, false);
    let (leaver, far) = (net.key(0), net.key(2));
    net.silent.push(far);
    net.user(0, LEAVE);
    assert_eq!(net.devs[2].m.asked(), None, "the first send vanished and no Sent came back");
    net.silent.clear();
    net.queue.push((0, Q::Reachable(far)));
    net.run();
    assert_eq!(net.devs[2].m.asked(), Some((leaver, 1, SALT)), "its beacon or Pong hands it the request");
}

#[test]
fn a_frame_reports_its_signer_and_address() {
    let mut net = Net::new(2);
    net.user(0, LEAVE);
    let frame = build(&super::Frame::DepartReq { hp: HP, t: net.now + 1, intent: 1, salt: [7; 32] }, &net.devs[0].kp, net.now).unwrap();
    let addr: core::net::SocketAddr = "192.0.2.7:4383".parse().unwrap();
    let s = net.devs[1].m.step(Event::Frame { bytes: &frame, from: Some(addr) }, net.now);
    assert!(s.actions.contains(&Action::Seen { device: net.key(0), addr }));
}

#[test]
fn a_send_in_flight_is_not_sent_again_when_its_device_shows_up() {
    // An app that reports every outcome (ferros): a beacon every few seconds must not start a duplicate transfer.
    let mut net = Net::new(3);
    let far = net.key(2);
    net.silent.push(far);
    net.user(0, LEAVE);
    let s = net.devs[0].m.step(Event::Reachable { from: far }, net.now);
    assert!(s.actions.iter().all(|a| !matches!(a, Action::Send { .. })), "still in flight, so no second send");
    // A send that gave up is handed again.
    let s = net.devs[0].m.step(Event::Sent { to: far, ok: false }, net.now);
    assert!(s.actions.is_empty());
    let s = net.devs[0].m.step(Event::Reachable { from: far }, net.now);
    assert!(s.actions.iter().any(|a| matches!(a, Action::Send { to: To::Device(k), .. } if *k == far)));
}

#[test]
fn the_approver_hands_the_leaver_the_new_chain() {
    let mut net = Net::new(2);
    let leaver = net.key(0);
    net.user(0, LEAVE);
    net.user(1, UserOp::Approve);
    assert!(net.pushed_chain.contains(&leaver));
}

#[test]
fn a_withdrawn_request_leaves_the_approvers() {
    let mut net = Net::new(2);
    let leaver = net.key(0);
    net.user(0, LEAVE);
    let t = net.devs[1].m.asked_t().unwrap();
    assert!(net.devs[0].m.own_frame().is_some(), "the leaver keeps its signed request");
    net.queue.push((1, Q::Members));
    net.run();
    let s = net.devs[1].m.step(Event::GaveUp { leaver, t }, net.now);
    assert!(s.actions.contains(&Action::Note(Note::DepartWithdrawn { leaver })));
    assert_eq!(net.devs[1].m.asked(), None);
}

#[test]
fn the_saved_state_holds_no_handle_proof() {
    let mut net = Net::new(2);
    net.user(0, LEAVE);
    let sec = net.devs[0].m.to_section();
    assert!(sec.get_field("hp").is_none());
    let doc = net.devs[0].m.to_vsf(net.now).unwrap();
    assert!(!doc.windows(32).any(|w| w == HP), "the handle proof never reaches the disk");
}
