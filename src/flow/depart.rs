//! A device leaving its fleet, both halves (photon docs/lifecycle.md, the bilateral removal).
//! The leaver signs a request naming itself with a fresh salt and hands it to every live member until each has it.
//! Each member asks its person, Approve or Deny: Approve countersigns and publishes the consented Remove; Deny refuses that salt for good on every device.
//! The leaver is done when the fold no longer lists it, and wipes.
//! The last device cannot ask: an identity must live somewhere.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vsf::file_format::VsfSection;
use vsf::types::EtType;
use vsf::VsfType;

use super::deliver::Deliver;
use super::{Action, Event, Frame, Job, Key, Note, Step, UserOp};

/// Our own request, while it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Own {
    /// The consent stamp.
    t: i64,
    salt: [u8; 32],
    intent: u8,
    /// The build asked for; its answer starts the delivery.
    build: u32,
    /// Built and on its way.
    deliver: Option<Deliver>,
}

/// Another device's request, waiting for this device's person.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Asked {
    leaver: Key,
    t: i64,
    consent_sig: Vec<u8>,
    intent: u8,
    salt: [u8; 32],
    /// The approval job is running.
    approving: bool,
}

/// A deny of ours on its way to the fleet.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DenyOut {
    build: u32,
    deliver: Option<Deliver>,
}

/// One device's departure state: its own request (as leaver) and the request it was asked about (as approver).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Depart {
    hp: Key,
    me: Key,
    /// The fold as last told: every member, this device among them.
    members: Vec<Key>,
    locked: Vec<Key>,
    /// Members have been told at least once.
    known: bool,
    own: Option<Own>,
    asked: Option<Asked>,
    /// Requests refused here or anywhere in the fleet: (leaver, salt, consent stamp).
    denied: Vec<(Key, [u8; 32], i64)>,
    denies: Vec<DenyOut>,
    next_build: u32,
}

impl Depart {
    /// A fresh machine for device `me` of the fleet `hp`. Tell it the members before anything else.
    pub fn new(hp: Key, me: Key) -> Self {
        Depart { hp, me, members: Vec::new(), locked: Vec::new(), known: false, own: None, asked: None, denied: Vec::new(), denies: Vec::new(), next_build: 0 }
    }

    /// Our request is out (or being built).
    pub fn asking(&self) -> bool {
        self.own.is_some()
    }

    /// The request this device's person is asked about: (leaver, intent, salt).
    pub fn asked(&self) -> Option<(Key, u8, [u8; 32])> {
        self.asked.as_ref().map(|a| (a.leaver, a.intent, a.salt))
    }

    /// The members a frame from this device goes to: live, not locked, not us.
    fn targets(&self) -> Vec<Key> {
        self.members.iter().filter(|k| **k != self.me && !self.locked.contains(k)).copied().collect()
    }

    fn live(&self, k: &Key) -> bool {
        self.members.contains(k) && !self.locked.contains(k)
    }

    fn is_denied(&self, leaver: &Key, salt: &[u8; 32], t: i64) -> bool {
        self.denied.iter().any(|(l, s, dt)| l == leaver && (s == salt || *dt == t))
    }

    fn take_build(&mut self) -> u32 {
        let id = self.next_build;
        self.next_build += 1;
        id
    }

    /// Refuse a request from now on; true when it was new here.
    fn deny_here(&mut self, leaver: Key, salt: [u8; 32], t: i64) -> bool {
        if self.denied.iter().any(|(l, s, dt)| *l == leaver && *s == salt && *dt == t) {
            return false;
        }
        self.denied.push((leaver, salt, t));
        true
    }

    /// One event. `now` is Eagle time in oscillations (the consent stamp of a new request).
    pub fn step(&mut self, ev: Event, now: i64) -> Step {
        let mut s = Step::default();
        match ev {
            Event::Members { members, locked } => self.on_members(members, locked, &mut s),
            Event::Frame { bytes } => self.on_frame(bytes, &mut s),
            Event::Sent { to, ok } => {
                if let Some(d) = self.own.as_mut().and_then(|o| o.deliver.as_mut()) {
                    d.on_sent(to, ok);
                }
                for d in self.denies.iter_mut().filter_map(|d| d.deliver.as_mut()) {
                    d.on_sent(to, ok);
                }
                self.denies.retain(|d| !d.deliver.as_ref().is_some_and(|x| x.done()));
            }
            Event::Pong { from } => {
                if let Some(d) = self.own.as_mut().and_then(|o| o.deliver.as_mut()) {
                    d.on_pong(from, &mut s.actions);
                }
                for d in self.denies.iter_mut().filter_map(|d| d.deliver.as_mut()) {
                    d.on_pong(from, &mut s.actions);
                }
            }
            Event::LinkUp => {
                if let Some(d) = self.own.as_mut().and_then(|o| o.deliver.as_mut()) {
                    d.on_link_up(&mut s.actions);
                }
                for d in self.denies.iter_mut().filter_map(|d| d.deliver.as_mut()) {
                    d.on_link_up(&mut s.actions);
                }
            }
            Event::Built { id, result } => self.on_built(id, result, &mut s),
            Event::Approved { leaver, result } => self.on_approved(leaver, result, &mut s),
            Event::DeniedKnown { denied } => {
                let mut changed = false;
                for (l, salt, t) in denied {
                    changed |= self.deny_here(*l, *salt, *t);
                }
                if let Some(a) = self.asked.as_ref() {
                    if self.is_denied(&a.leaver, &a.salt, a.t) {
                        self.asked = None;
                        changed = true;
                    }
                }
                if changed {
                    s.push(Action::Persist);
                }
            }
            Event::NfcRead { secret } => {
                // A tap of the leaving device, which serves its salt while its request stands, approves the request it names.
                if self.asked.as_ref().is_some_and(|a| a.salt == secret) {
                    self.approve(&mut s);
                }
            }
            Event::User(op) => match op {
                UserOp::Leave { intent, salt } => self.leave(intent, salt, now, &mut s),
                UserOp::GiveUp => {
                    if self.own.take().is_some() {
                        s.push(Action::NfcServe(None));
                        s.push(Action::Persist);
                    }
                }
                UserOp::Approve => self.approve(&mut s),
                UserOp::Deny => self.deny(&mut s),
            },
        }
        s
    }

    fn on_members(&mut self, members: &[Key], locked: &[Key], s: &mut Step) {
        self.members = members.to_vec();
        self.locked = locked.to_vec();
        self.known = true;
        // Our request is done when the fold no longer lists us.
        if self.own.is_some() && !self.members.contains(&self.me) {
            self.own = None;
            s.push(Action::NfcServe(None));
            s.push(Action::Persist);
            s.push(Action::Note(Note::DepartDone));
            s.push(Action::Wipe);
            return;
        }
        let targets = self.targets();
        if let Some(d) = self.own.as_mut().and_then(|o| o.deliver.as_mut()) {
            d.retain(&targets);
            for k in &targets {
                d.add(*k, &mut s.actions);
            }
        }
        for d in self.denies.iter_mut().filter_map(|d| d.deliver.as_mut()) {
            d.retain(&targets);
        }
        // A request whose leaver is gone was settled elsewhere.
        if let Some(a) = self.asked.as_ref() {
            if !self.members.contains(&a.leaver) {
                let leaver = a.leaver;
                self.asked = None;
                s.push(Action::Persist);
                s.push(Action::Note(Note::DepartSettled { leaver }));
            }
        }
    }

    fn leave(&mut self, intent: u8, salt: [u8; 32], now: i64, s: &mut Step) {
        // The last device cannot ask (identity never dies), and a fleet not known yet is treated as one device: fail toward refusal.
        if !self.known || self.members.len() <= 1 {
            s.push(Action::Note(Note::LastDevice));
            return;
        }
        let build = self.take_build();
        // Asking again is always a new request with a new salt; the old one is dropped here.
        self.own = Some(Own { t: now, salt, intent, build, deliver: None });
        s.push(Action::Build { id: build, frame: Frame::DepartReq { hp: self.hp, t: now, intent, salt } });
        s.push(Action::Persist);
    }

    fn on_built(&mut self, id: u32, result: Result<&[u8], &str>, s: &mut Step) {
        let targets = self.targets();
        if let Some(own) = self.own.as_mut().filter(|o| o.build == id && o.deliver.is_none()) {
            match result {
                Ok(frame) => {
                    own.deliver = Some(Deliver::new(frame.to_vec(), &targets, &mut s.actions));
                    let salt = own.salt;
                    s.push(Action::NfcServe(Some(salt)));
                    s.push(Action::Persist);
                    s.push(Action::Note(Note::DepartAsking));
                }
                Err(e) => {
                    self.own = None;
                    s.push(Action::Persist);
                    s.push(Action::Note(Note::DepartNotSent(e.to_string())));
                }
            }
            return;
        }
        if let Some(i) = self.denies.iter().position(|d| d.build == id && d.deliver.is_none()) {
            match result {
                Ok(frame) => self.denies[i].deliver = Some(Deliver::new(frame.to_vec(), &targets, &mut s.actions)),
                // The deny is already recorded here and in the fleet-shared settings; only its frame failed, so the others learn it from the settings sync.
                Err(_) => {
                    self.denies.remove(i);
                }
            }
        }
    }

    fn on_frame(&mut self, bytes: &[u8], s: &mut Step) {
        if let Ok((req, leaver)) = crate::protocol::parse_depart_req(bytes) {
            self.on_depart_req(req, leaver, s);
            return;
        }
        if let Ok((hp, leaver, salt, t, by)) = crate::protocol::parse_depart_deny(bytes) {
            self.on_depart_deny(hp, leaver, salt, t, by, s);
        }
    }

    fn on_depart_req(&mut self, req: crate::protocol::DepartReq, leaver: Key, s: &mut Step) {
        // Only a live member of this fleet, never ourselves, and only a consent its own key signed for this fleet.
        if leaver == self.me || !self.live(&leaver) {
            return;
        }
        if !crate::sponsor::depart_receipt_valid(&self.hp, &leaver, req.t, &req.consent_sig) {
            return;
        }
        if self.is_denied(&leaver, &req.salt, req.t) {
            return;
        }
        if self.asked.as_ref().is_some_and(|a| a.leaver == leaver && a.salt == req.salt) {
            return;
        }
        self.asked = Some(Asked { leaver, t: req.t, consent_sig: req.consent_sig, intent: req.intent, salt: req.salt, approving: false });
        s.push(Action::Persist);
        s.push(Action::Note(Note::DepartAsked { leaver }));
    }

    fn on_depart_deny(&mut self, hp: Key, leaver: Key, salt: [u8; 32], t: i64, by: Key, s: &mut Step) {
        if hp != self.hp || by == self.me || !self.live(&by) {
            return;
        }
        if leaver == self.me {
            // A deny of a request of ours that is no longer current changes nothing.
            if self.own.as_ref().is_some_and(|o| o.salt == salt) {
                self.own = None;
                s.push(Action::NfcServe(None));
                s.push(Action::Persist);
                s.push(Action::Note(Note::DepartDenied { by }));
            }
            return;
        }
        let mut changed = self.deny_here(leaver, salt, t);
        for d in self.denies.iter_mut().filter_map(|d| d.deliver.as_mut()) {
            d.answered(by);
        }
        if self.asked.as_ref().is_some_and(|a| a.leaver == leaver && (a.salt == salt || a.t == t)) {
            self.asked = None;
            changed = true;
            s.push(Action::Note(Note::DepartDeniedElsewhere { leaver, by }));
        }
        if changed {
            s.push(Action::Persist);
        }
    }

    fn approve(&mut self, s: &mut Step) {
        let Some(a) = self.asked.as_mut().filter(|a| !a.approving) else {
            return;
        };
        a.approving = true;
        s.push(Action::Job(Job::Approve { leaver: a.leaver, t: a.t, consent_sig: a.consent_sig.clone(), intent: a.intent }));
        s.push(Action::Persist);
    }

    fn on_approved(&mut self, leaver: Key, result: Result<&crate::sponsor::Approved, &str>, s: &mut Step) {
        if !self.asked.as_ref().is_some_and(|a| a.leaver == leaver && a.approving) {
            return;
        }
        match result {
            Ok(outcome) => {
                self.asked = None;
                if *outcome == crate::sponsor::Approved::Released(Ok(())) {
                    s.push(Action::RecordReleased { device: leaver });
                }
                s.push(Action::RefreshChain);
                s.push(Action::Persist);
                s.push(Action::Note(Note::DepartApproved { leaver, outcome: outcome.clone() }));
            }
            Err(e) => {
                if let Some(a) = self.asked.as_mut() {
                    a.approving = false;
                }
                s.push(Action::Persist);
                s.push(Action::Note(Note::DepartApproveFailed { leaver, reason: e.to_string() }));
            }
        }
    }

    fn deny(&mut self, s: &mut Step) {
        let Some(a) = self.asked.take() else {
            return;
        };
        self.deny_here(a.leaver, a.salt, a.t);
        s.push(Action::RecordDenied { leaver: a.leaver, salt: a.salt, t: a.t });
        let build = self.take_build();
        self.denies.push(DenyOut { build, deliver: None });
        s.push(Action::Build { id: build, frame: Frame::DepartDeny { hp: self.hp, leaver: a.leaver, salt: a.salt, t: a.t } });
        s.push(Action::Persist);
        s.push(Action::Note(Note::DepartDeniedHere { leaver: a.leaver }));
    }

    /// After a restart: carry on with what the saved state holds (build our request again if it never went out, hand it again to every member that has not taken it). Tell the members first.
    pub fn resume(&mut self) -> Step {
        let mut s = Step::default();
        let targets = self.targets();
        if let Some(own) = self.own.as_mut() {
            match own.deliver.as_mut() {
                Some(d) => {
                    d.retain(&targets);
                    for k in &targets {
                        d.owe(*k);
                    }
                    d.resume(&mut s.actions);
                    s.push(Action::NfcServe(Some(own.salt)));
                }
                None => {
                    let build = self.next_build;
                    self.next_build += 1;
                    own.build = build;
                    s.push(Action::Build { id: build, frame: Frame::DepartReq { hp: self.hp, t: own.t, intent: own.intent, salt: own.salt } });
                }
            }
        }
        if let Some(a) = self.asked.as_mut() {
            // An approval cut short by the restart is offered again; the person presses Approve once more.
            a.approving = false;
            let leaver = a.leaver;
            s.push(Action::Note(Note::DepartAsked { leaver }));
        }
        s
    }

    /// The state to keep in the vault: our request (with its signed frame once built), the request asked about, and the denied list.
    pub fn to_section(&self) -> VsfSection {
        let mut sec = VsfSection::new("depart");
        sec.add_field("hp", VsfType::hP(self.hp.to_vec()));
        sec.add_field("me", VsfType::ke(self.me.to_vec()));
        if let Some(o) = self.own.as_ref() {
            sec.add_field("own_t", VsfType::e(EtType::e6(o.t)));
            sec.add_field("own_salt", VsfType::hb(o.salt.to_vec()));
            sec.add_field("own_intent", VsfType::u(o.intent as usize, false));
            if let Some(d) = o.deliver.as_ref() {
                sec.add_field("own_frame", VsfType::v(b'r', d.frame().to_vec()));
            }
        }
        if let Some(a) = self.asked.as_ref() {
            sec.add_field("asked_leaver", VsfType::ke(a.leaver.to_vec()));
            sec.add_field("asked_t", VsfType::e(EtType::e6(a.t)));
            sec.add_field("asked_sig", VsfType::ge(a.consent_sig.clone()));
            sec.add_field("asked_intent", VsfType::u(a.intent as usize, false));
            sec.add_field("asked_salt", VsfType::hb(a.salt.to_vec()));
        }
        if !self.denied.is_empty() {
            let mut values = Vec::with_capacity(self.denied.len() * 3);
            for (l, salt, t) in &self.denied {
                values.push(VsfType::ke(l.to_vec()));
                values.push(VsfType::hb(salt.to_vec()));
                values.push(VsfType::e(EtType::e6(*t)));
            }
            sec.add_field_multi("denied", values);
        }
        sec
    }

    /// Read the state back. Members are not kept: tell them, then call [`Depart::resume`].
    pub fn from_section(sec: &VsfSection) -> Result<Self, String> {
        if sec.name != "depart" {
            return Err("not a depart section".to_string());
        }
        let first = |name: &str| sec.get_field(name).and_then(|f| f.values.first());
        let key = |name: &str| -> Option<Key> {
            first(name).and_then(|v| match v {
                VsfType::ke(b) | VsfType::hP(b) | VsfType::hb(b) if b.len() == 32 => b.as_slice().try_into().ok(),
                _ => None,
            })
        };
        let small = |name: &str| first(name).and_then(|v| v.as_u64()).and_then(|n| u8::try_from(n).ok());
        let hp = key("hp").ok_or("depart state missing hp")?;
        let me = key("me").ok_or("depart state missing me")?;
        let mut m = Depart::new(hp, me);
        if let (Some(t), Some(salt), Some(intent)) = (sec.eagle("own_t"), key("own_salt"), small("own_intent")) {
            let deliver = first("own_frame").and_then(|v| match v {
                VsfType::v(b'r', b) => Some(Deliver::new(b.clone(), &[], &mut Vec::new())),
                _ => None,
            });
            m.own = Some(Own { t, salt, intent, build: 0, deliver });
            m.next_build = 1;
        }
        if let (Some(leaver), Some(t), Some(salt), Some(intent)) = (key("asked_leaver"), sec.eagle("asked_t"), key("asked_salt"), small("asked_intent")) {
            let consent_sig = first("asked_sig")
                .and_then(|v| match v {
                    VsfType::ge(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or("depart state: an asked request without its consent")?;
            m.asked = Some(Asked { leaver, t, consent_sig, intent, salt, approving: false });
        }
        // The denied list by type marker: a ke opens an entry, the hb after it is its salt, the stamp closes it.
        if let Some(f) = sec.get_field("denied") {
            let (mut leaver, mut salt): (Option<Key>, Option<[u8; 32]>) = (None, None);
            for v in &f.values {
                match v {
                    VsfType::ke(b) => {
                        leaver = b.as_slice().try_into().ok();
                        salt = None;
                    }
                    VsfType::hb(b) => salt = b.as_slice().try_into().ok(),
                    VsfType::e(EtType::e6(t)) => {
                        if let (Some(l), Some(sl)) = (leaver.take(), salt.take()) {
                            m.denied.push((l, sl, *t));
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(m)
    }
}
