//! Adding a device, the sponsor's side (photon docs/lifecycle.md, docs/pairing-v2.md), written once for every app.
//! The Fleet page shown opens the flow; candidates come from binding requests heard on the LAN, BLE beacons, and fgtw.org's registry when the person asks for it.
//! An NFC tap or the newcomer's typed words add at once; a touch on a row only picks it, and Yes adds it.
//! The add binds, hands the chain to the fleet, grows the fan-out to the live members (never a locked one) and hands the grown key out, while the screen is already back on the Fleet page.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vsf::file_format::VsfSection;
use vsf::VsfType;

use super::deliver::Deliver;
use super::{Action, Event, Frame, Job, Key, Note, Step, UserOp, Wake};
use crate::fleet::{BindRequest, BINDREQ_FRESH_OSC};
use crate::pair::BEACON_UUID_LEN;
use crate::sponsor::{self, Candidate, WordMatch};

/// How long a device counts as nearby after its last BLE beacon or LAN beacon (ferros counts 32 s).
pub const NEARBY_OSC: i64 = (1 << 5) * vsf::OSCILLATIONS_PER_SECOND as i64;

/// Where the add screen stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Closed,
    Open,
    Selected,
    Binding,
    Growing,
}

/// One row of the add screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub device: Key,
    pub name: String,
    pub ble: bool,
    pub lan: bool,
    /// Offered as a pick now (nearby, and over Bluetooth only while the add is contended).
    pub pickable: bool,
    /// fgtw.org says it belongs to another fleet.
    pub owned_elsewhere: bool,
}

/// Where the words typed so far stand, by device key (the candidate indexes stay inside the machine).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WordState {
    /// No device to match against yet; the first bad word, if the spell-check found one.
    NoCandidates { typo: Option<String> },
    /// Nothing typed; how many devices are asking.
    Nothing { asking: usize },
    /// The words left every device at this word.
    NoMatch(String),
    /// Still matching exactly this device.
    One(Key),
    /// Still matching this many.
    Many(usize),
}

/// What the add screen shows: the app turns it into its own page.
#[derive(Clone, Debug, PartialEq)]
pub struct View {
    pub phase: Phase,
    pub rows: Vec<Row>,
    /// The picked device: its name and its masked words, to compare with its own screen.
    pub selected: Option<(Key, String, String)>,
    /// Where the words typed so far stand.
    pub words: Option<WordState>,
    /// The device being added (Binding or Growing): its key and name.
    pub adding: Option<(Key, String)>,
    pub contended: bool,
    /// fgtw.org's requests are being read.
    pub listing: bool,
    /// The last add: the device, and whether it went in.
    pub last: Option<(Key, bool)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step2 {
    Binding,
    Growing,
    /// The grown fan-out is being signed (build id).
    Handing(u32),
}

#[derive(Clone, Debug)]
struct Adding {
    device: Key,
    /// The request, while it is in hand (a restart keeps only the device key).
    req: Option<BindRequest>,
    step: Step2,
}

/// One device's add flow.
#[derive(Clone, Debug)]
pub struct Add {
    hp: Key,
    /// The identity seed: device names and words come from it. Never saved.
    seed: [u8; 32],
    me: Key,
    members: Vec<Key>,
    locked: Vec<Key>,
    known: bool,
    key_held: bool,
    locked_plates: Vec<[u8; 32]>,
    /// The Fleet page is showing (the flow may still be shut by the fleet-key gate).
    shown: bool,
    open: bool,
    lan: Vec<BindRequest>,
    registry: Vec<BindRequest>,
    owned_elsewhere: Vec<Key>,
    heard_ble: Vec<([u8; BEACON_UUID_LEN], i64)>,
    heard_lan: Vec<(Key, i64)>,
    cands: Vec<Candidate>,
    /// More than one device asked at once: only Bluetooth or NFC can add until an add finishes (P3).
    contended: bool,
    listing: bool,
    words: Option<WordState>,
    /// The words stopped matching and fgtw.org was asked once; asked again only after they match something in between.
    nomatch_asked: bool,
    /// The words typed so far, matched again whenever the candidates change (a device that answers after the last keystroke still lands). Never saved.
    typed: String,
    /// The person asked to look farther on this page (the button, or words that matched nothing): a list-may-have-changed hint reads again.
    looked: bool,
    /// resume() came before the members: it runs when they arrive.
    resume_pending: bool,
    selected: Option<Key>,
    select_build: Option<u32>,
    adding: Option<Adding>,
    /// The grown fan-out on its way to the newcomer and the members.
    handing: Option<Deliver>,
    last: Option<(Key, bool)>,
    next_build: u32,
    reports_sent: bool,
}

impl Add {
    /// A fresh add flow for device `me` of the fleet `hp`. Tell it the members and whether it holds the fleet key before anything else.
    pub fn new(hp: Key, seed: [u8; 32], me: Key, reports_sent: bool) -> Self {
        Add {
            hp,
            seed,
            me,
            members: Vec::new(),
            locked: Vec::new(),
            known: false,
            key_held: false,
            locked_plates: Vec::new(),
            shown: false,
            open: false,
            lan: Vec::new(),
            registry: Vec::new(),
            owned_elsewhere: Vec::new(),
            heard_ble: Vec::new(),
            heard_lan: Vec::new(),
            cands: Vec::new(),
            contended: false,
            listing: false,
            words: None,
            nomatch_asked: false,
            typed: String::new(),
            looked: false,
            resume_pending: false,
            selected: None,
            select_build: None,
            adding: None,
            handing: None,
            last: None,
            next_build: 0,
            reports_sent,
        }
    }

    fn take_build(&mut self) -> u32 {
        let id = self.next_build;
        self.next_build += 1;
        id
    }

    /// This device may add: it is a member and holds the fleet key (owner rule: no key, nothing written).
    fn can_add(&self) -> bool {
        self.known && self.key_held && self.members.contains(&self.me)
    }

    fn live_others(&self) -> Vec<Key> {
        self.members.iter().filter(|k| **k != self.me && !self.locked.contains(k)).copied().collect()
    }

    fn plate_locked(&self, req: &BindRequest) -> bool {
        req.plate.is_some_and(|p| self.locked_plates.contains(&p))
    }

    /// Rebuild the candidates from what is held and heard now; requests and nearby marks lapse by time.
    fn rebuild(&mut self, now: i64) {
        sponsor::retain_fresh(&mut self.lan, now);
        sponsor::retain_fresh(&mut self.registry, now);
        self.heard_ble.retain(|(_, at)| now - at <= NEARBY_OSC);
        self.heard_lan.retain(|(_, at)| now - at <= NEARBY_OSC);
        let reqs: Vec<BindRequest> = sponsor::merge_requests(&self.registry, &self.lan).into_iter().filter(|r| !self.members.contains(&r.device_pubkey)).collect();
        let ble: Vec<[u8; BEACON_UUID_LEN]> = self.heard_ble.iter().map(|(id, _)| *id).collect();
        let lan: Vec<Key> = self.heard_lan.iter().map(|(k, _)| *k).collect();
        self.cands = sponsor::candidates(reqs, &self.seed, &self.hp, &ble, &lan);
        if sponsor::contended(&self.cands) {
            self.contended = true;
        }
        if self.selected.is_some_and(|d| !self.cands.iter().any(|c| c.req.device_pubkey == d)) {
            self.selected = None;
        }
    }

    /// The next moment something lapses on its own, while the screen is open.
    fn next_lapse(&self) -> Option<(i64, Wake)> {
        if !self.open {
            return None;
        }
        let reqs = self.lan.iter().chain(self.registry.iter()).map(|r| r.t + BINDREQ_FRESH_OSC);
        let near = self.heard_ble.iter().map(|(_, at)| at + NEARBY_OSC).chain(self.heard_lan.iter().map(|(_, at)| at + NEARBY_OSC));
        reqs.chain(near).min().map(|t| (t, Wake::Lapse))
    }

    fn radios(&self) -> Action {
        Action::Radios { ble_scan: self.open, nfc_reader: self.open }
    }

    /// One event. `now` is Eagle time in oscillations.
    pub fn step(&mut self, ev: Event, now: i64) -> Step {
        let mut s = Step::default();
        match ev {
            Event::Members { members, locked } => {
                self.members = members.to_vec();
                self.locked = locked.to_vec();
                self.known = true;
                self.rebuild(now);
                // A resume that came before the fold runs now: a grow needs the members it names.
                if self.resume_pending {
                    self.resume_pending = false;
                    let r = self.resume();
                    s.actions.extend(r.actions);
                }
                // The fold can be what makes this device able to add: re-check the gate while the page shows.
                if self.shown && !self.open && self.can_add() {
                    self.page(true, now, &mut s);
                }
                self.rematch(false, &mut s);
            }
            Event::FleetKey { held } => {
                self.key_held = held;
                // A key that arrives while the page shows (a fan-out after this device's own join) opens the flow at once, no close and reopen.
                if self.shown && !self.open && self.can_add() {
                    self.page(true, now, &mut s);
                }
            }
            Event::LockedPlates { plates } => self.locked_plates = plates.to_vec(),
            Event::Page { shown } => self.page(shown, now, &mut s),
            Event::Frame { bytes, from } => self.on_frame(bytes, from, now, &mut s),
            Event::BeaconHeard { id } => {
                match self.heard_ble.iter_mut().find(|(h, _)| *h == id) {
                    Some((_, at)) => *at = now,
                    None => self.heard_ble.push((id, now)),
                }
                self.rebuild(now);
                self.rematch(false, &mut s);
            }
            Event::LanHeard { device } => {
                match self.heard_lan.iter_mut().find(|(k, _)| *k == device) {
                    Some((_, at)) => *at = now,
                    None => self.heard_lan.push((device, now)),
                }
                self.rebuild(now);
                self.rematch(false, &mut s);
            }
            Event::Wake { reason: Wake::Lapse } => {
                self.rebuild(now);
                self.rematch(false, &mut s);
            }
            Event::ListMayHaveChanged => {
                if self.looked {
                    self.list(&mut s);
                }
            }
            Event::ListFailed { reason } => {
                self.listing = false;
                s.push(Action::Note(Note::ListFailed { reason: reason.to_string() }));
            }
            Event::Listed { reqs, owned_elsewhere } => {
                self.listing = false;
                self.registry = reqs.to_vec();
                self.owned_elsewhere = owned_elsewhere.to_vec();
                self.rebuild(now);
                self.rematch(false, &mut s);
            }
            Event::Words { text } => {
                self.typed = text.to_string();
                self.rematch(true, &mut s);
            }
            Event::NfcRead { secret } => {
                // Physical proximity is the confirmation: an NFC match adds at once, contended or not.
                if self.open {
                    if let Some(i) = sponsor::nfc_match(&secret, &self.cands) {
                        let req = self.cands[i].req.clone();
                        self.add(req, &mut s);
                    }
                }
            }
            Event::User(op) => match op {
                UserOp::Touch { device } => self.pick(device, &mut s),
                UserOp::Yes => {
                    if let Some(req) = self.selected.and_then(|d| self.cands.iter().find(|c| c.req.device_pubkey == d)).map(|c| c.req.clone()) {
                        self.add(req, &mut s);
                    }
                }
                UserOp::No => {
                    self.selected = None;
                    self.select_build = None;
                }
                UserOp::LookFarther => {
                    self.looked = true;
                    self.list(&mut s);
                }
                _ => {}
            },
            Event::Built { id, result } => self.on_built(id, result, &mut s),
            Event::Sent { to, ok } => {
                if let Some(d) = self.handing.as_mut() {
                    d.on_sent(to, ok);
                }
                if !ok && self.selected == Some(to) && self.select_build.is_none() {
                    s.push(Action::Note(Note::PickUnreachable { device: to }));
                }
            }
            Event::Reachable { from } => {
                if let Some(d) = self.handing.as_mut() {
                    d.on_reachable(from, &mut s.actions);
                }
            }
            Event::LinkUp => {
                if let Some(d) = self.handing.as_mut() {
                    d.on_link_up(&mut s.actions);
                }
            }
            Event::Bound { device, result } => self.on_bound(device, result, &mut s),
            Event::Grown { device, result } => self.on_grown(device, result, &mut s),
            _ => {}
        }
        s.wake = self.next_lapse();
        s
    }

    fn page(&mut self, shown: bool, now: i64, s: &mut Step) {
        self.shown = shown;
        if shown {
            if !self.can_add() {
                // The fleet-key gate (owner rule): the flow does not open and nothing is written.
                self.open = false;
                s.push(self.radios());
                s.push(Action::Note(Note::AddNoFleetKey));
                return;
            }
            self.open = true;
            self.last = None;
            self.rebuild(now);
        } else {
            self.open = false;
            self.selected = None;
            self.select_build = None;
            self.words = None;
            self.typed.clear();
            self.looked = false;
        }
        s.push(self.radios());
    }

    fn on_frame(&mut self, bytes: &[u8], from: Option<core::net::SocketAddr>, now: i64, s: &mut Step) {
        let Ok((hp, req, sender)) = crate::protocol::parse_bind_req(bytes) else { return };
        if hp != self.hp || sender != req.device_pubkey {
            return;
        }
        if sponsor::check_lan_request(&req, &self.hp, &self.seed, now).is_err() {
            return;
        }
        let device = req.device_pubkey;
        if let Some(addr) = from {
            s.push(Action::Seen { device, addr });
        }
        match self.heard_lan.iter_mut().find(|(k, _)| *k == device) {
            Some((_, at)) => *at = now,
            None => self.heard_lan.push((device, now)),
        }
        let offered = sponsor::offer_lan(&mut self.lan, req);
        self.rebuild(now);
        self.rematch(false, s);
        // Join notices are LAN only (owner): a device on this network asking while the page is closed is announced once.
        if offered == sponsor::Offered::New && !self.open && !self.members.contains(&device) {
            s.push(Action::Note(Note::AsksToJoin { device }));
        }
    }

    fn list(&mut self, s: &mut Step) {
        if self.open && !self.listing {
            self.listing = true;
            s.push(Action::Job(Job::ListRequests));
        }
    }

    /// Match the words typed so far against the candidates as they are now. `may_list`: this is the person's keystroke, so words that stop matching may read fgtw.org (a candidate change never does).
    fn rematch(&mut self, may_list: bool, s: &mut Step) {
        if !self.open || self.typed.is_empty() || self.adding.is_some() {
            return;
        }
        let text = self.typed.clone();
        // While contended the network path is shut for words too: only a device heard over Bluetooth can be added by its words.
        let pool: Vec<Candidate> = if self.contended { self.cands.iter().filter(|c| c.heard_ble).cloned().collect() } else { self.cands.clone() };
        let state = match sponsor::match_words(&text, &pool) {
            WordMatch::Full(i) => {
                let req = pool[i].req.clone();
                self.words = None;
                self.typed.clear();
                self.add(req, s);
                return;
            }
            WordMatch::NoMatch(w) => WordState::NoMatch(w),
            WordMatch::NoCandidates { typo } => WordState::NoCandidates { typo },
            WordMatch::Nothing { asking } => WordState::Nothing { asking },
            WordMatch::One(i) => WordState::One(pool[i].req.device_pubkey),
            WordMatch::Many(k) => WordState::Many(k),
        };
        match state {
            // Words that match no device may belong to one only fgtw.org has heard: read its requests once when they stop matching, again only after they matched something in between (the person's edge, not every keystroke).
            WordState::NoMatch(_) | WordState::NoCandidates { .. } => {
                if may_list && !self.nomatch_asked {
                    self.nomatch_asked = true;
                    self.looked = true;
                    self.list(s);
                }
            }
            WordState::One(_) | WordState::Many(_) => self.nomatch_asked = false,
            WordState::Nothing { .. } => {}
        }
        self.words = Some(state);
    }

    fn pick(&mut self, device: Key, s: &mut Step) {
        if !self.open {
            return;
        }
        if self.adding.is_some() {
            s.push(Action::Note(Note::AddBusy));
            return;
        }
        let contended = self.contended;
        let Some(cand) = self.cands.iter().find(|c| c.req.device_pubkey == device && c.pickable(contended)) else { return };
        if self.owned_elsewhere.contains(&device) {
            s.push(Action::Note(Note::AddOwnedElsewhere { device }));
            return;
        }
        if self.plate_locked(&cand.req) {
            s.push(Action::Note(Note::AddLockedOut { device }));
            return;
        }
        // A pick, not an add: the device gets our chain (to check the select against) and a signed bind_select, and turns green; nothing is bound until Yes.
        self.selected = Some(device);
        self.words = None;
        let id = self.take_build();
        self.select_build = Some(id);
        s.push(Action::PushChain { to: device });
        s.push(Action::Build { id, frame: Frame::BindSelect { hp: self.hp, joiner: device } });
        s.push(Action::Note(Note::Picked { device }));
    }

    fn add(&mut self, req: BindRequest, s: &mut Step) {
        let device = req.device_pubkey;
        if !self.can_add() {
            s.push(Action::Note(Note::AddNoFleetKey));
            return;
        }
        if self.adding.is_some() {
            s.push(Action::Note(Note::AddBusy));
            return;
        }
        if self.owned_elsewhere.contains(&device) {
            s.push(Action::Note(Note::AddOwnedElsewhere { device }));
            return;
        }
        if self.plate_locked(&req) {
            s.push(Action::Note(Note::AddLockedOut { device }));
            return;
        }
        self.adding = Some(Adding { device, req: Some(req.clone()), step: Step2::Binding });
        self.selected = None;
        self.select_build = None;
        self.words = None;
        s.push(Action::Job(Job::Bind { req }));
        s.push(Action::Persist);
        s.push(Action::Note(Note::Adding { device }));
    }

    fn on_built(&mut self, id: u32, result: Result<&[u8], &str>, s: &mut Step) {
        if self.select_build == Some(id) {
            self.select_build = None;
            if let (Some(device), Ok(frame)) = (self.selected, result) {
                s.push(Action::Send { to: super::To::Device(device), frame: frame.to_vec() });
            }
            return;
        }
        let Some(a) = self.adding.as_ref().filter(|a| a.step == Step2::Handing(id)) else { return };
        let device = a.device;
        match result {
            Ok(frame) => {
                let mut targets = self.live_others();
                if !targets.contains(&device) {
                    targets.push(device);
                }
                self.handing = Some(Deliver::new(frame.to_vec(), &targets, self.reports_sent, &mut s.actions));
                self.finish(device, None, s);
            }
            Err(e) => self.finish(device, Some(e.to_string()), s),
        }
    }

    fn on_bound(&mut self, device: Key, result: Result<(), &str>, s: &mut Step) {
        if !self.adding.as_ref().is_some_and(|a| a.device == device && a.step == Step2::Binding) {
            return;
        }
        match result {
            Ok(()) => {
                // The extended chain to every device of ours, every contact, and the newcomer: their folds take it in before it ever speaks to them.
                s.push(Action::ChainNews { extra: Some(device) });
                self.grow(device, s);
            }
            Err(e) => self.finish(device, Some(e.to_string()), s),
        }
    }

    /// Grow the fan-out to the live members and the newcomer: a locked device never gets the key.
    fn grow(&mut self, device: Key, s: &mut Step) {
        let mut members: Vec<Key> = self.members.iter().filter(|k| !self.locked.contains(k)).copied().collect();
        if !members.contains(&device) {
            members.push(device);
        }
        if let Some(a) = self.adding.as_mut() {
            a.step = Step2::Growing;
            a.req = None;
        }
        s.push(Action::Job(Job::Grow { device, members }));
        s.push(Action::Persist);
    }

    fn on_grown(&mut self, device: Key, result: Result<&[u8], &str>, s: &mut Step) {
        if !self.adding.as_ref().is_some_and(|a| a.device == device && a.step == Step2::Growing) {
            return;
        }
        match result {
            Ok(blob) => {
                let id = self.take_build();
                if let Some(a) = self.adding.as_mut() {
                    a.step = Step2::Handing(id);
                }
                s.push(Action::Build { id, frame: Frame::FanoutResp { hp: self.hp, blob: blob.to_vec() } });
            }
            Err(e) => self.finish(device, Some(e.to_string()), s),
        }
    }

    /// The add ended: in (`failure` None) or stopped.
    fn finish(&mut self, device: Key, failure: Option<String>, s: &mut Step) {
        self.adding = None;
        self.last = Some((device, failure.is_none()));
        s.push(Action::Persist);
        match failure {
            None => {
                // The add a contention shut has finished; the next one starts open again (P3).
                self.contended = false;
                self.lan.retain(|r| r.device_pubkey != device);
                self.registry.retain(|r| r.device_pubkey != device);
                self.cands.retain(|c| c.req.device_pubkey != device);
                s.push(Action::Note(Note::Added { device }));
            }
            Some(reason) => s.push(Action::Note(Note::AddFailed { device, reason })),
        }
    }

    /// The screen as it stands, for the app's page.
    pub fn view(&self) -> View {
        let phase = match (&self.adding, self.selected, self.open) {
            (Some(a), _, _) if a.step == Step2::Binding => Phase::Binding,
            (Some(_), _, _) => Phase::Growing,
            (None, Some(_), true) => Phase::Selected,
            (None, None, true) => Phase::Open,
            _ => Phase::Closed,
        };
        let rows = self
            .cands
            .iter()
            .map(|c| Row {
                device: c.req.device_pubkey,
                name: c.name.clone(),
                ble: c.heard_ble,
                lan: c.heard_lan,
                pickable: c.pickable(self.contended),
                owned_elsewhere: self.owned_elsewhere.contains(&c.req.device_pubkey),
            })
            .collect();
        let selected = self.selected.and_then(|d| self.cands.iter().find(|c| c.req.device_pubkey == d)).map(|c| (c.req.device_pubkey, c.name.clone(), crate::pair::masked_device_words(&c.req.device_pubkey, &self.seed)));
        let adding = self.adding.as_ref().map(|a| (a.device, crate::pair::device_name_default(&a.device, &self.seed)));
        View { phase, rows, selected, words: self.words.clone(), adding, contended: self.contended, listing: self.listing, last: self.last }
    }

    /// After a restart: carry on with an add the saved state holds. A grow is asked for again; a bind cut short goes on to its grow when the fold already lists the newcomer, and is reported to do again when it does not (the request itself is not saved). Tell the members first.
    pub fn resume(&mut self) -> Step {
        let mut s = Step::default();
        if !self.known {
            self.resume_pending = true;
            return s;
        }
        let Some(a) = self.adding.clone() else { return s };
        match a.step {
            Step2::Binding if a.req.is_none() => {
                if self.known && self.members.contains(&a.device) {
                    self.grow(a.device, &mut s);
                } else {
                    self.finish(a.device, Some("the app stopped before the bind finished: add it again".to_string()), &mut s);
                }
            }
            Step2::Binding => {}
            Step2::Growing | Step2::Handing(_) => self.grow(a.device, &mut s),
        }
        s
    }

    /// The state to keep in the vault: only an add under way (the newcomer and how far it got). No root goes in it; the app hands the handle proof and the seed back.
    pub fn to_section(&self) -> VsfSection {
        let mut sec = VsfSection::new("add");
        sec.add_field("me", VsfType::ke(self.me.to_vec()));
        if let Some(a) = self.adding.as_ref() {
            sec.add_field("adding", VsfType::ke(a.device.to_vec()));
            let grown = !matches!(a.step, Step2::Binding);
            sec.add_field("adding_step", VsfType::u(grown as usize, false));
        }
        sec
    }

    /// The state as a complete VSF document stamped `time`.
    pub fn to_vsf(&self, time: i64) -> Result<Vec<u8>, String> {
        vsf::VsfBuilder::new()
            .creation_time_oscillations(time)
            .add_section_direct(self.to_section())
            .build()
            .map_err(|e| alloc::format!("add state: {e}"))
    }

    /// Read a document [`Add::to_vsf`] wrote. Tell the members, then call [`Add::resume`].
    pub fn from_vsf(bytes: &[u8], hp: Key, seed: [u8; 32], me: Key, reports_sent: bool) -> Result<Self, String> {
        let (header, end) = vsf::verification::read_verified(bytes, None).map_err(|e| alloc::format!("add state: {e}"))?;
        let sec = header.primary_section(bytes, end).map_err(|e| alloc::format!("add state: {e}"))?;
        Self::from_section(&sec, hp, seed, me, reports_sent)
    }

    /// Read the state back from its section. `me` is this device's key as the app holds it now: state saved under another key (a vault carried to a new device key) belongs to that device, and the machine starts fresh.
    pub fn from_section(sec: &VsfSection, hp: Key, seed: [u8; 32], me: Key, reports_sent: bool) -> Result<Self, String> {
        if sec.name != "add" {
            return Err("not an add section".to_string());
        }
        let key = |name: &str| -> Option<Key> {
            sec.get_field(name).and_then(|f| f.values.first()).and_then(|v| match v {
                VsfType::ke(b) if b.len() == 32 => b.as_slice().try_into().ok(),
                _ => None,
            })
        };
        let saved_me = key("me").ok_or("add state missing me")?;
        let mut m = Add::new(hp, seed, me, reports_sent);
        if saved_me != me {
            return Ok(m);
        }
        if let Some(device) = key("adding") {
            let grown = sec.get_field("adding_step").and_then(|f| f.values.first()).and_then(|v| v.as_u64()) == Some(1);
            m.adding = Some(Adding { device, req: None, step: if grown { Step2::Growing } else { Step2::Binding } });
        }
        Ok(m)
    }
}
