//! The Security page, written once for every TOKEN app (owner, 2026-11-24: "I'd like to get it synchronized in the FGTW crate so ferros and Photon render the same. So yes please, build the lock, revoke, shred, all that stuff needs to work on both.").
//!
//! The actions are photon docs/settings-panel.md's "Security", named by how much each destroys, and the owner's words for leaving (2026-11-24: "not retire, unbind/bind, shit like that. retire means never again which is wrong."):
//! - **lock**: the identity's keys in RAM forgotten, the sealed data kept; attesting again opens it. Tightening only, so no confirmation.
//! - **revoke** a device of the fleet, remotely (lost, stolen, sold, maybe offline): the chain's Lock op, the worker's refusal that survives a wipe, and a fresh fleet key wrapped to every device but it (photon docs/device-lifecycle.md 3: rotate on remove is not optional). From then on it cannot announce, write, or open anything sealed after. **reinstate** undoes it. Revoke, not "unbind remotely": an unbound device may be bound again by anyone, a revoked one is barred until its fleet reinstates it.
//! - **shred**: a crypto-shred of this device's copy of the identity: its keys destroyed, then its data deleted. The device stays in the fleet (the chain still lists it, the fan-out still wraps to it), so attesting again here with the same handle fetches everything back from the fleet: "wipe and refetch from my fleet".
//! - **unbind this device**: it leaves the fleet (the departure, `flow::depart`) and its data here is erased; anyone may bind it again.
//! - **wipe** before attest: not offered (owner, 2026-11-24: "if you cannot attest, there's ZERO reason my shit should get wiped"). Before attest the page has no row; `Act::Wipe` and its words stay only until every app has dropped them.
//!
//! **Destroying is a key operation** (owner, 2026-11-24, on unbind's bulk erase: "whoever's dumbfuck idea to add more writes to an SSD that has a fixed number of writes is beyond me but it's dead wrong. Sand on a beach my friend."): what is sealed is made unreadable by destroying its keys (wiped from memory) and renewing the device-only secret every key here is made from, one small write; nothing is deleted or overwritten, and the store's own rotation reclaims the room when it needs it.
//!
//! **Nothing is destroyed without the person** (owner, 2026-11-24: "if it does not get my consent from my other devices or a correct handle entry, nothing gets wiped. Lock is fine, but no wipe and certainly no unbind."; and on shred: "if you cannot attest, there's ZERO reason my shit should get wiped and pretty sure we discussed, that's mostly key management formalities and proper lifecycle/design."):
//! - shred takes a correct attest (the handle, the identity confirmation) and destroys only this device's keys; the device stays in its fleet;
//! - unbinding takes a correct attest and the fleet's consent: [`UNBIND`], in order;
//! - a wrong handle, no consent, a deny, no device reachable or a power cut at any step changes nothing: the device stays bound and its keys and secret stay; at most it locks.
//!
//! What is here: the actions, the rows each app draws and their order ([`rows`]), when each is enabled and why not, the confirmation each needs ([`Confirm`]), the page's own state across presses ([`Page`]), the words ([`crate::text::Msg`]'s `Sec*`), and the chain work of a revoke and a reinstatement ([`revoke`], [`reinstate`], [`rotate`]).
//! What stays each app's: the drawing (a [`Tone`] names the colour's meaning, the app picks the colour), how an identity confirmation is collected (ferros: the approve on the attest screen, the device locking at once; Photon: the handle typed, its memory-hard proof matched), and the storage behind lock, shred and wipe (ferros: the kernel's lock and release and the vault process's drops; Photon: kete's vault and the session clear).
//! A host may draw rows of its own after these (ferros: attest at boot; Photon: kill, the shell); the shared rows come first and in this order on both.
//!
//! no_std, no I/O in the page: the chain work is behind `protocol` and runs over the app's transport, off any screen.

use crate::text::Msg;
use alloc::vec::Vec;

/// A device key (Ed25519 public key).
pub type Key = [u8; 32];

/// What a row does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Act {
    /// Forget the identity's keys in RAM, keep the sealed data.
    Lock,
    /// Revoke this device of the fleet.
    Revoke(Key),
    /// Undo a revoke of this device of the fleet.
    Reinstate(Key),
    /// Crypto-shred this device's copy of the identity; it stays in the fleet.
    Shred,
    /// This device leaves the fleet, its data erased.
    Unbind,
    /// Before attest: not offered (owner, 2026-11-24: nothing is destroyed without an attest); kept until every app has dropped it.
    Wipe,
}

/// The confirmation an act needs before the app carries it out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirm {
    /// None: it only tightens (a lock).
    None,
    /// Two presses of the same row, the first arming it: before attest, where no identity is here to prove (the wipe).
    Arm,
    /// The person proves they are the identity: on ferros the approve on the attest screen (the device locks at once and the handle typed there, or a kept tag, applies exactly this act); in Photon the handle typed, its memory-hard proof matched.
    Identity,
}

impl Act {
    /// The confirmation this act needs. Every act that destroys or bars something of the person's is an identity confirmation (owner, 2026-11-24: protective changes are approved on the attest screen, never by a tap a child could make); the wipe has no identity to prove, so two presses.
    pub const fn confirm(self) -> Confirm {
        match self {
            Act::Lock => Confirm::None,
            Act::Wipe => Confirm::Arm,
            Act::Revoke(_) | Act::Reinstate(_) | Act::Shred | Act::Unbind => Confirm::Identity,
        }
    }

    /// The device a revoke or a reinstatement names.
    pub const fn device(self) -> Option<Key> {
        match self {
            Act::Revoke(k) | Act::Reinstate(k) => Some(k),
            _ => None,
        }
    }
}

/// What a row's colour means; the app maps it to its palette (Photon: green, yellow, orange, red).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Nothing is lost (a lock, a reinstatement).
    Calm,
    /// Another device is barred (a revoke).
    Caution,
    /// Data on this device is destroyed (shred, wipe).
    Warn,
    /// This device leaves its identity (unbind).
    Danger,
}

/// Another member of the fleet, as the page shows it. Its name is the app's to look up (`pair::device_name_default`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Other {
    pub key: Key,
    /// The chain has it locked out (revoked).
    pub revoked: bool,
}

/// What the app knows of this device and its identity as the page is drawn.
#[derive(Clone, Copy, Debug)]
pub struct Facts<'a> {
    /// A person attested here: the identity's roots are in hand. Without one only the wipe is offered.
    pub present: bool,
    /// This device folds as an unlocked member of the identity's chain.
    pub member: bool,
    /// This device holds the fleet key (a revoke mints the next one, a reinstatement grows the fan-out with it).
    pub fleet_key: bool,
    /// This device's departure is under way (asked, or confirmed and held).
    pub leaving: bool,
    /// The fleet's other members (every member but this device), in the chain's order.
    pub others: &'a [Other],
}

impl Facts<'_> {
    /// The other members not revoked.
    pub fn live_others(&self) -> usize {
        self.others.iter().filter(|o| !o.revoked).count()
    }
}

/// One row of the page, as both apps draw it: a line above it (the device a revoke names), the button, and under it what it does (or, disabled, why not) and a warning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub act: Act,
    /// Disabled rows are drawn and take no press.
    pub enabled: bool,
    pub tone: Tone,
    /// Words drawn before the row, once for a group (the first device row: what a revoke is).
    pub lead: Option<Msg<'static>>,
    /// Under the button: what it does, or, disabled, why not.
    pub note: Option<Msg<'static>>,
    /// Under the note, in the warning's colour.
    pub warn: Option<Msg<'static>>,
}

impl Row {
    /// The button's words; `armed` after the first press of a two-press row.
    pub const fn button(&self, armed: bool) -> Msg<'static> {
        match self.act {
            Act::Lock => Msg::SecLock,
            Act::Revoke(_) => Msg::SecRevoke,
            Act::Reinstate(_) => Msg::SecReinstate,
            Act::Shred => Msg::SecShred,
            Act::Unbind => Msg::SecUnbind,
            Act::Wipe => Msg::SecWipe { armed },
        }
    }

    /// The line above the button for a row that names a device: its name, and whether it is revoked. `name` is the app's (the two-word device name).
    pub const fn line<'a>(&self, name: &'a str) -> Option<Msg<'a>> {
        match self.act {
            Act::Revoke(_) => Some(Msg::SecDevice(name)),
            Act::Reinstate(_) => Some(Msg::SecDeviceRevoked(name)),
            _ => None,
        }
    }
}

/// One step of unbinding this device, in the owner's order (2026-11-24). Each app carries it out with its own hooks; none may skip ahead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnbindStep {
    /// The handle typed (the identity confirmation: ferros's approve on the attest screen, Photon's typed handle and its proof).
    Handle,
    /// The departure request to the fleet (`flow::depart`, `UserOp::Remove` then `Event::Unbind`), handed to every member reachable and kept until answered; the identity's last device refuses here.
    Request,
    /// A member's consent: its person approves (`UserOp::Approve`). Waited for, however long: no timer acts in its place. A deny ends it, nothing changed.
    Consent,
    /// The device signs itself out of the chain: the consented Remove carries the leaving device's own signature over its departure (its request's consent) with the approver's beside it (`sponsor::approve_departure`, the approver publishing).
    SignOut,
    /// The fleet rotates its key on the approving device ([`rotate_after_departure`]): the device that left has no wrap in the new fan-out, so it opens nothing sealed after.
    Rotate,
    /// The device that left, once the fold no longer lists it (`Action::Wipe`): its keys wiped from memory and the device-only secret renewed. Nothing deleted.
    Forget,
}

/// The unbind sequence, in order.
pub const UNBIND: [UnbindStep; 6] = [UnbindStep::Handle, UnbindStep::Request, UnbindStep::Consent, UnbindStep::SignOut, UnbindStep::Rotate, UnbindStep::Forget];

/// The words at the top of the page.
pub const fn intro(f: &Facts) -> Msg<'static> {
    if f.present {
        Msg::SecIntro
    } else {
        Msg::SecIntroWipe
    }
}

/// The page's rows, in the order both apps draw them: lock, each other device (revoke or reinstate), shred, unbind this device; before attest none (nothing is destroyed without an attest).
pub fn rows(f: &Facts) -> Vec<Row> {
    let mut v = Vec::new();
    if !f.present {
        return v;
    }
    v.push(Row { act: Act::Lock, enabled: true, tone: Tone::Calm, lead: None, note: Some(Msg::SecLockNote), warn: None });
    // A device acting on the chain must be an unlocked member, not on its way out, holding the fleet key: a revoke mints the next key and a reinstatement grows the fan-out with this one.
    let chain_ok = f.member && !f.leaving && f.fleet_key;
    let why_not = if f.leaving {
        Some(Msg::LeavingFleet)
    } else if !f.member {
        Some(Msg::NoIdentityHere)
    } else if !f.fleet_key {
        Some(Msg::NoFleetKey)
    } else {
        None
    };
    let live = f.live_others();
    for (i, o) in f.others.iter().enumerate() {
        let lead = if i == 0 { Some(Msg::SecRevokeNote) } else { None };
        if o.revoked {
            v.push(Row { act: Act::Reinstate(o.key), enabled: chain_ok, tone: Tone::Calm, lead, note: why_not, warn: None });
        } else {
            // The last other device able to reinstate: revoking it leaves this one alone (Photon's warning, `ConfirmRevoke { last_unlocker }`).
            let warn = if chain_ok && live == 1 { Some(Msg::SecRevokeLastOther) } else { None };
            v.push(Row { act: Act::Revoke(o.key), enabled: chain_ok, tone: Tone::Caution, lead, note: why_not, warn });
        }
    }
    let shred_warn = if live == 0 { Some(Msg::SecShredLast) } else { None };
    v.push(Row { act: Act::Shred, enabled: !f.leaving, tone: Tone::Warn, lead: None, note: Some(if f.leaving { Msg::LeavingFleet } else { Msg::SecShredNote }), warn: shred_warn });
    // The identity must live somewhere: the last live device cannot leave (flow::depart refuses it too).
    let unbind_ok = f.member && !f.leaving && live > 0;
    let unbind_note = if f.leaving {
        Msg::LeavingFleet
    } else if !f.member {
        Msg::NoIdentityHere
    } else if live == 0 {
        Msg::LastDevice
    } else {
        Msg::SecUnbindNote
    };
    v.push(Row { act: Act::Unbind, enabled: unbind_ok, tone: Tone::Danger, lead: None, note: Some(unbind_note), warn: None });
    v
}

/// Where an act stands on the page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The app is collecting the identity confirmation (ferros: the approve waits on the attest screen).
    Asked,
    /// The app is carrying it out.
    Running,
    /// Done.
    Done,
    /// It did not happen; nothing changed (an app that cannot say so for certain says Failed and why in its log).
    Failed,
}

/// An act and where it stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub act: Act,
    pub phase: Phase,
}

impl Status {
    /// The line the page shows for it, `name` the device a revoke or a reinstatement names. None where the app says nothing of its own (a lock is instant; an unbind speaks thru the departure's words, a shred and a wipe end in a restart).
    pub const fn msg<'a>(&self, name: &'a str) -> Option<Msg<'a>> {
        match (self.act, self.phase) {
            (Act::Revoke(_), Phase::Asked | Phase::Running) => Some(Msg::SecRevoking(name)),
            (Act::Revoke(_), Phase::Done) => Some(Msg::SecRevoked(name)),
            (Act::Revoke(_), Phase::Failed) => Some(Msg::SecRevokeFailed(name)),
            (Act::Reinstate(_), Phase::Asked | Phase::Running) => Some(Msg::SecReinstating(name)),
            (Act::Reinstate(_), Phase::Done) => Some(Msg::SecReinstated(name)),
            (Act::Reinstate(_), Phase::Failed) => Some(Msg::SecReinstateFailed(name)),
            (Act::Shred | Act::Wipe, Phase::Running) => Some(Msg::SecShredding),
            (Act::Shred | Act::Wipe, Phase::Failed) => Some(Msg::SecShredFailed),
            _ => None,
        }
    }
}

/// What the app does after a press or a confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Do {
    /// Nothing more (a row armed, a press refused); draw again.
    Nothing,
    /// Collect the identity confirmation for this act, then tell [`Page::confirmed`] (ferros: ask the kernel for the approve; Photon: ask for the handle).
    Confirm(Act),
    /// Carry this act out with the app's own hooks, then tell [`Page::finished`].
    Carry(Act),
}

/// The page's state across presses: the armed row and the act under way. Pure: no clock, no timer (an armed row stays armed until another press or the page is left).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Page {
    armed: Option<Act>,
    status: Option<Status>,
}

impl Page {
    pub const fn new() -> Page {
        Page { armed: None, status: None }
    }

    /// Whether this row is armed (its button says so).
    pub fn armed(&self, act: Act) -> bool {
        self.armed == Some(act)
    }

    /// The act under way or last ended, for its line.
    pub const fn status(&self) -> Option<Status> {
        self.status
    }

    /// A press on the row for `act`, against the rows drawn. A press on any other row disarms the armed one; a disabled row, or any press while an act is asked or running, does nothing.
    pub fn press(&mut self, rows: &[Row], act: Act) -> Do {
        let was = self.armed.take();
        let Some(row) = rows.iter().find(|r| r.act == act) else { return Do::Nothing };
        if !row.enabled || self.status.is_some_and(|s| matches!(s.phase, Phase::Asked | Phase::Running)) {
            return Do::Nothing;
        }
        match act.confirm() {
            Confirm::None => {
                self.status = Some(Status { act, phase: Phase::Running });
                Do::Carry(act)
            }
            Confirm::Arm if was == Some(act) => {
                self.status = Some(Status { act, phase: Phase::Running });
                Do::Carry(act)
            }
            Confirm::Arm => {
                self.armed = Some(act);
                Do::Nothing
            }
            Confirm::Identity => {
                self.status = Some(Status { act, phase: Phase::Asked });
                Do::Confirm(act)
            }
        }
    }

    /// The identity confirmation for `act` came back: confirmed, carry it out; refused or abandoned, nothing changed and the row is as before.
    pub fn confirmed(&mut self, act: Act, ok: bool) -> Do {
        if self.status != Some(Status { act, phase: Phase::Asked }) {
            return Do::Nothing;
        }
        if ok {
            self.status = Some(Status { act, phase: Phase::Running });
            Do::Carry(act)
        } else {
            self.status = None;
            Do::Nothing
        }
    }

    /// An act was carried out (by this page or, on ferros, by the service that took the approval), or failed.
    pub fn finished(&mut self, act: Act, ok: bool) {
        self.status = Some(Status { act, phase: if ok { Phase::Done } else { Phase::Failed } });
    }

    /// The page left: the armed row disarms and an ended act's line is said no more. An act asked or running stands.
    pub fn left(&mut self) {
        self.armed = None;
        if self.status.is_some_and(|s| matches!(s.phase, Phase::Done | Phase::Failed)) {
            self.status = None;
        }
    }
}

/// The fan-out's wrap set: every member of the fold but the locked (revoked) ones.
pub fn live(blob: &crate::fleet::MembershipBlob) -> Result<Vec<Key>, crate::fleet::FoldError> {
    let members = blob.fold()?;
    let locked = blob.locked_out()?;
    Ok(members.into_iter().filter(|m| !locked.contains(m)).collect())
}

/// What a revoke or a reinstatement needs of the chain, checked against the fold before anything is signed: `me` an unlocked member, `device` another member, revoked or not as the act wants. The same checks the fold makes of the op, said in words the app can log.
pub fn check(blob: &crate::fleet::MembershipBlob, me: &Key, act: Act) -> Result<(), &'static str> {
    let Some(device) = act.device() else { return Err("not a revoke or a reinstatement") };
    let members = blob.fold().map_err(|_| "the chain does not fold")?;
    let locked = blob.locked_out().map_err(|_| "the chain does not fold")?;
    if !members.contains(me) || locked.contains(me) {
        return Err("this device is not an unlocked member of the fleet");
    }
    if device == *me {
        return Err("a device cannot revoke itself");
    }
    if !members.contains(&device) {
        return Err("that device is not a member of the fleet");
    }
    match (act, locked.contains(&device)) {
        (Act::Revoke(_), true) => Err("that device is revoked already"),
        (Act::Reinstate(_), false) => Err("that device is not revoked"),
        _ => Ok(()),
    }
}

/// Revoke `device`: the chain's Lock op signed by this device and published (`client::lock_device_chain`: the floor drops it, it signs nothing that folds), then the worker's refusal, which survives a wipe of the device (`client::device_lock`: no announce, ever). Returns the live members after it, the next fleet key's wrap set: the app then preserves what it seals under the current key, calls [`rotate`] with them, and seals it again under the new key (the caller's atomic shrink duty, `client::mint_fleet_key`).
/// Idempotent: a device revoked already is Ok. A worker lock that did not take is an error after the chain op landed: run it again (the chain step is then a no-op).
#[cfg(feature = "protocol")]
pub fn revoke<T: crate::client::FgtwTransport>(t: &T, signer: &impl crate::pq::FleetSigner, handle_proof: &Key, device: &Key) -> Result<Vec<Key>, alloc::string::String> {
    let me = signer.keypair().public.to_bytes();
    if *device == me {
        return Err("a device cannot revoke itself".into());
    }
    crate::client::lock_device_chain(t, signer, handle_proof, device)?;
    crate::client::device_lock(t, signer, handle_proof, device)?;
    live_now(t, handle_proof)
}

/// Reinstate a revoked `device`: the chain's Unlock op (`client::unlock_device_chain`), then the worker's refusal lifted (`client::device_unlock`). Returns the live members after it: the app grows the fan-out to them with the key it holds (`client::grow_fleet_wraps`; never a mint, so nothing sealed changes key).
#[cfg(feature = "protocol")]
pub fn reinstate<T: crate::client::FgtwTransport>(t: &T, signer: &impl crate::pq::FleetSigner, handle_proof: &Key, device: &Key) -> Result<Vec<Key>, alloc::string::String> {
    crate::client::unlock_device_chain(t, signer, handle_proof, device)?;
    crate::client::device_unlock(t, signer, handle_proof, device)?;
    live_now(t, handle_proof)
}

/// The approving device's half of a departure ([`UnbindStep::Rotate`]): once the consented Remove is published, a fresh fleet key wrapped to the live members alone (the chain fetched again, so it is the fold after the Remove), as after a revoke. Returns (revision, key); the caller seals its state again under the key (Photon: the fstate slot; ferros: the identity space and the person key fact).
#[cfg(feature = "protocol")]
pub fn rotate_after_departure<T: crate::client::FgtwTransport>(t: &T, signer: &impl crate::pq::FleetSigner, handle_proof: &Key, leaver: &Key, identity_seed: &Key) -> Result<(u64, Key), alloc::string::String> {
    let live = live_now(t, handle_proof)?;
    if live.contains(leaver) {
        return Err("the device is still a member: the Remove did not land".into());
    }
    rotate(t, signer, handle_proof, &live, identity_seed)
}

/// The fresh fleet key after a revoke, wrapped to `live` alone and published (`client::mint_fleet_key`): the revoked device has no wrap, so it opens nothing sealed from now on. Returns (revision, key). The caller seals its state again under the key (Photon: the fstate slot; ferros: the identity space and the person key fact).
#[cfg(feature = "protocol")]
pub fn rotate<T: crate::client::FgtwTransport>(t: &T, signer: &impl crate::pq::FleetSigner, handle_proof: &Key, live: &[Key], identity_seed: &Key) -> Result<(u64, Key), alloc::string::String> {
    if live.is_empty() {
        return Err("no live member to wrap a fleet key to".into());
    }
    crate::client::mint_fleet_key(t, handle_proof, signer, live, identity_seed)
}

#[cfg(feature = "protocol")]
fn live_now<T: crate::client::FgtwTransport>(t: &T, handle_proof: &Key) -> Result<Vec<Key>, alloc::string::String> {
    let blob = crate::client::fetch(t, handle_proof)?.ok_or("no fleet chain")?;
    live(&blob).map_err(|e| alloc::format!("stored fleet invalid: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::{bindreq_signing_bytes, scheme, MembershipBlob};
    use crate::keys::Keypair;
    use crate::pq::FleetSigner;

    const HP: [u8; 32] = [0xab; 32];
    const SEED: [u8; 32] = [0xcd; 32];

    fn key(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }
    fn pk(k: &Keypair) -> Key {
        k.public.to_bytes()
    }
    fn add(blob: &mut MembershipBlob, by: &Keypair, d: &Keypair, t: i64) {
        let eggs = d.eggs(&bindreq_signing_bytes(&HP, &pk(d), t - 10), scheme::MASK_BASE);
        blob.add(by, pk(d), t, t - 10, eggs);
    }
    fn facts<'a>(others: &'a [Other]) -> Facts<'a> {
        Facts { present: true, member: true, fleet_key: true, leaving: false, others }
    }
    fn acts(rows: &[Row]) -> Vec<Act> {
        rows.iter().map(|r| r.act).collect()
    }

    /// Before attest the page is the wipe alone; after, lock, each other device, shred, unbind, in that order on every app.
    #[test]
    fn the_rows_and_their_order() {
        let pre = Facts { present: false, member: false, fleet_key: false, leaving: false, others: &[] };
        assert!(rows(&pre).is_empty(), "nothing is destroyed without an attest");
        assert_eq!(intro(&pre), Msg::SecIntroWipe);
        let others = [Other { key: [2; 32], revoked: false }, Other { key: [3; 32], revoked: true }];
        let r = rows(&facts(&others));
        assert_eq!(acts(&r), vec![Act::Lock, Act::Revoke([2; 32]), Act::Reinstate([3; 32]), Act::Shred, Act::Unbind]);
        assert!(r.iter().all(|r| r.enabled));
        assert_eq!(r[1].lead, Some(Msg::SecRevokeNote), "what a revoke is, once, before the first device");
        assert_eq!(r[2].lead, None);
        assert_eq!(r[1].warn, Some(Msg::SecRevokeLastOther), "the one live other device: revoking it leaves this one alone");
        assert_eq!(r[1].line("zesty otter"), Some(Msg::SecDevice("zesty otter")));
        assert_eq!(r[2].line("calm heron"), Some(Msg::SecDeviceRevoked("calm heron")));
        assert_eq!(intro(&facts(&others)), Msg::SecIntro);
    }

    /// The identity's last live device cannot unbind, and shredding it warns; a revoke needs the fleet key and says so.
    #[test]
    fn what_is_refused_and_why() {
        let none = rows(&facts(&[]));
        let unbind = none.iter().find(|r| r.act == Act::Unbind).unwrap();
        assert!(!unbind.enabled);
        assert_eq!(unbind.note, Some(Msg::LastDevice));
        assert_eq!(none.iter().find(|r| r.act == Act::Shred).unwrap().warn, Some(Msg::SecShredLast));
        let revoked_only = [Other { key: [2; 32], revoked: true }];
        assert!(!rows(&facts(&revoked_only)).iter().find(|r| r.act == Act::Unbind).unwrap().enabled, "a revoked device holds nothing up");
        let others = [Other { key: [2; 32], revoked: false }, Other { key: [4; 32], revoked: false }];
        let keyless = Facts { fleet_key: false, ..facts(&others) };
        let r = rows(&keyless);
        let rv = r.iter().find(|r| r.act == Act::Revoke([2; 32])).unwrap();
        assert!(!rv.enabled);
        assert_eq!(rv.note, Some(Msg::NoFleetKey));
        assert_eq!(rv.warn, None, "two live others: no warning");
        let leaving = rows(&Facts { leaving: true, ..facts(&others) });
        assert!(leaving.iter().filter(|r| r.act != Act::Lock).all(|r| !r.enabled), "leaving: only the lock");
    }

    /// Lock carries out at once; an identity act asks first and carries out only when confirmed; the wipe takes two presses of its own row.
    #[test]
    fn presses_and_confirmations() {
        let others = [Other { key: [2; 32], revoked: false }, Other { key: [4; 32], revoked: false }];
        let r = rows(&facts(&others));
        let mut p = Page::new();
        assert_eq!(p.press(&r, Act::Lock), Do::Carry(Act::Lock));
        p.finished(Act::Lock, true);
        assert_eq!(p.press(&r, Act::Shred), Do::Confirm(Act::Shred));
        assert_eq!(p.press(&r, Act::Lock), Do::Nothing, "one act at a time");
        assert_eq!(p.confirmed(Act::Unbind, true), Do::Nothing, "a confirmation for an act not asked");
        assert_eq!(p.confirmed(Act::Shred, false), Do::Nothing);
        assert_eq!(p.status(), None, "refused: as before");
        assert_eq!(p.press(&r, Act::Revoke([2; 32])), Do::Confirm(Act::Revoke([2; 32])));
        assert_eq!(p.status().unwrap().msg("otter"), Some(Msg::SecRevoking("otter")));
        assert_eq!(p.confirmed(Act::Revoke([2; 32]), true), Do::Carry(Act::Revoke([2; 32])));
        p.finished(Act::Revoke([2; 32]), true);
        assert_eq!(p.status().unwrap().msg("otter"), Some(Msg::SecRevoked("otter")));
        p.left();
        assert_eq!(p.status(), None, "said once");

        let pre = rows(&Facts { present: false, member: false, fleet_key: false, leaving: false, others: &[] });
        let mut x = Page::new();
        assert_eq!(x.press(&pre, Act::Wipe), Do::Nothing, "before attest no row is drawn");
        assert_eq!(x.press(&pre, Act::Shred), Do::Nothing);
        assert_eq!(x.press(&pre, Act::Unbind), Do::Nothing);
        assert_eq!(UNBIND.first(), Some(&UnbindStep::Handle), "the handle first");
        assert_eq!(UNBIND.last(), Some(&UnbindStep::Forget), "forgetting last, after consent and the rotation");
    }

    /// A revoke on the chain leaves the device a member, out of the live set (no wrap in the next fan-out) and barred from signing; a reinstatement brings it back; the checks refuse what the fold would.
    #[test]
    fn the_chain_half() {
        let (a, b, c) = (key(1), key(2), key(3));
        let mut blob = MembershipBlob::genesis(&a, HP, &SEED, 100);
        add(&mut blob, &a, &b, 200);
        add(&mut blob, &a, &c, 300);
        assert_eq!(live(&blob).unwrap(), vec![pk(&a), pk(&b), pk(&c)]);
        assert_eq!(check(&blob, &pk(&a), Act::Revoke(pk(&a))), Err("a device cannot revoke itself"));
        assert_eq!(check(&blob, &pk(&a), Act::Revoke([9; 32])), Err("that device is not a member of the fleet"));
        assert_eq!(check(&blob, &pk(&a), Act::Reinstate(pk(&c))), Err("that device is not revoked"));
        assert_eq!(check(&blob, &pk(&a), Act::Revoke(pk(&c))), Ok(()));
        blob.lock(&a, pk(&c), 400);
        assert!(blob.fold().unwrap().contains(&pk(&c)), "still a member: membership leaves by its own hand only");
        assert_eq!(live(&blob).unwrap(), vec![pk(&a), pk(&b)], "no wrap for it in the next fan-out");
        assert_eq!(check(&blob, &pk(&c), Act::Revoke(pk(&b))), Err("this device is not an unlocked member of the fleet"));
        assert_eq!(check(&blob, &pk(&a), Act::Revoke(pk(&c))), Err("that device is revoked already"));
        assert_eq!(check(&blob, &pk(&b), Act::Reinstate(pk(&c))), Ok(()));
        blob.unlock(&b, pk(&c), 500);
        assert_eq!(live(&blob).unwrap(), vec![pk(&a), pk(&b), pk(&c)]);
    }
}
