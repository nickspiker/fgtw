// German: an exhaustive match over the same messages as en.rs (the reference).
// Photon's arms are Photon's German (photon 9a93f16c, src/ui/lang/de.rs); ferros's arms are ferros's, in its lower-case voice, nouns keeping their capitals.
// Photon's de.rs falls back to English for SelectedDevice, SelectedBy, JoinAskFgtw, JoinAskedFgtw, AddLookFgtw and AddLookingFgtw, so those six are translated here from Photon's English.
use super::Msg;
use core::fmt::{self, Write};

pub fn text(m: Msg, o: &mut dyn Write) -> fmt::Result {
    match m {
        // ---- Photon's: adding a device ----
        Msg::AddDeviceTitle => o.write_str("Ein Gerät hinzufügen"),
        Msg::TapNearby => o.write_str("oder tippe auf das Gerät in der Nähe, das beitreten will:"),
        Msg::AddDeviceNearby(name) => write!(o, "{name}   \u{00b7} in der Nähe"),
        Msg::TypeWords => o.write_str("Tippe die Wörter ein, die das neue Gerät zeigt"),
        Msg::InvalidWord(w) => write!(o, "'{w}' ist keines der Wörter"),
        Msg::WaitingForDevice => o.write_str("Warte auf das neue Gerät\u{2026} es sollte seine Wörter zeigen"),
        Msg::DevicesAskingToJoin { count, shown } => {
            if count == 1 {
                write!(o, "{shown} Gerät will beitreten: tippe die Wörter von dem in deiner Hand")
            } else {
                write!(o, "{shown} Geräte wollen beitreten: tippe die Wörter von dem in deiner Hand")
            }
        }
        Msg::NoMatchingDevice(bad) => write!(o, "'{bad}' passt zu keinem Gerät, das beitreten will"),
        Msg::MatchingDevice(name) => write!(o, "gleiche mit {name} ab\u{2026}"),
        Msg::MatchingMultiple { shown, .. } => write!(o, "gleiche ab\u{2026} ({shown} Geräte)"),
        Msg::Preparing => o.write_str("Bereite vor\u{2026}"),
        Msg::NoFleetKey => o.write_str("Dieses Gerät hält den Flottenschlüssel noch nicht.\nMach das von einem anderen deiner Geräte aus."),
        Msg::NoDeviceKey => o.write_str("Der Schlüssel dieses Geräts ist noch nicht bereit. Versuch es gleich nochmal."),
        Msg::AddingDevice(name) => write!(o, "Füge {name} hinzu\u{2026}"),
        Msg::DeviceAdded => o.write_str("Gerät hinzugefügt \u{221a}"),
        Msg::JoinContended => o.write_str("Mehr als ein Gerät will beitreten, darum kann jetzt nur ein Gerät neben diesem hinzugefügt werden, per Bluetooth oder NFC. Fügst du nur eins hinzu, kennt jemand anderes dein Handle."),
        Msg::AddFromSignedIn => o.write_str("Füge dieses Gerät von einem hinzu, das schon deins ist:"),
        Msg::AddDevicePill => o.write_str("Gerät hinzufügen"),
        Msg::SelectedDevice(name) => write!(o, "Ausgewählt: {name}"),
        Msg::IsNewDeviceGreen => o.write_str("Leuchtet dein neues Gerät hellgrün?"),
        Msg::YesPill => o.write_str("Ja"),
        Msg::NoPill => o.write_str("Nein"),
        Msg::AddLookFgtw => o.write_str("Nicht in der Nähe? Über fgtw.org suchen"),
        Msg::AddLookingFgtw => o.write_str("Suche auch über fgtw.org"),
        // ---- ferros's: adding a device ----
        Msg::DeviceAsksToJoin => o.write_str("ein Gerät in diesem Netz will beitreten"),
        Msg::AddAsking => o.write_str("Gerät hinzufügen: Geräte, die beitreten wollen"),
        Msg::AddSelected => o.write_str("Gerät hinzufügen: ausgewählt"),
        Msg::AddingToFleet => o.write_str("wird zur Flotte hinzugefügt"),
        Msg::HandingKey => o.write_str("der Flottenschlüssel wird übergeben"),
        Msg::Added => o.write_str("hinzugefügt"),
        Msg::AddingFailed => o.write_str("Hinzufügen fehlgeschlagen"),
        Msg::CandAdded(name) => write!(o, "{name}  hinzugefügt"),
        Msg::CandNearby(name) => write!(o, "{name}  in der Nähe: zum Auswählen tippen"),
        Msg::CandNotNearby(name) => write!(o, "{name}  nicht in der Nähe: tippe seine Wörter ein"),
        Msg::OpenPhotonJoin => o.write_str("öffne auf dem Gerät den Beitrittsbildschirm von Photon"),
        Msg::TypeItsWordsPill => o.write_str("seine Wörter eintippen"),
        Msg::HoldTogether => o.write_str("oder halte die beiden Geräte aneinander: es tritt sofort bei"),
        Msg::DonePill => o.write_str("fertig"),
        Msg::ClosePill => o.write_str("schließen"),
        // ---- Photon's: the joining device ----
        Msg::SelectedBy(name) => write!(o, "Ausgewählt von {name}"),
        Msg::JoinerSelected => o.write_str("Ausgewählt!"),
        Msg::JoinerConfirmOther => o.write_str("Bestätige auf deinem anderen Gerät, dann ist es fertig."),
        Msg::LaunchJoinConfirmNote => o.write_str("Du bestätigst das Hinzufügen auf jenem Gerät."),
        Msg::JoinAskFgtw => o.write_str("Meine Geräte sind nicht in der Nähe: über fgtw.org fragen"),
        Msg::JoinAskedFgtw => o.write_str("Über fgtw.org gefragt: tippe die Wörter auf deinem anderen Gerät ein"),
        Msg::HandlesDontMatch => o.write_str("die beiden stimmen nicht überein\nkorrigiere den Namen und versuch es nochmal"),
        Msg::DeviceBrandedHint => o.write_str("Diese Hardware ist noch auf eine andere Flotte registriert.\nWer sie besitzt, kann sie mit Freigeben auf der eigenen Flotten-Seite freigeben."),
        // ---- ferros's: the joining device ----
        Msg::UseExistingDevice => o.write_str("Binde dieses Gerät mit einem vorhandenen Gerät an deine Flotte."),
        Msg::WaitingFleetKeys => o.write_str("Warte auf die Schlüssel der Flotte."),
        Msg::BoundWaitingKeys => o.write_str("An deine Flotte gebunden.\nWarte auf ihre Schlüssel."),
        Msg::DeniedBoundOther => o.write_str("Abgelehnt. Dieses Gerät ist an eine andere Identität gebunden."),
        Msg::OwnedByOther => o.write_str("Dieses Gerät gehört einer anderen Identität.\nNur ihre Flotte kann es gehen lassen."),
        // ---- the fleet's devices ----
        Msg::ThisDevice => o.write_str("dieses Gerät"),
        Msg::ADevice => o.write_str("ein Gerät"),
        Msg::TheDevice => o.write_str("das Gerät"),
        Msg::OneOfYourDevices => o.write_str("eines deiner Geräte"),
        Msg::MemberThisDevice(name) => write!(o, "{name}  dieses Gerät"),
        Msg::MemberNearby(name) => write!(o, "{name}  in der Nähe"),
        Msg::NoIdentityHere => o.write_str("keine Identität hier"),
        Msg::JoiningConfirm => o.write_str("Beitritt: bestätige auf einem deiner Geräte"),
        Msg::InFleetWaitingKey => o.write_str("in der Flotte, wartet auf den Schlüssel"),
        Msg::InFleet => o.write_str("in der Flotte"),
        Msg::LeavingFleet => o.write_str("verlässt die Flotte"),
        Msg::NewIdentityNoFleet => o.write_str("eine neue Identität: noch hält keine Flotte sie"),
        Msg::HandleHasOtherFleet => o.write_str("dieses Handle hat die Flotte einer anderen Identität"),
        Msg::NoVerdict => o.write_str("kein Urteil: nichts antwortet"),
        Msg::LookingUp => o.write_str("die Identität wird gesucht"),
        // ---- Photon's: leaving, on the other devices ----
        Msg::DepartureApproval(name) => write!(o, "{name} bittet darum, deine Flotte zu verlassen. Stimm zu unter Einstellungen → Flotte."),
        Msg::DepartRequestLine(name) => write!(o, "{name} bittet darum, deine Flotte zu verlassen."),
        Msg::DepartFreesHardware => o.write_str("Die Zustimmung löscht es und gibt seine Hardware frei, damit sie jeder Flotte beitreten kann."),
        Msg::DepartKeepsHardware => o.write_str("Die Zustimmung löscht es.\nSeine Hardware bleibt auf deine Flotte registriert."),
        Msg::DepartApprovePill => o.write_str("Zustimmen"),
        Msg::DepartDenyPill => o.write_str("Ablehnen"),
        Msg::DepartDeniedHere(name) => write!(o, "Abgelehnt. {name} bleibt in deiner Flotte."),
        Msg::DepartComplete(n) => write!(o, "{n} hat deine Flotte verlassen.\nSeine Hardware ist frei."),
        Msg::FleetSignedOut(name) => write!(o, "{name} hat die Flotte verlassen."),
        Msg::DepartReleasePending(n) => write!(o, "{n} hat deine Flotte verlassen, aber seine Hardware wurde nicht freigegeben.\nNimm Freigeben in seiner stillgelegten Zeile für einen neuen Versuch."),
        Msg::DeviceReleased(name) => write!(o, "{name} ist freigegeben.\nEs kann jetzt jeder Flotte beitreten."),
        // ---- ferros's: leaving, on the other devices ----
        Msg::DepartDenyKeeps => o.write_str("die Ablehnung behält es in deiner Flotte"),
        Msg::DepartApproveAgainPill => o.write_str("erneut zustimmen: die letzte Zustimmung ging nicht hinaus"),
        Msg::DepartApproving => o.write_str("Zustimmung läuft"),
        Msg::DepartApproved => o.write_str("zugestimmt: es verlässt deine Flotte"),
        // ---- Photon's: leaving, this device ----
        Msg::DepartWaitingLine => o.write_str("Deine anderen Geräte werden gefragt, ob dieses gehen darf. Stimm auf einem davon zu."),
        Msg::DepartDenied => o.write_str("Eines deiner Geräte hat diese Anfrage abgelehnt, also bleibt dieses Gerät in deiner Flotte. Tipp auf Freigeben, um erneut zu fragen."),
        // ---- ferros's: leaving, this device ----
        Msg::RemovePill { armed } => o.write_str(if armed { "noch einmal tippen: dieses Gerät entfernen" } else { "dieses Gerät entfernen" }),
        Msg::DepartAsking => o.write_str("dieses Gerät bittet deine Flotte, es freizugeben"),
        Msg::DepartSending => o.write_str("die Anfrage geht an deine Geräte"),
        Msg::DepartTapHint => o.write_str("stimme auf einem deiner anderen Geräte zu oder lehne ab,\noder halte eines davon an dieses"),
        Msg::DepartThen => o.write_str("nach der Zustimmung werden deine Daten davon gelöscht\nund es startet neu; zurück bricht den Austritt ab"),
        Msg::DepartDeniedOn(name) => write!(o, "der Austritt wurde auf {name} abgelehnt"),
        Msg::DepartNotStarted => o.write_str("der Austritt hat nicht begonnen"),
    }
}
