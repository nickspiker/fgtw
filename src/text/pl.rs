// Polish: an exhaustive match over the same messages as en.rs (the reference).
// Photon's arms are Photon's Polish (photon 9a93f16c, src/ui/lang/pl.rs); ferros's arms are ferros's, in its lower-case voice.
// Photon's pl.rs falls back to English for SelectedDevice, SelectedBy, JoinAskFgtw, JoinAskedFgtw, AddLookFgtw and AddLookingFgtw, so those six are translated here from Photon's English.
use super::Msg;
use core::fmt::{self, Write};

pub fn text(m: Msg, o: &mut dyn Write) -> fmt::Result {
    match m {
        // ---- Photon's: adding a device ----
        Msg::AddDeviceTitle => o.write_str("Dodaj urządzenie"),
        Msg::TapNearby => o.write_str("albo dotknij pobliskiego urządzenia, które prosi o dołączenie:"),
        Msg::AddDeviceNearby(name) => write!(o, "{name}   \u{00b7} w pobliżu"),
        Msg::TypeWords => o.write_str("Wpisz słowa pokazane na nowym urządzeniu"),
        Msg::InvalidWord(w) => write!(o, "'{w}' nie jest jednym z tych słów"),
        Msg::WaitingForDevice => o.write_str("Czekanie na nowe urządzenie\u{2026} powinno pokazywać swoje słowa"),
        // The count is the subject: 2-4 (not 12-14) take "urządzenia proszą", every other count but one "urządzeń prosi".
        Msg::DevicesAskingToJoin { count, shown } => {
            if count == 1 {
                write!(o, "{shown} urządzenie prosi o dołączenie: wpisz słowa z tego, które trzymasz w ręce")
            } else if matches!(count % 10, 2..=4) && !matches!(count % 100, 12..=14) {
                write!(o, "{shown} urządzenia proszą o dołączenie: wpisz słowa z tego, które trzymasz w ręce")
            } else {
                write!(o, "{shown} urządzeń prosi o dołączenie: wpisz słowa z tego, które trzymasz w ręce")
            }
        }
        Msg::NoMatchingDevice(bad) => write!(o, "'{bad}' nie pasuje do żadnego urządzenia proszącego o dołączenie"),
        Msg::MatchingDevice(name) => write!(o, "dopasowywanie: {name}\u{2026}"),
        Msg::MatchingMultiple { count, shown } => write!(
            o,
            "dopasowywanie\u{2026} ({shown} {})",
            if count == 1 {
                "urządzenie"
            } else if matches!(count % 10, 2..=4) && !matches!(count % 100, 12..=14) {
                "urządzenia"
            } else {
                "urządzeń"
            }
        ),
        Msg::Preparing => o.write_str("Przygotowywanie\u{2026}"),
        Msg::NoFleetKey => o.write_str("To urządzenie nie trzyma jeszcze klucza floty.\nZrób to z innego swojego urządzenia."),
        Msg::NoDeviceKey => o.write_str("Klucz tego urządzenia nie jest jeszcze gotowy. Spróbuj za chwilę."),
        Msg::AddingDevice(name) => write!(o, "Dodawanie: {name}\u{2026}"),
        Msg::DeviceAdded => o.write_str("Urządzenie dodane \u{221a}"),
        Msg::JoinContended => o.write_str("Więcej niż jedno urządzenie prosi o dołączenie, więc teraz można dodać tylko urządzenie leżące obok tego, przez Bluetooth lub NFC. Jeśli dodajesz tylko jedno, ktoś inny zna twój handle."),
        Msg::AddFromSignedIn => o.write_str("Dodaj to urządzenie z takiego, które już jest twoje:"),
        Msg::AddDevicePill => o.write_str("Dodaj urządzenie"),
        Msg::SelectedDevice(name) => write!(o, "Wybrane: {name}"),
        Msg::IsNewDeviceGreen => o.write_str("Czy twoje nowe urządzenie świeci na jaskrawozielono?"),
        Msg::YesPill => o.write_str("Tak"),
        Msg::NoPill => o.write_str("Nie"),
        Msg::AddLookFgtw => o.write_str("Nie w pobliżu? Szukaj przez fgtw.org"),
        Msg::AddLookingFgtw => o.write_str("Szukanie także przez fgtw.org"),
        // ---- ferros's: adding a device ----
        Msg::DeviceAsksToJoin => o.write_str("urządzenie w tej sieci prosi o dołączenie"),
        Msg::AddAsking => o.write_str("dodaj urządzenie: urządzenia proszące o dołączenie"),
        Msg::AddSelected => o.write_str("dodaj urządzenie: wybrane"),
        Msg::AddingToFleet => o.write_str("dodawanie do floty"),
        Msg::HandingKey => o.write_str("przekazywanie klucza floty"),
        Msg::Added => o.write_str("dodane"),
        Msg::AddingFailed => o.write_str("dodawanie nie powiodło się"),
        Msg::CandAdded(name) => write!(o, "{name}  dodane"),
        Msg::CandNearby(name) => write!(o, "{name}  w pobliżu: dotknij, by wybrać"),
        Msg::CandNotNearby(name) => write!(o, "{name}  nie w pobliżu: wpisz jego słowa"),
        Msg::OpenPhotonJoin => o.write_str("otwórz na urządzeniu ekran dołączania Photon"),
        Msg::TypeItsWordsPill => o.write_str("wpisz jego słowa"),
        Msg::HoldTogether => o.write_str("albo zetknij oba urządzenia: dołączy od razu"),
        Msg::DonePill => o.write_str("gotowe"),
        Msg::ClosePill => o.write_str("zamknij"),
        // ---- Photon's: the joining device ----
        Msg::SelectedBy(name) => write!(o, "Wybrane przez {name}"),
        Msg::JoinerSelected => o.write_str("Wybrane!"),
        Msg::JoinerConfirmOther => o.write_str("Potwierdź na drugim urządzeniu, by zakończyć."),
        Msg::LaunchJoinConfirmNote => o.write_str("Dodanie potwierdzisz na tamtym urządzeniu."),
        Msg::JoinAskFgtw => o.write_str("Moich urządzeń nie ma w pobliżu: poproś przez fgtw.org"),
        Msg::JoinAskedFgtw => o.write_str("Poproszono przez fgtw.org: wpisz słowa na drugim urządzeniu"),
        Msg::HandlesDontMatch => o.write_str("te dwie się nie zgadzają\npopraw nazwę i spróbuj ponownie"),
        Msg::DeviceBrandedHint => o.write_str("Ten sprzęt jest wciąż zarejestrowany w innej flocie.\nJej właściciel może go zwolnić przyciskiem Zwolnij na swojej stronie Flota."),
        // ---- ferros's: the joining device ----
        Msg::UseExistingDevice => o.write_str("Użyj istniejącego urządzenia, by związać to urządzenie ze swoją flotą."),
        Msg::WaitingFleetKeys => o.write_str("Czekanie na klucze floty."),
        Msg::BoundWaitingKeys => o.write_str("Związane z twoją flotą.\nCzekanie na jej klucze."),
        Msg::DeniedBoundOther => o.write_str("Odmowa. To urządzenie jest związane z inną tożsamością."),
        Msg::OwnedByOther => o.write_str("To urządzenie należy do innej tożsamości.\nTylko jej flota może je wypuścić."),
        // ---- the fleet's devices ----
        Msg::ThisDevice => o.write_str("to urządzenie"),
        Msg::ADevice => o.write_str("urządzenie"),
        Msg::TheDevice => o.write_str("wybrane urządzenie"),
        Msg::OneOfYourDevices => o.write_str("jedno z twoich urządzeń"),
        Msg::MemberThisDevice(name) => write!(o, "{name}  to urządzenie"),
        Msg::MemberNearby(name) => write!(o, "{name}  w pobliżu"),
        Msg::NoIdentityHere => o.write_str("brak tu tożsamości"),
        Msg::JoiningConfirm => o.write_str("dołączanie: potwierdź na jednym ze swoich urządzeń"),
        Msg::InFleetWaitingKey => o.write_str("we flocie, czeka na klucz"),
        Msg::InFleet => o.write_str("we flocie"),
        Msg::LeavingFleet => o.write_str("opuszczanie floty"),
        Msg::NewIdentityNoFleet => o.write_str("nowa tożsamość: żadna flota jej jeszcze nie ma"),
        Msg::HandleHasOtherFleet => o.write_str("ten handle ma flotę innej tożsamości"),
        Msg::NoVerdict => o.write_str("brak werdyktu: nic nie odpowiada"),
        Msg::LookingUp => o.write_str("wyszukiwanie tożsamości"),
        // ---- Photon's: leaving, on the other devices ----
        Msg::DepartureApproval(name) => write!(o, "{name} prosi o odejście z twojej floty. Zatwierdź to w Ustawienia → Flota."),
        Msg::DepartRequestLine(name) => write!(o, "{name} prosi o odejście z twojej floty."),
        Msg::DepartFreesHardware => o.write_str("Zatwierdzenie wymazuje urządzenie i zwalnia jego sprzęt, by mógł dołączyć do dowolnej floty."),
        Msg::DepartKeepsHardware => o.write_str("Zatwierdzenie wymazuje urządzenie.\nJego sprzęt pozostaje zarejestrowany w twojej flocie."),
        Msg::DepartApprovePill => o.write_str("Zatwierdź"),
        Msg::DepartDenyPill => o.write_str("Odrzuć"),
        Msg::DepartDeniedHere(name) => write!(o, "Odrzucono. {name} zostaje w twojej flocie."),
        Msg::DepartComplete(n) => write!(o, "Urządzenie {n} opuściło twoją flotę.\nJego sprzęt jest wolny."),
        Msg::FleetSignedOut(name) => write!(o, "Urządzenie {name} opuściło flotę."),
        Msg::DepartReleasePending(n) => write!(o, "Urządzenie {n} opuściło twoją flotę, ale jego sprzęt nie został zwolniony.\nNaciśnij Zwolnij w jego wycofanym wierszu, by spróbować ponownie."),
        Msg::DeviceReleased(name) => write!(o, "Urządzenie {name} jest zwolnione.\nMoże teraz dołączyć do dowolnej floty."),
        // ---- ferros's: leaving, on the other devices ----
        Msg::DepartDenyKeeps => o.write_str("odrzucenie zatrzymuje je w twojej flocie"),
        Msg::DepartApproveAgainPill => o.write_str("zatwierdź ponownie: poprzednie zatwierdzenie nie zostało wysłane"),
        Msg::DepartApproving => o.write_str("zatwierdzanie"),
        Msg::DepartApproved => o.write_str("zatwierdzone: opuszcza twoją flotę"),
        // ---- Photon's: leaving, this device ----
        Msg::DepartWaitingLine => o.write_str("Pytam twoje inne urządzenia, czy wypuścić to. Zatwierdź na dowolnym z nich."),
        Msg::DepartDenied => o.write_str("Jedno z twoich urządzeń odrzuciło tę prośbę, więc to urządzenie zostaje we flocie. Aby poprosić ponownie, naciśnij Zwolnij."),
        // ---- ferros's: leaving, this device ----
        Msg::RemovePill { armed } => o.write_str(if armed { "dotknij ponownie: usuń to urządzenie" } else { "usuń to urządzenie" }),
        Msg::DepartAsking => o.write_str("to urządzenie prosi twoją flotę o zwolnienie"),
        Msg::DepartSending => o.write_str("wysyłanie prośby do twoich urządzeń"),
        Msg::DepartTapHint => o.write_str("zatwierdź lub odrzuć na dowolnym z twoich innych urządzeń,\nalbo zetknij jedno z nich z tym"),
        Msg::DepartThen => o.write_str("po zatwierdzeniu twoje dane zostaną z niego wymazane\ni uruchomi się ponownie; wstecz rezygnuje z odejścia"),
        Msg::DepartDeniedOn(name) => write!(o, "odejście odrzucono na urządzeniu {name}"),
        Msg::DepartNotStarted => o.write_str("odejście się nie rozpoczęło"),
        Msg::LastDevice => o.write_str("To ostatnie urządzenie twojej tożsamości.\nNie może odejść. Najpierw dodaj inne, potem wycofaj to."),
    }
}
