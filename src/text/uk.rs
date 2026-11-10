// Ukrainian: an exhaustive match over the same messages as en.rs (the reference).
// Photon's arms are Photon's words (photon 9a93f16c, src/ui/lang/uk.rs); SelectedDevice, SelectedBy, JoinAskFgtw, JoinAskedFgtw, AddLookFgtw and AddLookingFgtw, which Photon's uk.rs still shows in English, are translated here from Photon's English. ferros's arms are ferros's, in its lower-case voice, vocabulary following Photon's (флот, ідентичність, handle, схвалити, відхилити, слова), addressing the person as «ти» as Photon does. A device's name never takes a case ending: «пристрій» before it carries the case.
use super::Msg;
use core::fmt::{self, Write};

/// Photon's uk.rs plural: 1 (but not 11) takes the singular, 2 to 4 (but not 12 to 14) the few form, the rest the many form.
fn plural(n: u64, one: &'static str, few: &'static str, many: &'static str) -> &'static str {
    match (n % 100, n % 10) {
        (11..=14, _) => many,
        (_, 1) => one,
        (_, 2..=4) => few,
        _ => many,
    }
}

pub fn text(m: Msg, o: &mut dyn Write) -> fmt::Result {
    match m {
        // ---- Photon's: adding a device ----
        Msg::AddDeviceTitle => o.write_str("Додати пристрій"),
        Msg::TapNearby => o.write_str("або торкнись пристрою поруч, який просить приєднатися:"),
        Msg::AddDeviceNearby(name) => write!(o, "{name}   \u{00b7} поруч"),
        Msg::TypeWords => o.write_str("Введи слова, показані на новому пристрої"),
        Msg::InvalidWord(w) => write!(o, "'{w}': не одне з тих слів"),
        Msg::WaitingForDevice => o.write_str("Чекаю на новий пристрій\u{2026} він має показувати свої слова"),
        Msg::DevicesAskingToJoin { count, shown } => write!(o, "{shown} {}: введи слова того, що в тебе в руці", plural(count, "пристрій просить приєднатися", "пристрої просять приєднатися", "пристроїв просять приєднатися")),
        Msg::NoMatchingDevice(bad) => write!(o, "'{bad}' не збігається з жодним пристроєм, що просить приєднатися"),
        Msg::MatchingDevice(name) => write!(o, "звіряю: {name}\u{2026}"),
        Msg::MatchingMultiple { count, shown } => write!(o, "звіряю\u{2026} ({shown} {})", plural(count, "пристрій", "пристрої", "пристроїв")),
        Msg::Preparing => o.write_str("Готую\u{2026}"),
        Msg::NoFleetKey => o.write_str("Цей пристрій ще не тримає ключа флоту.\nЗроби це з іншого свого пристрою."),
        Msg::NoDeviceKey => o.write_str("Ключ цього пристрою ще не готовий. Спробуй за мить."),
        Msg::AddingDevice(name) => write!(o, "Додаю пристрій {name}\u{2026}"),
        Msg::DeviceAdded => o.write_str("Пристрій додано \u{221a}"),
        Msg::JoinContended => o.write_str("Приєднатися просять кілька пристроїв, тож зараз можна додати лише пристрій поруч із цим, через Bluetooth або NFC. Якщо ти додаєш лише один, хтось інший знає твій handle."),
        Msg::AddFromSignedIn => o.write_str("Додай цей пристрій з того, який уже твій:"),
        Msg::AddDevicePill => o.write_str("Додати пристрій"),
        Msg::SelectedDevice(name) => write!(o, "Вибрано: {name}"),
        Msg::IsNewDeviceGreen => o.write_str("Твій новий пристрій світиться яскраво-зеленим?"),
        Msg::YesPill => o.write_str("Так"),
        Msg::NoPill => o.write_str("Ні"),
        Msg::AddLookFgtw => o.write_str("Не поруч? Шукати через fgtw.org"),
        Msg::AddLookingFgtw => o.write_str("Шукаю і через fgtw.org"),
        // ---- ferros's: adding a device ----
        Msg::DeviceAsksToJoin => o.write_str("пристрій у цій мережі просить приєднатися"),
        Msg::AddAsking => o.write_str("додати пристрій: пристрої, що просять приєднатися"),
        Msg::AddSelected => o.write_str("додати пристрій: вибрано"),
        Msg::AddingToFleet => o.write_str("додаю його до флоту"),
        Msg::HandingKey => o.write_str("передаю йому ключ флоту"),
        Msg::Added => o.write_str("додано"),
        Msg::AddingFailed => o.write_str("додати не вдалося"),
        Msg::CandAdded(name) => write!(o, "{name}  додано"),
        Msg::CandNearby(name) => write!(o, "{name}  поруч: торкнись, щоб вибрати"),
        Msg::CandNotNearby(name) => write!(o, "{name}  не поруч: введи його слова"),
        Msg::OpenPhotonJoin => o.write_str("відкрий на пристрої екран приєднання Photon"),
        Msg::TypeItsWordsPill => o.write_str("ввести його слова"),
        Msg::HoldTogether => o.write_str("або приклади два пристрої один до одного: він приєднається одразу"),
        Msg::DonePill => o.write_str("готово"),
        Msg::ClosePill => o.write_str("закрити"),
        // ---- Photon's: the joining device ----
        Msg::SelectedBy(name) => write!(o, "Вибрано пристроєм {name}"),
        Msg::JoinerSelected => o.write_str("Вибрано!"),
        Msg::JoinerConfirmOther => o.write_str("Підтверди на іншому своєму пристрої, щоб завершити."),
        Msg::LaunchJoinConfirmNote => o.write_str("Додавання ти підтвердиш на тому пристрої."),
        Msg::JoinAskFgtw => o.write_str("Моїх пристроїв немає поруч: запитати через fgtw.org"),
        Msg::JoinAskedFgtw => o.write_str("Запитано через fgtw.org: введи слова на іншому своєму пристрої"),
        Msg::HandlesDontMatch => o.write_str("вони не збігаються\nвиправ ім'я і спробуй знову"),
        Msg::DeviceBrandedHint => o.write_str("Це залізо досі зареєстроване в іншому флоті.\nВласник того флоту може звільнити його кнопкою Звільнити на своїй сторінці Флот."),
        // ---- ferros's: the joining device ----
        Msg::UseExistingDevice => o.write_str("Прив'яжи цей пристрій до свого флоту з одного зі своїх пристроїв."),
        Msg::WaitingFleetKeys => o.write_str("Чекаю на ключі флоту."),
        Msg::BoundWaitingKeys => o.write_str("Прив'язано до твого флоту.\nЧекаю на його ключі."),
        Msg::DeniedBoundOther => o.write_str("Відмовлено. Цей пристрій прив'язаний до іншої ідентичності."),
        Msg::OwnedByOther => o.write_str("Цей пристрій належить іншій ідентичності.\nВідпустити його може лише її флот."),
        // ---- the fleet's devices ----
        Msg::ThisDevice => o.write_str("цей пристрій"),
        Msg::ADevice => o.write_str("пристрій"),
        Msg::TheDevice => o.write_str("пристрій"),
        Msg::OneOfYourDevices => o.write_str("один із твоїх пристроїв"),
        Msg::MemberThisDevice(name) => write!(o, "{name}  цей пристрій"),
        Msg::MemberNearby(name) => write!(o, "{name}  поруч"),
        Msg::NoIdentityHere => o.write_str("тут немає ідентичності"),
        Msg::JoiningConfirm => o.write_str("приєднання: підтверди на одному зі своїх пристроїв"),
        Msg::InFleetWaitingKey => o.write_str("у флоті, чекає на ключ флоту"),
        Msg::InFleet => o.write_str("у флоті"),
        Msg::LeavingFleet => o.write_str("вихід із флоту"),
        Msg::NewIdentityNoFleet => o.write_str("нова ідентичність: жоден флот її ще не тримає"),
        Msg::HandleHasOtherFleet => o.write_str("цей handle має флот іншої ідентичності"),
        Msg::NoVerdict => o.write_str("рішення немає: ніхто не відповідає"),
        Msg::LookingUp => o.write_str("шукаю ідентичність"),
        // ---- Photon's: leaving, on the other devices ----
        Msg::DepartureApproval(name) => write!(o, "Пристрій {name} просить піти з твого флоту. Схвали це: Налаштування \u{2192} Флот."),
        Msg::DepartRequestLine(name) => write!(o, "Пристрій {name} просить піти з твого флоту."),
        Msg::DepartFreesHardware => o.write_str("Схвалення стирає пристрій і звільняє його залізо, щоб воно могло приєднатися до будь-якого флоту."),
        Msg::DepartKeepsHardware => o.write_str("Схвалення стирає пристрій.\nЙого залізо лишається зареєстрованим у твоєму флоті."),
        Msg::DepartApprovePill => o.write_str("Схвалити"),
        Msg::DepartDenyPill => o.write_str("Відхилити"),
        Msg::DepartDeniedHere(name) => write!(o, "Відхилено. Пристрій {name} лишається у твоєму флоті."),
        Msg::DepartComplete(n) => write!(o, "Пристрій {n} пішов із твого флоту.\nЙого залізо вільне."),
        Msg::FleetSignedOut(name) => write!(o, "Пристрій {name} покинув флот."),
        Msg::DepartReleasePending(n) => write!(o, "Пристрій {n} пішов із твого флоту, але його залізо не звільнилося.\nНатисни Звільнити в його рядку на спочинку, щоб повторити."),
        Msg::DeviceReleased(name) => write!(o, "Пристрій {name} звільнено.\nТепер він може приєднатися до будь-якого флоту."),
        // ---- ferros's: leaving, on the other devices ----
        Msg::DepartDenyKeeps => o.write_str("відхилення лишає його у твоєму флоті"),
        Msg::DepartApproveAgainPill => o.write_str("схвалити знову: попереднє схвалення не надіслано"),
        Msg::DepartApproving => o.write_str("схвалюю"),
        Msg::DepartApproved => o.write_str("схвалено: він виходить із твого флоту"),
        // ---- Photon's: leaving, this device ----
        Msg::DepartWaitingLine => o.write_str("Питаємо твої інші пристрої, чи відпустити цей. Схвали на будь-якому з них."),
        Msg::DepartDenied => o.write_str("Один із твоїх пристроїв відхилив цей запит, тож цей пристрій лишається у флоті. Щоб попросити знову, натисни Звільнити."),
        // ---- ferros's: leaving, this device ----
        Msg::RemovePill { armed } => o.write_str(if armed { "торкнись ще раз: вилучити цей пристрій" } else { "вилучити цей пристрій" }),
        Msg::DepartAsking => o.write_str("цей пристрій просить твій флот відпустити його"),
        Msg::DepartSending => o.write_str("надсилаю запит твоїм пристроям"),
        Msg::DepartTapHint => o.write_str("схвали або відхили на будь-якому іншому своєму пристрої\nабо приклади один із них до цього"),
        Msg::DepartThen => o.write_str("після схвалення твої дані зітруться з нього\nі він перезапуститься; «назад» скасовує вихід"),
        Msg::DepartDeniedOn(name) => write!(o, "вихід відхилено на пристрої {name}"),
        Msg::DepartNotStarted => o.write_str("вихід не розпочався"),
    }
}
