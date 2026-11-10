// Russian: an exhaustive match over the same messages as en.rs (the reference).
// Photon's arms are Photon's words (photon 9a93f16c, src/ui/lang/ru.rs); SelectedDevice, SelectedBy, JoinAskFgtw, JoinAskedFgtw, AddLookFgtw and AddLookingFgtw, which Photon's ru.rs still shows in English, are translated here from Photon's English. ferros's arms are ferros's, in its lower-case voice, vocabulary following Photon's (флот, личность, handle, одобрить, отклонить, слова), addressing the person as «ты» as Photon does. A device's name never takes a case ending: «устройство» before it carries the case.
use super::Msg;
use core::fmt::{self, Write};

pub fn text(m: Msg, o: &mut dyn Write) -> fmt::Result {
    match m {
        // ---- Photon's: adding a device ----
        Msg::AddDeviceTitle => o.write_str("Добавить устройство"),
        Msg::TapNearby => o.write_str("или коснись ближнего устройства, которое просится во флот:"),
        Msg::AddDeviceNearby(name) => write!(o, "{name}   \u{00b7} рядом"),
        Msg::TypeWords => o.write_str("Введи слова, показанные на новом устройстве"),
        Msg::InvalidWord(w) => write!(o, "'{w}': не одно из слов"),
        Msg::WaitingForDevice => o.write_str("Ждём новое устройство\u{2026} оно должно показывать свои слова"),
        Msg::DevicesAskingToJoin { count, shown } => {
            let (noun, verb) = match (count % 10, count % 100) { (1, 11) => ("устройств", "просятся"), (1, _) => ("устройство", "просится"), (2..=4, 12..=14) => ("устройств", "просятся"), (2..=4, _) => ("устройства", "просятся"), _ => ("устройств", "просятся") };
            write!(o, "{shown} {noun} {verb} во флот: введи слова того, что у тебя в руках")
        }
        Msg::NoMatchingDevice(bad) => write!(o, "'{bad}' не совпадает ни с одним устройством, которое просится во флот"),
        Msg::MatchingDevice(name) => write!(o, "сверяем {name}\u{2026}"),
        Msg::MatchingMultiple { count, shown } => {
            let word = match (count % 10, count % 100) { (1, 11) => "устройств", (1, _) => "устройство", (2..=4, 12..=14) => "устройств", (2..=4, _) => "устройства", _ => "устройств" };
            write!(o, "сверяем\u{2026} ({shown} {word})")
        }
        Msg::Preparing => o.write_str("Готовим\u{2026}"),
        Msg::NoFleetKey => o.write_str("У этого устройства пока нет ключа флота.\nСделай это с другого своего устройства."),
        Msg::NoDeviceKey => o.write_str("Ключ этого устройства пока не готов. Попробуй через мгновение."),
        Msg::AddingDevice(name) => write!(o, "Добавляем {name}\u{2026}"),
        Msg::DeviceAdded => o.write_str("Устройство добавлено \u{221a}"),
        Msg::JoinContended => o.write_str("Присоединиться просят несколько устройств, поэтому сейчас можно добавить только устройство рядом с этим, по Bluetooth или NFC. Если ты добавляешь только одно, кто-то ещё знает твой handle."),
        Msg::AddFromSignedIn => o.write_str("Добавь это устройство с того, которое уже твоё:"),
        Msg::AddDevicePill => o.write_str("Добавить устройство"),
        Msg::SelectedDevice(name) => write!(o, "Выбрано: {name}"),
        Msg::IsNewDeviceGreen => o.write_str("Твоё новое устройство светится ярко-зелёным?"),
        Msg::YesPill => o.write_str("Да"),
        Msg::NoPill => o.write_str("Нет"),
        Msg::AddLookFgtw => o.write_str("Не рядом? Искать через fgtw.org"),
        Msg::AddLookingFgtw => o.write_str("Ищем и через fgtw.org"),
        // ---- ferros's: adding a device ----
        Msg::DeviceAsksToJoin => o.write_str("устройство в этой сети просится во флот"),
        Msg::AddAsking => o.write_str("добавить устройство: устройства, которые просятся во флот"),
        Msg::AddSelected => o.write_str("добавить устройство: выбрано"),
        Msg::AddingToFleet => o.write_str("добавляем его во флот"),
        Msg::HandingKey => o.write_str("передаём ему ключ флота"),
        Msg::Added => o.write_str("добавлено"),
        Msg::AddingFailed => o.write_str("добавить не удалось"),
        Msg::CandAdded(name) => write!(o, "{name}  добавлено"),
        Msg::CandNearby(name) => write!(o, "{name}  рядом: коснись, чтобы выбрать"),
        Msg::CandNotNearby(name) => write!(o, "{name}  не рядом: введи его слова"),
        Msg::OpenPhotonJoin => o.write_str("открой на устройстве экран вступления Photon"),
        Msg::TypeItsWordsPill => o.write_str("ввести его слова"),
        Msg::HoldTogether => o.write_str("или приложи два устройства друг к другу: оно вступит сразу"),
        Msg::DonePill => o.write_str("готово"),
        Msg::ClosePill => o.write_str("закрыть"),
        // ---- Photon's: the joining device ----
        Msg::SelectedBy(name) => write!(o, "Выбрано устройством {name}"),
        Msg::JoinerSelected => o.write_str("Выбрано!"),
        Msg::JoinerConfirmOther => o.write_str("Подтверди на другом своём устройстве, чтобы закончить."),
        Msg::LaunchJoinConfirmNote => o.write_str("Добавление ты подтвердишь на том устройстве."),
        Msg::JoinAskFgtw => o.write_str("Моих устройств нет рядом: спросить через fgtw.org"),
        Msg::JoinAskedFgtw => o.write_str("Спросили через fgtw.org: введи слова на другом своём устройстве"),
        Msg::HandlesDontMatch => o.write_str("они не совпадают\nисправь имя и попробуй снова"),
        Msg::DeviceBrandedHint => o.write_str("Это железо всё ещё зарегистрировано в другом флоте.\nВладелец того флота может освободить его кнопкой Освободить на своей странице Флота."),
        // ---- ferros's: the joining device ----
        Msg::UseExistingDevice => o.write_str("Привяжи это устройство к своему флоту с одного из своих устройств."),
        Msg::WaitingFleetKeys => o.write_str("Ждём ключи флота."),
        Msg::BoundWaitingKeys => o.write_str("Привязано к твоему флоту.\nЖдём его ключи."),
        Msg::DeniedBoundOther => o.write_str("Отказано. Это устройство привязано к другой личности."),
        Msg::OwnedByOther => o.write_str("Это устройство принадлежит другой личности.\nОтпустить его может только её флот."),
        // ---- the fleet's devices ----
        Msg::ThisDevice => o.write_str("это устройство"),
        Msg::ADevice => o.write_str("устройство"),
        Msg::TheDevice => o.write_str("устройство"),
        Msg::OneOfYourDevices => o.write_str("одно из твоих устройств"),
        Msg::MemberThisDevice(name) => write!(o, "{name}  это устройство"),
        Msg::MemberNearby(name) => write!(o, "{name}  рядом"),
        Msg::NoIdentityHere => o.write_str("здесь нет личности"),
        Msg::JoiningConfirm => o.write_str("вступление: подтверди на одном из своих устройств"),
        Msg::InFleetWaitingKey => o.write_str("во флоте, ждёт ключ флота"),
        Msg::InFleet => o.write_str("во флоте"),
        Msg::LeavingFleet => o.write_str("выход из флота"),
        Msg::NewIdentityNoFleet => o.write_str("новая личность: ни один флот её пока не держит"),
        Msg::HandleHasOtherFleet => o.write_str("у этого handle флот другой личности"),
        Msg::NoVerdict => o.write_str("решения нет: никто не отвечает"),
        Msg::LookingUp => o.write_str("ищем личность"),
        // ---- Photon's: leaving, on the other devices ----
        Msg::DepartureApproval(name) => write!(o, "Устройство {name} просит уйти из твоего флота. Одобри это в Настройках \u{2192} Флот."),
        Msg::DepartRequestLine(name) => write!(o, "Устройство {name} просит уйти из твоего флота."),
        Msg::DepartFreesHardware => o.write_str("Одобрение стирает устройство и освобождает его железо, чтобы оно могло войти в любой флот."),
        Msg::DepartKeepsHardware => o.write_str("Одобрение стирает устройство.\nЕго железо остаётся зарегистрированным в твоём флоте."),
        Msg::DepartApprovePill => o.write_str("Одобрить"),
        Msg::DepartDenyPill => o.write_str("Отклонить"),
        Msg::DepartDeniedHere(name) => write!(o, "Отклонено. Устройство {name} остаётся в твоём флоте."),
        Msg::DepartComplete(n) => write!(o, "Устройство {n} покинуло твой флот.\nЕго железо свободно."),
        Msg::FleetSignedOut(name) => write!(o, "Устройство {name} покинуло флот."),
        Msg::DepartReleasePending(n) => write!(o, "Устройство {n} покинуло твой флот, но его железо не освободилось.\nНажми Освободить в его строке на покое, чтобы повторить."),
        Msg::DeviceReleased(name) => write!(o, "Устройство {name} освобождено.\nТеперь оно может войти в любой флот."),
        // ---- ferros's: leaving, on the other devices ----
        Msg::DepartDenyKeeps => o.write_str("отклонение оставляет его в твоём флоте"),
        Msg::DepartApproveAgainPill => o.write_str("одобрить снова: прошлое одобрение не ушло"),
        Msg::DepartApproving => o.write_str("одобряем"),
        Msg::DepartApproved => o.write_str("одобрено: оно уходит из твоего флота"),
        // ---- Photon's: leaving, this device ----
        Msg::DepartWaitingLine => o.write_str("Спрашиваем твои другие устройства, отпустить ли это. Одобри на любом из них."),
        Msg::DepartDenied => o.write_str("Одно из твоих устройств отклонило этот запрос, так что это устройство остаётся во флоте. Чтобы спросить снова, нажми Освободить."),
        // ---- ferros's: leaving, this device ----
        Msg::RemovePill { armed } => o.write_str(if armed { "коснись ещё раз: удалить это устройство" } else { "удалить это устройство" }),
        Msg::DepartAsking => o.write_str("это устройство просит твой флот отпустить его"),
        Msg::DepartSending => o.write_str("отправляем запрос твоим устройствам"),
        Msg::DepartTapHint => o.write_str("одобри или отклони на любом другом своём устройстве\nили приложи одно из них к этому"),
        Msg::DepartThen => o.write_str("после одобрения твои данные сотрутся с него\nи оно перезапустится; «назад» отменяет уход"),
        Msg::DepartDeniedOn(name) => write!(o, "уход отклонён на устройстве {name}"),
        Msg::DepartNotStarted => o.write_str("уход не начался"),
    }
}
