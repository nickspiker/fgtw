// French: an exhaustive match over the same messages as en.rs (the reference).
// Photon's arms are Photon's French (photon 9a93f16c, src/ui/lang/fr.rs); ferros's arms are ferros's, in its lower-case voice.
// Photon's fr.rs falls back to English for SelectedDevice, SelectedBy, JoinAskFgtw, JoinAskedFgtw, AddLookFgtw and AddLookingFgtw, so those six are translated here from Photon's English.
use super::Msg;
use core::fmt::{self, Write};

pub fn text(m: Msg, o: &mut dyn Write) -> fmt::Result {
    match m {
        // ---- Photon's: adding a device ----
        Msg::AddDeviceTitle => o.write_str("Ajouter un appareil"),
        Msg::TapNearby => o.write_str("ou touche l\u{2019}appareil proche qui demande à rejoindre :"),
        Msg::AddDeviceNearby(name) => write!(o, "{name}   \u{00b7} à proximité"),
        Msg::TypeWords => o.write_str("Écris les mots affichés sur le nouvel appareil"),
        Msg::InvalidWord(w) => write!(o, "'{w}' n\u{2019}est pas un des mots"),
        Msg::WaitingForDevice => o.write_str("Attente du nouvel appareil\u{2026} il devrait afficher ses mots"),
        Msg::DevicesAskingToJoin { shown, .. } => write!(o, "{shown} appareils demandent à rejoindre : écris les mots de celui que tu as en main"),
        Msg::NoMatchingDevice(bad) => write!(o, "'{bad}' ne correspond à aucun appareil qui demande à rejoindre"),
        Msg::MatchingDevice(name) => write!(o, "correspondance avec {name}\u{2026}"),
        Msg::MatchingMultiple { shown, .. } => write!(o, "correspondance\u{2026} ({shown} appareils)"),
        Msg::Preparing => o.write_str("Préparation\u{2026}"),
        Msg::NoFleetKey => o.write_str("Cet appareil ne détient pas encore la clé de la flotte.\nFais-le depuis un autre de tes appareils."),
        Msg::NoDeviceKey => o.write_str("La clé de cet appareil n\u{2019}est pas encore prête. Réessaie dans un instant."),
        // Photon's de(): "de" elides to "d’" before a vowel.
        Msg::AddingDevice(name) => {
            let first = name.chars().next().unwrap_or(' ').to_lowercase().next().unwrap_or(' ');
            if matches!(first, 'a' | 'à' | 'â' | 'ä' | 'e' | 'é' | 'è' | 'ê' | 'ë' | 'i' | 'î' | 'ï' | 'o' | 'ô' | 'ö' | 'u' | 'ù' | 'û' | 'ü' | 'y') {
                write!(o, "Ajout d\u{2019}{name}\u{2026}")
            } else {
                write!(o, "Ajout de {name}\u{2026}")
            }
        }
        Msg::DeviceAdded => o.write_str("Appareil ajouté \u{221a}"),
        Msg::JoinContended => o.write_str("Plus d'un appareil demande à rejoindre : seul un appareil posé à côté de celui-ci peut être ajouté maintenant, par Bluetooth ou NFC. Si tu n'en ajoutes qu'un, quelqu'un d'autre connaît ton handle."),
        Msg::AddFromSignedIn => o.write_str("Ajoute cet appareil depuis un appareil qui est déjà le tien :"),
        Msg::AddDevicePill => o.write_str("Ajouter un appareil"),
        Msg::SelectedDevice(name) => write!(o, "Sélectionné : {name}"),
        Msg::IsNewDeviceGreen => o.write_str("Ton nouvel appareil est-il vert vif ?"),
        Msg::YesPill => o.write_str("Oui"),
        Msg::NoPill => o.write_str("Non"),
        Msg::AddLookFgtw => o.write_str("Pas à proximité ? Cherche via fgtw.org"),
        Msg::AddLookingFgtw => o.write_str("Recherche aussi via fgtw.org"),
        // ---- ferros's: adding a device ----
        Msg::DeviceAsksToJoin => o.write_str("un appareil de ce réseau demande à rejoindre"),
        Msg::AddAsking => o.write_str("ajouter un appareil : appareils qui demandent à rejoindre"),
        Msg::AddSelected => o.write_str("ajouter un appareil : sélectionné"),
        Msg::AddingToFleet => o.write_str("ajout à la flotte"),
        Msg::HandingKey => o.write_str("remise de la clé de la flotte"),
        Msg::Added => o.write_str("ajouté"),
        Msg::AddingFailed => o.write_str("l’ajout a échoué"),
        Msg::CandAdded(name) => write!(o, "{name}  ajouté"),
        Msg::CandNearby(name) => write!(o, "{name}  à proximité : touche pour sélectionner"),
        Msg::CandNotNearby(name) => write!(o, "{name}  pas à proximité : écris ses mots"),
        Msg::OpenPhotonJoin => o.write_str("ouvre l’écran «\u{a0}rejoindre\u{a0}» de Photon sur l’appareil"),
        Msg::TypeItsWordsPill => o.write_str("écrire ses mots"),
        Msg::HoldTogether => o.write_str("ou tiens les deux appareils l’un contre l’autre : il rejoint aussitôt"),
        Msg::DonePill => o.write_str("terminé"),
        Msg::ClosePill => o.write_str("fermer"),
        // ---- Photon's: the joining device ----
        Msg::SelectedBy(name) => write!(o, "Sélectionné par {name}"),
        Msg::JoinerSelected => o.write_str("Sélectionné !"),
        Msg::JoinerConfirmOther => o.write_str("Confirme sur ton autre appareil pour terminer."),
        Msg::LaunchJoinConfirmNote => o.write_str("Tu confirmeras l\u{2019}ajout sur cet appareil-là."),
        Msg::JoinAskFgtw => o.write_str("Mes appareils ne sont pas à proximité : demander via fgtw.org"),
        Msg::JoinAskedFgtw => o.write_str("Demandé via fgtw.org : écris les mots sur ton autre appareil"),
        Msg::HandlesDontMatch => o.write_str("les deux ne correspondent pas\ncorrige le nom et réessaie"),
        Msg::DeviceBrandedHint => o.write_str("Ce matériel est encore enregistré auprès d\u{2019}une autre flotte.\nSon propriétaire peut le libérer avec Libérer sur sa page Flotte."),
        // ---- ferros's: the joining device ----
        Msg::UseExistingDevice => o.write_str("Utilise un appareil existant pour lier celui-ci à ta flotte."),
        Msg::WaitingFleetKeys => o.write_str("En attente des clés de la flotte."),
        Msg::BoundWaitingKeys => o.write_str("Lié à ta flotte.\nEn attente de ses clés."),
        Msg::DeniedBoundOther => o.write_str("Refusé. Cet appareil est lié à une autre identité."),
        Msg::OwnedByOther => o.write_str("Cet appareil appartient à une autre identité.\nSeule sa flotte peut le laisser partir."),
        // ---- the fleet's devices ----
        Msg::ThisDevice => o.write_str("cet appareil"),
        Msg::ADevice => o.write_str("un appareil"),
        Msg::TheDevice => o.write_str("l’appareil"),
        Msg::OneOfYourDevices => o.write_str("un de tes appareils"),
        Msg::MemberThisDevice(name) => write!(o, "{name}  cet appareil"),
        Msg::MemberNearby(name) => write!(o, "{name}  à proximité"),
        Msg::NoIdentityHere => o.write_str("aucune identité ici"),
        Msg::JoiningConfirm => o.write_str("en train de rejoindre : confirme sur l’un de tes appareils"),
        Msg::InFleetWaitingKey => o.write_str("dans la flotte, en attente de sa clé"),
        Msg::InFleet => o.write_str("dans la flotte"),
        Msg::LeavingFleet => o.write_str("départ de la flotte en cours"),
        Msg::NewIdentityNoFleet => o.write_str("une nouvelle identité : aucune flotte ne la porte encore"),
        Msg::HandleHasOtherFleet => o.write_str("ce handle a la flotte d’une autre identité"),
        Msg::NoVerdict => o.write_str("pas de verdict : rien ne répond"),
        Msg::LookingUp => o.write_str("recherche de l’identité"),
        // ---- Photon's: leaving, on the other devices ----
        Msg::DepartureApproval(name) => write!(o, "{name} demande à quitter ta flotte. Approuve-le dans Réglages → Flotte."),
        Msg::DepartRequestLine(name) => write!(o, "{name} demande à quitter ta flotte."),
        Msg::DepartFreesHardware => o.write_str("Approuver l\u{2019}efface et libère son matériel pour rejoindre n\u{2019}importe quelle flotte."),
        Msg::DepartKeepsHardware => o.write_str("Approuver l\u{2019}efface.\nSon matériel reste enregistré auprès de ta flotte."),
        Msg::DepartApprovePill => o.write_str("Approuver"),
        Msg::DepartDenyPill => o.write_str("Refuser"),
        Msg::DepartDeniedHere(name) => write!(o, "Refusé. {name} reste dans ta flotte."),
        Msg::DepartComplete(n) => write!(o, "{n} a quitté ta flotte.\nSon matériel est libre."),
        Msg::FleetSignedOut(name) => write!(o, "{name} a quitté la flotte."),
        Msg::DepartReleasePending(n) => write!(o, "{n} a quitté ta flotte, mais son matériel n\u{2019}a pas été libéré.\nUtilise Libérer sur sa ligne retirée pour réessayer."),
        Msg::DeviceReleased(name) => write!(o, "{name} est libéré.\nIl peut maintenant rejoindre n\u{2019}importe quelle flotte."),
        // ---- ferros's: leaving, on the other devices ----
        Msg::DepartDenyKeeps => o.write_str("refuser le garde dans ta flotte"),
        Msg::DepartApproveAgainPill => o.write_str("approuver à nouveau : la dernière approbation n’est pas partie"),
        Msg::DepartApproving => o.write_str("approbation en cours"),
        Msg::DepartApproved => o.write_str("approuvé : il quitte ta flotte"),
        // ---- Photon's: leaving, this device ----
        Msg::DepartWaitingLine => o.write_str("Tes autres appareils sont sollicités pour laisser partir celui-ci. Approuve sur n'importe lequel d'entre eux."),
        Msg::DepartDenied => o.write_str("Un de tes appareils a refusé cette demande, donc cet appareil reste dans ta flotte. Appuie sur Libérer pour redemander."),
        // ---- ferros's: leaving, this device ----
        Msg::RemovePill { armed } => o.write_str(if armed { "touche encore : retirer cet appareil" } else { "retirer cet appareil" }),
        Msg::DepartAsking => o.write_str("cet appareil demande à ta flotte de le libérer"),
        Msg::DepartSending => o.write_str("envoi de la demande à tes appareils"),
        Msg::DepartTapHint => o.write_str("approuve ou refuse sur n’importe lequel de tes autres appareils,\nou mets-en un contre celui-ci"),
        Msg::DepartThen => o.write_str("une fois approuvé, tes données en sont effacées\net il redémarre ; retour annule le départ"),
        Msg::DepartDeniedOn(name) => write!(o, "le départ a été refusé sur {name}"),
        Msg::DepartNotStarted => o.write_str("le départ n’a pas commencé"),
    }
}
