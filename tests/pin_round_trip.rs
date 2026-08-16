#[test]
fn pin_sized_setting_round_trips() {
    use vsf::VsfType;
use fgtw::fstate::*;
    let entries = vec![
        SettingEntry { key: "logs.hard".into(), value: VsfType::e(vsf::types::EtType::e6(1)), updated: 5, tombstone: false },
        SettingEntry { key: "profile.avatar_pin".into(), value: VsfType::hR(vec![0xAB; 64]), updated: 7, tombstone: false },
        SettingEntry { key: "profile.avatar_ts".into(), value: VsfType::e(vsf::types::EtType::e6(99)), updated: 6, tombstone: false },
        SettingEntry { key: "profile.name".into(), value: VsfType::x("Peer".into()), updated: 4, tombstone: false },
    ];
    let bytes = settings_to_bytes(&entries, &[]);
    let (back, _) = settings_from_bytes(&bytes).expect("parse");
    assert_eq!(back.len(), 4, "an entry was dropped in the round-trip: {:?}", back.iter().map(|e| &e.key).collect::<Vec<_>>());
    assert_eq!(back.iter().find(|e| e.key == "profile.avatar_pin").unwrap().value, VsfType::hR(vec![0xAB; 64]));
}
