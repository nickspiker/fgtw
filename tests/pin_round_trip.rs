#[test]
fn pin_sized_setting_round_trips() {
    use fgtw::fstate::*;
    let entries = vec![
        SettingEntry { key: "logs.hard".into(), value: vec![1], updated: 5, tombstone: false },
        SettingEntry { key: "profile.avatar_pin".into(), value: vec![0xAB; 64], updated: 7, tombstone: false },
        SettingEntry { key: "profile.avatar_ts".into(), value: 99i64.to_le_bytes().to_vec(), updated: 6, tombstone: false },
        SettingEntry { key: "profile.name".into(), value: b"Peer".to_vec(), updated: 4, tombstone: false },
    ];
    let bytes = settings_to_bytes(&entries, &[]);
    let (back, _) = settings_from_bytes(&bytes).expect("parse");
    assert_eq!(back.len(), 4, "an entry was dropped in the round-trip: {:?}", back.iter().map(|e| &e.key).collect::<Vec<_>>());
    assert_eq!(back.iter().find(|e| e.key == "profile.avatar_pin").unwrap().value, vec![0xAB; 64]);
}
