// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::pop::{PopOptions, looks_like_pop, uid_of};
use crate::sync::FolderState;

#[test]
fn pop_servers_are_recognised() {
    assert!(looks_like_pop("pop.example.org", 995));
    assert!(looks_like_pop("POP3.example.org", 0));
    assert!(looks_like_pop("pop3s.example.org", 993));
    assert!(looks_like_pop("mail.example.org", 110));
    assert!(looks_like_pop("mail.example.org", 995));
    assert!(looks_like_pop(" Pop.example.org ", 0));
}

#[test]
fn imap_servers_are_not() {
    assert!(!looks_like_pop("imap.example.org", 993));
    assert!(!looks_like_pop("popcorn.example.org", 993));
    assert!(!looks_like_pop("mail.example.org", 143));
    assert!(!looks_like_pop("mail.pop.example.org", 993));
    assert!(!looks_like_pop("", 0));
}

#[test]
fn hostile_input_never_panics() {
    let huge = "pop".repeat(100_000);
    assert!(!looks_like_pop(&huge, 993));
    assert!(!looks_like_pop(&format!("pop{}", ".a".repeat(200)), 993));
    for host in ["", ".", "..", "ｐｏｐ.example", "pöp.example", "\u{0}", "pop\u{202e}.example", "💥💥"] {
        let _ = looks_like_pop(host, 0);
        let _ = looks_like_pop(host, u16::MAX);
    }
}

#[test]
fn pop_options_start_as_the_norm() {
    // Nothing said: mail is left on the server, forever.
    let nothing = PopOptions::default();
    assert!(nothing.leave_mail);
    assert_eq!(nothing.leave_days, 0);
    // One a file had with days over the cap is clamped when read back through the account.
    let mut many = PopOptions { leave_mail: true, leave_days: u32::MAX };
    many.clamp();
    assert_eq!(many.leave_days, PopOptions::MAX_DAYS);
}

#[test]
fn a_uidl_stands_for_one_uid_and_the_list_decides() {
    let a = uid_of("000000abc123");
    let b = uid_of("000000abc124");
    assert_ne!(a, b, "UIDLs that differ name different messages");
    assert_eq!(a, uid_of("000000abc123"), "the same UIDL is the same message every run");
    // The state that carries the UIDLs is round-tripped through a file.
    let state = FolderState { remote: "INBOX".into(), pop_uidls: vec!["000000abc123".into(), "9".into()], ..Default::default() };
    let json = serde_json::to_string(&state).unwrap();
    assert!(json.contains("popUidls"), "the UIDLs are kept in a file under their camelCase name");
    let read: FolderState = serde_json::from_str(&json).unwrap();
    assert_eq!(read.pop_uidls, state.pop_uidls);
    // And an older file that says nothing of them reads as one without.
    let old: FolderState = serde_json::from_str(r#"{"id": 3, "remote": "INBOX"}"#).unwrap();
    assert!(old.pop_uidls.is_empty());
}
