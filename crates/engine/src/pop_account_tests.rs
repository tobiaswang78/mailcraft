// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A POP account, the engine side (#402): what `account.add` and `account.edit` take of it, and
//! what a run is asked to do for it.

use mailcraft_model::{AccountKind, FolderKind};
use serde_json::json;

use crate::Session;

fn pop(leave_mail: bool) -> serde_json::Value {
    json!({
        "email": "ada@example.org",
        "kind": "pop",
        "username": "ada@example.org",
        "incoming": {"host": "pop.example.org", "port": 995, "security": "tls"},
        "outgoing": {"host": "smtp.example.org", "port": 465, "security": "tls"},
        "pop": {"leaveMail": leave_mail},
    })
}

#[test]
fn a_pop_account_is_added_with_its_servers_and_its_say() {
    let mut s = Session::empty();
    let id = s.run("account.add", &pop(true)).unwrap()["id"].as_u64().unwrap();
    let a = s.mailbox.account(id).unwrap();
    assert_eq!(a.kind, AccountKind::Pop);
    assert_eq!(a.incoming.as_ref().unwrap().host, "pop.example.org");
    assert_eq!(a.outgoing.as_ref().unwrap().host, "smtp.example.org");
    assert!(a.oauth.is_none() && a.jmap.is_none() && a.ews.is_none());
    assert!(a.pop_options().leave_mail);
    // The days said are kept within what can be kept.
    let mut params = pop(true);
    params["pop"]["leaveDays"] = json!(9_999_999u64);
    let id = s.run("account.edit", &json!({"id": id, "pop": {"leaveDays": 9999999u64}})).unwrap()["id"].as_u64().unwrap();
    assert_eq!(s.mailbox.account(id).unwrap().pop_options().leave_days, mailcraft_model::PopOptions::MAX_DAYS);
    // (And a value that isn't one is refused.)
    let err = s.run("account.edit", &json!({"id": id, "pop": {"leaveMail": "yes"}})).unwrap_err().to_string();
    assert!(err.contains("true or false"), "{err}");
}

#[test]
fn a_run_for_a_pop_account_asks_for_its_inbox_alone() {
    let mut s = Session::empty();
    let id = s.run("account.add", &pop(false)).unwrap()["id"].as_u64().unwrap();
    let request = crate::cmd::account::sync_request(&s, id).unwrap();
    // Nothing is pushed: POP carries no flags, moves or deletions back.
    assert!(request.ops.is_empty() && request.places.is_empty() && request.gmail_moves.is_empty());
    // Its say about the server side goes with the account, so the run can keep it.
    assert!(!request.account.pop_options().leave_mail);
    // Mail that came down keeps its UIDLs in the folder, so the next run knows what is new.
    let inbox = request.folders.iter().find(|f| f.kind == FolderKind::Inbox).unwrap();
    let delta = mailcraft_model::sync::FolderDelta {
        id: Some(inbox.id),
        remote: "INBOX".into(),
        kind: FolderKind::Inbox,
        uid_validity: 1,
        new: vec![mailcraft_model::Message { uid: mailcraft_model::pop::uid_of("1"), subject: "One".into(), date: 10, ..Default::default() }],
        pop_uidls: vec!["1".into()],
        complete: true,
        ..Default::default()
    };
    let answer = mailcraft_model::sync::SyncResult { account: id, email: "ada@example.org".into(), folders: vec![delta], ..Default::default() };
    s.run("sync.apply", &json!({"result": answer})).unwrap();
    let again = crate::cmd::account::sync_request(&s, id).unwrap();
    let again = again.folders.iter().find(|f| f.kind == FolderKind::Inbox).unwrap();
    assert_eq!(again.pop_uidls, ["1"], "what the server has is remembered");
    assert_eq!(again.known_uids, [mailcraft_model::pop::uid_of("1")]);
}

#[test]
fn kind_stays_pop_when_its_settings_are_saved_again() {
    let mut s = Session::empty();
    let id = s.run("account.add", &pop(true)).unwrap()["id"].as_u64().unwrap();
    // Saving the servers again (no kind said) doesn't turn the account into an IMAP one.
    s.run("account.edit", &json!({"id": id, "incoming": {"host": "pop.example.org", "port": 995}})).unwrap();
    assert_eq!(s.mailbox.account(id).unwrap().kind, AccountKind::Pop);
    assert!(s.mailbox.account(id).unwrap().pop_options().leave_mail, "what wasn't said stays as it was");
}
