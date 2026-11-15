// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A run against a fake POP server (#402): what is new comes down once, what leaves the server
//! goes from here, and the owner's choice about leaving mail there is kept to.

use mailcraft_model::sync::{FolderState, SyncRequest};
use mailcraft_model::{Account, AccountKind, FolderKind, Security, Server, pop};

use crate::fake::{Fake, FakePop, FakePopMessage, PopWorld};

const PASSWORD: &str = "pop-test-password-never-real";

fn pop_world(messages: Vec<FakePopMessage>) -> PopWorld {
    PopWorld { user: "ada@example.org".into(), password: PASSWORD.into(), uidl_and_top: true, messages, ..Default::default() }
}

fn mail(uidl: &str, subject: &str) -> FakePopMessage {
    let body = format!(
        "From: Bob <bob@example.org>\r\nTo: Ada <ada@example.org>\r\nSubject: {subject}\r\nDate: Tue, 01 Jul 2003 10:52:37 +0200\r\n\
         Message-ID: <{uidl}@example.org>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThe body of {subject}.\r\n"
    );
    FakePopMessage { uidl: uidl.into(), body: body.into_bytes() }
}

fn account(pop: &FakePop) -> Account {
    Account {
        id: 7,
        name: "Ada".into(),
        email: "ada@example.org".into(),
        kind: AccountKind::Pop,
        incoming: Some(Server { host: "127.0.0.1".into(), port: pop.port, security: Security::None }),
        username: "ada@example.org".into(),
        ..Default::default()
    }
}

fn request(pop: &FakePop, inbox: FolderState) -> SyncRequest {
    SyncRequest { account: account(pop), password: PASSWORD.into(), folders: vec![inbox], ..Default::default() }
}

fn inbox(uidls: &[&str]) -> FolderState {
    FolderState {
        id: 100,
        remote: "INBOX".into(),
        kind: FolderKind::Inbox,
        uid_validity: pop::uid_of("POP-VALIDITY").max(1),
        known_uids: uidls.iter().map(|u| pop::uid_of(u)).collect(),
        pop_uidls: uidls.iter().map(|u| (*u).to_string()).collect(),
        ..Default::default()
    }
}

fn dropped(pop: &FakePop) -> Vec<String> {
    pop.world().dropped.clone()
}

#[test]
fn new_mail_comes_down_once() {
    let pop = Fake::pop(pop_world(vec![mail("1", "One"), mail("2", "Two")]));
    // Nothing known yet: both come, whole, and the UIDLs are said.
    let result = crate::sync(&request(&pop, inbox(&[])));
    let delta = result.folders.first().unwrap();
    assert_eq!(delta.new.len(), 2, "{result:?}");
    assert!(delta.complete);
    assert_eq!(delta.pop_uidls, ["1", "2"]);
    assert_eq!(delta.remote, "INBOX");
    assert_eq!(delta.kind, FolderKind::Inbox);
    assert!(delta.removed.is_empty());
    let (one, two) = (&delta.new[0], &delta.new[1]);
    assert_eq!((one.subject.as_str(), one.uid), ("One", pop::uid_of("1")));
    assert_eq!(two.subject, "Two");
    assert!(!one.read, "mail that comes by POP is unread");
    // Nothing was deleted: mail is left on the server.
    assert!(dropped(&pop).is_empty());

    // A second run, knowing both: nothing comes again, and the server's list says so once more.
    let result = crate::sync(&request(&pop, inbox(&["1", "2"])));
    let delta = result.folders.first().unwrap();
    assert!(delta.new.is_empty(), "{result:?}");
    assert!(delta.removed.is_empty());
    assert!(delta.complete);

    // A message that left the server goes from here too.
    pop.world().messages.remove(0);
    let result = crate::sync(&request(&pop, inbox(&["1", "2"])));
    let delta = result.folders.first().unwrap();
    assert_eq!(delta.removed, [pop::uid_of("1")], "{result:?}");
    assert!(delta.new.is_empty());
}

#[test]
fn mail_the_owner_says_not_to_leave_is_deleted() {
    let mut world = pop_world(vec![mail("1", "One"), mail("2", "Two")]);
    world.messages.remove(1);
    let pop = Fake::pop(world);
    let mut asking = request(&pop, inbox(&[]));
    asking.account.pop = Some(pop::PopOptions { leave_mail: false, ..Default::default() });
    let result = crate::sync(&asking);
    assert_eq!(result.folders.first().unwrap().new.len(), 1, "{result:?}");
    assert_eq!(dropped(&pop), ["1"], "what was fetched was dropped at the goodbye");

    // Left alone, the same server keeps everything.
    let pop = Fake::pop(pop_world(vec![mail("1", "One")]));
    let result = crate::sync(&request(&pop, inbox(&[])));
    assert_eq!(result.folders.first().unwrap().new.len(), 1);
    assert!(dropped(&pop).is_empty());
}

#[test]
fn a_large_message_comes_as_its_header_and_a_note() {
    let mut big = mail("1", "The big one");
    big.body =
        format!("Subject: The big one\r\nFrom: bob@example.org\r\nDate: Tue, 01 Jul 2003 10:52:37 +0200\r\n\r\n{}", "x".repeat(4096)).into_bytes();
    let pop = Fake::pop(pop_world(vec![big]));
    let asking = request(&pop, inbox(&[]));
    // (The run's own limit is what a message may be; the tests' `sync` keeps everything whole.)
    let result = crate::sync::sync_within(&asking, crate::sync::Limits { largest: 1024, ..crate::sync::Limits::kept_whole() });
    let m = result.folders.first().unwrap().new.first().unwrap();
    assert_eq!(m.subject, "The big one", "{m:?}");
    assert!(m.not_downloaded > 1024, "{m:?}");
    assert!(m.body.text.contains("on the server"));
}

#[test]
fn a_server_without_uidl_is_said_so_and_not_emptied() {
    let mut world = pop_world(vec![mail("1", "One")]);
    world.uidl_and_top = false;
    let pop = Fake::pop(world);
    let result = crate::sync(&request(&pop, inbox(&[])));
    assert!(result.folders.is_empty(), "{result:?}");
    assert!(result.errors.iter().any(|e| e.contains("UIDL")), "{result:?}");
}

#[test]
fn a_refused_sign_in_is_an_error_and_nothing_comes() {
    let mut world = pop_world(vec![mail("1", "One")]);
    world.refuse_login = true;
    let pop = Fake::pop(world);
    let result = crate::sync(&request(&pop, inbox(&[])));
    assert!(result.folders.is_empty());
    assert!(!result.errors.is_empty());
}

#[test]
fn deletions_that_fail_are_taken_back_whole() {
    let mut world = pop_world(vec![mail("1", "One")]);
    world.refuse.push("DELE".into());
    let pop = Fake::pop(world);
    let mut asking = request(&pop, inbox(&[]));
    asking.account.pop = Some(pop::PopOptions { leave_mail: false, ..Default::default() });
    let result = crate::sync(&asking);
    assert_eq!(result.folders.first().unwrap().new.len(), 1);
    assert!(result.errors.iter().any(|e| e.contains("delete")), "{result:?}");
    assert!(dropped(&pop).is_empty(), "nothing was dropped: the marks were taken back");
    // And the message is still known, so it is not fetched twice while it stays.
    assert!(!result.folders.first().unwrap().pop_uidls.is_empty());
}

#[test]
fn the_servers_are_checked_the_pop_way_before_the_account_is_added() {
    // (What the wizard's Connect runs, which once greeted the POP server as an IMAP one.)
    let mut world = pop_world(vec![mail("1", "One")]);
    world.password = "hunter2".into();
    let pop = Fake::pop(world);
    let mut account = account(&pop);
    assert_eq!(crate::test_account(&account, "hunter2"), Ok(()));
    assert!(pop.world().sign_ins >= 1);
    assert_eq!(crate::test_account(&account, "wrong"), Err(crate::not_signed_in(&account)));
    // Without an incoming server named, there is nothing to greet.
    account.incoming = None;
    assert!(matches!(crate::test_account(&account, "hunter2"), Err(crate::NetError::Config(_))));
}
