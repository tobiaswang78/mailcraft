// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! What a POP server is told apart from, and what picking POP adds up to (#402).
use super::*;

fn with_incoming(host: &str, port: &str) -> AccountSetup {
    let mut w = AccountSetup::blank(Page::Password);
    w.email = "ada@example.org".into();
    w.incoming = ServerFields { host: host.into(), port: port.into(), ..Default::default() };
    w
}

#[test]
fn a_pop_server_on_the_imap_path_is_said_so_and_makes_no_account() {
    for (host, port) in [("pop.example.org", "995"), ("POP3.example.org", ""), ("mail.example.org", "110")] {
        let w = with_incoming(host, port);
        let why = w.settings_problem(true).unwrap_or_default();
        assert!(why.contains("Other (POP)"), "{host}:{port}: {why}");
        assert!(w.account().is_none(), "{host}:{port} would have been added as IMAP");
    }
}

#[test]
fn imap_servers_are_left_alone() {
    for (host, port) in [("imap.example.org", "993"), ("popcorn.example.org", "993"), ("mail.example.org", "143")] {
        assert_eq!(with_incoming(host, port).settings_problem(true), None, "{host}:{port}");
    }
}

#[test]
fn pop_picked_by_hand_is_a_pop_account_that_leaves_its_mail() {
    let mut w = with_incoming("pop.example.org", "995");
    w.outgoing = ServerFields { host: "smtp.example.org".into(), port: "465".into(), ..Default::default() };
    w.pop = true;
    assert_eq!(w.settings_problem(true), None, "a POP server is fine, once POP is what was picked");
    let account = w.account().unwrap();
    assert_eq!(account.kind, AccountKind::Pop);
    assert!(account.pop_options().leave_mail, "the POP norm until the owner says otherwise");

    // The command that adds it says so, and what it says of the server side.
    let (command, params) = w.add_command("Ada").unwrap();
    assert_eq!(command, "account.add");
    assert_eq!(params.get("kind").and_then(Value::as_str), Some("pop"));
    assert_eq!(params.get("pop").and_then(|p| p.get("leaveMail")).and_then(Value::as_bool), Some(true));
    w.pop_leave = false;
    let (_, params) = w.add_command("Ada").unwrap();
    assert_eq!(params.get("pop").and_then(|p| p.get("leaveMail")).and_then(Value::as_bool), Some(false));

    // Account Settings for it keeps it POP and sends what its owner changed.
    let kept = w.account().unwrap();
    let mut w = AccountSetup::edit(&kept);
    w.pop_leave = false;
    let (command, params) = w.edit_command().unwrap();
    assert_eq!(command, "account.edit");
    assert_eq!(params.get("pop").and_then(|p| p.get("leaveMail")).and_then(Value::as_bool), Some(false));
}

#[test]
fn a_pop_account_is_edited_as_one_even_when_nothing_changed_of_it() {
    let mut w = with_incoming("pop.example.org", "995");
    w.pop = true;
    let kept = w.account().unwrap();
    // Nothing changed: no command goes out at all.
    assert!(AccountSetup::edit(&kept).edit_command().is_none());
}
