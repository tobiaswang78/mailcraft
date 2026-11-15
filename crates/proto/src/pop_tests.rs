// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
use std::io::ErrorKind;

use proptest::prelude::*;

use crate::ProtoError;
use crate::pop::{MAX_MESSAGES, MAX_UIDL, Pop};
use crate::script::{Broken, Script};

/// A greeting, then the answers to what is asked, one per line of `answers`.
fn server(answers: &[&str]) -> Script {
    let mut out = String::from("+OK pop.example.org ready\r\n");
    for answer in answers {
        out.push_str(answer);
    }
    Script::new(out)
}

#[test]
fn the_end_of_an_answer_is_one_dot_alone() {
    use crate::pop::is_end;
    assert!(is_end(b"."));
    assert!(!is_end(b".."));
    assert!(!is_end(b". "));
    assert!(!is_end(b""));
    assert!(!is_end(b".x"));
}

#[test]
fn an_argument_keeps_what_can_be_sent_alone() {
    use crate::pop::sanitize;
    assert_eq!(sanitize("ada@example.org"), "ada@example.org");
    assert_eq!(sanitize("ada example\r\nQUIT"), "adaexampleQUIT");
    assert_eq!(sanitize("a\u{0}b"), "ab");
}

#[test]
fn greetings() {
    let mut s = server(&[]);
    assert!(!Pop::connect(&mut s).unwrap().is_authenticated());

    let mut s = Script::new("-ERR mailbox locked\r\n");
    assert_eq!(Pop::connect(&mut s).unwrap_err(), ProtoError::Rejected("mailbox locked".into()));

    for junk in ["hello\r\n", "A0001 OK early\r\n", "+ go on\r\n", "* 3 EXISTS\r\n", "220 smtp.example.org ESMTP\r\n", "\r\n"] {
        let mut s = Script::new(junk);
        assert!(matches!(Pop::connect(&mut s), Err(ProtoError::Protocol(_))), "{junk:?}");
    }
    let mut s = Script::new("");
    assert!(matches!(Pop::connect(&mut s), Err(ProtoError::Io(_))));
}

#[test]
fn capabilities_come_upper_cased_and_a_server_without_them_is_not_an_error() {
    let mut s = server(&["+OK\r\nUIDL\r\nTOP\r\nSTLS\r\n.\r\n", "-ERR what is CAPA?\r\n"]);
    let mut pop = Pop::connect(&mut s).unwrap();
    assert_eq!(pop.capabilities().unwrap(), ["UIDL", "TOP", "STLS"]);

    // A server from before RFC 2449 refuses, and the session goes on.
    let mut s = server(&["-ERR what is CAPA?\r\n"]);
    let mut pop = Pop::connect(&mut s).unwrap();
    assert_eq!(pop.capabilities().unwrap(), Vec::<String>::new());
}

#[test]
fn sign_in_takes_user_then_pass_and_hides_the_password() {
    let mut s = server(&["+OK user accepted\r\n", "+OK signed in\r\n"]);
    let mut pop = Pop::connect(&mut s).unwrap();
    pop.login("ada@example.org", "hunter2").unwrap();
    assert!(pop.is_authenticated());
    assert_eq!(s.sent(), "USER ada@example.org\r\nPASS hunter2\r\n");

    // A refusal of the user name or of the password is a sign-in failure.
    for answers in [["-ERR no such user\r\n"].as_slice(), ["+OK\r\n", "-ERR wrong password\r\n"].as_slice()] {
        let mut s = server(answers);
        let mut pop = Pop::connect(&mut s).unwrap();
        assert!(matches!(pop.login("ada@example.org", "hunter2"), Err(ProtoError::Auth(_))), "{answers:?}");
    }

    // Nothing that could break out of one line is sent.
    let mut s = server(&[]);
    let mut pop = Pop::connect(&mut s).unwrap();
    assert!(matches!(pop.login("ada\r\nQUIT", "x"), Err(ProtoError::Auth(_))));
    assert!(matches!(pop.login("ada", "x\0y"), Err(ProtoError::Auth(_))));
    assert_eq!(s.sent(), "", "nothing was sent");
}

#[test]
fn stat_says_how_many_and_how_many_bytes() {
    let mut s = server(&["+OK 2 320\r\n"]);
    assert_eq!(Pop::connect(&mut s).unwrap().stat().unwrap(), (2, 320));

    for junk in ["+OK two 320\r\n", "+OK 2\r\n", "+OK 99999999 320\r\n", "-ERR no\r\n", "+OK 2 320 7\r\n"] {
        let mut s = server(&[junk]);
        assert!(Pop::connect(&mut s).unwrap().stat().is_err(), "{junk:?}");
    }
}

#[test]
fn list_and_uidl_read_their_tables() {
    let mut s = server(&["+OK 2 messages\r\n1 120\r\n2 200\r\n.\r\n", "+OK\r\n1 abc123\r\n2 def-456.\r\n.\r\n"]);
    let mut pop = Pop::connect(&mut s).unwrap();
    assert_eq!(pop.list().unwrap(), [(1, 120), (2, 200)]);
    assert_eq!(pop.uidl().unwrap(), [(1, "abc123".to_string()), (2, "def-456.".to_string())]);
    assert_eq!(s.sent(), "LIST\r\nUIDL\r\n");
}

#[test]
fn uidl_tables_are_checked() {
    // The same UIDL twice, an empty one, one too long, and a number that isn't.
    let too_long = "x".repeat(MAX_UIDL + 1);
    for table in [
        "+OK\r\n1 a\r\n1 a\r\n.\r\n",
        "+OK\r\n1 \r\n.\r\n",
        &format!("+OK\r\n1 {too_long}\r\n.\r\n"),
        "+OK\r\none a\r\n.\r\n",
        "+OK\r\n1 a\r\n2 b extra words\r\n.\r\n",
    ] {
        let mut s = server(&[table]);
        assert!(Pop::connect(&mut s).unwrap().uidl().is_err(), "{table:?}");
    }
    // Too many messages.
    let mut many = String::from("+OK\r\n");
    for n in 1..=MAX_MESSAGES + 1 {
        many.push_str(&format!("{n} u{n}\r\n"));
    }
    many.push_str(".\r\n");
    let mut s = server(&[&many]);
    assert!(Pop::connect(&mut s).unwrap().uidl().is_err());
}

#[test]
fn retr_and_top_take_the_byte_stuffing_back() {
    // `..dot at line start` was a `.dot`; a line ending in `\r\n` stays one.
    let mut s = server(&["+OK 87 octets\r\nFrom: ada@example.org\r\n..was a dot\r\n\r\nbody\r\n.\r\n", "+OK\r\nSubject: hi\r\n\r\nfirst\r\n.\r\n"]);
    let mut pop = Pop::connect(&mut s).unwrap();
    assert_eq!(pop.retr(1).unwrap(), b"From: ada@example.org\n.was a dot\n\nbody\n");
    assert_eq!(pop.top(2, 1).unwrap(), b"Subject: hi\n\nfirst\n");
    assert_eq!(s.sent(), "RETR 1\r\nTOP 2 1\r\n");

    // A refusal of the number is the server's own words.
    let mut s = server(&["-ERR no such message\r\n"]);
    assert_eq!(Pop::connect(&mut s).unwrap().retr(9).unwrap_err(), ProtoError::Rejected("no such message".into()));
}

#[test]
fn an_answer_that_never_ends_is_refused() {
    // No terminating dot: the caps stop the reading instead of the memory growing for ever.
    let body: String = "line\r\n".repeat(10_000);
    let mut s = server(&[&format!("+OK\r\n{body}")]);
    assert!(Pop::connect(&mut s).unwrap().retr(1).is_err());
}

#[test]
fn dele_rset_noop_and_quit_go_through() {
    let mut s = server(&["+OK\r\n", "+OK\r\n", "+OK\r\n", "+OK\r\n", "+OK bye\r\n"]);
    let mut pop = Pop::connect(&mut s).unwrap();
    pop.dele(1).unwrap();
    pop.rset().unwrap();
    pop.noop().unwrap();
    pop.quit().unwrap();
    assert_eq!(s.sent(), "DELE 1\r\nRSET\r\nNOOP\r\nQUIT\r\n");

    // A refusal is the server's words.
    let mut s = server(&["-ERR 1 already deleted\r\n"]);
    assert_eq!(Pop::connect(&mut s).unwrap().dele(1).unwrap_err(), ProtoError::Rejected("1 already deleted".into()));
}

#[test]
fn starttls_is_refused_without_the_servers_word_and_waits_for_nothing() {
    // Never said it could: not asked.
    let mut s = server(&[]);
    assert!(matches!(Pop::connect(&mut s).unwrap().starttls(), Err(ProtoError::Protocol(_))));

    // With its word, the stream comes back clean.
    let mut s = server(&["+OK\r\nSTLS\r\n.\r\n", "+OK going encrypted\r\n"]);
    let mut pop = Pop::connect(&mut s).unwrap();
    assert_eq!(pop.capabilities().unwrap(), ["STLS"]);
    let _stream = pop.starttls().unwrap();
    assert_eq!(s.sent(), "CAPA\r\nSTLS\r\n");

    // Bytes slipped in before the encryption started are refused.
    let out = String::from("+OK pop.example.org ready\r\n+OK\r\nSTLS\r\n.\r\n+OK\r\nslipped\r\n");
    let mut s = Script::whole(out);
    let mut pop = Pop::connect(&mut s).unwrap();
    let _ = pop.capabilities().unwrap();
    assert!(matches!(pop.starttls(), Err(ProtoError::Protocol(_))));
}

#[test]
fn stream_errors_become_connection_problems() {
    let mut pop = Pop::resume(Broken(ErrorKind::TimedOut));
    assert!(matches!(pop.stat(), Err(ProtoError::Io(_))));
    assert!(matches!(pop.noop(), Err(ProtoError::Io(_))));
}

#[test]
fn the_session_hides_its_secrets_in_its_debug() {
    let mut s = server(&[]);
    let pop = Pop::connect(&mut s).unwrap();
    let shown = format!("{pop:?}");
    assert!(!shown.contains("stream"), "{shown}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn hostile_answers_never_panic(
        greeting in "(?:[^\r\n]{0,40}\r\n){0,4}",
        exchanges in "(?:[^\r\n]{0,40}\r\n){0,8}",
    ) {
        let server = format!("+OK ready\r\n{greeting}{exchanges}");
        let mut s = Script::whole(server.as_bytes());
        if let Ok(mut pop) = Pop::connect(&mut s) {
            let _ = pop.capabilities();
            let _ = pop.stat();
            let _ = pop.list();
            let _ = pop.uidl();
            let _ = pop.retr(1);
            let _ = pop.top(1, 2);
            let _ = pop.dele(1);
            let _ = pop.rset();
            let _ = pop.noop();
            let _ = pop.quit();
        }
    }

    #[test]
    fn hostile_signins_never_panic(
        user in "[^\r\n]{0,60}",
        password in "[^\r\n]{0,60}",
        answers in "(?:[^\r\n]{0,40}\r\n){0,4}",
    ) {
        let server = format!("+OK ready\r\n{answers}");
        let mut s = Script::whole(server.as_bytes());
        if let Ok(mut pop) = Pop::connect(&mut s) {
            let _ = pop.login(&user, &password);
        }
    }
}
