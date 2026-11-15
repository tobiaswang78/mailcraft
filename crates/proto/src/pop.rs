// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! POP3 (RFC 1939) without sockets: [`Pop`] speaks it over any `Read + Write` stream — a TLS
//! socket on the desktop (`mailcraft-net`), a scripted transcript in the tests.
//!
//! What MailCraft asks of a POP server: `CAPA` (RFC 2449), `STLS` (RFC 2595), `USER`/`PASS`,
//! `STAT`, `LIST`, `UIDL`, `RETR`, `TOP`, `DELE`, `RSET`, `NOOP` and `QUIT`. There are no
//! folders and no flags on POP: the one state a run changes is which fetched messages the server
//! is to drop ([`Pop::dele`]) before [`Pop::quit`] makes it so.
//!
//! Everything a server sends is hostile: lines and message sizes are capped, the terminating
//! dot of a multi-line answer is recognised only where it belongs, and nothing here panics on
//! junk. Passwords never reach a log or an error text, even when a server echoes them back.

use std::io::{Read, Write};

use crate::line::Wire;
use crate::{Arg, said};
use crate::{MAX_LINE, MAX_LITERAL, ProtoError, Secrets, for_trace, tidy};

/// How much is asked of the stream in one read (what [`Wire`] asks itself).
const CHUNK: usize = 16 * 1024;

/// Most messages one mailbox may have, from `UIDL` or `LIST`: more than that is refused, not
/// read into memory.
pub const MAX_MESSAGES: usize = 100_000;
/// Longest one UIDL (RFC 1939 §7 says up to 70 characters; a hostile server may say more).
pub const MAX_UIDL: usize = 512;
/// Most bytes of UIDLs in one answer.
const MAX_UIDL_BYTES: usize = 8 * 1024 * 1024;
/// Most lines of one multi-line answer.
const MAX_LINES: usize = 4 * 1024 * 1024;

/// A POP3 session over a stream.
pub struct Pop<S> {
    wire: Wire<S>,
    secrets: Secrets,
    /// What the server said it can do ([`Pop::capabilities`]); `None` while it hasn't said anything.
    capabilities: Option<Vec<String>>,
    authenticated: bool,
    commands: u32,
}

impl<S> std::fmt::Debug for Pop<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The secrets never show, and the stream may not either.
        f.debug_struct("Pop").field("commands", &self.commands).field("authenticated", &self.authenticated).finish()
    }
}

/// `+OK`/`-ERR` and what the server said after it, in a form that can be shown.
fn said_of(line: &[u8]) -> (bool, String) {
    let text = tidy(&String::from_utf8_lossy(line));
    if let Some(rest) = text.strip_prefix("-ERR ") {
        (false, rest.to_string())
    } else if text == "-ERR" {
        (false, String::new())
    } else {
        (text.starts_with("+OK"), text.trim_start_matches("+OK ").trim_start().to_string())
    }
}

/// Whether a line of a multi-line answer is the one that ends it (`.` alone).
pub(crate) fn is_end(line: &[u8]) -> bool {
    line == b"."
}

impl<S> Pop<S> {
    /// Continue on a stream that has already greeted (after the caller wrapped it in TLS).
    pub fn resume(stream: S) -> Pop<S> {
        Pop { wire: Wire::new(stream), secrets: Secrets::default(), capabilities: None, authenticated: false, commands: 0 }
    }

    /// Whether the session is signed in: after [`login`](Self::login).
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// How many commands the session has run.
    pub fn commands(&self) -> u32 {
        self.commands
    }
}

impl<S: Read + Write> Pop<S> {
    /// Read the greeting (`+OK`; anything else, or a silence, is an error).
    pub fn connect(stream: S) -> Result<Pop<S>, ProtoError> {
        let mut pop = Pop::resume(stream);
        let greeting = pop.line()?;
        let (ok, said) = said_of(&greeting);
        if !ok {
            return Err(if greeting.starts_with(b"-ERR") {
                // A server that won't talk to us said so itself.
                ProtoError::Rejected(said.into())
            } else {
                ProtoError::Protocol(said!("the server didn't greet like a POP server: {reason}", reason = Arg::said(said.into())))
            });
        }
        Ok(pop)
    }

    /// The stream the session runs on, for its owner to set up between commands (how long a
    /// socket waits, say). Reading from it or writing to it would take the session apart.
    pub fn get_mut(&mut self) -> &mut S {
        self.wire.get_mut()
    }

    /// One line from the server, said as a trace without its secrets.
    fn line(&mut self) -> Result<Vec<u8>, ProtoError> {
        let line = self.wire.read_line()?;
        log::trace!("S: {}", for_trace(&self.secrets.hide(&String::from_utf8_lossy(&line))));
        Ok(line)
    }

    /// Send one command line; a hostile name or argument was refused by its caller.
    fn send(&mut self, command: &str) -> Result<(), ProtoError> {
        self.commands = self.commands.saturating_add(1);
        log::trace!("C: {command}");
        self.wire.write(command.as_bytes())?;
        self.wire.write(b"\r\n")?;
        self.wire.flush()
    }

    /// Run one single-line command and read its answer: `Ok(rest)` for `+OK …`,
    /// `Err(ProtoError::Rejected)` for `-ERR …`.
    fn command(&mut self, command: &str) -> Result<String, ProtoError> {
        self.send(command)?;
        let answer = self.line()?;
        let (ok, said) = said_of(&answer);
        if ok {
            Ok(said)
        } else if answer.starts_with(b"-ERR") {
            Err(ProtoError::Rejected(said.into()))
        } else {
            Err(ProtoError::Protocol(said!("the server answered a command with neither +OK nor -ERR")))
        }
    }

    /// The lines of a multi-line answer, its byte-stuffing taken back (RFC 1939 §3: a line the
    /// server begins with an extra `.` comes with it gone, and a `.` alone ends it). At most
    /// `cap` bytes, counted as the bytes arrive; more is an error, not a silence.
    fn multiline(&mut self, cap: usize) -> Result<Vec<u8>, ProtoError> {
        let mut out = Vec::with_capacity(cap.min(CHUNK));
        let mut lines = 0usize;
        loop {
            lines = lines.saturating_add(1);
            if lines > MAX_LINES {
                return Err(ProtoError::Protocol(said!("the server sent more lines than MailCraft reads")));
            }
            let line = self.line()?;
            if is_end(&line) {
                return Ok(out);
            }
            // The sender's byte-stuffing taken back: a line that began with a dot loses the one
            // it was given (RFC 1939 §3), so `..` was `.` and `.x` was `x`.
            let line = line.strip_prefix(b".").unwrap_or(line.as_slice());
            if out.len().saturating_add(line.len()) > cap {
                return Err(ProtoError::Protocol(said!("the server sent more than MailCraft reads of one answer")));
            }
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }

    /// What the server says it can do (RFC 2449), upper-cased: `UIDL`, `TOP`, `STLS`, `PIPELINING`….
    /// A server that refuses `CAPA` (one from before RFC 2449) or says nothing of itself is
    /// answered with an empty list, not an error: the session can still be used the RFC 1939 way.
    pub fn capabilities(&mut self) -> Result<Vec<String>, ProtoError> {
        if self.send("CAPA").is_err() {
            self.capabilities = Some(Vec::new());
            return Ok(Vec::new());
        }
        let answer = self.line()?;
        if !answer.starts_with(b"+OK") {
            self.capabilities = Some(Vec::new());
            return Ok(Vec::new());
        }
        let lines = self.multiline(MAX_LINE)?;
        let caps: Vec<String> =
            String::from_utf8_lossy(&lines).lines().filter_map(|line| line.split_whitespace().next()).map(|word| word.to_ascii_uppercase()).collect();
        self.capabilities = Some(caps.clone());
        Ok(caps)
    }

    fn offers(&self, capability: &str) -> bool {
        self.capabilities.as_ref().is_some_and(|caps| caps.iter().any(|c| c == capability))
    }

    /// Send STLS and hand the stream back for the caller to wrap; call
    /// [`resume`](Self::resume) afterwards. A server that never said it could is not asked.
    pub fn starttls(mut self) -> Result<S, ProtoError> {
        if !self.offers("STLS") {
            return Err(ProtoError::Protocol(said!("the server never said it could start a secure connection")));
        }
        self.command("STLS")?;
        // Anything after the go-ahead was slipped in before encryption started.
        if self.wire.has_pending() {
            return Err(ProtoError::Protocol(said!("the server sent data before the secure connection started")));
        }
        Ok(self.wire.into_inner())
    }

    /// `USER` then `PASS`. A refusal of either is a sign-in failure carrying the server's own
    /// words; the password never shows in an error, a log or a trace.
    pub fn login(&mut self, user: &str, password: &str) -> Result<(), ProtoError> {
        if user.contains(['\0', '\r', '\n']) || password.contains(['\0', '\r', '\n']) || user.len() > MAX_LINE || password.len() > MAX_LINE {
            return Err(ProtoError::Auth(said!("the user name or password has a character that can't be sent")));
        }
        self.secrets.add(password);
        let refused = |e: ProtoError, what: &str| match e {
            ProtoError::Rejected(said) => ProtoError::Auth(said!("the server refused {what}: {reason}", what, reason = Arg::said(said))),
            e => e,
        };
        self.command(&format!("USER {}", sanitize(user))).map_err(|e| refused(e, "the user name"))?;
        self.command(&format!("PASS {}", sanitize(password))).map_err(|e| refused(e, "the password"))?;
        self.authenticated = true;
        Ok(())
    }

    /// How many messages wait and how many bytes they are, all told (`STAT`).
    pub fn stat(&mut self) -> Result<(u32, u64), ProtoError> {
        let said = self.command("STAT")?;
        let mut parts = said.split_whitespace();
        let count = parts.next().and_then(|n| n.parse::<u32>().ok());
        let bytes = parts.next().and_then(|n| n.parse::<u64>().ok());
        match (count, bytes, parts.next()) {
            (Some(count), Some(bytes), None) if usize::try_from(count).unwrap_or(usize::MAX) <= MAX_MESSAGES => Ok((count, bytes)),
            _ => Err(ProtoError::Protocol(said!("the server's answer to STAT said nothing MailCraft reads"))),
        }
    }

    /// Every message, its number and its size in bytes (`LIST`).
    pub fn list(&mut self) -> Result<Vec<(u32, u64)>, ProtoError> {
        self.send("LIST")?;
        let answer = self.line()?;
        let (ok, said) = said_of(&answer);
        if !ok {
            return Err(ProtoError::Rejected(said.into()));
        }
        let lines = self.multiline(MAX_LINE * 4)?;
        let mut out = Vec::new();
        for line in String::from_utf8_lossy(&lines).lines() {
            let mut parts = line.split_whitespace();
            let (n, size) = (parts.next().and_then(|n| n.parse::<u32>().ok()), parts.next().and_then(|n| n.parse::<u64>().ok()));
            if let (Some(n), Some(size)) = (n, size) {
                out.push((n, size));
            }
            if out.len() > MAX_MESSAGES {
                return Err(ProtoError::Protocol(said!("the server holds more messages than MailCraft reads")));
            }
        }
        Ok(out)
    }

    /// Every message, its number and its UIDL (`UIDL`). A message without a UIDL, one whose
    /// UIDL is too long, or too many messages, are an error: without a UIDL a message can't be
    /// told from one already downloaded, so it is better to say so than to hand out doubles.
    pub fn uidl(&mut self) -> Result<Vec<(u32, String)>, ProtoError> {
        self.send("UIDL")?;
        let answer = self.line()?;
        let (ok, said) = said_of(&answer);
        if !ok {
            return Err(ProtoError::Rejected(said.into()));
        }
        let lines = self.multiline(MAX_UIDL_BYTES)?;
        let mut out: Vec<(u32, String)> = Vec::new();
        let mut bytes = 0usize;
        for line in String::from_utf8_lossy(&lines).lines() {
            let mut parts = line.splitn(2, ' ');
            let n = parts.next().and_then(|n| n.parse::<u32>().ok());
            let uidl = parts.next().unwrap_or("").trim().to_string();
            bytes = bytes.saturating_add(uidl.len());
            match (n, uidl.len()) {
                (Some(n), len) if len > 0 && len <= MAX_UIDL && bytes <= MAX_UIDL_BYTES && uidl.chars().all(is_uidl_char) => {
                    if out.iter().any(|(_, known)| *known == uidl) {
                        return Err(ProtoError::Protocol(said!("the server gave the same UIDL to two messages")));
                    }
                    out.push((n, uidl));
                }
                _ => return Err(ProtoError::Protocol(said!("the server named a message in a way MailCraft can't keep"))),
            }
            if out.len() > MAX_MESSAGES {
                return Err(ProtoError::Protocol(said!("the server holds more messages than MailCraft reads")));
            }
        }
        Ok(out)
    }

    /// One message whole, its lines' byte-stuffing taken back (`RETR`). At most
    /// [`MAX_LITERAL`] bytes; the server's number, the one `LIST` and `UIDL` handed out.
    pub fn retr(&mut self, id: u32) -> Result<Vec<u8>, ProtoError> {
        self.fetch(&format!("RETR {id}"), MAX_LITERAL)
    }

    /// A message's headers and its first `lines` lines of body (`TOP`). A server that doesn't
    /// say it can (`TOP` is optional) is not asked by its caller.
    pub fn top(&mut self, id: u32, lines: u32) -> Result<Vec<u8>, ProtoError> {
        self.fetch(&format!("TOP {id} {lines}"), MAX_LITERAL.min(512 * 1024))
    }

    fn fetch(&mut self, command: &str, cap: usize) -> Result<Vec<u8>, ProtoError> {
        self.send(command)?;
        let answer = self.line()?;
        let (ok, said) = said_of(&answer);
        if !ok {
            return Err(ProtoError::Rejected(said.into()));
        }
        self.multiline(cap)
    }

    /// Mark a message to be dropped from the server when the session ends well ([`Pop::quit`]).
    /// Until then nothing has happened: `RSET` ([`Pop::rset`]) takes every mark back.
    pub fn dele(&mut self, id: u32) -> Result<(), ProtoError> {
        self.command(&format!("DELE {id}")).map(|_| ())
    }

    /// Take every [`Pop::dele`] mark back: the server keeps all its mail.
    pub fn rset(&mut self) -> Result<(), ProtoError> {
        self.command("RSET").map(|_| ())
    }

    /// Keep the session from timing out, and learn the server is still there.
    pub fn noop(&mut self) -> Result<(), ProtoError> {
        self.command("NOOP").map(|_| ())
    }

    /// End the session well: only this makes the [`Pop::dele`] marks happen. An ending that the
    /// server refused is a rejection, and what was marked stays marked on some servers (RFC 1939
    /// leaves it to them), so the caller treats every error here as "nothing was deleted".
    pub fn quit(mut self) -> Result<(), ProtoError> {
        self.command("QUIT")?;
        Ok(())
    }
}

/// What a UIDL may be made of: RFC 1939 §7 allows the characters 0x21 to 0x7E — no space, no
/// control character, nothing outside ASCII.
fn is_uidl_char(c: char) -> bool {
    ('\u{21}'..='\u{7e}').contains(&c)
}

/// A name or password is one POP argument of one line: no space, no control character.
/// Anything else is refused by [`Pop::login`] rather than sent.
pub(crate) fn sanitize(text: &str) -> String {
    text.chars().filter(|c| !c.is_control() && *c != ' ').collect()
}
