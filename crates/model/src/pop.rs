// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Telling a POP server from an IMAP one by its name and port alone, so that Add Account can
//! say "MailCraft has no POP yet" instead of trying IMAP on it and showing a TLS error (#402).
//!
//! Pure: nothing is looked up or sent. A host name typed by the owner is hostile text, so it
//! is only compared, never sliced at a byte offset.

use serde::{Deserialize, Serialize};

/// The usual POP3 ports: 110 (STARTTLS or none) and 995 (TLS from the first byte).
const PORTS: [u16; 2] = [110, 995];

/// Longest host name looked at (RFC 1035 allows 253); anything longer is not taken for POP.
const MAX_HOST: usize = 253;

/// Whether an incoming server looks like POP: port 110 or 995, or a host whose first label is
/// `pop`, `pop3` or `pop3s` (any case). `port` 0 means "the usual one" and says nothing.
pub fn looks_like_pop(host: &str, port: u16) -> bool {
    if PORTS.contains(&port) {
        return true;
    }
    let host = host.trim();
    if host.len() > MAX_HOST {
        return false;
    }
    let first = host.split('.').next().unwrap_or("");
    ["pop", "pop3", "pop3s"].iter().any(|label| first.eq_ignore_ascii_case(label))
}

/// What a message downloaded from a POP server does there afterwards (a POP account's only
/// choice about the server side, #402): POP3 has no folders and no flags, so the one thing a
/// run can change is whether the messages it fetched are deleted ([`DELE`]) before it says
/// goodbye, and when.
///
/// [`DELE`]: https://datatracker.ietf.org/doc/html/rfc1939#page-9
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PopOptions {
    /// Whether mail that has been fetched stays on the server. On (the POP norm, and the only
    /// way to read the same mail on two computers) the server keeps it; off, a run deletes what
    /// it fetched, and a message deleted here is gone for good.
    pub leave_mail: bool,
    /// When left: how many days after it arrived the server is asked to drop it, 0 for forever.
    /// Only looked at with [`PopOptions::leave_mail`]. Capped at [`PopOptions::MAX_DAYS`].
    pub leave_days: u32,
}

impl Default for PopOptions {
    fn default() -> PopOptions {
        PopOptions { leave_mail: true, leave_days: 0 }
    }
}

impl PopOptions {
    /// Longest a "drop it after this many days" can be (ten years); anything longer is clamped.
    pub const MAX_DAYS: u32 = 3650;

    /// The options a new account starts with, and what a file that says nothing means.
    pub fn new() -> PopOptions {
        PopOptions::default()
    }

    /// Keep the answer to what can be answered: days within [`PopOptions::MAX_DAYS`].
    pub fn clamp(&mut self) {
        self.leave_days = self.leave_days.min(PopOptions::MAX_DAYS);
    }
}

/// The number a POP message is known by here, from its UIDL (RFC 1939 §3.5): FNV-1a, a hash
/// that needs no table and depends on nothing. POP has no UIDs, so this stands in where the rest
/// of the program asks for one. Two UIDLs can hash to one number, so what has been seen is
/// decided by the UIDL list ([`crate::sync::FolderState::pop_uidls`]) and never by this alone:
/// the hash only carries a message's identity through the parts that speak of UIDs.
pub fn uid_of(uidl: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in uidl.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}
