// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reading a POP account's Inbox (RFC 1939) and turning what came into the answer a run hands
//! over, as an IMAP run does: new mail in [`FolderDelta::new`], what the server no longer has in
//! [`FolderDelta::removed`], and its UIDLs in [`FolderDelta::pop_uidls`].
//!
//! POP knows one folder and no flags. What has been seen is decided by the UIDL list, never by
//! the UID a message goes by here (a hash of its UIDL, [`mailcraft_model::pop::uid_of`]): two
//! UIDLs can share a hash, so only the list is the truth. The one thing a run changes on the
//! server is which fetched messages it deletes ([`Pop::dele`]), when the owner said not to leave
//! mail there.

use std::collections::HashSet;
use std::sync::atomic::AtomicBool;

use mailcraft_i18n::said;
use mailcraft_model::sync::{FolderDelta, SyncStage, SyncStep};
use mailcraft_model::{Account, FolderKind, Security};
use mailcraft_proto::imap::Fetched;
use mailcraft_proto::pop::Pop;

use crate::sync::{BATCH_BYTES, BATCH_MESSAGES, Run, label};
use crate::transport::{self, Patience, Service, Stream};
use crate::{NetError, not_signed_in};

/// The `UIDVALIDITY` every POP folder goes by: there are no UIDs and no renumbering to tell
/// apart, so one constant keeps the engine's UID bookkeeping quiet.
const POP_VALIDITY: u32 = 1;
/// The Inbox's path, as every POP server names it.
const INBOX: &str = "INBOX";

/// Connect to the account's POP server, encrypt as it asks, and sign in with `secret` as the
/// password. A POP account signs in with a password alone: there is no OAuth on POP.
pub(crate) fn open_pop_with<'a>(
    account: &Account,
    secret: &str,
    patience: &Patience,
    cancel: Option<&'a AtomicBool>,
) -> Result<Pop<Stream<'a>>, NetError> {
    let server = account.incoming.as_ref().ok_or_else(|| NetError::Config(said!("the account has no incoming server")))?;
    if account.oauth.is_some() {
        return Err(NetError::Config(said!("a POP server is not signed in to through Microsoft or Google: it takes a password")));
    }
    let user = account.login();
    if user.is_empty() {
        return Err(NetError::Config(said!("the account has no user name or e-mail address to sign in with")));
    }
    if secret.is_empty() {
        return Err(NetError::Config(said!("enter a password to sign in")));
    }
    let (mut stream, host) = transport::open(server, Service::Pop, patience)?;
    stream.watch(cancel);
    let mut pop = Pop::connect(stream)?;
    let caps = pop.capabilities()?;
    if server.security == Security::StartTls {
        // Never carry on in the clear when encryption was asked for.
        if !caps.iter().any(|c| c == "STLS") {
            return Err(NetError::Tls { host, reason: said!("the server doesn't offer STARTTLS") });
        }
        let plain = pop.starttls()?;
        pop = Pop::resume(transport::upgrade(plain, &host)?);
        pop.capabilities()?;
    }
    pop.login(user, secret).map_err(|e| match e {
        mailcraft_proto::ProtoError::Auth(_) => not_signed_in(account),
        e => NetError::from(e),
    })?;
    Ok(pop)
}

/// Read the account's Inbox and note what changed in the run's answer. The outbox went out
/// before this ([`crate::sync::send_outbox`], through the account's own SMTP server); there are
/// no folders to list, no changes to push and no flags to read: only what the server has and we
/// don't comes down.
pub(crate) fn exchange_pop(run: &mut Run<'_>) {
    let request = run.request;
    if request.account.incoming.is_none() {
        return;
    }
    if run.cancelled() {
        return;
    }
    run.hand_over(SyncStep::new(SyncStage::Connecting, "", 0, 0));
    let mut pop = match open_pop_with(&request.account, request.secret(), &run.limits.patience, Some(run.cancel)) {
        Ok(pop) => pop,
        Err(e) => {
            run.failed(said!("Couldn't check for new mail"), &e);
            return;
        }
    };
    // What we know of the Inbox already: the messages known here, by UIDL.
    let state = request.folders.iter().find(|f| f.kind == FolderKind::Inbox);
    let (id, known) = state.map_or((None, Vec::new()), |s| (Some(s.id), s.pop_uidls.clone()));
    let known: HashSet<&str> = known.iter().map(String::as_str).collect();
    let caps = pop.capabilities().unwrap_or_default();
    let sizes = match pop.list() {
        Ok(sizes) => sizes,
        Err(e) => {
            pop.get_mut().leave();
            let _ = pop.quit();
            run.failed(said!("Couldn't read the account's mail"), &e.into());
            return;
        }
    };
    let listed = if caps.iter().any(|c| c == "UIDL") {
        match pop.uidl() {
            Ok(listed) => Some(listed),
            Err(e) => {
                pop.get_mut().leave();
                let _ = pop.quit();
                run.failed(said!("Couldn't read the account's mail"), &e.into());
                return;
            }
        }
    } else {
        None
    };
    let Some(listed) = listed else {
        // Without UIDL a message can't be told from one already here: saying nothing would
        // bring everything down again at every run.
        pop.get_mut().leave();
        let _ = pop.quit();
        run.out.problem(said!("The server can't name its messages (no UIDL), so MailCraft can't tell what is new"));
        return;
    };
    let have: HashSet<&str> = listed.iter().map(|(_, uidl)| uidl.as_str()).collect();
    let sizes: std::collections::HashMap<u32, u64> = sizes.into_iter().collect();
    let removed: Vec<u32> = known.iter().filter(|uidl| !have.contains(**uidl)).map(|uidl| mailcraft_model::pop::uid_of(uidl)).collect();
    let mut delta = FolderDelta { id, remote: INBOX.into(), kind: FolderKind::Inbox, uid_validity: POP_VALIDITY, removed, ..Default::default() };
    // What to download, in the order the server keeps them (the order they arrived).
    let wanted: Vec<(u32, &String, u64)> =
        listed.iter().filter(|(_, uidl)| !known.contains(uidl.as_str())).map(|(n, uidl)| (*n, uidl, sizes.get(n).copied().unwrap_or(0))).collect();
    let wanted_total = wanted.len();
    let leave = request.account.pop_options();
    let mut waiting = 0usize;
    let mut fetched = 0usize;
    let mut alive = true;
    let mut to_delete: Vec<u32> = Vec::new();
    run.hand_over(SyncStep::new(SyncStage::Reading, &label(INBOX), 0, wanted_total));
    for (at, (n, uidl, size)) in wanted.iter().enumerate() {
        if !alive || run.cancelled() || run.limits.messages == 0 || run.limits.bytes == 0 {
            break;
        }
        run.limits.messages = run.limits.messages.saturating_sub(1);
        let uid = mailcraft_model::pop::uid_of(uidl);
        if *size > run.limits.largest {
            // Only its header comes, and a note in the place of its text (#300). A server that
            // can't send a header alone leaves the message where it is, for the next run.
            if !caps.iter().any(|c| c == "TOP") {
                run.out.problem(said!("A message larger than MailCraft takes stays on the server: it can't be read a part at a time"));
                continue;
            }
            match pop.top(*n, 100) {
                Ok(bytes) => {
                    let got = Fetched { uid, flags: Vec::new(), internal_date: None, body: Some(bytes), gmail_id: None, gmail_labels: None };
                    delta.new.push(crate::sync::too_large(got, *size, run.limits.largest));
                    fetched += 1;
                    if !leave.leave_mail {
                        to_delete.push(*n);
                    }
                }
                Err(e) => alive = run.failed(said!("Couldn't read a message of the Inbox"), &e.into()),
            }
        } else {
            match pop.retr(*n) {
                Ok(bytes) => {
                    let mut m = mailcraft_mime_model::parse_fetched(&bytes);
                    m.uid = uid;
                    // POP says nothing of what has been read: mail that comes is unread.
                    m.read = false;
                    run.limits.bytes = run.limits.bytes.saturating_sub(bytes.len());
                    waiting = waiting.saturating_add(bytes.len());
                    delta.new.push(m);
                    fetched += 1;
                    if !leave.leave_mail {
                        to_delete.push(*n);
                    }
                }
                Err(e) => alive = run.failed(said!("Couldn't read a message of the Inbox"), &e.into()),
            }
        }
        let full = delta.new.len() >= BATCH_MESSAGES || waiting >= BATCH_BYTES;
        // The last of them go with what ends the Inbox, below.
        if full && at + 1 < wanted_total {
            let rest = FolderDelta { id, remote: INBOX.into(), kind: FolderKind::Inbox, uid_validity: POP_VALIDITY, ..Default::default() };
            let mut batch = std::mem::replace(&mut delta, rest);
            batch.new.sort_by_key(|m| m.uid);
            run.out.folders.push(batch);
            run.hand_over(SyncStep::new(SyncStage::Reading, &label(INBOX), at + 1, wanted_total));
            waiting = 0;
        }
    }
    // Everything wanted came: the Inbox is read whole, and its UIDLs are said with this piece.
    delta.complete = alive && fetched == wanted_total;
    if delta.complete {
        delta.pop_uidls = listed.iter().map(|(_, uidl)| uidl.clone()).collect();
    }
    delta.new.sort_by_key(|m| m.uid);
    run.out.folders.push(delta);
    // Delete what was fetched, when the owner said so: marked first, made so by the goodbye.
    if alive && !run.cancelled() && !to_delete.is_empty() {
        let failed = to_delete.iter().filter(|n| pop.dele(**n).is_err()).count();
        if failed > 0 {
            run.out.problem(match failed {
                1 => said!("The server wouldn't delete 1 of the messages MailCraft fetched; they are all left there"),
                count => said!("The server wouldn't delete {count} of the messages MailCraft fetched; they are all left there", count),
            });
            // All or nothing: what was marked is taken back, so no message is lost twice over
            // (the run said it couldn't, and they come here again if the setting changes).
            let _ = pop.rset();
        }
    }
    pop.get_mut().leave();
    // The goodbye is what makes the deletions happen; without it, nothing was deleted.
    if pop.quit().is_err() && !to_delete.is_empty() && alive && !run.cancelled() {
        run.out.problem(said!("The session ended without the server saying the fetched mail was deleted; it may come again"));
    }
}
