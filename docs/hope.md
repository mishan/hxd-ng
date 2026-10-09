# HOPE: the secure login on the classic wire

Status: partial, 2026-10. Built: the login, Blowfish OFB-64 with gzip or
LZ4 beneath it, `[hope]`. Planned: ChaCha20-Poly1305 with its encrypted
file transfers (§5), and `DATA_LINK_USER_TRANSPORT` on server links (§6).

HOPE replaces the classic login's XOR-scrambled password with a MAC of it
under a key the server picks, and can go on to encrypt the rest of the
connection. The protocol is hx-libs' `hxhope`, which GtkHx's client runs
too, tested against mhxd and Janus field for field; this server adds the
I/O, the accounts and the limits around it. A client that does not speak
HOPE never sends its first step, and sees nothing different.

## 1. Where it is offered

On the plain classic port, and inside a `/trtp` tunnel the client
declared cleartext downstream. It is refused, with a reason the client
shows, on any transport already encrypted: the TLS port and an encrypted
tunnel. The same protection twice buys nothing, and GtkHx refuses the
combination from its side too.

## 2. The login

Step 1 is a LOGIN whose login is a single zero byte. The server answers
with its choices and a random 64-byte session key: of each list the
client offered, the first it has (mhxd's rule).
Step 2 is a second LOGIN carrying the login and the password, each a MAC
under that key; its name, icon, version and capabilities are read as a
plain login's are, Text-Encoding included.

- **The login is named only as a MAC**, so the server tries each
  account's, as mhxd does: an HMAC per account per HOPE login. An empty
  login is the guest's. Account logins are lower case, and a HOPE client
  must type its login that way, where the plain login takes any case: a
  MAC cannot be lowered.
- **The password is checked as the client typed it**: the account's
  stored password, encoded the way the connection reads text (Mac Roman,
  or UTF-8 when Text-Encoding was negotiated), is what the MAC must be
  of. The check runs inside the auth backend (`Proof::Keyed`), which
  derives the session's keys from the password and never hands it back.
- **Everything else is the plain login's**: the throttle on wrong
  passwords (`Core::login_attempt` before, `Core::login_failed` after),
  the bans, the login permit, the move to the account's count, the
  identity reconciliation of a tunnel. A step 2 naming no account is a
  wrong guess at its address alone.

From the reply to step 2 on, both directions run through the transport,
a refusal after the password included. A wrong password agrees nothing,
and is refused in plaintext.

## 3. The transport

The connection's socket halves run through adaptors that pass bytes as
they are until the password verifies, when the transport's sending half
and receiving half go into them, before the reply to step 2 is queued.
Nothing earlier is still waiting to be written: the only frame before it
is the reply to step 1, which the client has read. The writer hands its
adaptor whole transactions, which a Blowfish transport's rekey markers
are placed by.

A session under a cipher is `encrypted` (`hotline-ng-auth.md` §8): an ng
client sees it so, and the cleartext marker is not set for it.

RC4, which some legacy HOPE clients offer, is not: `hxhope` has no RC4,
and it would not be counted as encrypted if it did. A client offering
nothing else logs in with HOPE's password protection over plaintext,
unless `require_cipher` refuses it.

## 4. Configuration

```toml
[hope]
enabled = true          # false refuses step 1 with a reason
require_cipher = false  # true refuses a client with no cipher in common
```

On by default, off by default respectively, as mhxd has them. The image
takes `HXD_HOPE` and `HXD_HOPE_REQUIRE_CIPHER` (`docker.md`).

## 5. ChaCha20-Poly1305 and file transfers

A client that agrees ChaCha20-Poly1305 also encrypts its file transfers,
with keys `hxhope` derives per transfer. Until the transfer port does the
same, such a client's transfers would fail, so the cipher is not offered.
When it is, a Blowfish session's transfers stay plaintext, as on mhxd.

## 6. Across server links

`DATA_LINK_USER_TRANSPORT` (proposed `0x0645`) tells linked servers
whether a user's own connection is encrypted. A HOPE session under
Blowfish or ChaCha20-Poly1305 is `1`, one with no cipher `2`. Proposed to
fogWraith and not yet assigned.
