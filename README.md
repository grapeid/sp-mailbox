# sp-mailbox

A mailbox is a relay that stores instead of forwarding.

A relay works when both parties are up at the same time: something arrives, it
goes down the tunnel, the agent answers. That covers most of the day and none of
the awkward parts — a laptop that sleeps, a phone in a tunnel, a machine being
rebuilt. For anything that must not be lost because the recipient happened to be
away, somebody has to hold it.

The shape is the same as the relay's; the timing is not. An agent enrolls,
proves the AID is its own, and is given somewhere to be written to. The
difference is that a **deposit succeeds whether or not the recipient is there**,
and the recipient collects later.

## What this operator can see

Stated plainly, because a service that holds other people's messages should be
honest about what it learns.

| | |
|---|---|
| **Can see** | that an AID has a mailbox here, and when it collects |
| **Can see** | that somebody deposited for that AID, when, from what address, and how big it was |
| **Cannot see** | the content. Deposits are DIDComm envelopes encrypted to the recipient. This process has no key that opens them and is not meant to |
| **Cannot usefully see** | who sent it. The sender's identity is inside the ciphertext. The source IP is visible — a real signal, worth saying out loud — but it is not an identity |

The remaining exposure is **traffic analysis**: timing, size, frequency. That is
not solved here and should not be claimed to be. It is reduced by using more
than one operator, so no single one sees a whole conversation — which is why the
registry an agent draws from is meant to grow.

## The asymmetry that shapes the design

**Writing is open. Reading is signed.**

A stranger must be able to reach you without an account here first — that is
what a mailbox is *for*. So `/deposit` takes no signature. The recipient
authenticates the sender from inside the ciphertext, where the evidence actually
is; requiring a signature at the transport layer would exclude the people the
mailbox exists for while proving nothing the recipient cannot establish itself.

Reading somebody's mail is precisely the thing that has to be proven, so
`/collect`, `/ack` and `/release` are all signed against the key recorded at
enrollment.

What stands between "open" and "abusable" is therefore not authentication but
limits: a size cap, per-AID and per-IP rate limits, and a ceiling on what one
mailbox may accumulate.

## Collection does not delete

Messages are held until the recipient **acknowledges** them.

Deleting on read means a collection that fails halfway loses whatever had
already been sent — the sender believing it was delivered, the recipient never
knowing it existed. Holding until the recipient says it has them costs storage
and loses nothing.

## Enrollment binds the key to the AID

A signature on an enrollment proves the caller holds the key they are
presenting. It proves nothing about whose AID it is — anybody can generate a
key, sign with it, and name somebody else's identifier.

The binding lives in the identity's own key event log. A self-addressing AID is
the Blake3 SAID of its inception event, so an inception containing these keys
either derives this AID or it does not; producing one that derives somebody
else's means finding a hash collision.

So an enrolment carries the identity's signed key event log (`kel`, a CESR
stream in base64url), and this service checks it **in process with keri-go**,
the engine the Identity Agent itself runs, through `sp-common/verify`: the log
must verify, derive the AID claimed, and name the presented key as the current
one. Nothing is fetched and no other service is asked. This is on by default.

Running unverified is a legitimate choice for development and a bad one to make
by omission, so it must be said out loud:

```sh
./mailbox -apex http://localhost:8090 -allow-unverified-enrollment
```

That mode logs a warning on every enrollment, not just at startup.

### What unverified enrollment costs

Squatting, not interception. An attacker who claims an AID that isn't theirs:

- **cannot read anything** — deposits are encrypted to the recipient, and the
  deposit URL is handed out by the recipient out of band, so a token nobody uses
  receives nothing;
- **can deny the real owner** the use of this operator, since a second key for
  an existing AID is refused.

### Signed requests carry only strings

Every signed request is signed over the Identity Agent's one canonical form
(ADR-049): string fields of printable ASCII, keys sorted, no HTML escaping, the
`signature` field left out. So a collect request's `limit` is a decimal string
(`"limit": "50"`), and an acknowledgement's `message_ids` is one string with the
ids separated by single spaces. A number or a list is refused. The signature is
checked over the fields exactly as sent, so a field a client includes counts
even when it is empty.

### A signed request cannot be replayed

Collect, acknowledge and release each carry a `nonce` and a time `t` (RFC 3339),
both signed. The mailbox refuses a request whose time is more than two minutes
from its own, and keeps each nonce (as a digest of identifier and nonce) until
that window has passed, refusing one it has seen. A nonce is recorded only after
the signature verifies, so nobody can spend somebody else's.

### A rotated key keeps its mailbox

An identity that rotates enrols again with its new key and its newer key event
log. When that log extends the one the mailbox holds (every held event, in
order, as keri-go reads them) and names the new key, the mailbox moves to the
new key and keeps its deposit token; the old key stops working at once. Keys are
compared as bytes, so the same key in another base64 spelling is the same key.

### One protocol version

Every request carries `v`. A request in any other version is refused, saying
which version this mailbox speaks.

## Running it

```sh
go build ./cmd/mailbox
./mailbox -apex https://mailbox.example.org -aid EYourOperatorAID -db mailbox.db
```

`-apex` is required and is deliberately not inferred from the request `Host`
header: it is baked into every deposit URL this service hands out, so taking it
from something a caller controls would let somebody redirect other people's
deposits.

| Flag | Env | Default | |
|---|---|---|---|
| `-addr` | `MAILBOX_ADDR`, else `PORT` | `:8090` | listen address |
| `-db` | `MAILBOX_DB` | `mailbox.db` | SQLite path |
| `-apex` | `MAILBOX_APEX` | — | **required**, public origin |
| `-aid` | `MAILBOX_AID` | — | this operator's own AID |
| `-retention` | — | `720h` (30 days) | how long an uncollected message is kept |
| `-trust-proxy` | `MAILBOX_TRUST_PROXY=1` | off | trust `X-Forwarded-For` |
| `-allow-unverified-enrollment` | `MAILBOX_ALLOW_UNVERIFIED=1` | off | **development only**; accepts any key for any AID |

**`-trust-proxy` only behind a proxy that sets the header itself.** Trusting it
while directly exposed lets any caller forge a source address and walk straight
through the per-IP rate limit.

## Protocol

This is one operator's implementation of the mailbox service an Identity Agent
uses to be reached while it is offline. The Identity Agent is open source at
[identity-bot](https://github.com/LF-Decentralized-Trust-labs/identity-bot), and
the network roles it relies on — witness, watcher, relay and the services around
them — are described in its ADR-024 (*KERI Network Participation*). Signed
requests use the same canonical form as the relay, set by ADR-049 (*One signing
form for every service-provider request*). The
mailbox wire format itself is defined by this repository; the body version string
is `IAMAILBOX11JSON`.

Anybody may run this service. An agent is not tied to one operator.

An agent reads `/.well-known/mailbox-service.json` and needs nothing else — the
descriptor carries every endpoint and limit, so switching to a different
operator is configuration rather than a rebuild.

| Endpoint | Signed | |
|---|---|---|
| `GET /.well-known/mailbox-service.json` | no | how this operator works |
| `POST /enroll` | yes | claim a mailbox for an AID |
| `POST /deposit` | **no** | leave one envelope, using a deposit token |
| `POST /collect` | yes | read waiting messages, without deleting them |
| `POST /ack` | yes | confirm messages are held elsewhere; drop them |
| `POST /release` | yes | give up the mailbox and destroy its contents |
| `GET /health` | no | aggregate counts only, never anybody's mailbox |

### Limits

| | |
|---|---|
| Deposit size | 256 KiB — a mailbox is a way to reach somebody, not a place to park data |
| Retention | 30 days, swept on a timer so an abandoned mailbox is emptied |
| Per mailbox | 500 uncollected messages, 32 MiB |
| Rate | 30 deposits/min per AID, 120/min per IP, 60 collections/min |

## Notes for maintainers

Canonical signing, the SSRF guard and key-to-identifier verification come from
`github.com/grapeid/sp-common` rather than living here. They must behave
identically across every service, and a copy per service is how that stops being
true — the canonical form especially, since a one-character disagreement makes
every signature fail with nothing pointing at why.

It is fetched like any other public Go module; no extra configuration is needed.

## Licence

Apache License 2.0 — see `LICENSE`. Contributions require a DCO sign-off; see
`CONTRIBUTING.md`. To report a vulnerability, see `SECURITY.md`.
