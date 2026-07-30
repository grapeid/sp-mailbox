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

## Known limitation: enrollment does not bind a key to an AID

**This is the one thing to read before running this in production.**

`/enroll` verifies the signature against the public key **supplied in the
request**. That proves the caller holds the key it is presenting. It does *not*
prove the key belongs to the AID being claimed, because doing so means resolving
the AID's KEL and checking the current signing key — which this service does not
do.

The practical consequence is **squatting, not interception**:

- Someone can claim an AID that is not theirs, if they get there first.
- They cannot read anything as a result. Deposits are encrypted to the
  recipient's key, and the deposit URL is handed out by the recipient
  out of band — an attacker holding a token nobody uses receives nothing.
- What they can do is **deny the real owner the use of this operator**, since a
  second key for an existing AID is refused.

The fix is to resolve the enrolling AID's OOBI and require the presented key to
match its current signing key, behind an SSRF guard. `sp-url-relay` has the same
gap and the same fix, which is part of why it is worth doing once, properly,
rather than twice.

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

**`-trust-proxy` only behind a proxy that sets the header itself.** Trusting it
while directly exposed lets any caller forge a source address and walk straight
through the per-IP rate limit.

## Protocol

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

`internal/sign` is a **copy** of the equivalent in `sp-url-relay`. The canonical
form must agree byte for byte across every service or signatures fail, and two
copies drifting produces `signature invalid` with no clue why. It should become
a shared module rather than a copy per service — an architecture decision, not
one to make here.
