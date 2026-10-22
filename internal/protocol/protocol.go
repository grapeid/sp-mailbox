package protocol

import "time"

// A mailbox is a relay that stores instead of forwarding.
//
// A relay works when both parties are up at the same time: something arrives,
// it goes down the tunnel, the agent answers. That covers most of the day and
// none of the awkward parts — a laptop that sleeps, a phone in a tunnel, a
// machine being rebuilt. For anything that must not be lost because the
// recipient happened to be away, somebody has to hold it.
//
// So the shape is the same as the relay's and the timing is not. An agent
// enrolls, proves the AID is its own, and is given somewhere to be written to.
// The difference is that a deposit succeeds whether or not the recipient is
// there, and the recipient collects later.
//
// WHAT THIS OPERATOR CAN SEE, stated plainly, because a service that holds
// other people's messages should be honest about it:
//
//   - That an AID has a mailbox here, and when it collects.
//   - That somebody deposited for that AID, when, from what address, and how
//     big it was.
//   - NOT the content. Deposits are DIDComm envelopes encrypted to the
//     recipient. This process has no key that opens them and is not meant to.
//   - NOT, usefully, who sent it. The sender's identity is inside the
//     ciphertext. The source IP is visible, which is a real signal and worth
//     saying out loud, but it is not an identity.
//
// The remaining exposure is traffic analysis — timing, size, frequency — and
// that is not solved here. It is reduced by using more than one operator, so
// that no single one sees a whole conversation, which is why the registry an
// agent draws from is meant to grow.

// SignedRequestWindow is how far a signed request's time may be from the
// mailbox's.
const SignedRequestWindow = 2 * time.Minute

const (
	Version     = "1.1"
	JSONVersion = "IAMAILBOX11JSON"

	// A deposit is one DIDComm envelope. The cap is generous for a message and
	// mean for a file: a mailbox is a way to reach somebody who is away, not a
	// place to park data.
	MaxDepositBytes = 256 * 1024

	// How long an uncollected message is kept. Long enough to cover a holiday,
	// short enough that a mailbox is not an archive of everything anybody ever
	// sent you. An operator holding messages forever is an operator with a
	// great deal to lose.
	DefaultRetention = 30 * 24 * time.Hour

	// Bounds on what one AID can accumulate. Without these, anyone can fill a
	// stranger's mailbox and either bankrupt the operator or deny the service
	// to its owner.
	MaxUncollectedPerAID = 500
	MaxBytesPerAID       = 32 * 1024 * 1024

	// Deposits are open by design — a stranger must be able to reach you
	// without an account here first — so the limits are what stands between
	// open and abusable.
	DepositPerMinutePerAID = 30
	DepositPerMinutePerIP  = 120
	CollectPerMinute       = 60
)

// ServiceDescriptor is what an agent reads to learn how to use this operator,
// served at /.well-known/mailbox-service.json.
//
// Published rather than assumed so that an agent is not compiled against one
// operator. Everything an agent needs to switch to a different mailbox should
// be in this document.
type ServiceDescriptor struct {
	V                string         `json:"v"`
	ProtocolVersion  string         `json:"protocol_version"`
	MailboxAID       string         `json:"mailbox_aid"`
	Apex             string         `json:"apex"`
	EnrollEndpoint   string         `json:"enroll_endpoint"`
	DepositEndpoint  string         `json:"deposit_endpoint"`
	CollectEndpoint  string         `json:"collect_endpoint"`
	AckEndpoint      string         `json:"ack_endpoint"`
	ReleaseEndpoint  string         `json:"release_endpoint"`
	MaxDepositBytes  int            `json:"max_deposit_bytes"`
	RetentionSeconds int            `json:"retention_seconds"`
	MaxUncollected   int            `json:"max_uncollected_per_aid"`
	RateLimitsPerMin map[string]int `json:"rate_limits_per_min"`
}

// EnrollRequest claims a mailbox for an AID.
//
// The AID here should be a pairwise identity minted for this operator and used
// nowhere else. Nothing enforces that — this process cannot tell one AID from
// another — but it is what keeps an operator from learning that two mailboxes
// belong to one person.
type EnrollRequest struct {
	V            string `json:"v"`
	AID          string `json:"aid"`
	PublicKeyB64 string `json:"public_key_b64"`
	OOBI         string `json:"oobi,omitempty"`
	// KEL is the identity's signed key event log, a CESR stream in base64url.
	// It is what proves the key belongs to the AID, and it is signed with the
	// rest of the request.
	KEL       string `json:"kel"`
	Signature string `json:"signature"`
}

type EnrollResponse struct {
	Enrolled     bool   `json:"enrolled"`
	AID          string `json:"aid"`
	DepositToken string `json:"deposit_token"`
	DepositURL   string `json:"deposit_url"`
}

// DepositRequest leaves one envelope for an AID.
//
// Deliberately unsigned. A stranger must be able to write to a mailbox without
// first having an account here, which is the entire point of having one — and
// the recipient authenticates the sender from inside the ciphertext, where the
// evidence actually is. Requiring a signature at this layer would exclude the
// people the mailbox exists for while proving nothing the recipient cannot
// establish for itself.
type DepositRequest struct {
	V            string `json:"v"`
	DepositToken string `json:"deposit_token"`
	// Envelope is an opaque DIDComm envelope. Its shape is the recipient's
	// business; this operator only checks that it is JSON and within size.
	Envelope map[string]interface{} `json:"envelope"`
}

type DepositResponse struct {
	Accepted  bool   `json:"accepted"`
	MessageID string `json:"message_id"`
	ExpiresAt string `json:"expires_at"`
}

// CollectRequest asks for waiting messages. Signed: reading somebody's mail is
// exactly the thing that must be proven.
type CollectRequest struct {
	V   string `json:"v"`
	AID string `json:"aid"`
	// Limit is a decimal count, carried as a string because every signed
	// field is a string (the Identity Agent's ADR-049).
	Limit string `json:"limit,omitempty"`
	// Nonce and T make a captured request useless: the mailbox refuses a
	// request whose time is outside SignedRequestWindow, or whose nonce it
	// has already seen.
	Nonce     string `json:"nonce"`
	T         string `json:"t"`
	Signature string `json:"signature"`
}

// StoredMessage is one waiting envelope.
type StoredMessage struct {
	MessageID   string                 `json:"message_id"`
	Envelope    map[string]interface{} `json:"envelope"`
	DepositedAt string                 `json:"deposited_at"`
	ExpiresAt   string                 `json:"expires_at"`
	SizeBytes   int                    `json:"size_bytes"`
}

type CollectResponse struct {
	AID      string          `json:"aid"`
	Messages []StoredMessage `json:"messages"`
	More     bool            `json:"more"`
}

// AckRequest confirms messages are safely held elsewhere and may be dropped.
//
// Separate from collection on purpose. Deleting on read means a collection that
// fails halfway loses whatever had already been sent, and the sender has no way
// to know. Holding until the recipient says it has them costs storage and loses
// nothing.
type AckRequest struct {
	V   string `json:"v"`
	AID string `json:"aid"`
	// MessageIDs are separated by single spaces: one string, because every
	// signed field is a string (the Identity Agent's ADR-049).
	MessageIDs string `json:"message_ids"`
	// Nonce and T make a captured request useless: the mailbox refuses a
	// request whose time is outside SignedRequestWindow, or whose nonce it
	// has already seen.
	Nonce     string `json:"nonce"`
	T         string `json:"t"`
	Signature string `json:"signature"`
}

type AckResponse struct {
	Dropped int `json:"dropped"`
}

// ReleaseRequest gives up a mailbox and destroys what is in it.
type ReleaseRequest struct {
	V   string `json:"v"`
	AID string `json:"aid"`
	// Nonce and T make a captured request useless: the mailbox refuses a
	// request whose time is outside SignedRequestWindow, or whose nonce it
	// has already seen.
	Nonce     string `json:"nonce"`
	T         string `json:"t"`
	Signature string `json:"signature"`
}
