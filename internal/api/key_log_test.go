package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"
	"github.com/grapeid/sp-common/sign"
	"github.com/grapeid/sp-common/verify"
	"github.com/grapeid/sp-mailbox/internal/protocol"
	"github.com/grapeid/sp-mailbox/internal/store"
)

// keriIdentity is a real self-addressing identity with a signed key event log,
// the way an Identity Agent enrols, and can rotate.
type keriIdentity struct {
	t        *testing.T
	aid      string
	signer   keri.Signer
	next     keri.Signer
	lastSAID string
	sn       int
	messages [][]byte
}

func newKeriIdentity(t *testing.T) *keriIdentity {
	t.Helper()
	cur, _ := keri.GenerateSigner(true)
	nxt, _ := keri.GenerateSigner(true)
	pub, _ := cur.PublicKey()
	npub, _ := nxt.PublicKey()
	nd, _ := keri.NextDigest(npub)
	ev, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub}, NextDigests: []string{nd}, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	signed, err := keri.SignEvent(ev, cur)
	if err != nil {
		t.Fatal(err)
	}
	return &keriIdentity{t: t, aid: parsed.Identifier, signer: cur, next: nxt, lastSAID: parsed.SAID, messages: [][]byte{signed.Message}}
}

func (k *keriIdentity) rotate() {
	newNext, _ := keri.GenerateSigner(true)
	pub, _ := k.next.PublicKey()
	npub, _ := newNext.PublicKey()
	nd, _ := keri.NextDigest(npub)
	ev, err := keri.BuildRotation(keri.RotationInput{Prefix: k.aid, Keys: []string{pub}, PriorSAID: k.lastSAID, SN: k.sn + 1, NextDigests: []string{nd}})
	if err != nil {
		k.t.Fatal(err)
	}
	signed, err := keri.SignEvent(ev, k.next)
	if err != nil {
		k.t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	k.sn++
	k.lastSAID = parsed.SAID
	k.signer, k.next = k.next, newNext
	k.messages = append(k.messages, signed.Message)
}

func (k *keriIdentity) rawPub() []byte {
	q, _ := k.signer.PublicKey()
	raw, err := keri.MatterRaw(keri.CodeEd25519, q, ed25519.PublicKeySize)
	if err != nil {
		k.t.Fatal(err)
	}
	return raw
}

func (k *keriIdentity) pubB64() string { return base64.StdEncoding.EncodeToString(k.rawPub()) }

func (k *keriIdentity) kelB64() string {
	kel, err := keri.ExportKEL(k.messages)
	if err != nil {
		k.t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(kel)
}

// sign signs a request (a struct or map) over the canonical form and returns
// the signature.
func (k *keriIdentity) sign(req interface{}) string {
	k.t.Helper()
	body, err := sign.CanonicalBody(req)
	if err != nil {
		k.t.Fatal(err)
	}
	sig, err := k.signer.Sign(body)
	if err != nil {
		k.t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(sig)
}

func (k *keriIdentity) enrol(t *testing.T, s *Server, pub string) *httptest.ResponseRecorder {
	t.Helper()
	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: k.aid, PublicKeyB64: pub, KEL: k.kelB64()}
	req.Signature = k.sign(req)
	return post(t, s, "/enroll", req)
}

func (k *keriIdentity) collect(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	req := protocol.CollectRequest{V: protocol.JSONVersion, AID: k.aid, Nonce: nonce(), T: now()}
	req.Signature = k.sign(req)
	return post(t, s, "/collect", req)
}

func keyLogServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(Config{Store: st, Apex: "https://mailbox.test", AID: "EMailboxOperator", Verifier: verify.KeyLog{}})
}

// An identity enrols with its own signed key log, and the mailbox checks it in
// process: no other service is asked.
func TestAnIdentityEnrolsWithItsOwnKeyLog(t *testing.T) {
	s := keyLogServer(t)
	id := newKeriIdentity(t)
	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: id.aid, PublicKeyB64: id.pubB64(), KEL: id.kelB64()}
	req.Signature = id.sign(req)
	if w := post(t, s, "/enroll", req); w.Code != http.StatusOK {
		t.Fatalf("a genuine enrolment was refused: %d %s", w.Code, w.Body.String())
	}
}

// A genuine log of somebody else's, signed for with that somebody's key, does
// not claim this AID.
func TestSomebodyElsesKeyLogCannotClaimAnAID(t *testing.T) {
	s := keyLogServer(t)
	victim, attacker := newKeriIdentity(t), newKeriIdentity(t)
	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: victim.aid, PublicKeyB64: attacker.pubB64(), KEL: attacker.kelB64()}
	req.Signature = attacker.sign(req)
	if w := post(t, s, "/enroll", req); w.Code == http.StatusOK {
		t.Fatal("an attacker's own key log claimed somebody else's AID")
	}
}

func TestEnrollingWithoutAKeyLogIsRefused(t *testing.T) {
	s := keyLogServer(t)
	id := newKeriIdentity(t)
	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: id.aid, PublicKeyB64: id.pubB64()}
	req.Signature = id.sign(req)
	if w := post(t, s, "/enroll", req); w.Code == http.StatusOK {
		t.Fatal("enrolled with no key log to check the key against")
	}
}

// Counts travel as strings, so a client and the mailbox sign the same bytes.
// A number is refused rather than read.
func TestALimitIsADecimalString(t *testing.T) {
	s, _ := newTestServer(t)
	raw, _ := json.Marshal(map[string]any{"v": protocol.JSONVersion, "aid": "EAlice", "limit": 5, "signature": "x"})
	var bad map[string]any
	json.Unmarshal(raw, &bad)
	if w := post(t, s, "/collect", bad); w.Code != http.StatusBadRequest {
		t.Fatalf("a numeric limit gave %d; it must be refused as unreadable", w.Code)
	}
}

// An identity that rotates keeps its mailbox: its newer log extends the one
// held and names the new key, so the key moves, and the old one stops working.
func TestAMailboxFollowsAKeyRotation(t *testing.T) {
	s := keyLogServer(t)
	id := newKeriIdentity(t)
	first := id.enrol(t, s, id.pubB64())
	if first.Code != http.StatusOK {
		t.Fatalf("enrolment failed: %s", first.Body.String())
	}
	old := *id
	id.rotate()
	second := id.enrol(t, s, id.pubB64())
	if second.Code != http.StatusOK {
		t.Fatalf("the rotated key was refused: %d %s", second.Code, second.Body.String())
	}
	var a, b protocol.EnrollResponse
	json.Unmarshal(first.Body.Bytes(), &a)
	json.Unmarshal(second.Body.Bytes(), &b)
	if a.DepositToken != b.DepositToken {
		t.Error("rotating gave the identity a different mailbox")
	}
	if w := id.collect(t, s); w.Code != http.StatusOK {
		t.Fatalf("the new key cannot collect: %d %s", w.Code, w.Body.String())
	}
	if w := old.collect(t, s); w.Code == http.StatusOK {
		t.Fatal("the key rotated away from can still collect")
	}
}

// The same key in another base64 spelling is the same key, not a takeover.
// Checked on an operator without key-log verification, where no newer log can
// move a key, so only a byte comparison of the keys can accept it.
func TestTheSameKeyInAnotherSpellingIsTheSameMailbox(t *testing.T) {
	s, _ := newTestServer(t)
	id := newKeriIdentity(t)
	if w := id.enrol(t, s, id.pubB64()); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	if w := id.enrol(t, s, base64.RawURLEncoding.EncodeToString(id.rawPub())); w.Code != http.StatusOK {
		t.Fatalf("the same key, spelled url-safe, was refused: %d %s", w.Code, w.Body.String())
	}
}

// A captured signed request cannot be sent again, and an old one is refused.
func TestASignedRequestCannotBeReplayedOrAged(t *testing.T) {
	s := keyLogServer(t)
	id := newKeriIdentity(t)
	id.enrol(t, s, id.pubB64())
	req := protocol.CollectRequest{V: protocol.JSONVersion, AID: id.aid, Nonce: nonce(), T: now()}
	req.Signature = id.sign(req)
	if w := post(t, s, "/collect", req); w.Code != http.StatusOK {
		t.Fatalf("first use refused: %s", w.Body.String())
	}
	if w := post(t, s, "/collect", req); w.Code == http.StatusOK {
		t.Fatal("the same signed request was accepted twice")
	}
	aged := protocol.CollectRequest{V: protocol.JSONVersion, AID: id.aid, Nonce: nonce(),
		T: time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)}
	aged.Signature = id.sign(aged)
	if w := post(t, s, "/collect", aged); w.Code == http.StatusOK {
		t.Fatal("a request signed ten minutes ago was accepted")
	}
}

// The signature covers what was sent: a field a struct would leave out (an
// empty limit) is still part of the signed bytes.
func TestTheSignatureCoversTheFieldsAsSent(t *testing.T) {
	s := keyLogServer(t)
	id := newKeriIdentity(t)
	id.enrol(t, s, id.pubB64())
	fields := map[string]string{"v": protocol.JSONVersion, "aid": id.aid, "limit": "", "nonce": nonce(), "t": now()}
	fields["signature"] = id.sign(fields)
	if w := post(t, s, "/collect", fields); w.Code != http.StatusOK {
		t.Fatalf("a request with an explicit empty limit did not verify: %d %s", w.Code, w.Body.String())
	}
}

func TestAnotherProtocolVersionIsRefusedPlainly(t *testing.T) {
	s := keyLogServer(t)
	w := post(t, s, "/collect", map[string]string{"v": "IAMAILBOX10JSON", "aid": "EAID"})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), protocol.JSONVersion) {
		t.Fatalf("an old version gave %d %s; it must be refused naming the version spoken", w.Code, w.Body.String())
	}
}
