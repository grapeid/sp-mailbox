package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/grapeid/sp-mailbox/internal/protocol"
	"github.com/grapeid/sp-common/sign"
	"github.com/grapeid/sp-mailbox/internal/store"
	"github.com/grapeid/sp-common/verify"
)

type identity struct {
	aid  string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newIdentity(t *testing.T, aid string) identity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return identity{aid: aid, pub: pub, priv: priv}
}

func (i identity) pubB64() string { return base64.StdEncoding.EncodeToString(i.pub) }

// signRequest fills in the signature over the canonical body, the way an agent
// would.
func (i identity) signRequest(t *testing.T, req interface{}, set func(sig string)) {
	t.Helper()
	body, err := sign.CanonicalBody(req)
	if err != nil {
		t.Fatal(err)
	}
	set(base64.StdEncoding.EncodeToString(ed25519.Sign(i.priv, body)))
}

func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(Config{Store: st, Apex: "https://mailbox.test", AID: "EMailboxOperator"}), st
}

func post(t *testing.T, s *Server, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	r.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	return w
}

func enroll(t *testing.T, s *Server, id identity) protocol.EnrollResponse {
	t.Helper()
	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: id.aid, PublicKeyB64: id.pubB64()}
	id.signRequest(t, req, func(sig string) { req.Signature = sig })

	w := post(t, s, "/enroll", req)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d %s", w.Code, w.Body.String())
	}
	var out protocol.EnrollResponse
	json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func sampleEnvelope() map[string]interface{} {
	return map[string]interface{}{
		"mode": "authcrypt", "ciphertext": "not-readable-by-the-operator",
		"iv": "aXY", "recipients": []interface{}{map[string]interface{}{"kid": "ERecipient"}},
	}
}

// Claiming a mailbox decides who may later read what arrives, so it must be
// proven. An unauthenticated enroll would let anybody register somebody else's
// AID and collect their mail.
func TestEnrollWithoutASignatureIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	id := newIdentity(t, "EAlice")
	w := post(t, s, "/enroll", protocol.EnrollRequest{
		V: protocol.JSONVersion, AID: id.aid, PublicKeyB64: id.pubB64(),
	})
	if w.Code == http.StatusOK {
		t.Fatal("a mailbox was claimed with no signature")
	}
}

func TestEnrollWithAWrongSignatureIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	alice, mallory := newIdentity(t, "EAlice"), newIdentity(t, "EMallory")

	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: alice.aid, PublicKeyB64: alice.pubB64()}
	// Mallory signs a claim on Alice's AID with Alice's key advertised.
	mallory.signRequest(t, req, func(sig string) { req.Signature = sig })

	if w := post(t, s, "/enroll", req); w.Code == http.StatusOK {
		t.Fatal("a claim signed by the wrong key was accepted")
	}
}

// Re-enrolling after a restart should return the same mailbox, not a second
// one.
func TestEnrollIsIdempotentForTheSameKey(t *testing.T) {
	s, _ := newTestServer(t)
	id := newIdentity(t, "EAlice")
	first, second := enroll(t, s, id), enroll(t, s, id)
	if first.DepositToken != second.DepositToken {
		t.Error("re-enrolling produced a different mailbox")
	}
}

// A different key for an existing AID is either a mistake or an attempt to take
// over a mailbox. Neither should be handled by overwriting.
func TestADifferentKeyCannotTakeOverAMailbox(t *testing.T) {
	s, _ := newTestServer(t)
	enroll(t, s, newIdentity(t, "EAlice"))

	attacker := newIdentity(t, "EAlice") // same AID, different key
	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: "EAlice", PublicKeyB64: attacker.pubB64()}
	attacker.signRequest(t, req, func(sig string) { req.Signature = sig })

	if w := post(t, s, "/enroll", req); w.Code == http.StatusOK {
		t.Fatal("a second key took over an existing mailbox")
	}
}

// The whole point: a stranger with no account here can still reach you.
func TestAStrangerCanDepositWithoutAnAccount(t *testing.T) {
	s, _ := newTestServer(t)
	claim := enroll(t, s, newIdentity(t, "EAlice"))

	w := post(t, s, "/deposit", protocol.DepositRequest{
		V: protocol.JSONVersion, DepositToken: claim.DepositToken, Envelope: sampleEnvelope(),
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("an open deposit was refused: %d %s", w.Code, w.Body.String())
	}
}

// Reading somebody's mail is exactly the thing that must be proven.
func TestCollectingWithoutASignatureIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	enroll(t, s, newIdentity(t, "EAlice"))

	w := post(t, s, "/collect", protocol.CollectRequest{V: protocol.JSONVersion, AID: "EAlice"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an unsigned collection returned %d, expected 401", w.Code)
	}
}

// Signing with your own key does not let you read somebody else's mailbox: the
// signature is checked against the ENROLLED key, not one supplied with the
// request.
func TestOneIdentityCannotCollectAnothersMail(t *testing.T) {
	s, _ := newTestServer(t)
	alice := newIdentity(t, "EAlice")
	claim := enroll(t, s, alice)
	post(t, s, "/deposit", protocol.DepositRequest{
		V: protocol.JSONVersion, DepositToken: claim.DepositToken, Envelope: sampleEnvelope()})

	mallory := newIdentity(t, "EMallory")
	req := protocol.CollectRequest{V: protocol.JSONVersion, AID: "EAlice"}
	mallory.signRequest(t, req, func(sig string) { req.Signature = sig })

	if w := post(t, s, "/collect", req); w.Code == http.StatusOK {
		t.Fatal("one identity collected another's mail")
	}
}

// Deposit, collect, acknowledge, and it is gone.
func TestTheFullRoundTrip(t *testing.T) {
	s, _ := newTestServer(t)
	alice := newIdentity(t, "EAlice")
	claim := enroll(t, s, alice)

	for i := 0; i < 3; i++ {
		if w := post(t, s, "/deposit", protocol.DepositRequest{
			V: protocol.JSONVersion, DepositToken: claim.DepositToken, Envelope: sampleEnvelope(),
		}); w.Code != http.StatusCreated {
			t.Fatalf("deposit %d failed: %s", i, w.Body.String())
		}
	}

	collectReq := protocol.CollectRequest{V: protocol.JSONVersion, AID: alice.aid}
	alice.signRequest(t, collectReq, func(sig string) { collectReq.Signature = sig })
	w := post(t, s, "/collect", collectReq)
	if w.Code != http.StatusOK {
		t.Fatalf("collect failed: %s", w.Body.String())
	}
	var collected protocol.CollectResponse
	json.Unmarshal(w.Body.Bytes(), &collected)
	if len(collected.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(collected.Messages))
	}

	// Collecting again must still return them: nothing is dropped until the
	// recipient says it has them.
	alice.signRequest(t, collectReq, func(sig string) { collectReq.Signature = sig })
	w = post(t, s, "/collect", collectReq)
	var again protocol.CollectResponse
	json.Unmarshal(w.Body.Bytes(), &again)
	if len(again.Messages) != 3 {
		t.Errorf("collection deleted on read; second collect returned %d", len(again.Messages))
	}

	ids := []string{}
	for _, m := range collected.Messages {
		ids = append(ids, m.MessageID)
	}
	ackReq := protocol.AckRequest{V: protocol.JSONVersion, AID: alice.aid, MessageIDs: ids}
	alice.signRequest(t, ackReq, func(sig string) { ackReq.Signature = sig })
	w = post(t, s, "/ack", ackReq)
	if w.Code != http.StatusOK {
		t.Fatalf("ack failed: %s", w.Body.String())
	}

	alice.signRequest(t, collectReq, func(sig string) { collectReq.Signature = sig })
	w = post(t, s, "/collect", collectReq)
	var empty protocol.CollectResponse
	json.Unmarshal(w.Body.Bytes(), &empty)
	if len(empty.Messages) != 0 {
		t.Errorf("acknowledged messages were kept: %d remain", len(empty.Messages))
	}
}

// Knowing a message ID must not be enough to delete somebody else's mail.
func TestAckIsScopedToTheOwner(t *testing.T) {
	s, _ := newTestServer(t)
	alice := newIdentity(t, "EAlice")
	claim := enroll(t, s, alice)
	w := post(t, s, "/deposit", protocol.DepositRequest{
		V: protocol.JSONVersion, DepositToken: claim.DepositToken, Envelope: sampleEnvelope()})
	var deposited protocol.DepositResponse
	json.Unmarshal(w.Body.Bytes(), &deposited)

	mallory := newIdentity(t, "EMallory")
	enroll(t, s, mallory)
	ackReq := protocol.AckRequest{
		V: protocol.JSONVersion, AID: mallory.aid, MessageIDs: []string{deposited.MessageID}}
	mallory.signRequest(t, ackReq, func(sig string) { ackReq.Signature = sig })

	w = post(t, s, "/ack", ackReq)
	var out protocol.AckResponse
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Dropped != 0 {
		t.Error("one identity deleted another's message by knowing its id")
	}
}

// An unknown token says only that, so this endpoint cannot be used to find out
// who has a mailbox here.
func TestAnUnknownTokenRevealsNothing(t *testing.T) {
	s, _ := newTestServer(t)
	enroll(t, s, newIdentity(t, "EAlice"))

	w := post(t, s, "/deposit", protocol.DepositRequest{
		V: protocol.JSONVersion, DepositToken: "not-a-real-token", Envelope: sampleEnvelope()})
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("EAlice")) {
		t.Error("the response disclosed an enrolled AID")
	}
}

// A mailbox is a way to reach somebody, not a place to park data.
func TestAnOversizedDepositIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	claim := enroll(t, s, newIdentity(t, "EAlice"))

	big := make([]byte, protocol.MaxDepositBytes+1024)
	for i := range big {
		big[i] = 'a'
	}
	w := post(t, s, "/deposit", protocol.DepositRequest{
		V: protocol.JSONVersion, DepositToken: claim.DepositToken,
		Envelope: map[string]interface{}{"ciphertext": string(big)},
	})
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

// Releasing destroys what is in the mailbox.
func TestReleaseDestroysTheMailbox(t *testing.T) {
	s, st := newTestServer(t)
	alice := newIdentity(t, "EAlice")
	claim := enroll(t, s, alice)
	post(t, s, "/deposit", protocol.DepositRequest{
		V: protocol.JSONVersion, DepositToken: claim.DepositToken, Envelope: sampleEnvelope()})

	req := protocol.ReleaseRequest{V: protocol.JSONVersion, AID: alice.aid}
	alice.signRequest(t, req, func(sig string) { req.Signature = sig })
	if w := post(t, s, "/release", req); w.Code != http.StatusOK {
		t.Fatalf("release failed: %s", w.Body.String())
	}

	enrollments, messages, _, err := st.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if enrollments != 0 || messages != 0 {
		t.Errorf("release left %d enrollments and %d messages behind", enrollments, messages)
	}
}

// Retention that only applies when somebody looks is not retention.
func TestExpiredMessagesAreSwept(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "sweep.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, err := st.Enroll("EAlice", "cHVi", ""); err != nil {
		t.Fatal(err)
	}
	// Negative retention: already expired when written.
	if _, err := st.Deposit("EAlice", []byte(`{"ciphertext":"x"}`), -time.Hour,
		protocol.MaxUncollectedPerAID, protocol.MaxBytesPerAID); err != nil {
		t.Fatal(err)
	}

	n, err := st.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 expired message swept, got %d", n)
	}
}

// The descriptor is what lets an agent use a different operator without being
// recompiled, so it has to carry everything needed to do so.
func TestTheDescriptorDescribesTheWholeService(t *testing.T) {
	s, _ := newTestServer(t)
	r := httptest.NewRequest(http.MethodGet, "/.well-known/mailbox-service.json", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("descriptor unavailable: %d", w.Code)
	}
	var d protocol.ServiceDescriptor
	json.Unmarshal(w.Body.Bytes(), &d)
	for name, got := range map[string]string{
		"enroll": d.EnrollEndpoint, "deposit": d.DepositEndpoint,
		"collect": d.CollectEndpoint, "ack": d.AckEndpoint, "release": d.ReleaseEndpoint,
	} {
		if got == "" {
			t.Errorf("descriptor omits the %s endpoint, so an agent cannot use this operator", name)
		}
	}
	if d.MaxDepositBytes == 0 || d.RetentionSeconds == 0 {
		t.Error("descriptor omits the limits an agent needs to know before depositing")
	}
}

// X-Forwarded-For is only meaningful behind a proxy that sets it. Trusting it
// when directly exposed lets any caller forge a source address and walk through
// the per-IP rate limit.
func TestForwardedHeadersAreIgnoredUnlessTrusted(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "xff.db"))
	defer st.Close()
	s := New(Config{Store: st, Apex: "https://mailbox.test"})

	r := httptest.NewRequest(http.MethodPost, "/deposit", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	if got := s.sourceAddr(r); got != "192.0.2.10" {
		t.Errorf("a forged forwarded header was trusted: got %q", got)
	}

	trusting := New(Config{Store: st, Apex: "https://mailbox.test", TrustProxyHeaders: true})
	if got := trusting.sourceAddr(r); got != "203.0.113.99" {
		t.Errorf("behind a proxy the forwarded address should be used, got %q", got)
	}
}

// stubVerifier stands in for a KERI service, so enrollment binding can be
// tested without one running.
type stubVerifier struct {
	// bound maps AID to the key that genuinely belongs to it.
	bound map[string]string
}

func (stubVerifier) Enabled() bool { return true }

func (v stubVerifier) Verify(_ context.Context, aid, _, publicKeyB64 string) verify.Result {
	real, ok := v.bound[aid]
	if !ok {
		return verify.Result{Reason: "no KEL published for that AID"}
	}
	if real != publicKeyB64 {
		return verify.Result{Reason: "the key presented is not this identity's current signing key"}
	}
	return verify.Result{Verified: true, CurrentKey: real}
}

func serverWithVerifier(t *testing.T, bound map[string]string) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "verified.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(Config{
		Store: st, Apex: "https://mailbox.test", AID: "EMailboxOperator",
		Verifier: stubVerifier{bound: bound},
	})
}

// The attack T-263 exists to stop: holding a key proves possession, not
// ownership of an identifier. Without binding, anybody can take any AID and
// lock its real owner out of this operator.
func TestAKeyThatDoesNotBelongToTheAIDIsRefused(t *testing.T) {
	alice := newIdentity(t, "EAlice")
	attacker := newIdentity(t, "EAlice") // same AID, their own key
	s := serverWithVerifier(t, map[string]string{"EAlice": alice.pubB64()})

	req := protocol.EnrollRequest{
		V: protocol.JSONVersion, AID: "EAlice",
		PublicKeyB64: attacker.pubB64(), OOBI: "https://attacker.test/oobi/EAlice",
	}
	// The signature is perfectly valid — over their own key.
	attacker.signRequest(t, req, func(sig string) { req.Signature = sig })

	w := post(t, s, "/enroll", req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("an unbound key claimed an AID: %d %s", w.Code, w.Body.String())
	}
}

// The real owner still gets in.
func TestTheRealOwnerEnrollsNormally(t *testing.T) {
	alice := newIdentity(t, "EAlice")
	s := serverWithVerifier(t, map[string]string{"EAlice": alice.pubB64()})

	req := protocol.EnrollRequest{
		V: protocol.JSONVersion, AID: "EAlice",
		PublicKeyB64: alice.pubB64(), OOBI: "https://alice.test/oobi/EAlice",
	}
	alice.signRequest(t, req, func(sig string) { req.Signature = sig })

	if w := post(t, s, "/enroll", req); w.Code != http.StatusOK {
		t.Fatalf("the genuine owner was refused: %d %s", w.Code, w.Body.String())
	}
}

// An AID with nothing published cannot be claimed either — "we could not check"
// is a refusal, not an approval.
func TestAnUncheckableAIDIsRefused(t *testing.T) {
	stranger := newIdentity(t, "EUnknown")
	s := serverWithVerifier(t, map[string]string{"EAlice": "somekey"})

	req := protocol.EnrollRequest{
		V: protocol.JSONVersion, AID: "EUnknown", PublicKeyB64: stranger.pubB64(),
	}
	stranger.signRequest(t, req, func(sig string) { req.Signature = sig })

	if w := post(t, s, "/enroll", req); w.Code != http.StatusForbidden {
		t.Fatalf("an unverifiable AID was accepted: %d", w.Code)
	}
}
