package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	keri "github.com/grapeid/keri-go"
	"github.com/grapeid/sp-common/sign"
	"github.com/grapeid/sp-common/verify"
	"github.com/grapeid/sp-mailbox/internal/protocol"
	"github.com/grapeid/sp-mailbox/internal/store"
)

// keriIdentity is a real self-addressing identity with a signed key event log,
// the way an Identity Agent enrols.
type keriIdentity struct {
	aid    string
	signer keri.Signer
	pubB64 string
	kelB64 string
}

func newKeriIdentity(t *testing.T) keriIdentity {
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
	kel, err := keri.ExportKEL([][]byte{signed.Message})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := keri.MatterRaw(keri.CodeEd25519, pub, ed25519.PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}
	return keriIdentity{aid: parsed.Identifier, signer: cur, pubB64: base64.StdEncoding.EncodeToString(raw),
		kelB64: base64.RawURLEncoding.EncodeToString(kel)}
}

func (k keriIdentity) signed(t *testing.T, req *protocol.EnrollRequest) {
	t.Helper()
	body, err := sign.CanonicalBody(req)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := k.signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	req.Signature = base64.RawURLEncoding.EncodeToString(sig)
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
	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: id.aid, PublicKeyB64: id.pubB64, KEL: id.kelB64}
	id.signed(t, &req)
	if w := post(t, s, "/enroll", req); w.Code != http.StatusOK {
		t.Fatalf("a genuine enrolment was refused: %d %s", w.Code, w.Body.String())
	}
}

// A genuine log of somebody else's, signed for with that somebody's key, does
// not claim this AID.
func TestSomebodyElsesKeyLogCannotClaimAnAID(t *testing.T) {
	s := keyLogServer(t)
	victim, attacker := newKeriIdentity(t), newKeriIdentity(t)
	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: victim.aid, PublicKeyB64: attacker.pubB64, KEL: attacker.kelB64}
	attacker.signed(t, &req)
	if w := post(t, s, "/enroll", req); w.Code == http.StatusOK {
		t.Fatal("an attacker's own key log claimed somebody else's AID")
	}
}

func TestEnrollingWithoutAKeyLogIsRefused(t *testing.T) {
	s := keyLogServer(t)
	id := newKeriIdentity(t)
	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: id.aid, PublicKeyB64: id.pubB64}
	id.signed(t, &req)
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
