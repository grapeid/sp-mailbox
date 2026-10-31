package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/grapeid/sp-mailbox/internal/protocol"
)

const stdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// A key enrols in one string per base64 alphabet. Padded standard base64 of 32
// bytes carries 2 bits before the padding that mean nothing, and the mailbox's
// own lenient decoder read every value of them as the same key.
func TestAKeyInASecondSpellingDoesNotEnrol(t *testing.T) {
	s, _ := newTestServer(t)
	id := newIdentity(t, "EAlice")
	canonical := id.pubB64()
	i := len(canonical) - 2
	second := canonical[:i] + string(stdAlphabet[strings.IndexByte(stdAlphabet, canonical[i])^1]) + canonical[i+1:]

	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: id.aid, PublicKeyB64: second, KEL: "unchecked"}
	id.signRequest(t, req, func(sig string) { req.Signature = sig })
	if w := post(t, s, "/enroll", req); w.Code == http.StatusOK {
		t.Fatalf("enrolled with %q, a second spelling of %q", second, canonical)
	}
}

// A signature has one string per alphabet too: 64 bytes leave 4 bits over.
func TestASignatureInASecondSpellingDoesNotEnrol(t *testing.T) {
	s, _ := newTestServer(t)
	id := newIdentity(t, "EAlice")
	req := protocol.EnrollRequest{V: protocol.JSONVersion, AID: id.aid, PublicKeyB64: id.pubB64(), KEL: "unchecked"}
	id.signRequest(t, req, func(sig string) { req.Signature = sig })
	i := len(req.Signature) - 3 // padded: two "=" follow
	req.Signature = req.Signature[:i] + string(stdAlphabet[strings.IndexByte(stdAlphabet, req.Signature[i])^1]) + req.Signature[i+1:]
	if w := post(t, s, "/enroll", req); w.Code == http.StatusOK {
		t.Fatal("enrolled with a second spelling of the signature")
	}
}
