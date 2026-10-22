package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	"github.com/grapeid/sp-common/sign"
	"github.com/grapeid/sp-common/verify"
	"github.com/grapeid/sp-mailbox/internal/protocol"
	"github.com/grapeid/sp-mailbox/internal/store"
)

// The HTTP surface.
//
// Five things an agent can do: learn how this operator works, claim a mailbox,
// write to somebody's, read your own, and give yours up.
//
// The asymmetry between writing and reading is the whole design. WRITING is
// open, because a stranger must be able to reach you without an account here
// first — that is what a mailbox is for. READING is signed, because reading
// somebody's mail is precisely the thing that has to be proven.

type Server struct {
	store    *store.Store
	apex     string
	aid      string
	retain   time.Duration
	trustXFF bool
	verifier verify.Verifier
}

type Config struct {
	Store *store.Store
	// Apex is this service's public origin, used to build the URLs it hands
	// out. Configured rather than inferred from the request, so a Host header
	// somebody else controls cannot redirect deposits.
	Apex string
	// AID is this operator's own identity, published so an agent can name the
	// mailbox it is relying on.
	AID       string
	Retention time.Duration
	// TrustProxyHeaders should be on only behind a proxy that sets
	// X-Forwarded-For itself. Trusting it when directly exposed lets any caller
	// forge a source address and walk straight through the per-IP rate limit.
	TrustProxyHeaders bool
	// Verifier binds an enrolling key to its AID. When nil, enrollment accepts
	// any key for any AID and the operator is open to squatting — which is a
	// choice, but has to be an explicit one.
	Verifier verify.Verifier
}

func New(cfg Config) *Server {
	retain := cfg.Retention
	if retain <= 0 {
		retain = protocol.DefaultRetention
	}
	v := cfg.Verifier
	if v == nil {
		v = verify.Unverified{}
	}
	return &Server{
		store:    cfg.Store,
		apex:     strings.TrimRight(cfg.Apex, "/"),
		aid:      cfg.AID,
		retain:   retain,
		trustXFF: cfg.TrustProxyHeaders,
		verifier: v,
	}
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/mailbox-service.json", s.handleDescriptor)
	mux.HandleFunc("/enroll", s.handleEnroll)
	mux.HandleFunc("/deposit", s.handleDeposit)
	mux.HandleFunc("/collect", s.handleCollect)
	mux.HandleFunc("/ack", s.handleAck)
	mux.HandleFunc("/release", s.handleRelease)
	mux.HandleFunc("/health", s.handleHealth)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// sourceAddr is the caller's address for rate-limiting purposes.
func (s *Server) sourceAddr(r *http.Request) string {
	if s.trustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Leftmost is the original client. Everything after is proxies.
			if i := strings.IndexByte(xff, ','); i > 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleDescriptor(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, protocol.ServiceDescriptor{
		V:                protocol.JSONVersion,
		ProtocolVersion:  protocol.Version,
		MailboxAID:       s.aid,
		Apex:             s.apex,
		EnrollEndpoint:   s.apex + "/enroll",
		DepositEndpoint:  s.apex + "/deposit",
		CollectEndpoint:  s.apex + "/collect",
		AckEndpoint:      s.apex + "/ack",
		ReleaseEndpoint:  s.apex + "/release",
		MaxDepositBytes:  protocol.MaxDepositBytes,
		RetentionSeconds: int(s.retain.Seconds()),
		MaxUncollected:   protocol.MaxUncollectedPerAID,
		RateLimitsPerMin: map[string]int{
			"deposit_per_aid": protocol.DepositPerMinutePerAID,
			"deposit_per_ip":  protocol.DepositPerMinutePerIP,
			"collect":         protocol.CollectPerMinute,
		},
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	enrollments, messages, bytes, err := s.store.Stats()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "enrollments": enrollments,
		"messages_waiting": messages, "bytes_waiting": bytes,
	})
}

// readBody reads a request body with a hard ceiling, so an oversized or endless
// body cannot exhaust memory before it is rejected.
func readBody(r *http.Request, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, max+1))
}

// handleEnroll claims a mailbox for an AID.
//
// Signed, because a claim decides who may later read what arrives. An
// unauthenticated enroll would let anybody register somebody else's AID and
// collect their mail.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	raw, err := readBody(r, 96*1024)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read body")
		return
	}
	var req protocol.EnrollRequest
	fields, err := decodeSigned(raw, &req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.AID == "" || req.PublicKeyB64 == "" || req.KEL == "" || req.Signature == "" {
		writeErr(w, http.StatusBadRequest, "aid, public_key_b64, kel and signature are required")
		return
	}
	presented, err := rawKey(req.PublicKeyB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Signed over exactly what was sent, not a re-encoding of it: a field the
	// client included and a struct would have dropped still counts.
	body, err := sign.CanonicalBody(fields)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not canonicalise request: "+err.Error())
		return
	}
	// First: the caller holds the key they are presenting.
	if err := sign.VerifyEd25519(req.PublicKeyB64, req.Signature, body); err != nil {
		writeErr(w, http.StatusUnauthorized, "signature did not verify: "+err.Error())
		return
	}

	// Second, and the one that matters: the key belongs to the AID.
	//
	// The signature above proves possession of a key, which anybody can
	// generate. It says nothing about whose identifier this is. Without the
	// check below, an attacker can claim any AID they can name — not to read
	// anything, since deposits are encrypted to the recipient, but to take the
	// identifier and deny its real owner the use of this operator.
	verified := false
	if s.verifier.Enabled() {
		result := s.verifier.Verify(req.AID, req.KEL, req.PublicKeyB64)
		if !result.Verified {
			writeErr(w, http.StatusForbidden,
				"could not confirm this key belongs to that identity: "+result.Reason)
			return
		}
		verified = true
	} else {
		// Says so on every enrollment rather than only at startup. An operator
		// running without verification should be reminded by its own logs.
		s.verifier.Verify(req.AID, req.KEL, req.PublicKeyB64)
	}

	key := base64.StdEncoding.EncodeToString(presented)
	existing, err := s.store.EnrollmentByAID(req.AID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not look up the mailbox")
		return
	}
	var enrollment *store.Enrollment
	switch {
	case existing == nil:
		enrollment, err = s.store.Enroll(req.AID, key, req.OOBI, req.KEL)
		if err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
	case sameKey(existing.PublicKeyB64, presented):
		// The same key again, after a restart: the same mailbox. A newer log
		// for it is kept, so a later rotation is checked against the newest.
		if verified && extendsHeld(req.KEL, existing.KEL) {
			_ = s.store.KeepKEL(req.AID, req.KEL)
		}
		enrollment = existing
	case verified && existing.KEL != "" && extendsHeld(req.KEL, existing.KEL):
		// The identity rotated. Its newer log extends the one this mailbox
		// holds and names the presented key now, so the key moves and the old
		// one stops working. The mailbox and its deposit token stay.
		if err := s.store.ReplaceKey(req.AID, key, req.KEL); err != nil {
			writeErr(w, http.StatusInternalServerError, "could not follow the rotation")
			return
		}
		existing.PublicKeyB64, existing.KEL = key, req.KEL
		enrollment = existing
	default:
		// A different key with no log that extends the one held is either a
		// mistake or somebody trying to take over a mailbox. Neither is
		// handled by overwriting.
		writeErr(w, http.StatusConflict, "this AID is already enrolled with a different key, and no newer key event log moves it")
		return
	}
	writeJSON(w, http.StatusOK, protocol.EnrollResponse{
		Enrolled:     true,
		AID:          enrollment.AID,
		DepositToken: enrollment.DepositToken,
		DepositURL:   fmt.Sprintf("%s/deposit?t=%s", s.apex, enrollment.DepositToken),
	})
}

// handleDeposit accepts one envelope for whoever holds the token.
//
// Unsigned on purpose. A stranger must be able to write without an account
// here, and the recipient authenticates the sender from inside the ciphertext,
// where the evidence is. What stands between "open" and "abusable" is the size
// cap, the per-AID and per-IP rate limits, and the standing mailbox limits.
func (s *Server) handleDeposit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if ok, _ := s.store.Allow("ip:"+s.sourceAddr(r), protocol.DepositPerMinutePerIP); !ok {
		writeErr(w, http.StatusTooManyRequests, "too many deposits from this address")
		return
	}

	raw, err := readBody(r, protocol.MaxDepositBytes+8*1024)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read body")
		return
	}
	var req protocol.DepositRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "body is not valid JSON")
		return
	}

	token := req.DepositToken
	if token == "" {
		token = r.URL.Query().Get("t")
	}
	if token == "" {
		writeErr(w, http.StatusBadRequest, "a deposit token is required")
		return
	}
	if req.Envelope == nil {
		writeErr(w, http.StatusBadRequest, "an envelope is required")
		return
	}

	enrollment, err := s.store.EnrollmentByToken(token)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not look up the mailbox")
		return
	}
	if enrollment == nil {
		// Says the token is unknown and nothing else. Reporting whether an AID
		// exists here would turn this endpoint into a way to enumerate who has
		// a mailbox with this operator.
		writeErr(w, http.StatusNotFound, "unknown deposit token")
		return
	}

	if ok, _ := s.store.Allow("aid:"+enrollment.AID, protocol.DepositPerMinutePerAID); !ok {
		writeErr(w, http.StatusTooManyRequests, "too many deposits for this mailbox")
		return
	}

	envelope, err := json.Marshal(req.Envelope)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "envelope could not be re-encoded")
		return
	}
	if len(envelope) > protocol.MaxDepositBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
			"envelope is %d bytes, limit is %d — a mailbox is a way to reach somebody, not a place to park data",
			len(envelope), protocol.MaxDepositBytes))
		return
	}

	msg, err := s.store.Deposit(enrollment.AID, envelope, s.retain,
		protocol.MaxUncollectedPerAID, protocol.MaxBytesPerAID)
	if err != nil {
		writeErr(w, http.StatusInsufficientStorage, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, protocol.DepositResponse{
		Accepted:  true,
		MessageID: msg.ID,
		ExpiresAt: msg.ExpiresAt.Format(time.RFC3339),
	})
}

// authenticate verifies a signed request against the enrolled key for its AID:
// over exactly the fields that were sent, fresh in time, and never seen before.
func (s *Server) authenticate(aid, signature string, fields map[string]interface{}) (*store.Enrollment, error) {
	if aid == "" || signature == "" {
		return nil, fmt.Errorf("aid and signature are required")
	}
	nonce, _ := fields["nonce"].(string)
	t, _ := fields["t"].(string)
	if nonce == "" || t == "" {
		return nil, fmt.Errorf("nonce and t are required, so a captured request cannot be replayed")
	}
	at, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return nil, fmt.Errorf("t is not an RFC 3339 time")
	}
	if d := time.Since(at); d > protocol.SignedRequestWindow || d < -protocol.SignedRequestWindow {
		return nil, fmt.Errorf("the request's time is more than %s from the mailbox's; sign a new one", protocol.SignedRequestWindow)
	}
	enrollment, err := s.store.EnrollmentByAID(aid)
	if err != nil {
		return nil, fmt.Errorf("could not look up the mailbox")
	}
	if enrollment == nil {
		return nil, fmt.Errorf("no mailbox for that AID")
	}
	body, err := sign.CanonicalBody(fields)
	if err != nil {
		return nil, fmt.Errorf("could not canonicalise request: %w", err)
	}
	// Against the ENROLLED key, not one supplied with the request. Trusting a
	// key from the request would let anybody sign their own way in.
	if err := sign.VerifyEd25519(enrollment.PublicKeyB64, signature, body); err != nil {
		return nil, fmt.Errorf("signature did not verify: %w", err)
	}
	// Recorded only once it verified, so nobody can burn another's nonce.
	digest := sha256.Sum256([]byte(aid + " " + nonce))
	fresh, err := s.store.UseNonce(hex.EncodeToString(digest[:]), at.Add(protocol.SignedRequestWindow))
	if err != nil {
		return nil, fmt.Errorf("could not record the request")
	}
	if !fresh {
		return nil, fmt.Errorf("this request has been seen before; sign a new one")
	}
	return enrollment, nil
}

// decodeSigned reads a request into v and also returns its fields exactly as
// sent, which is what the signature covers. A request in another version of
// this protocol is refused in plain words.
func decodeSigned(raw []byte, v interface{}) (map[string]interface{}, error) {
	var fields map[string]interface{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("body is not a JSON object")
	}
	if got, _ := fields["v"].(string); got != protocol.JSONVersion {
		return nil, fmt.Errorf("this mailbox speaks %s; the request says %q", protocol.JSONVersion, got)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return nil, fmt.Errorf("body does not match this request: %v", err)
	}
	return fields, nil
}

// rawKey reads a base64 Ed25519 public key in any common spelling.
func rawKey(b64 string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(b64); err == nil && len(raw) == ed25519.PublicKeySize {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("public_key_b64 is not a base64 Ed25519 key")
}

// sameKey compares keys as bytes: the same key in two base64 spellings is the
// same key.
func sameKey(storedB64 string, presented []byte) bool {
	held, err := rawKey(storedB64)
	return err == nil && ed25519.PublicKey(held).Equal(ed25519.PublicKey(presented))
}

// extendsHeld reports whether a presented key event log extends the one held,
// by relayproto's rule: every held event, in order, compared as keri-go reads
// them. A log that rewrites history extends nothing.
func extendsHeld(presentedB64, heldB64 string) bool {
	presented, err := base64.RawURLEncoding.DecodeString(presentedB64)
	if err != nil {
		return false
	}
	held, err := base64.RawURLEncoding.DecodeString(heldB64)
	if err != nil {
		return false
	}
	return relayproto.LogExtends(presented, held)
}

// handleCollect returns waiting messages to their owner, without deleting them.
func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	raw, err := readBody(r, 16*1024)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read body")
		return
	}
	var req protocol.CollectRequest
	fields, err := decodeSigned(raw, &req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if ok, _ := s.store.Allow("collect:"+req.AID, protocol.CollectPerMinute); !ok {
		writeErr(w, http.StatusTooManyRequests, "too many collections")
		return
	}
	if _, err := s.authenticate(req.AID, req.Signature, fields); err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}

	limit := 0
	if req.Limit != "" {
		n, err := strconv.Atoi(req.Limit)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "limit is a decimal count")
			return
		}
		limit = n
	}
	messages, more, err := s.store.Collect(req.AID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read the mailbox")
		return
	}
	out := make([]protocol.StoredMessage, 0, len(messages))
	for _, m := range messages {
		var envelope map[string]interface{}
		if err := json.Unmarshal(m.Envelope, &envelope); err != nil {
			// Stored bytes that will not parse are this operator's fault, not
			// the recipient's. Skipping one bad row is better than failing the
			// whole collection and stranding everything behind it.
			log.Printf("[mailbox] message %s is unreadable, skipping: %v", m.ID, err)
			continue
		}
		out = append(out, protocol.StoredMessage{
			MessageID:   m.ID,
			Envelope:    envelope,
			DepositedAt: m.DepositedAt.Format(time.RFC3339),
			ExpiresAt:   m.ExpiresAt.Format(time.RFC3339),
			SizeBytes:   m.SizeBytes,
		})
	}
	writeJSON(w, http.StatusOK, protocol.CollectResponse{
		AID: req.AID, Messages: out, More: more,
	})
}

// handleAck drops messages the recipient confirms it holds.
func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	raw, err := readBody(r, 64*1024)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read body")
		return
	}
	var req protocol.AckRequest
	fields, err := decodeSigned(raw, &req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.authenticate(req.AID, req.Signature, fields); err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	dropped, err := s.store.Ack(req.AID, strings.Fields(req.MessageIDs))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not drop messages")
		return
	}
	writeJSON(w, http.StatusOK, protocol.AckResponse{Dropped: dropped})
}

// handleRelease gives up a mailbox and destroys what is in it.
func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	raw, err := readBody(r, 16*1024)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read body")
		return
	}
	var req protocol.ReleaseRequest
	fields, err := decodeSigned(raw, &req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.authenticate(req.AID, req.Signature, fields); err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.store.Release(req.AID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not release the mailbox")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"released": true, "aid": req.AID})
}
