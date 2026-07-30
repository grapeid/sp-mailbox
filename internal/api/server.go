package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/grapeid/sp-mailbox/internal/protocol"
	"github.com/grapeid/sp-mailbox/internal/sign"
	"github.com/grapeid/sp-mailbox/internal/store"
	"github.com/grapeid/sp-mailbox/internal/verify"
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
	raw, err := readBody(r, 16*1024)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read body")
		return
	}
	var req protocol.EnrollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "body is not valid JSON")
		return
	}
	if req.AID == "" || req.PublicKeyB64 == "" || req.Signature == "" {
		writeErr(w, http.StatusBadRequest, "aid, public_key_b64 and signature are required")
		return
	}

	body, err := sign.CanonicalBody(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not canonicalise request")
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
	if s.verifier.Enabled() {
		result := s.verifier.Verify(r.Context(), req.AID, req.OOBI, req.PublicKeyB64)
		if !result.Verified {
			writeErr(w, http.StatusForbidden,
				"could not confirm this key belongs to that identity: "+result.Reason)
			return
		}
	} else {
		// Says so on every enrollment rather than only at startup. An operator
		// running without verification should be reminded by its own logs.
		s.verifier.Verify(r.Context(), req.AID, req.OOBI, req.PublicKeyB64)
	}

	enrollment, err := s.store.Enroll(req.AID, req.PublicKeyB64, req.OOBI)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
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

// authenticate verifies a signed request against the enrolled key for its AID.
func (s *Server) authenticate(aid, signature string, req interface{}) (*store.Enrollment, error) {
	if aid == "" || signature == "" {
		return nil, fmt.Errorf("aid and signature are required")
	}
	enrollment, err := s.store.EnrollmentByAID(aid)
	if err != nil {
		return nil, fmt.Errorf("could not look up the mailbox")
	}
	if enrollment == nil {
		return nil, fmt.Errorf("no mailbox for that AID")
	}
	body, err := sign.CanonicalBody(req)
	if err != nil {
		return nil, fmt.Errorf("could not canonicalise request")
	}
	// Against the ENROLLED key, not one supplied with the request. Trusting a
	// key from the request would let anybody sign their own way in.
	if err := sign.VerifyEd25519(enrollment.PublicKeyB64, signature, body); err != nil {
		return nil, fmt.Errorf("signature did not verify: %w", err)
	}
	return enrollment, nil
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
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "body is not valid JSON")
		return
	}
	if ok, _ := s.store.Allow("collect:"+req.AID, protocol.CollectPerMinute); !ok {
		writeErr(w, http.StatusTooManyRequests, "too many collections")
		return
	}
	if _, err := s.authenticate(req.AID, req.Signature, req); err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}

	messages, more, err := s.store.Collect(req.AID, req.Limit)
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
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "body is not valid JSON")
		return
	}
	if _, err := s.authenticate(req.AID, req.Signature, req); err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	dropped, err := s.store.Ack(req.AID, req.MessageIDs)
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
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "body is not valid JSON")
		return
	}
	if _, err := s.authenticate(req.AID, req.Signature, req); err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.store.Release(req.AID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not release the mailbox")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"released": true, "aid": req.AID})
}
