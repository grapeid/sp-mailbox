package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/grapeid/sp-mailbox/internal/oobi"
)

// Proving that a key belongs to the AID enrolling with it.
//
// Enrollment arrives with an AID and a public key, and a signature made by that
// key over the request. That proves the caller holds the key they are
// presenting. It proves nothing about whose AID it is — anybody can generate a
// key, sign with it, and name somebody else's identifier.
//
// The binding lives in the identity's own key event log. A self-addressing AID
// is the Blake3 SAID of its inception event, so an inception containing these
// keys either derives this AID or it does not; producing one that derives
// somebody else's means finding a hash collision.
//
// This service does NOT do that check itself. Getting KERI validation right
// means exact serialisation, exact hash inputs, and the same dummied fields the
// reference implementation uses — reimplemented per service, that is four
// chances to differ subtly and fail in ways nobody can debug. So the KEL goes
// to a KERI service that already does it, and this package's job is to fetch
// honestly, ask, and refuse clearly.
//
// Without verification the consequence is SQUATTING rather than interception:
// an attacker cannot read anything, because deposits are encrypted to the
// recipient and the deposit URL is handed out by the recipient out of band. But
// they can take an AID and deny its real owner the use of this operator, since
// a second key for an existing AID is refused.

// Result is what verification concluded.
type Result struct {
	// Verified is true only when the KEL was checked AND bound to the AID AND
	// the presented key is the identity's current one.
	Verified bool
	// CurrentKey is the signing key the KEL says is active. Empty unless
	// verified — an unverified chain's idea of the current key is exactly the
	// thing not to trust.
	CurrentKey string
	// Reason explains a refusal in terms somebody can act on.
	Reason string
}

// Verifier binds an enrolling key to its AID.
type Verifier interface {
	// Verify reports whether publicKeyB64 is the current signing key of aid,
	// according to the KEL published at oobiURL.
	Verify(ctx context.Context, aid, oobiURL, publicKeyB64 string) Result
	// Enabled reports whether this verifier actually checks anything, so the
	// service can say so at startup rather than appearing to be strict.
	Enabled() bool
}

// Unverified accepts every enrollment without checking.
//
// Exists so that development and testing do not require a KERI service, and is
// deliberately loud: a service running with this is open to AID squatting and
// should say so on every enrollment rather than only in a README nobody rereads.
type Unverified struct{}

func (Unverified) Enabled() bool { return false }

func (Unverified) Verify(_ context.Context, aid, _, _ string) Result {
	log.Printf("[verify] WARNING: enrolling %s without checking the key belongs to it — "+
		"this operator is open to AID squatting", aid)
	return Result{Verified: false, Reason: "verification is disabled on this operator"}
}

// KeriService verifies by resolving the OOBI and asking a KERI service whether
// the KEL is genuine and bound to the AID.
type KeriService struct {
	// BaseURL is the KERI service that performs validation.
	BaseURL string
	Client  *http.Client
}

func NewKeriService(baseURL string) *KeriService {
	return &KeriService{
		BaseURL: baseURL,
		// Bounded on purpose. Resolution reaches an address the caller chose,
		// so a slow or hanging endpoint is a way to tie up this service.
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (k *KeriService) Enabled() bool { return k.BaseURL != "" }

func (k *KeriService) Verify(ctx context.Context, aid, oobiURL, publicKeyB64 string) Result {
	if oobiURL == "" {
		return Result{Reason: "an OOBI is required: without one there is no KEL to check this key against"}
	}
	if err := oobi.Validate(oobiURL); err != nil {
		return Result{Reason: "OOBI address refused: " + err.Error()}
	}

	events, resolvedAID, err := k.fetchKEL(ctx, oobiURL)
	if err != nil {
		return Result{Reason: "could not read the KEL: " + err.Error()}
	}
	if resolvedAID != "" && resolvedAID != aid {
		// The OOBI is somebody else's. Worth naming precisely, because the
		// honest version of this mistake — pasting the wrong link — looks
		// identical to the dishonest one.
		return Result{Reason: fmt.Sprintf(
			"that OOBI publishes %s, not %s", resolvedAID, aid)}
	}
	if len(events) == 0 {
		return Result{Reason: "that OOBI published no key events"}
	}

	validated, err := k.validate(ctx, aid, events)
	if err != nil {
		return Result{Reason: "KEL validation failed: " + err.Error()}
	}
	if !validated.KelVerified {
		reason := "the KEL did not verify"
		if len(validated.ValidationErrors) > 0 {
			reason += ": " + validated.ValidationErrors[0]
		}
		return Result{Reason: reason}
	}
	if validated.CurrentPublicKey == "" {
		return Result{Reason: "the KEL verified but reported no current key"}
	}
	if validated.CurrentPublicKey != publicKeyB64 {
		// The key is real and the AID is real; they are just not each other's.
		// Most often this is an agent enrolling with a key it has since
		// rotated away from.
		return Result{Reason: "the key presented is not this identity's current signing key"}
	}
	return Result{Verified: true, CurrentKey: validated.CurrentPublicKey}
}

// fetchKEL resolves an OOBI and returns its key events.
func (k *KeriService) fetchKEL(ctx context.Context, oobiURL string) ([]map[string]interface{}, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oobiURL, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := k.Client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("endpoint returned %d", resp.StatusCode)
	}
	// Capped: this reads from an address the caller chose, and an endless body
	// is the cheapest denial of service there is.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, "", err
	}

	var payload struct {
		AID string                   `json:"aid"`
		KEL []map[string]interface{} `json:"kel"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", fmt.Errorf("response was not a readable OOBI document")
	}
	return payload.KEL, payload.AID, nil
}

type validationResult struct {
	KelVerified      bool     `json:"kel_verified"`
	EventsValidated  int      `json:"events_validated"`
	CurrentPublicKey string   `json:"current_public_key"`
	ValidationErrors []string `json:"validation_errors"`
}

// validate asks the KERI service whether this KEL is genuine and belongs to
// this AID.
//
// The AID is sent because that is the question that matters. A KEL that is
// merely self-consistent proves only that somebody built a chain; what makes it
// this identity's chain is that its inception derives this AID.
func (k *KeriService) validate(ctx context.Context, aid string, events []map[string]interface{}) (*validationResult, error) {
	body, err := json.Marshal(map[string]interface{}{"aid": aid, "events": events})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		k.BaseURL+"/validate-kel", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := k.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("validation service returned %d", resp.StatusCode)
	}
	var out validationResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("validation response was unreadable: %w", err)
	}
	return &out, nil
}
