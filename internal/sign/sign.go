package sign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
)

// Proving a request came from the AID it claims.
//
// The scheme is the one the URL relay uses, and deliberately so: an agent
// talking to a relay and a mailbox should not have to sign two different ways,
// and an operator running both should not have to implement two verifiers.
//
// NOTE FOR WHOEVER MAINTAINS THIS: this file is a copy of the equivalent in the
// URL relay service. That is a duplication worth removing — the canonical form
// has to agree byte for byte across every service or signatures fail, and two
// copies drifting is a failure that shows up as "signature invalid" with no
// clue why. It should become a shared module rather than a copy in each
// service, which is a decision for the architect rather than something to do
// here.

// CanonicalBody returns deterministic JSON bytes for signing: the body with its
// signature field removed, keys sorted.
//
// Sorting is what makes this reproducible. Go's map iteration is deliberately
// unordered, so signing a marshalled map without sorting produces a different
// byte string on each run and verification fails at random — which is worse
// than failing consistently, because it looks like an intermittent network
// problem.
func CanonicalBody(v interface{}) ([]byte, error) {
	m, err := toMap(v)
	if err != nil {
		return nil, err
	}
	delete(m, "signature")
	return marshalSorted(m)
}

// VerifyEd25519 checks a signature over the canonical body.
func VerifyEd25519(publicKeyB64, signatureB64 string, body []byte) error {
	pubRaw, err := decode(publicKeyB64)
	if err != nil {
		return fmt.Errorf("public key is not valid base64")
	}
	if len(pubRaw) != ed25519.PublicKeySize {
		return fmt.Errorf("public key is %d bytes, expected %d", len(pubRaw), ed25519.PublicKeySize)
	}
	sigRaw, err := decode(signatureB64)
	if err != nil {
		return fmt.Errorf("signature is not valid base64")
	}
	if len(sigRaw) != ed25519.SignatureSize {
		return fmt.Errorf("signature is %d bytes, expected %d", len(sigRaw), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), body, sigRaw) {
		return fmt.Errorf("signature does not verify")
	}
	return nil
}

// decode accepts both standard and url-safe base64, padded or not.
//
// Not laxness for its own sake. The agent side encodes signatures url-safe and
// unpadded while keys arrive standard-padded, and an operator that accepted
// only one spelling would reject valid requests for a reason nobody could see
// from the error message.
func decode(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("not base64")
}

func toMap(v interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// marshalSorted writes an object with its keys in order, recursing into nested
// objects so a nested map cannot reintroduce the randomness this exists to
// remove.
func marshalSorted(m map[string]interface{}) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := marshalValue(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func marshalValue(v interface{}) ([]byte, error) {
	switch t := v.(type) {
	case map[string]interface{}:
		return marshalSorted(t)
	case []interface{}:
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			ib, err := marshalValue(item)
			if err != nil {
				return nil, err
			}
			buf.Write(ib)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil
	default:
		return json.Marshal(v)
	}
}
