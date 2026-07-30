package oobi

import "testing"

// A name is not a location. Anybody can point a public domain at 127.0.0.1, so
// refusing "localhost" while trusting everything else stops nothing — the check
// has to be on the resolved address.
func TestPrivateAndReservedAddressesAreRefused(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1/oobi",
		"http://localhost/oobi",
		"http://10.1.2.3/oobi",
		"http://192.168.1.1/oobi",
		"http://172.16.0.1/oobi",
		"https://169.254.169.254/latest/meta-data/", // cloud metadata
		"http://[::1]/oobi",
		"http://0.0.0.0/oobi",
	} {
		if err := Validate(raw); err == nil {
			t.Errorf("%s was allowed — this service would fetch it on a caller's behalf", raw)
		}
	}
}

// Only http(s). A file:// or gopher:// URL is a way to reach things HTTP cannot.
func TestOnlyHTTPSchemesAreAllowed(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd",
		"gopher://example.com/",
		"ftp://example.com/oobi",
		"//example.com/oobi",
	} {
		if err := Validate(raw); err == nil {
			t.Errorf("%s was allowed", raw)
		}
	}
}

// A name that cannot be resolved is not evidence of safety. Allowing it means a
// name resolving differently a moment later, or differently from inside this
// network, gets through.
func TestUnresolvableHostsAreRefused(t *testing.T) {
	err := Validate("https://this-name-should-not-resolve.invalid/oobi")
	if err == nil {
		t.Error("an unresolvable host was allowed")
	}
}

func TestAPublicAddressIsAllowed(t *testing.T) {
	if err := Validate("https://93.184.216.34/oobi"); err != nil {
		t.Errorf("a public literal address was refused: %v", err)
	}
}

func TestMalformedURLsAreRefused(t *testing.T) {
	for _, raw := range []string{"", "https://", "not a url at all", "http://"} {
		if err := Validate(raw); err == nil {
			t.Errorf("%q was allowed", raw)
		}
	}
}
