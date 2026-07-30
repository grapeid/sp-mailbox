package oobi

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Fetching a URL somebody else chose.
//
// Enrollment asks this service to go and read an OOBI at an address supplied by
// the caller. That is a request to make an outbound connection to wherever they
// say, from inside whatever network this service runs in — which is the shape
// of a server-side request forgery. A caller who cannot reach a metadata
// endpoint or an internal admin port directly can ask us to reach it for them.
//
// So the address is checked before anything is fetched, and the check is on the
// RESOLVED addresses rather than the hostname. A name is not a location:
// anybody can point a public domain at 127.0.0.1, so refusing "localhost" while
// trusting "not-localhost.example.com" stops nothing.
//
// NOTE FOR WHOEVER MAINTAINS THIS: sp-url-relay has an equivalent guard. Like
// the signing module, this should be shared rather than copied — a rule tightened
// in one service and not the other is a gap nobody will notice.

var blockedNetworks = []string{
	"127.0.0.0/8",    // loopback
	"10.0.0.0/8",     // private
	"172.16.0.0/12",  // private
	"192.168.0.0/16", // private
	"169.254.0.0/16", // link-local, which is where cloud metadata lives
	"100.64.0.0/10",  // carrier-grade NAT
	"192.0.0.0/24",   // IETF protocol assignments
	"0.0.0.0/8",      // "this network"
	"::1/128",        // loopback
	"fc00::/7",       // unique local
	"fe80::/10",      // link-local
}

var parsedBlocked []*net.IPNet

func init() {
	for _, cidr := range blockedNetworks {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			parsedBlocked = append(parsedBlocked, network)
		}
	}
}

// Validate checks an OOBI URL is safe to fetch.
//
// Refuses when the host cannot be resolved, which is the opposite of the
// permissive choice. An unresolvable name is not evidence of safety, and
// allowing it means a name that resolves differently a moment later — or
// differently from inside this network — gets through.
func Validate(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("scheme %q is not allowed; use https", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("no host in URL")
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("localhost is not a reachable identity endpoint")
	}

	// A literal address needs no lookup, and looking it up would be a way to
	// smuggle one past this check.
	if ip := net.ParseIP(host); ip != nil {
		if isBlocked(ip) {
			return fmt.Errorf("%s is a private or reserved address", ip)
		}
		return nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("could not resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%s resolves to nothing", host)
	}
	// EVERY address must be acceptable. A name that returns one public address
	// and one private one is a way to get the check to pass and the connection
	// to land somewhere else.
	for _, ip := range ips {
		if isBlocked(ip) {
			return fmt.Errorf("%s resolves to %s, a private or reserved address", host, ip)
		}
	}
	return nil
}

func isBlocked(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, network := range parsedBlocked {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
