package ban

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func event(ip string, status, n int, at time.Time) Event {
	return Event{
		IP: netip.MustParseAddr(ip), PodUID: fmt.Sprintf("pod-%d", n%2),
		RequestID: fmt.Sprintf("req-%d", n), Host: "plane.api.shadeform.ai",
		Path: "/v1/operations/example", Status: status, LimitReqStatus: "REJECTED", At: at,
	}
}

func newTestDetector() *Detector {
	return NewDetector("plane.api.shadeform.ai", "/v1", AuthThreshold, 5*time.Minute, RateThreshold, time.Minute)
}

func TestAuthBurstAggregatesPodsAndDeduplicates(t *testing.T) {
	d := newTestDetector()
	now := time.Now()
	for n := range AuthThreshold - 1 {
		e := event("203.0.113.8", 401, n, now)
		d.Observe(e)
		d.Observe(e)
	}
	if len(d.Pending()) != 0 {
		t.Fatal("duplicate requests caused an early ban")
	}
	d.Observe(event("203.0.113.8", 401, AuthThreshold-1, now))
	if got := d.Pending()[netip.MustParseAddr("203.0.113.8")]; got != "auth_401" {
		t.Fatalf("ban reason = %q, want auth_401", got)
	}
}

func TestRateBurstCountsOnlyGatewayRejections(t *testing.T) {
	d := newTestDetector()
	now := time.Now()
	for n := range RateThreshold - 1 {
		e := event("198.51.100.7", 429, n, now)
		e.LimitReqStatus = ""
		d.Observe(e)
	}
	if len(d.Pending()) != 0 {
		t.Fatal("backend 429s triggered a ban")
	}
	for n := range RateThreshold {
		d.Observe(event("198.51.100.7", 429, n+100, now))
	}
	if got := d.Pending()[netip.MustParseAddr("198.51.100.7")]; got != "rate_429" {
		t.Fatalf("ban reason = %q, want rate_429", got)
	}
}

func TestAllowlistAndScope(t *testing.T) {
	d := newTestDetector()
	allow, err := ParseAllowlist("# operator\n203.0.113.0/24\n")
	if err != nil {
		t.Fatal(err)
	}
	d.SetAllowlist(allow)
	now := time.Now()
	for n := range AuthThreshold {
		d.Observe(event("203.0.113.8", 401, n, now))
		e := event("198.51.100.7", 401, n+1000, now)
		e.Host = "other.example"
		d.Observe(e)
	}
	if len(d.Pending()) != 0 {
		t.Fatal("allowlisted or out-of-scope traffic triggered a ban")
	}
	for n := range AuthThreshold {
		d.Observe(event("198.51.100.7", 401, n+2000, now))
	}
	if len(d.Pending()) != 1 {
		t.Fatal("expected one pending ban")
	}
	d.SetAllowlist([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")})
	if len(d.Pending()) != 0 {
		t.Fatal("new allowlist did not clear pending ban")
	}
}

func TestWindowAndRender(t *testing.T) {
	d := newTestDetector()
	now := time.Now()
	for n := range AuthThreshold - 1 {
		d.Observe(event("203.0.113.8", 401, n, now.Add(-6*time.Minute)))
	}
	d.Observe(event("203.0.113.8", 401, 1000, now))
	if len(d.Pending()) != 0 {
		t.Fatal("expired events counted toward threshold")
	}
	value := RenderSnippet(map[string]Ban{
		"203.0.113.8":  {ExpiresAt: now.Add(time.Minute), Reason: "auth_401"},
		"198.51.100.7": {ExpiresAt: now.Add(-time.Minute), Reason: "rate_429"},
		"bad;include":  {ExpiresAt: now.Add(time.Minute), Reason: "auth_401"},
	}, now)
	if !strings.Contains(value, "deny 203.0.113.8;") || strings.Contains(value, "198.51.100.7") || strings.Contains(value, "bad;include") {
		t.Fatalf("unsafe or expired ban in snippet: %s", value)
	}
}

func TestSeenCapacityEvictsOldestWithoutStoppingDetection(t *testing.T) {
	d := newTestDetector()
	d.maxSeen = 3
	now := time.Now()
	for n := range 4 {
		d.Observe(event("203.0.113.8", 401, n, now))
	}
	if got := len(d.byIP[netip.MustParseAddr("203.0.113.8")].auth); got != 4 {
		t.Fatalf("counted %d requests after dedup cache filled, want 4", got)
	}
	if got := len(d.seen); got != 3 {
		t.Fatalf("dedup cache size = %d, want 3", got)
	}
	if _, exists := d.seen["pod-0/req-0"]; exists {
		t.Fatal("oldest request was not evicted")
	}
}

func TestSharedAddressIsNotBannedAndMappedIPv4IsNormalized(t *testing.T) {
	d := newTestDetector()
	now := time.Now()
	for n := range AuthThreshold {
		d.Observe(event("100.64.1.2", 401, n, now))
		d.Observe(event("::ffff:8.8.8.8", 401, n+1000, now))
	}
	if len(d.Pending()) != 1 || d.Pending()[netip.MustParseAddr("8.8.8.8")] != "auth_401" {
		t.Fatalf("unexpected pending bans: %v", d.Pending())
	}
}

func TestConfigurableScopeAndThreshold(t *testing.T) {
	d := NewDetector("api.example.com", "/login", 2, time.Minute, 3, time.Minute)
	now := time.Now()
	first := event("8.8.8.8", 401, 1, now)
	d.Observe(first)
	first.Host, first.Path = "api.example.com", "/login/check"
	d.Observe(first)
	first.RequestID = "req-2"
	d.Observe(first)
	if d.Pending()[netip.MustParseAddr("8.8.8.8")] != "auth_401" {
		t.Fatal("configured host, path and threshold were not applied")
	}
}
