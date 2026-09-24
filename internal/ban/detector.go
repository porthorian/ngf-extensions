package ban

import (
	"container/list"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	AuthThreshold   = 120
	RateThreshold   = 30
	MaxActiveBans   = 200
	MaxTrackedIPs   = 10000
	MaxSeenRequests = 100000
)

var sharedIPv4Space = netip.MustParsePrefix("100.64.0.0/10")

type Event struct {
	IP             netip.Addr
	PodUID         string
	RequestID      string
	Host           string
	Path           string
	Status         int
	LimitReqStatus string
	At             time.Time
}

type Ban struct {
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
}

type windows struct {
	auth []time.Time
	rate []time.Time
	last time.Time
}

type seenRequest struct {
	key string
	at  time.Time
}

type Detector struct {
	mu         sync.Mutex
	host       string
	path       string
	authLimit  int
	authWindow time.Duration
	rateLimit  int
	rateWindow time.Duration
	maxWindow  time.Duration
	allow      []netip.Prefix
	byIP       map[netip.Addr]*windows
	seen       map[string]*list.Element
	seenOrder  *list.List
	maxSeen    int
	pending    map[netip.Addr]string
}

func NewDetector(host, path string, authLimit int, authWindow time.Duration, rateLimit int, rateWindow time.Duration) *Detector {
	maxWindow := authWindow
	if rateWindow > maxWindow {
		maxWindow = rateWindow
	}
	return &Detector{
		host:       host,
		path:       strings.TrimRight(path, "/"),
		authLimit:  authLimit,
		authWindow: authWindow,
		rateLimit:  rateLimit,
		rateWindow: rateWindow,
		maxWindow:  maxWindow,
		byIP:       make(map[netip.Addr]*windows),
		seen:       make(map[string]*list.Element),
		seenOrder:  list.New(),
		maxSeen:    MaxSeenRequests,
		pending:    make(map[netip.Addr]string),
	}
}

func (d *Detector) MaxWindow() time.Duration { return d.maxWindow }

func ParseAllowlist(raw string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			addr, addrErr := netip.ParseAddr(line)
			if addrErr != nil {
				return nil, fmt.Errorf("invalid allowlist address %q: %w", line, err)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func (d *Detector) SetAllowlist(prefixes []netip.Prefix) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.allow = slices.Clone(prefixes)
	for ip := range d.pending {
		if d.allowed(ip) {
			delete(d.pending, ip)
		}
	}
}

func (d *Detector) allowed(ip netip.Addr) bool {
	for _, prefix := range d.allow {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !sharedIPv4Space.Contains(ip)
}

func pruneTimes(times []time.Time, after time.Time) []time.Time {
	return slices.DeleteFunc(times, func(t time.Time) bool { return t.Before(after) })
}

// Observe accepts only configured-host auth failures or gateway rate-limit rejections.
// Request IDs deduplicate reconnects to the same Kubernetes pod log stream.
func (d *Detector) Observe(e Event) {
	e.IP = e.IP.Unmap()
	if !publicIP(e.IP) || e.Host != d.host ||
		!(e.Path == d.path || strings.HasPrefix(e.Path, d.path+"/")) ||
		e.RequestID == "" || e.PodUID == "" ||
		(e.Status != 401 && !(e.Status == 429 && e.LimitReqStatus == "REJECTED")) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.allowed(e.IP) {
		return
	}
	if _, exists := d.pending[e.IP]; exists {
		return
	}
	now := time.Now()
	d.pruneSeenLocked(now.Add(-d.maxWindow))
	key := e.PodUID + "/" + e.RequestID
	if _, exists := d.seen[key]; exists {
		return
	}
	if len(d.byIP) >= MaxTrackedIPs {
		if _, exists := d.byIP[e.IP]; !exists {
			return
		}
	}
	if len(d.seen) >= d.maxSeen {
		oldest := d.seenOrder.Front()
		delete(d.seen, oldest.Value.(seenRequest).key)
		d.seenOrder.Remove(oldest)
	}
	d.seen[key] = d.seenOrder.PushBack(seenRequest{key: key, at: now})
	w := d.byIP[e.IP]
	if w == nil {
		w = &windows{}
		d.byIP[e.IP] = w
	}
	reference := e.At
	if w.last.After(reference) {
		reference = w.last
	}
	w.last = reference
	w.auth = pruneTimes(w.auth, reference.Add(-d.authWindow))
	w.rate = pruneTimes(w.rate, reference.Add(-d.rateWindow))
	if e.Status == 401 {
		if e.At.Before(reference.Add(-d.authWindow)) {
			return
		}
		w.auth = append(w.auth, e.At)
		if len(w.auth) >= d.authLimit {
			d.pending[e.IP] = "auth_401"
		}
	} else {
		if e.At.Before(reference.Add(-d.rateWindow)) {
			return
		}
		w.rate = append(w.rate, e.At)
		if len(w.rate) >= d.rateLimit {
			d.pending[e.IP] = "rate_429"
		}
	}
}

func (d *Detector) Pending() map[netip.Addr]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make(map[netip.Addr]string, len(d.pending))
	for ip, reason := range d.pending {
		result[ip] = reason
	}
	return result
}

func (d *Detector) ClearPending(ips []netip.Addr) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, ip := range ips {
		delete(d.pending, ip)
		delete(d.byIP, ip)
	}
}

func (d *Detector) Prune(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneSeenLocked(now.Add(-d.maxWindow))
	for ip, w := range d.byIP {
		if w.last.Before(now.Add(-d.maxWindow)) {
			delete(d.byIP, ip)
		}
	}
}

func (d *Detector) pruneSeenLocked(before time.Time) {
	for oldest := d.seenOrder.Front(); oldest != nil; oldest = d.seenOrder.Front() {
		if !oldest.Value.(seenRequest).at.Before(before) {
			break
		}
		delete(d.seen, oldest.Value.(seenRequest).key)
		d.seenOrder.Remove(oldest)
	}
}

func RenderSnippet(active map[string]Ban, now time.Time) string {
	ips := make([]string, 0, len(active))
	for ip, ban := range active {
		if !ban.ExpiresAt.After(now) {
			continue
		}
		if addr, err := netip.ParseAddr(ip); err == nil && publicIP(addr) {
			ips = append(ips, addr.Unmap().String())
		}
	}
	slices.Sort(ips)
	var out strings.Builder
	out.WriteString("# Generated temporary IP bans; expires are stored in the controller state ConfigMap.\n")
	for _, ip := range ips {
		fmt.Fprintf(&out, "deny %s;\n", ip)
	}
	return out.String()
}
