package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/porthorian/ngf-extensions/internal/ban"
	"github.com/porthorian/ngf-extensions/internal/config"
	"github.com/porthorian/ngf-extensions/internal/kube"
)

type accessLog struct {
	ClientIP       string `json:"client_ip"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	LimitReqStatus string `json:"limit_req_status"`
	RequestID      string `json:"request_id"`
}

type controller struct {
	api         *kube.Client
	config      config.Config
	detector    *ban.Detector
	active      atomic.Int64
	watchers    atomic.Int64
	lastSuccess atomic.Int64
	authBans    atomic.Int64
	rateBans    atomic.Int64
}

func main() {
	if len(os.Args) != 2 || os.Args[1] != "timed-ban-controller" {
		fmt.Fprintln(os.Stderr, "Usage: ngf-extensions timed-ban-controller")
		if len(os.Args) == 1 || os.Args[1] == "--help" {
			return
		}
		os.Exit(2)
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	api, err := kube.NewClient(kube.Config{Namespace: cfg.Namespace, GatewayName: cfg.GatewayName, PolicyName: cfg.PolicyName})
	if err != nil {
		return err
	}
	c := &controller{api: api, config: cfg, detector: ban.NewDetector(cfg.Host, cfg.PathPrefix, cfg.AuthThreshold, cfg.AuthWindow, cfg.RateThreshold, cfg.RateWindow)}
	go c.serveMetrics(ctx)
	for {
		if err := c.reconcile(ctx); err == nil {
			break
		} else {
			log.Printf("initial reconcile failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	go c.watchPods(ctx)
	ticker := time.NewTicker(cfg.ReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			if err := c.reconcile(ctx); err != nil {
				log.Printf("reconcile failed: %v", err)
			}
			c.detector.Prune(now)
		}
	}
}

func (c *controller) serveMetrics(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if time.Since(time.Unix(c.lastSuccess.Load(), 0)) > 3*c.config.ReconcileInterval {
			http.Error(w, "reconcile stale", http.StatusServiceUnavailable)
		}
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# TYPE ngf_timed_bans_active gauge\nngf_timed_bans_active %d\n", c.active.Load())
		fmt.Fprintf(w, "# TYPE ngf_timed_bans_log_watchers gauge\nngf_timed_bans_log_watchers %d\n", c.watchers.Load())
		fmt.Fprintf(w, "# TYPE ngf_timed_bans_last_success_timestamp_seconds gauge\nngf_timed_bans_last_success_timestamp_seconds %d\n", c.lastSuccess.Load())
		fmt.Fprintf(w, "# TYPE ngf_timed_bans_added_total counter\nngf_timed_bans_added_total{reason=\"auth_401\"} %d\nngf_timed_bans_added_total{reason=\"rate_429\"} %d\n", c.authBans.Load(), c.rateBans.Load())
	})
	server := &http.Server{Addr: ":9090", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("metrics server failed: %v", err)
	}
}

func (c *controller) watchPods(ctx context.Context) {
	watching := make(map[string]context.CancelFunc)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		pods, err := c.api.ListGatewayPods(ctx)
		if err != nil {
			log.Printf("listing external Gateway pods failed: %v", err)
		} else {
			present := make(map[string]bool, len(pods))
			for _, pod := range pods {
				uid := pod.Metadata.UID
				present[uid] = true
				if _, exists := watching[uid]; !exists {
					watchCtx, cancel := context.WithCancel(ctx)
					watching[uid] = cancel
					go c.watchLog(watchCtx, pod.Metadata.Name, uid)
				}
			}
			for uid, cancel := range watching {
				if !present[uid] {
					cancel()
					delete(watching, uid)
				}
			}
		}
		select {
		case <-ctx.Done():
			for _, cancel := range watching {
				cancel()
			}
			return
		case <-ticker.C:
		}
	}
}

func (c *controller) watchLog(ctx context.Context, podName, uid string) {
	since := time.Now()
	for ctx.Err() == nil {
		err := c.api.FollowLogs(ctx, podName, logResumeTime(since, time.Now(), c.detector.MaxWindow()), func() { c.watchers.Add(1) }, func() { c.watchers.Add(-1) }, func(line []byte) {
			stamp, payload, ok := bytes.Cut(line, []byte(" "))
			if !ok {
				return
			}
			at, err := time.Parse(time.RFC3339Nano, string(stamp))
			if err != nil {
				return
			}
			if at.After(since) {
				since = at
			}
			if at.Before(time.Now().Add(-c.detector.MaxWindow())) || at.After(time.Now().Add(time.Minute)) {
				return
			}
			if event, ok := decodeAccessLog(payload, uid, at); ok {
				c.detector.Observe(event)
			}
		})
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("following external Gateway pod %s logs failed: %v", podName, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func logResumeTime(last, now time.Time, window time.Duration) time.Time {
	resume := last.Add(-2 * time.Second)
	if floor := now.Add(-window); resume.Before(floor) {
		return floor
	}
	return resume
}

func decodeAccessLog(payload []byte, podUID string, at time.Time) (ban.Event, bool) {
	var entry accessLog
	if json.Unmarshal(payload, &entry) != nil {
		return ban.Event{}, false
	}
	ip, err := netip.ParseAddr(entry.ClientIP)
	if err != nil {
		return ban.Event{}, false
	}
	return ban.Event{
		IP: ip, PodUID: podUID, RequestID: entry.RequestID, Host: entry.Host,
		Path: entry.Path, Status: entry.Status, LimitReqStatus: entry.LimitReqStatus, At: at,
	}, true
}

func (c *controller) reconcile(ctx context.Context) error {
	allowCM, err := c.api.GetConfigMap(ctx, c.config.Namespace, c.config.AllowlistName)
	if err != nil {
		return fmt.Errorf("load Git-managed allowlist: %w", err)
	}
	allow, err := ban.ParseAllowlist(allowCM.Data["allow-cidrs"])
	if err != nil {
		return err
	}
	c.detector.SetAllowlist(allow)
	state, err := c.ensureState(ctx)
	if err != nil {
		return err
	}
	active := make(map[string]ban.Ban)
	if raw := state.Data["bans.json"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &active); err != nil {
			return fmt.Errorf("decode ban state: %w", err)
		}
	}
	now := time.Now().UTC()
	changed := false
	for ip, item := range active {
		addr, parseErr := netip.ParseAddr(ip)
		if parseErr != nil || !item.ExpiresAt.After(now) || contains(allow, addr) {
			delete(active, ip)
			changed = true
		}
	}
	pending := c.detector.Pending()
	addresses := make([]netip.Addr, 0, len(pending))
	for ip := range pending {
		addresses = append(addresses, ip)
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	var accepted []netip.Addr
	var authAdded, rateAdded int64
	for _, ip := range addresses {
		if contains(allow, ip) {
			accepted = append(accepted, ip)
			continue
		}
		if _, exists := active[ip.String()]; exists {
			accepted = append(accepted, ip)
			continue
		}
		if len(active) >= c.config.MaxActiveBans {
			accepted = append(accepted, ip)
			continue
		}
		reason := pending[ip]
		active[ip.String()] = ban.Ban{ExpiresAt: now.Add(c.config.BanDuration), Reason: reason}
		accepted = append(accepted, ip)
		changed = true
		if reason == "auth_401" {
			authAdded++
		} else {
			rateAdded++
		}
	}
	if changed {
		encoded, err := json.Marshal(active)
		if err != nil {
			return err
		}
		state.Data["bans.json"] = string(encoded)
		if err := c.api.UpdateConfigMap(ctx, state); err != nil {
			return fmt.Errorf("persist ban state: %w", err)
		}
	}
	if err := c.applyPolicy(ctx, ban.RenderSnippet(active, now)); err != nil {
		return err
	}
	c.detector.ClearPending(accepted)
	c.active.Store(int64(len(active)))
	c.authBans.Add(authAdded)
	c.rateBans.Add(rateAdded)
	c.lastSuccess.Store(now.Unix())
	return nil
}

func contains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *controller) ensureState(ctx context.Context) (kube.ConfigMap, error) {
	state, err := c.api.GetConfigMap(ctx, c.config.Namespace, c.config.StateName)
	if err == nil {
		if state.Metadata.Labels["app.kubernetes.io/managed-by"] != "ngf-timed-ban-controller" {
			return state, errors.New("ban state ConfigMap is not controller-owned")
		}
		return state, nil
	}
	if !kube.IsNotFound(err) {
		return state, err
	}
	state = kube.ConfigMap{
		APIVersion: "v1", Kind: "ConfigMap",
		Metadata: kube.Metadata{Name: c.config.StateName, Namespace: c.config.Namespace,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "ngf-timed-ban-controller"}},
		Data: map[string]string{"bans.json": "{}"},
	}
	if err := c.api.CreateConfigMap(ctx, state); err != nil {
		return state, err
	}
	return c.api.GetConfigMap(ctx, c.config.Namespace, c.config.StateName)
}

func (c *controller) applyPolicy(ctx context.Context, value string) error {
	policy, err := c.api.GetPolicy(ctx)
	if kube.IsNotFound(err) {
		policy = kube.SnippetsPolicy{
			APIVersion: "gateway.nginx.org/v1alpha1", Kind: "SnippetsPolicy",
			Metadata: kube.Metadata{Name: c.config.PolicyName, Namespace: c.config.Namespace,
				Labels: map[string]string{"app.kubernetes.io/managed-by": "ngf-timed-ban-controller"}},
		}
		policy.Spec.TargetRefs = []map[string]string{{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": c.config.GatewayName}}
		policy.Spec.Snippets = []kube.Snippet{{Context: "http.server.location", Value: value}}
		return c.api.CreatePolicy(ctx, policy)
	}
	if err != nil {
		return err
	}
	if policy.Metadata.Labels["app.kubernetes.io/managed-by"] != "ngf-timed-ban-controller" {
		return errors.New("temporary ban SnippetsPolicy is not controller-owned")
	}
	target := map[string]string{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": c.config.GatewayName}
	targetMatches := len(policy.Spec.TargetRefs) == 1 && policy.Spec.TargetRefs[0]["group"] == target["group"] && policy.Spec.TargetRefs[0]["kind"] == target["kind"] && policy.Spec.TargetRefs[0]["name"] == target["name"]
	if targetMatches && len(policy.Spec.Snippets) == 1 && policy.Spec.Snippets[0].Context == "http.server.location" && policy.Spec.Snippets[0].Value == value {
		return nil
	}
	policy.Spec.TargetRefs = []map[string]string{target}
	policy.Spec.Snippets = []kube.Snippet{{Context: "http.server.location", Value: value}}
	if err := c.api.UpdatePolicy(ctx, policy); err != nil {
		return fmt.Errorf("update temporary ban policy: %w", err)
	}
	return nil
}

func init() { log.SetOutput(os.Stdout); log.SetFlags(log.LstdFlags | log.LUTC) }
