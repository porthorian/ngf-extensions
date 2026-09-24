package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Namespace         string
	GatewayName       string
	Host              string
	PathPrefix        string
	AllowlistName     string
	StateName         string
	PolicyName        string
	AuthThreshold     int
	AuthWindow        time.Duration
	RateThreshold     int
	RateWindow        time.Duration
	BanDuration       time.Duration
	ReconcileInterval time.Duration
	MaxActiveBans     int
}

func FromEnv() (Config, error) {
	c := Config{
		Namespace:     os.Getenv("NGF_NAMESPACE"),
		GatewayName:   os.Getenv("NGF_GATEWAY_NAME"),
		Host:          os.Getenv("NGF_TARGET_HOST"),
		PathPrefix:    os.Getenv("NGF_PATH_PREFIX"),
		AllowlistName: os.Getenv("NGF_ALLOWLIST_CONFIGMAP"),
		StateName:     os.Getenv("NGF_STATE_CONFIGMAP"),
		PolicyName:    os.Getenv("NGF_POLICY_NAME"),
	}
	if c.Namespace == "" {
		data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return c, fmt.Errorf("NGF_NAMESPACE is required outside a Kubernetes Pod: %w", err)
		}
		c.Namespace = strings.TrimSpace(string(data))
	}
	if c.GatewayName == "" || c.Host == "" || !strings.HasPrefix(c.PathPrefix, "/") || c.PathPrefix == "//" || c.AllowlistName == "" || c.StateName == "" || c.PolicyName == "" {
		return c, fmt.Errorf("gateway name, target host, absolute path prefix, allowlist ConfigMap, state ConfigMap, and policy name are required")
	}
	var err error
	for _, field := range []struct {
		name string
		dst  *int
		def  int
	}{
		{"NGF_AUTH_THRESHOLD", &c.AuthThreshold, 120},
		{"NGF_RATE_THRESHOLD", &c.RateThreshold, 30},
		{"NGF_MAX_ACTIVE_BANS", &c.MaxActiveBans, 200},
	} {
		*field.dst, err = positiveInt(field.name, field.def)
		if err != nil {
			return c, err
		}
	}
	if c.MaxActiveBans > 200 {
		return c, fmt.Errorf("NGF_MAX_ACTIVE_BANS must not exceed 200")
	}
	for _, field := range []struct {
		name string
		dst  *time.Duration
		def  time.Duration
	}{
		{"NGF_AUTH_WINDOW", &c.AuthWindow, 5 * time.Minute},
		{"NGF_RATE_WINDOW", &c.RateWindow, time.Minute},
		{"NGF_BAN_DURATION", &c.BanDuration, 15 * time.Minute},
		{"NGF_RECONCILE_INTERVAL", &c.ReconcileInterval, 30 * time.Second},
	} {
		*field.dst, err = positiveDuration(field.name, field.def)
		if err != nil {
			return c, err
		}
	}
	return c, nil
}

func positiveInt(name string, fallback int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func positiveDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration", name)
	}
	return value, nil
}
