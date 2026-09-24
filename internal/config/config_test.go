package config

import (
	"testing"
	"time"
)

func TestFromEnv(t *testing.T) {
	t.Setenv("NGF_NAMESPACE", "gateway-system")
	t.Setenv("NGF_GATEWAY_NAME", "public")
	t.Setenv("NGF_TARGET_HOST", "api.example.com")
	t.Setenv("NGF_PATH_PREFIX", "/login")
	t.Setenv("NGF_ALLOWLIST_CONFIGMAP", "allowed-clients")
	t.Setenv("NGF_STATE_CONFIGMAP", "ban-state")
	t.Setenv("NGF_POLICY_NAME", "temporary-bans")
	t.Setenv("NGF_AUTH_THRESHOLD", "7")
	t.Setenv("NGF_BAN_DURATION", "10m")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Namespace != "gateway-system" || c.GatewayName != "public" || c.AuthThreshold != 7 || c.BanDuration != 10*time.Minute {
		t.Fatalf("unexpected config: %+v", c)
	}
	t.Setenv("NGF_BAN_DURATION", "never")
	if _, err := FromEnv(); err == nil {
		t.Fatal("accepted invalid duration")
	}
	t.Setenv("NGF_BAN_DURATION", "15m")
	t.Setenv("NGF_MAX_ACTIVE_BANS", "201")
	if _, err := FromEnv(); err == nil {
		t.Fatal("accepted more than 200 active bans")
	}
}
