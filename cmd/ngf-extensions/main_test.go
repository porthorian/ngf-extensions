package main

import (
	"testing"
	"time"
)

func TestDecodeAccessLog(t *testing.T) {
	at := time.Now()
	payload := []byte(`{"client_ip":"203.0.113.8","host":"plane.api.shadeform.ai","method":"GET","path":"/v1/operations/x","status":429,"limit_req_status":"REJECTED","request_id":"abc"}`)
	event, ok := decodeAccessLog(payload, "pod-1", at)
	if !ok || event.IP.String() != "203.0.113.8" || event.Status != 429 || event.LimitReqStatus != "REJECTED" || event.RequestID != "abc" {
		t.Fatalf("unexpected decoded access log: %+v, valid=%v", event, ok)
	}
	if _, ok := decodeAccessLog([]byte(`{"level":"info","msg":"not an access log"}`), "pod-1", at); ok {
		t.Fatal("accepted a non-access log")
	}
}

func TestLogResumeTimeKeepsBoundedOverlap(t *testing.T) {
	now := time.Now()
	if got, want := logResumeTime(now.Add(-time.Minute), now, 5*time.Minute), now.Add(-time.Minute-2*time.Second); !got.Equal(want) {
		t.Fatalf("resume time = %s, want %s", got, want)
	}
	if got, want := logResumeTime(now.Add(-time.Hour), now, 5*time.Minute), now.Add(-5*time.Minute); !got.Equal(want) {
		t.Fatalf("stale resume time = %s, want %s", got, want)
	}
}
