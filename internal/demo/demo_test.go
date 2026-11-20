package demo

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestDemoRun(t *testing.T) {
	sessPath := filepath.Join(t.TempDir(), "demo.jsonl")
	var out bytes.Buffer

	res, err := Run(t.Context(), Options{
		SessionPath:  sessPath,
		MaxBodyBytes: 512,
		Out:          &out,
	})
	if err != nil {
		t.Fatalf("demo.Run failed: %v", err)
	}
	if len(res.Exchanges) != 6 {
		t.Fatalf("expected 6 exchanges, got %d", len(res.Exchanges))
	}
	if res.UpstreamHitOn5 {
		t.Fatal("blocked DELETE request reached upstream")
	}
	if res.SecretsLeaked {
		t.Fatal("raw secrets leaked into demo session file")
	}
	if !res.Exchanges[4].Blocked || res.Exchanges[4].StatusCode != 403 {
		t.Fatalf("expected exchange 5 to be blocked 403, got %+v", res.Exchanges[4])
	}
	if !res.Exchanges[5].ResponseTruncated || res.Exchanges[5].ResponseSize != 2048 {
		t.Fatalf("expected exchange 6 to show 2048B truncated response, got size=%d trunc=%v",
			res.Exchanges[5].ResponseSize, res.Exchanges[5].ResponseTruncated)
	}
}
