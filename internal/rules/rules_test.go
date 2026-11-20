package rules

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestRuleMatchBlockAndRewrite(t *testing.T) {
	rawRules := []Rule{
		{
			Name: "block-admin-delete",
			Match: Match{
				Host:   "api.example.com",
				Path:   "/api/admin/*",
				Method: "DELETE",
			},
			Action: "block",
			Status: 403,
			Body:   "denied",
		},
		{
			Name: "inject-trace",
			Match: Match{
				Host: "*.example.com",
				Path: "/api/*",
			},
			Action: "rewrite",
			SetRequestHeaders: map[string]string{
				"X-Trace": "wirecut-123",
			},
			RemoveRequestHeaders: []string{"X-Remove-Me"},
			SetResponseHeaders: map[string]string{
				"X-Proxied-By": "wirecut",
			},
			RemoveResponseHeaders: []string{"Server"},
		},
	}

	eng, err := NewEngine(rawRules)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// 1. Blocked request
	reqH := http.Header{"X-Remove-Me": {"val"}}
	dec := eng.ApplyRequest("delete", "api.example.com:443", "/api/admin/users", reqH)
	if !dec.Blocked || dec.Status != 403 || dec.Body != "denied" {
		t.Fatalf("expected block 403, got %+v", dec)
	}

	// 2. Non-blocked request gets rewritten
	reqH2 := http.Header{"X-Remove-Me": {"gone"}}
	dec2 := eng.ApplyRequest("GET", "api.example.com:443", "/api/v1/items", reqH2)
	if dec2.Blocked {
		t.Fatalf("did not expect block, got %+v", dec2)
	}
	if got := reqH2.Get("X-Trace"); got != "wirecut-123" {
		t.Fatalf("expected X-Trace injected, got %q", got)
	}
	if got := reqH2.Get("X-Remove-Me"); got != "" {
		t.Fatalf("expected X-Remove-Me removed, got %q", got)
	}

	respH := http.Header{"Server": {"nginx"}}
	applied := eng.ApplyResponse("GET", "api.example.com:443", "/api/v1/items", respH)
	if len(applied) != 1 || applied[0] != "inject-trace" {
		t.Fatalf("expected inject-trace applied to response, got %v", applied)
	}
	if got := respH.Get("X-Proxied-By"); got != "wirecut" {
		t.Fatalf("expected X-Proxied-By header, got %q", got)
	}
	if got := respH.Get("Server"); got != "" {
		t.Fatalf("expected Server header removed, got %q", got)
	}

	// 3. Root domain does not match *.example.com
	reqH3 := http.Header{}
	dec3 := eng.ApplyRequest("GET", "example.com", "/api/v1/items", reqH3)
	if len(dec3.Applied) != 0 {
		t.Fatalf("expected no match for bare example.com, got %v", dec3.Applied)
	}
}

func TestLoadFileAndParseRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	content := `{
		"rules": [
			{"name":"block-ads","match":{"host":"ads.test"},"action":"block","status":451},
			{"name":"tag","match":{"path":"/v1/*"},"set_request_headers":{"X-Env":"dev"}}
		]
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	if len(loaded) != 2 || loaded[0].Status != 451 || loaded[1].Action != "rewrite" {
		t.Fatalf("unexpected loaded rules: %+v", loaded)
	}

	inline, err := ParseRule(`block:name=no-del,host=localhost,path=/admin/*,method=DELETE,status=403`)
	if err != nil {
		t.Fatalf("ParseRule shorthand failed: %v", err)
	}
	if inline.Name != "no-del" || inline.Match.Method != "DELETE" || inline.Status != 403 {
		t.Fatalf("unexpected inline rule: %+v", inline)
	}
}
