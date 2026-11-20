package redact

import (
	"net/http"
	"testing"
)

func TestCloneHeadersRedaction(t *testing.T) {
	orig := http.Header{
		"Authorization": {"Bearer secret-token"},
		"Cookie":        {"session=abc123"},
		"X-Api-Key":     {"key-999"},
		"Set-Cookie":    {"sid=xyz; HttpOnly"},
		"Content-Type":  {"application/json"},
		"X-Custom":      {"one", "two"},
	}

	redacted := CloneHeaders(orig, true)

	for _, name := range []string{"Authorization", "Cookie", "X-Api-Key", "Set-Cookie"} {
		if got := redacted.Get(name); got != Placeholder {
			t.Fatalf("expected %s to be %q, got %q", name, Placeholder, got)
		}
	}
	if got := redacted.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected Content-Type to stay intact, got %q", got)
	}
	if got := len(redacted.Values("X-Custom")); got != 2 {
		t.Fatalf("expected 2 X-Custom values, got %d", got)
	}

	// Ensure original headers were not mutated.
	if got := orig.Get("Authorization"); got != "Bearer secret-token" {
		t.Fatalf("original Authorization was mutated: %q", got)
	}

	// Ensure --no-redact preserves sensitive headers.
	raw := CloneHeaders(orig, false)
	if got := raw.Get("Authorization"); got != "Bearer secret-token" {
		t.Fatalf("expected raw Authorization with redact=false, got %q", got)
	}
	if got := raw.Get("X-Api-Key"); got != "key-999" {
		t.Fatalf("expected raw X-Api-Key with redact=false, got %q", got)
	}
}

func TestIsSensitiveHeaderCaseInsensitive(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"authorization", true},
		{"AUTHORIZATION", true},
		{"cookie", true},
		{"x-api-key", true},
		{"X-API-KEY", true},
		{"set-cookie", true},
		{"proxy-authorization", true},
		{"x-request-id", false},
		{"accept", false},
	}
	for _, tc := range cases {
		if got := IsSensitiveHeader(tc.name); got != tc.want {
			t.Errorf("IsSensitiveHeader(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
