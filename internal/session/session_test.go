package session

import (
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestJSONLRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "session.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	ts := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	ex1 := Exchange{
		ID:                  "ex_000001",
		Timestamp:           ts,
		DurationMS:          14.25,
		Scheme:              "https",
		Method:              "POST",
		URL:                 "https://api.example.com/v1/items",
		Host:                "api.example.com",
		Path:                "/v1/items",
		StatusCode:          201,
		Status:              "201 Created",
		RequestHeaders:      http.Header{"Authorization": {"[REDACTED]"}, "Content-Type": {"application/json"}},
		RequestBody:         `{"name":"widget"}`,
		RequestBodyEncoding: "utf-8",
		RequestSize:         17,
		ResponseHeaders:     http.Header{"Content-Type": {"application/json"}},
		ResponseBody:        `{"id":42}`,
		ResponseBodyEncoding: "utf-8",
		ResponseSize:        9,
		Redacted:            true,
	}
	binBody, binEnc := EncodeBody([]byte{0x00, 0xff, 0x10, 0x20})
	ex2 := Exchange{
		ID:                   "ex_000002",
		Timestamp:            ts.Add(time.Second),
		DurationMS:           5.5,
		Scheme:               "http",
		Method:               "GET",
		URL:                  "http://example.com/blob",
		Host:                 "example.com",
		Path:                 "/blob",
		StatusCode:           200,
		Status:               "200 OK",
		RequestHeaders:       http.Header{},
		ResponseHeaders:      http.Header{},
		ResponseBody:         binBody,
		ResponseBodyEncoding: binEnc,
		ResponseSize:         4096,
		ResponseTruncated:    true,
		Blocked:              false,
		RuleMatches:          []string{"tag-env"},
		Redacted:             true,
	}

	if err := w.Write(ex1); err != nil {
		t.Fatalf("Write ex1 failed: %v", err)
	}
	if err := w.Write(ex2); err != nil {
		t.Fatalf("Write ex2 failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 exchanges, got %d", len(got))
	}
	if !reflect.DeepEqual(got[0], ex1) {
		t.Fatalf("ex1 mismatch:\ngot:  %+v\nwant: %+v", got[0], ex1)
	}
	if !reflect.DeepEqual(got[1], ex2) {
		t.Fatalf("ex2 mismatch:\ngot:  %+v\nwant: %+v", got[1], ex2)
	}
	if got[1].ResponseBodyEncoding != "base64" {
		t.Fatalf("expected base64 encoding for binary body, got %q", got[1].ResponseBodyEncoding)
	}
}
