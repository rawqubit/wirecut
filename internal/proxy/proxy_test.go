package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rawqubit/wirecut/internal/ca"
	"github.com/rawqubit/wirecut/internal/redact"
	"github.com/rawqubit/wirecut/internal/rules"
	"github.com/rawqubit/wirecut/internal/session"
)

func TestEndToEndHTTPSMITM(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Saw-Injected", r.Header.Get("X-Injected"))
		w.Header().Set("X-Secret-Server", "remove-me")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	caDir := t.TempDir()
	localCA, err := ca.LoadOrCreate(caDir)
	if err != nil {
		t.Fatalf("LoadOrCreate CA failed: %v", err)
	}

	sessPath := filepath.Join(t.TempDir(), "session.jsonl")
	sw, err := session.NewWriter(sessPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}
	defer sw.Close()

	eng, err := rules.NewEngine([]rules.Rule{
		{
			Name:   "block-admin",
			Match:  rules.Match{Path: "/admin/*", Method: "DELETE"},
			Action: "block",
			Status: http.StatusForbidden,
			Body:   "blocked-by-test",
		},
		{
			Name:                  "rewrite-headers",
			Match:                 rules.Match{Path: "/echo"},
			Action:                "rewrite",
			SetRequestHeaders:     map[string]string{"X-Injected": "yes-mitm"},
			SetResponseHeaders:    map[string]string{"X-Wirecut": "active"},
			RemoveResponseHeaders: []string{"X-Secret-Server"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	px, err := New(Config{
		Addr:            "127.0.0.1:0",
		CA:              localCA,
		Rules:           eng,
		Session:         sw,
		MaxBodyBytes:    256,
		UpstreamRootCAs: upstreamPool,
	})
	if err != nil {
		t.Fatalf("proxy.New failed: %v", err)
	}
	addr, err := px.Start()
	if err != nil {
		t.Fatalf("proxy.Start failed: %v", err)
	}
	defer px.Shutdown(t.Context())

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: localCA.CertPool()},
		},
	}

	// 1. HTTPS POST through CONNECT + MITM
	payload := `{"hello":"wirecut","n":42}`
	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/echo", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("Cookie", "sid=secret-cookie")
	req.Header.Set("x-api-key", "secret-api-key")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request via proxy failed: %v", err)
	}
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	if string(respBody) != payload {
		t.Fatalf("body mismatch: got %q, want %q", string(respBody), payload)
	}
	if got := resp.Header.Get("X-Upstream-Saw-Injected"); got != "yes-mitm" {
		t.Fatalf("expected injected request header to reach upstream, got %q", got)
	}
	if got := resp.Header.Get("X-Wirecut"); got != "active" {
		t.Fatalf("expected X-Wirecut response header, got %q", got)
	}
	if got := resp.Header.Get("X-Secret-Server"); got != "" {
		t.Fatalf("expected X-Secret-Server removed, got %q", got)
	}

	// 2. Blocked rule request
	delReq, _ := http.NewRequest(http.MethodDelete, upstream.URL+"/admin/nuke", nil)
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("blocked request failed: %v", err)
	}
	delBody, _ := io.ReadAll(delResp.Body)
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for blocked request, got %d", delResp.StatusCode)
	}
	if string(delBody) != "blocked-by-test" {
		t.Fatalf("expected blocked body, got %q", string(delBody))
	}

	// 3. Large body response: wire intact (1024B), session truncated at 256B
	bigUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("A"), 1024))
	}))
	defer bigUpstream.Close()
	upstreamPool.AddCert(bigUpstream.Certificate())

	bigResp, err := client.Get(bigUpstream.URL + "/big")
	if err != nil {
		t.Fatalf("big request failed: %v", err)
	}
	bigBytes, _ := io.ReadAll(bigResp.Body)
	bigResp.Body.Close()
	if len(bigBytes) != 1024 {
		t.Fatalf("expected full 1024 bytes on wire, got %d", len(bigBytes))
	}

	_ = sw.Close()

	// Verify raw secrets never touched session file on disk.
	rawFile, err := os.ReadFile(sessPath)
	if err != nil {
		t.Fatalf("read session file failed: %v", err)
	}
	for _, secret := range []string{"super-secret-token", "secret-cookie", "secret-api-key"} {
		if bytes.Contains(rawFile, []byte(secret)) {
			t.Fatalf("raw secret %q leaked into session file!", secret)
		}
	}

	exchanges, err := session.ReadFile(sessPath)
	if err != nil {
		t.Fatalf("session.ReadFile failed: %v", err)
	}
	if len(exchanges) != 3 {
		t.Fatalf("expected 3 exchanges, got %d", len(exchanges))
	}
	if exchanges[0].RequestHeaders.Get("Authorization") != redact.Placeholder {
		t.Fatalf("expected redacted Authorization, got %q", exchanges[0].RequestHeaders.Get("Authorization"))
	}
	if !exchanges[1].Blocked {
		t.Fatal("expected second exchange to be marked blocked")
	}
	if exchanges[2].ResponseSize != 1024 || !exchanges[2].ResponseTruncated || len(exchanges[2].ResponseBody) != 256 {
		t.Fatalf("unexpected truncation metadata: size=%d truncated=%v bodyLen=%d",
			exchanges[2].ResponseSize, exchanges[2].ResponseTruncated, len(exchanges[2].ResponseBody))
	}
}

func TestPlainHTTPAndNoRedact(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("plain-ok:" + r.Method))
	}))
	defer upstream.Close()

	localCA, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sessPath := filepath.Join(t.TempDir(), "noredact.jsonl")
	sw, err := session.NewWriter(sessPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()

	px, err := New(Config{
		Addr:     "127.0.0.1:0",
		CA:       localCA,
		Session:  sw,
		NoRedact: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := px.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer px.Shutdown(t.Context())

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/ping", nil)
	req.Header.Set("Authorization", "Bearer raw-allowed")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("plain HTTP via proxy failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "plain-ok:GET" {
		t.Fatalf("unexpected body: %q", string(body))
	}

	_ = sw.Close()
	exchanges, err := session.ReadFile(sessPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(exchanges) != 1 || exchanges[0].RequestHeaders.Get("Authorization") != "Bearer raw-allowed" {
		t.Fatalf("expected raw Authorization with NoRedact=true, got %+v", exchanges)
	}
}

func TestMalformedRequestsDoNotPanic(t *testing.T) {
	localCA, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	px, err := New(Config{
		Addr: "127.0.0.1:0",
		CA:   localCA,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := px.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer px.Shutdown(t.Context())

	// 1. Raw garbage bytes (not HTTP)
	conn1, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn1.Write([]byte("NOT_HTTP \x00\xff\xfe GARBAGE\r\n\r\n"))
	_ = conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(conn1)
	_ = conn1.Close()

	// 2. Invalid CONNECT target
	conn2, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn2.Write([]byte("CONNECT :notaport HTTP/1.1\r\nHost: :notaport\r\n\r\n"))
	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp2, _ := io.ReadAll(conn2)
	_ = conn2.Close()
	if !bytes.Contains(resp2, []byte("400")) {
		t.Fatalf("expected 400 response for malformed CONNECT, got %q", string(resp2))
	}

	// 3. Valid CONNECT followed by non-TLS garbage bytes
	conn3, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn3.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	_ = conn3.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn3)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		_ = conn3.Close()
		t.Fatalf("expected 200 Connection Established, got %q (err=%v)", statusLine, err)
	}
	_, _ = conn3.Write([]byte("definitely-not-a-tls-client-hello\r\n"))
	_, _ = io.ReadAll(conn3)
	_ = conn3.Close()

	// 4. Plain HTTP request missing Host/scheme
	conn4, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn4.Write([]byte("GET /relative HTTP/1.0\r\n\r\n"))
	_ = conn4.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp4, _ := io.ReadAll(conn4)
	_ = conn4.Close()
	if !bytes.Contains(resp4, []byte("400")) {
		t.Fatalf("expected 400 for proxy request without host, got %q", string(resp4))
	}
}
