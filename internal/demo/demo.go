package demo

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rawqubit/wirecut/internal/ca"
	"github.com/rawqubit/wirecut/internal/proxy"
	"github.com/rawqubit/wirecut/internal/rules"
	"github.com/rawqubit/wirecut/internal/session"
)

type Options struct {
	SessionPath  string
	CADir        string
	MaxBodyBytes int64
	NoRedact     bool
	Out          io.Writer
}

type Result struct {
	SessionPath     string
	Exchanges       []session.Exchange
	UpstreamHitOn5  bool
	SecretsLeaked   bool
}

func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.SessionPath == "" {
		opts.SessionPath = "wirecut-demo.jsonl"
	}
	if opts.MaxBodyBytes == 0 {
		opts.MaxBodyBytes = 512
	}

	caDir := opts.CADir
	tempCA := false
	if caDir == "" {
		var err error
		caDir, err = os.MkdirTemp("", "wirecut-demo-ca-*")
		if err != nil {
			return nil, fmt.Errorf("create temp CA dir: %w", err)
		}
		tempCA = true
	}
	if tempCA {
		defer os.RemoveAll(caDir)
	}

	localCA, err := ca.LoadOrCreate(caDir)
	if err != nil {
		return nil, fmt.Errorf("init CA: %w", err)
	}

	// Remove previous demo session file so each demo run produces a clean 6-line session.
	_ = os.Remove(opts.SessionPath)
	sw, err := session.NewWriter(opts.SessionPath)
	if err != nil {
		return nil, fmt.Errorf("open session writer: %w", err)
	}
	defer sw.Close()

	var adminDeleteHit atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"service":"demo-upstream"}`))
	})
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Internal-Debug", "strip-this-header")
		_, _ = fmt.Fprintf(w, `{"role":%q,"trace_header":%q,"users":["alice","bob"]}`,
			r.URL.Query().Get("role"), r.Header.Get("X-Wirecut-Trace"))
	})
	mux.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"order_id": "ord_1001",
			"received": in,
			"trace":    r.Header.Get("X-Wirecut-Trace"),
		})
	})
	mux.HandleFunc("/api/orders/42", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"order_id":42,"updated":%s}`, string(body))
	})
	mux.HandleFunc("/api/admin/reset", func(w http.ResponseWriter, r *http.Request) {
		adminDeleteHit.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"reset":true}`))
	})
	mux.HandleFunc("/api/blob", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(bytes.Repeat([]byte("W"), 2048))
	})

	plainUpstream := httptest.NewServer(mux)
	defer plainUpstream.Close()

	tlsUpstream := httptest.NewTLSServer(mux)
	defer tlsUpstream.Close()

	ruleEngine, err := rules.NewEngine([]rules.Rule{
		{
			Name:   "block-admin-delete",
			Match:  rules.Match{Method: "DELETE", Path: "/api/admin/*"},
			Action: "block",
			Status: http.StatusForbidden,
			Body:   "blocked by wirecut rule: admin deletes disabled in demo\n",
		},
		{
			Name:                  "inject-trace-and-strip",
			Match:                 rules.Match{Path: "/api/*"},
			Action:                "rewrite",
			SetRequestHeaders:     map[string]string{"X-Wirecut-Trace": "demo-run"},
			SetResponseHeaders:    map[string]string{"X-Wirecut-Proxy": "intercepted"},
			RemoveResponseHeaders: []string{"X-Internal-Debug"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("init rules: %w", err)
	}

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(tlsUpstream.Certificate())

	px, err := proxy.New(proxy.Config{
		Addr:            "127.0.0.1:0",
		CA:              localCA,
		Rules:           ruleEngine,
		Session:         sw,
		MaxBodyBytes:    opts.MaxBodyBytes,
		NoRedact:        opts.NoRedact,
		UpstreamRootCAs: upstreamPool,
	})
	if err != nil {
		return nil, fmt.Errorf("create proxy: %w", err)
	}
	proxyAddr, err := px.Start()
	if err != nil {
		return nil, fmt.Errorf("start proxy: %w", err)
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = px.Shutdown(shutCtx)
	}()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: localCA.CertPool()},
		},
	}

	fmt.Fprintf(opts.Out, "wirecut demo\n")
	fmt.Fprintf(opts.Out, "  CA:       %s (ephemeral MITM CA)\n", localCA.Certificate().Subject.CommonName)
	fmt.Fprintf(opts.Out, "  Proxy:    http://%s (HTTP/1.1 + CONNECT MITM)\n", proxyAddr)
	fmt.Fprintf(opts.Out, "  Upstream: %s (in-process TLS) + %s (HTTP)\n", tlsUpstream.URL, plainUpstream.URL)
	fmt.Fprintf(opts.Out, "  Rules:    block-admin-delete, inject-trace-and-strip\n")
	fmt.Fprintf(opts.Out, "  Cap:      %d bytes | Redact: %v | Session: %s\n\n", opts.MaxBodyBytes, !opts.NoRedact, opts.SessionPath)

	type step struct {
		label   string
		method  string
		url     string
		headers map[string]string
		body    string
	}

	steps := []step{
		{
			label:  "plain HTTP health check",
			method: http.MethodGet,
			url:    plainUpstream.URL + "/api/health",
		},
		{
			label:  "HTTPS GET with header rewrite",
			method: http.MethodGet,
			url:    tlsUpstream.URL + "/api/users?role=admin",
		},
		{
			label:  "HTTPS JSON POST with redacted secrets",
			method: http.MethodPost,
			url:    tlsUpstream.URL + "/api/orders",
			headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer sk-demo-secret-token-999",
				"Cookie":        "session=demo-cookie-xyz",
				"x-api-key":     "wk-demo-key-777",
			},
			body: `{"item":"logic-analyzer","qty":2,"priority":"rush"}`,
		},
		{
			label:  "HTTPS JSON PUT",
			method: http.MethodPut,
			url:    tlsUpstream.URL + "/api/orders/42",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body: `{"status":"shipped"}`,
		},
		{
			label:  "HTTPS DELETE blocked by rule",
			method: http.MethodDelete,
			url:    tlsUpstream.URL + "/api/admin/reset",
		},
		{
			label:  "HTTPS large body (> capture cap)",
			method: http.MethodGet,
			url:    tlsUpstream.URL + "/api/blob",
		},
	}

	for i, st := range steps {
		var bodyReader io.Reader
		if st.body != "" {
			bodyReader = strings.NewReader(st.body)
		}
		req, err := http.NewRequestWithContext(ctx, st.method, st.url, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("step %d build request: %w", i+1, err)
		}
		for k, v := range st.headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("step %d execute request: %w", i+1, err)
		}
		wireBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		note := st.label
		if blk := resp.Header.Get("X-Wirecut-Blocked"); blk != "" {
			note += " [blocked:" + blk + "]"
		} else if pxHdr := resp.Header.Get("X-Wirecut-Proxy"); pxHdr != "" {
			note += " [proxy-hdr:" + pxHdr + "]"
		}
		fmt.Fprintf(opts.Out, "  [%d/6] %-6s %-5s %-22s -> %d  (%4d B wire)  %s\n",
			i+1, st.method, req.URL.Scheme, req.URL.Path, resp.StatusCode, len(wireBytes), note)
	}

	// Ensure all writes are flushed before reading back.
	if err := sw.Close(); err != nil {
		return nil, fmt.Errorf("close session writer: %w", err)
	}

	exchanges, err := session.ReadFile(opts.SessionPath)
	if err != nil {
		return nil, fmt.Errorf("read back demo session: %w", err)
	}

	rawSession, err := os.ReadFile(opts.SessionPath)
	if err != nil {
		return nil, fmt.Errorf("read raw session bytes: %w", err)
	}
	leaked := false
	for _, secret := range []string{"sk-demo-secret-token-999", "demo-cookie-xyz", "wk-demo-key-777"} {
		if bytes.Contains(rawSession, []byte(secret)) {
			leaked = true
		}
	}

	blockedCount := 0
	truncatedCount := 0
	for _, ex := range exchanges {
		if ex.Blocked {
			blockedCount++
		}
		if ex.ResponseTruncated {
			truncatedCount++
		}
	}

	fmt.Fprintf(opts.Out, "\nSummary:\n")
	fmt.Fprintf(opts.Out, "  Exchanges recorded: %d (blocked=%d, truncated=%d)\n", len(exchanges), blockedCount, truncatedCount)
	fmt.Fprintf(opts.Out, "  Upstream saw blocked DELETE: %v\n", adminDeleteHit.Load())
	fmt.Fprintf(opts.Out, "  Raw secrets on disk: %v\n", leaked)
	fmt.Fprintf(opts.Out, "  Session file: %s (%d bytes)\n", opts.SessionPath, len(rawSession))

	return &Result{
		SessionPath:    opts.SessionPath,
		Exchanges:      exchanges,
		UpstreamHitOn5: adminDeleteHit.Load(),
		SecretsLeaked:  leaked,
	}, nil
}
