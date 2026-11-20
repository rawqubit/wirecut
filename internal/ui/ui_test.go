package ui

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rawqubit/wirecut/internal/ca"
	"github.com/rawqubit/wirecut/internal/proxy"
	"github.com/rawqubit/wirecut/internal/session"
)

func TestUIEndpointsSSEAndReplay(t *testing.T) {
	// Embedded SPA must contain zero external asset URLs.
	html := string(indexHTML)
	if strings.Contains(html, "http://") || strings.Contains(html, "https://") {
		t.Fatal("embedded UI HTML must not reference external URLs")
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"edited_header":"` + r.Header.Get("X-Replay-Edit") + `","body":` + string(body) + `}`))
	}))
	defer upstream.Close()

	localCA, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	uiSrv := New(Config{
		Addr: "127.0.0.1:0",
		CA:   localCA,
	})

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	px, err := proxy.New(proxy.Config{
		Addr:            "127.0.0.1:0",
		CA:              localCA,
		UpstreamRootCAs: upstreamPool,
		OnExchange:      uiSrv.Publish,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr, err := px.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer px.Shutdown(t.Context())

	uiSrv.SetProxyAddr(proxyAddr)
	uiAddr, err := uiSrv.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer uiSrv.Shutdown(t.Context())

	baseUI := "http://" + uiAddr

	// 1. Index returns HTML.
	idxResp, err := http.Get(baseUI + "/")
	if err != nil {
		t.Fatal(err)
	}
	idxResp.Body.Close()
	if idxResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /, got %d", idxResp.StatusCode)
	}

	// 2. Open SSE stream and wait for connected comment, then trigger replay via proxy.
	sseResp, err := http.Get(baseUI + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer sseResp.Body.Close()
	reader := bufio.NewReader(sseResp.Body)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, ": connected") {
		t.Fatalf("expected SSE connected preamble, got %q (err=%v)", line, err)
	}

	// 3. Replay request with edited header -> flows through proxy -> captured -> broadcast on SSE.
	replayPayload, _ := json.Marshal(ReplayRequest{
		Method: "POST",
		URL:    upstream.URL + "/replay-check",
		Headers: map[string][]string{
			"Content-Type":  {"application/json"},
			"X-Replay-Edit": {"replayed-v2"},
		},
		Body: `{"ok":true}`,
	})
	rpResp, err := http.Post(baseUI+"/api/replay", "application/json", bytes.NewReader(replayPayload))
	if err != nil {
		t.Fatalf("POST /api/replay failed: %v", err)
	}
	rpBody, _ := io.ReadAll(rpResp.Body)
	rpResp.Body.Close()
	if rpResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /api/replay, got %d: %s", rpResp.StatusCode, string(rpBody))
	}
	if !strings.Contains(string(rpBody), "replayed-v2") {
		t.Fatalf("expected replay response to echo edited header, got %s", string(rpBody))
	}

	// Read SSE event produced by the replayed exchange.
	done := make(chan session.Exchange, 1)
	go func() {
		for {
			l, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(l, "data: ") {
				var ex session.Exchange
				if json.Unmarshal([]byte(strings.TrimPrefix(l, "data: ")), &ex) == nil {
					done <- ex
					return
				}
			}
		}
	}()

	select {
	case gotEx := <-done:
		if gotEx.Method != "POST" || gotEx.RequestHeaders.Get("X-Replay-Edit") != "replayed-v2" {
			t.Fatalf("unexpected SSE exchange: %+v", gotEx)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SSE exchange event after replay")
	}

	// 4. /api/exchanges lists the captured exchange.
	listResp, err := http.Get(baseUI + "/api/exchanges")
	if err != nil {
		t.Fatal(err)
	}
	var listData struct {
		Exchanges []session.Exchange `json:"exchanges"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listData); err != nil {
		t.Fatal(err)
	}
	listResp.Body.Close()
	if len(listData.Exchanges) != 1 {
		t.Fatalf("expected 1 exchange in UI store, got %d", len(listData.Exchanges))
	}
}
