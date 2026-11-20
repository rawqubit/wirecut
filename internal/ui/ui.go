package ui

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rawqubit/wirecut/internal/ca"
	"github.com/rawqubit/wirecut/internal/rules"
	"github.com/rawqubit/wirecut/internal/session"
)

//go:embed static/index.html
var indexHTML []byte

const defaultMaxHistory = 2000

type Config struct {
	Addr       string
	ProxyAddr  string
	CA         *ca.CA
	Rules      *rules.Engine
	Initial    []session.Exchange
	MaxHistory int
	ErrorLog   *log.Logger
}

type Server struct {
	cfg        Config
	maxHistory int
	logger     *log.Logger
	httpServer *http.Server
	listener   net.Listener

	mu          sync.RWMutex
	exchanges   []session.Exchange
	subscribers map[chan session.Exchange]struct{}
}

func New(cfg Config) *Server {
	if cfg.Addr == "" {
		cfg.Addr = ":8099"
	}
	maxHist := cfg.MaxHistory
	if maxHist <= 0 {
		maxHist = defaultMaxHistory
	}
	logger := cfg.ErrorLog
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	initCopy := make([]session.Exchange, len(cfg.Initial))
	copy(initCopy, cfg.Initial)
	if len(initCopy) > maxHist {
		initCopy = initCopy[len(initCopy)-maxHist:]
	}

	s := &Server{
		cfg:         cfg,
		maxHistory:  maxHist,
		logger:      logger,
		exchanges:   initCopy,
		subscribers: make(map[chan session.Exchange]struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /api/exchanges", s.handleGetExchanges)
	mux.HandleFunc("POST /api/exchanges/clear", s.handleClearExchanges)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("POST /api/replay", s.handleReplay)
	mux.HandleFunc("GET /api/rules", s.handleRules)
	mux.HandleFunc("GET /api/ca.pem", s.handleCA)

	s.httpServer = &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		ErrorLog:          logger,
	}
	return s
}

func (s *Server) SetProxyAddr(addr string) {
	s.mu.Lock()
	s.cfg.ProxyAddr = addr
	s.mu.Unlock()
}

func (s *Server) Start() (string, error) {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return "", fmt.Errorf("listen UI %s: %w", s.cfg.Addr, err)
	}
	s.listener = ln
	go func() {
		if err := s.httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			s.logger.Printf("ui server error: %v", err)
		}
	}()
	return ln.Addr().String(), nil
}

func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.cfg.Addr
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Publish(ex session.Exchange) {
	s.mu.Lock()
	s.exchanges = append(s.exchanges, ex)
	if len(s.exchanges) > s.maxHistory {
		s.exchanges = s.exchanges[len(s.exchanges)-s.maxHistory:]
	}
	for ch := range s.subscribers {
		select {
		case ch <- ex:
		default:
		}
	}
	s.mu.Unlock()
}

func (s *Server) Exchanges() []session.Exchange {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]session.Exchange, len(s.exchanges))
	copy(cp, s.exchanges)
	return cp
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTML)
}

func (s *Server) handleGetExchanges(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	cp := make([]session.Exchange, len(s.exchanges))
	copy(cp, s.exchanges)
	proxyAddr := s.cfg.ProxyAddr
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"exchanges":      cp,
		"proxy_addr":     proxyAddr,
		"replay_enabled": strings.TrimSpace(proxyAddr) != "",
	})
}

func (s *Server) handleClearExchanges(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.exchanges = nil
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan session.Exchange, 64)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.subscribers, ch)
		s.mu.Unlock()
	}()

	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ex := <-ch:
			data, err := json.Marshal(ex)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: exchange\ndata: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

type ReplayRequest struct {
	Method       string              `json:"method"`
	URL          string              `json:"url"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body"`
	BodyEncoding string              `json:"body_encoding"`
}

func (s *Server) handleReplay(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	proxyAddr := strings.TrimSpace(s.cfg.ProxyAddr)
	s.mu.RUnlock()

	if proxyAddr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "replay is disabled because no proxy address is configured",
		})
		return
	}

	var reqBody ReplayRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&reqBody); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload: " + err.Error()})
		return
	}

	method := strings.ToUpper(strings.TrimSpace(reqBody.Method))
	if method == "" {
		method = http.MethodGet
	}
	parsedURL, err := url.Parse(strings.TrimSpace(reqBody.URL))
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url must be an absolute http:// or https:// URL"})
		return
	}

	proxyURL, err := normalizeProxyURL(proxyAddr)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var bodyBytes []byte
	if reqBody.Body != "" {
		if reqBody.BodyEncoding == "base64" {
			bodyBytes, err = base64.StdEncoding.DecodeString(reqBody.Body)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid base64 body: " + err.Error()})
				return
			}
		} else {
			bodyBytes = []byte(reqBody.Body)
		}
	}

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = strings.NewReader(string(bodyBytes))
	}
	outReq, err := http.NewRequestWithContext(r.Context(), method, parsedURL.String(), bodyReader)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	for k, vals := range reqBody.Headers {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if strings.EqualFold(k, "Host") && len(vals) > 0 {
			outReq.Host = vals[0]
			continue
		}
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vals {
			outReq.Header.Add(k, v)
		}
	}

	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	if s.cfg.CA != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: s.cfg.CA.CertPool()}
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(outReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "replay request failed: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "read replay response: " + err.Error()})
		return
	}
	bodyText, bodyEnc := session.EncodeBody(respBytes)

	writeJSON(w, http.StatusOK, map[string]any{
		"status_code":   resp.StatusCode,
		"status":        resp.Status,
		"headers":       resp.Header,
		"body":          bodyText,
		"body_encoding": bodyEnc,
		"duration_ms":   float64(time.Since(start).Microseconds()) / 1000.0,
	})
}

func normalizeProxyURL(addr string) (*url.URL, error) {
	if !strings.Contains(addr, "://") {
		if strings.HasPrefix(addr, ":") {
			addr = "127.0.0.1" + addr
		}
		addr = "http://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address %q: %w", addr, err)
	}
	return u, nil
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	var list []rules.Rule
	if s.cfg.Rules != nil {
		list = s.cfg.Rules.Rules()
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": list})
}

func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	if s.cfg.CA == nil {
		http.Error(w, "no CA configured", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="wirecut-ca.pem"`)
	_, _ = w.Write(s.cfg.CA.CertPEM())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
