package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rawqubit/wirecut/internal/ca"
	"github.com/rawqubit/wirecut/internal/redact"
	"github.com/rawqubit/wirecut/internal/rules"
	"github.com/rawqubit/wirecut/internal/session"
)

const DefaultMaxBodyBytes int64 = 1 << 20 // 1 MiB

type Config struct {
	Addr               string
	CA                 *ca.CA
	Rules              *rules.Engine
	Session            *session.Writer
	MaxBodyBytes       int64
	NoRedact           bool
	InsecureSkipVerify bool
	UpstreamRootCAs    *x509.CertPool
	ErrorLog           *log.Logger
	OnExchange         func(session.Exchange)
}

type Proxy struct {
	cfg          Config
	maxBodyBytes int64
	logger       *log.Logger
	transport    *http.Transport
	mainServer   *http.Server
	mitmServer   *http.Server
	mitmListener *connQueueListener
	mitmTargets  sync.Map // net.Conn -> string (host:port)

	listener net.Listener
	seq      atomic.Uint64

	subMu       sync.RWMutex
	subscribers map[chan session.Exchange]struct{}

	wg sync.WaitGroup
}

func New(cfg Config) (*Proxy, error) {
	if cfg.CA == nil {
		return nil, errors.New("proxy config requires a CA")
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody == 0 {
		maxBody = DefaultMaxBodyBytes
	} else if maxBody < 0 {
		maxBody = 0
	}
	logger := cfg.ErrorLog
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		RootCAs:            cfg.UpstreamRootCAs,
	}

	transport := &http.Transport{
		Proxy:               nil, // never recursively proxy
		TLSClientConfig:     tlsCfg,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		TLSNextProto:        make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}

	p := &Proxy{
		cfg:          cfg,
		maxBodyBytes: maxBody,
		logger:       logger,
		transport:    transport,
		mitmListener: newConnQueueListener(),
		subscribers:  make(map[chan session.Exchange]struct{}),
	}

	p.mainServer = &http.Server{
		Addr:              cfg.Addr,
		Handler:           http.HandlerFunc(p.handleRoot),
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          logger,
	}

	p.mitmServer = &http.Server{
		Handler:           http.HandlerFunc(p.handleMITM),
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          logger,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if target, ok := p.mitmTargets.Load(c); ok {
				return context.WithValue(ctx, mitmTargetKey{}, target.(string))
			}
			return ctx
		},
		ConnState: func(c net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				p.mitmTargets.Delete(c)
			}
		},
	}

	return p, nil
}

type mitmTargetKey struct{}

func (p *Proxy) Start() (string, error) {
	ln, err := net.Listen("tcp", p.cfg.Addr)
	if err != nil {
		return "", fmt.Errorf("listen %s: %w", p.cfg.Addr, err)
	}
	p.listener = ln

	p.wg.Add(2)
	go func() {
		defer p.wg.Done()
		if err := p.mitmServer.Serve(p.mitmListener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			p.logger.Printf("mitm server error: %v", err)
		}
	}()
	go func() {
		defer p.wg.Done()
		if err := p.mainServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			p.logger.Printf("proxy server error: %v", err)
		}
	}()

	return ln.Addr().String(), nil
}

func (p *Proxy) Addr() string {
	if p.listener != nil {
		return p.listener.Addr().String()
	}
	return p.cfg.Addr
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	var errs []error
	if err := p.mainServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errs = append(errs, err)
	}
	_ = p.mitmListener.Close()
	if err := p.mitmServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errs = append(errs, err)
	}
	p.transport.CloseIdleConnections()
	p.wg.Wait()
	return errors.Join(errs...)
}

func (p *Proxy) Subscribe() (<-chan session.Exchange, func()) {
	ch := make(chan session.Exchange, 128)
	p.subMu.Lock()
	p.subscribers[ch] = struct{}{}
	p.subMu.Unlock()

	cancel := func() {
		p.subMu.Lock()
		if _, ok := p.subscribers[ch]; ok {
			delete(p.subscribers, ch)
			close(ch)
		}
		p.subMu.Unlock()
	}
	return ch, cancel
}

func (p *Proxy) emit(ex session.Exchange) {
	if p.cfg.Session != nil {
		if err := p.cfg.Session.Write(ex); err != nil {
			p.logger.Printf("session write error (%s): %v", ex.ID, err)
		}
	}
	if p.cfg.OnExchange != nil {
		p.cfg.OnExchange(ex)
	}
	p.subMu.RLock()
	for ch := range p.subscribers {
		select {
		case ch <- ex:
		default:
		}
	}
	p.subMu.RUnlock()
}

func (p *Proxy) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	targetHost := r.URL.Host
	if targetHost == "" {
		targetHost = r.Host
	}
	if targetHost == "" {
		http.Error(w, "missing target host in HTTP proxy request", http.StatusBadRequest)
		return
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	} else if scheme != "http" && scheme != "https" {
		http.Error(w, "unsupported URL scheme", http.StatusBadRequest)
		return
	}

	p.forwardHTTP(w, r, scheme, targetHost)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	rawTarget := r.Host
	if rawTarget == "" {
		rawTarget = r.URL.Host
	}
	if rawTarget == "" {
		rawTarget = r.RequestURI
	}
	host, port, err := parseConnectTarget(rawTarget)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target := net.JoinHostPort(host, port)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, bufRW, err := hj.Hijack()
	if err != nil {
		p.logger.Printf("hijack failed for %s: %v", target, err)
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		return
	}

	var underlying net.Conn = clientConn
	if bufRW != nil && bufRW.Reader.Buffered() > 0 {
		underlying = &bufferedConn{Conn: clientConn, r: bufRW.Reader}
	}

	tlsConn := tls.Server(underlying, &tls.Config{
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello != nil && hello.ServerName != "" {
				return p.cfg.CA.MintLeaf(host, hello.ServerName)
			}
			return p.cfg.CA.MintLeaf(host)
		},
	})

	hsCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		p.logger.Printf("client TLS handshake failed for %s: %v", target, err)
		_ = tlsConn.Close()
		return
	}

	p.mitmTargets.Store(tlsConn, target)
	if !p.mitmListener.Push(tlsConn) {
		p.mitmTargets.Delete(tlsConn)
		_ = tlsConn.Close()
	}
}

func (p *Proxy) handleMITM(w http.ResponseWriter, r *http.Request) {
	dialHost := ""
	if v := r.Context().Value(mitmTargetKey{}); v != nil {
		dialHost, _ = v.(string)
	}
	if dialHost == "" {
		dialHost = r.Host
	}
	if dialHost == "" {
		http.Error(w, "missing target host in HTTPS tunnel", http.StatusBadRequest)
		return
	}
	p.forwardHTTP(w, r, "https", dialHost)
}

func (p *Proxy) forwardHTTP(w http.ResponseWriter, r *http.Request, scheme, dialHost string) {
	start := time.Now()
	id := fmt.Sprintf("ex_%06d", p.seq.Add(1))

	hostHeader := r.Host
	if hostHeader == "" {
		hostHeader = dialHost
	}

	displayURL := *r.URL
	displayURL.Scheme = scheme
	displayURL.Host = hostHeader

	reqHeaders := stripHopByHop(r.Header)
	decision := p.cfg.Rules.ApplyRequest(r.Method, hostHeader, r.URL.Path, reqHeaders)

	reqCap := newCaptureReader(r.Body, p.maxBodyBytes)

	if decision.Blocked {
		// Drain up to capture limit so blocked POST payloads are still inspectable.
		_, _ = io.CopyN(io.Discard, reqCap, p.maxBodyBytes+1)
		_ = reqCap.Close()

		respHeaders := http.Header{
			"Content-Type":      {"text/plain; charset=utf-8"},
			"X-Wirecut-Blocked": {decision.MatchedRule},
		}
		for k, vals := range respHeaders {
			w.Header()[k] = vals
		}
		w.WriteHeader(decision.Status)
		_, _ = io.WriteString(w, decision.Body)

		reqBodyText, reqBodyEnc := session.EncodeBody(reqCap.Captured())
		respBytes := []byte(decision.Body)
		respCapBytes := respBytes
		respTrunc := false
		if int64(len(respCapBytes)) > p.maxBodyBytes {
			respCapBytes = respCapBytes[:p.maxBodyBytes]
			respTrunc = true
		}
		respBodyText, respBodyEnc := session.EncodeBody(respCapBytes)

		p.emit(session.Exchange{
			ID:                   id,
			Timestamp:            start.UTC(),
			DurationMS:           roundMS(time.Since(start)),
			Scheme:               scheme,
			Method:               r.Method,
			URL:                  displayURL.String(),
			Host:                 hostHeader,
			Path:                 r.URL.Path,
			StatusCode:           decision.Status,
			Status:               fmt.Sprintf("%d %s", decision.Status, http.StatusText(decision.Status)),
			RequestHeaders:       redact.CloneHeaders(reqHeaders, !p.cfg.NoRedact),
			RequestBody:          reqBodyText,
			RequestBodyEncoding:  reqBodyEnc,
			RequestSize:          reqCap.Total(),
			RequestTruncated:     reqCap.Truncated(),
			ResponseHeaders:      redact.CloneHeaders(respHeaders, !p.cfg.NoRedact),
			ResponseBody:         respBodyText,
			ResponseBodyEncoding: respBodyEnc,
			ResponseSize:         int64(len(respBytes)),
			ResponseTruncated:    respTrunc,
			Blocked:              true,
			RuleMatches:          decision.Applied,
			Redacted:             !p.cfg.NoRedact,
		})
		return
	}

	outURL := *r.URL
	outURL.Scheme = scheme
	outURL.Host = dialHost

	recordedReqHeaders := redact.CloneHeaders(reqHeaders, !p.cfg.NoRedact)

	outHeaders := reqHeaders.Clone()
	if _, hasUA := outHeaders["User-Agent"]; !hasUA {
		// Prevent net/http.Transport from injecting Go-http-client/1.1 when absent.
		outHeaders["User-Agent"] = nil
	}

	outReq := &http.Request{
		Method:        r.Method,
		URL:           &outURL,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        outHeaders,
		Host:          hostHeader,
		Body:          reqCap,
		ContentLength: r.ContentLength,
	}
	outReq = outReq.WithContext(r.Context())

	resp, err := p.transport.RoundTrip(outReq)
	_ = reqCap.Close()

	reqBodyText, reqBodyEnc := session.EncodeBody(reqCap.Captured())

	if err != nil {
		errMsg := fmt.Sprintf("upstream error: %v", err)
		http.Error(w, errMsg, http.StatusBadGateway)
		p.emit(session.Exchange{
			ID:                  id,
			Timestamp:           start.UTC(),
			DurationMS:          roundMS(time.Since(start)),
			Scheme:              scheme,
			Method:              r.Method,
			URL:                 displayURL.String(),
			Host:                hostHeader,
			Path:                r.URL.Path,
			StatusCode:          http.StatusBadGateway,
			Status:              fmt.Sprintf("%d %s", http.StatusBadGateway, http.StatusText(http.StatusBadGateway)),
			RequestHeaders:      recordedReqHeaders,
			RequestBody:         reqBodyText,
			RequestBodyEncoding: reqBodyEnc,
			RequestSize:         reqCap.Total(),
			RequestTruncated:    reqCap.Truncated(),
			RuleMatches:         decision.Applied,
			Error:               err.Error(),
			Redacted:            !p.cfg.NoRedact,
		})
		return
	}
	defer resp.Body.Close()

	respHeaders := stripHopByHop(resp.Header)
	respApplied := p.cfg.Rules.ApplyResponse(r.Method, hostHeader, r.URL.Path, respHeaders)

	allMatches := append([]string(nil), decision.Applied...)
	for _, m := range respApplied {
		if !containsString(allMatches, m) {
			allMatches = append(allMatches, m)
		}
	}

	for k, vals := range respHeaders {
		w.Header()[k] = vals
	}
	w.WriteHeader(resp.StatusCode)

	respCap := newCaptureWriter(w, p.maxBodyBytes)
	if _, copyErr := io.Copy(respCap, resp.Body); copyErr != nil {
		p.logger.Printf("response copy error (%s): %v", id, copyErr)
	}

	respBodyText, respBodyEnc := session.EncodeBody(respCap.Captured())

	p.emit(session.Exchange{
		ID:                   id,
		Timestamp:            start.UTC(),
		DurationMS:           roundMS(time.Since(start)),
		Scheme:               scheme,
		Method:               r.Method,
		URL:                  displayURL.String(),
		Host:                 hostHeader,
		Path:                 r.URL.Path,
		StatusCode:           resp.StatusCode,
		Status:               resp.Status,
		RequestHeaders:       recordedReqHeaders,
		RequestBody:          reqBodyText,
		RequestBodyEncoding:  reqBodyEnc,
		RequestSize:          reqCap.Total(),
		RequestTruncated:     reqCap.Truncated(),
		ResponseHeaders:      redact.CloneHeaders(respHeaders, !p.cfg.NoRedact),
		ResponseBody:         respBodyText,
		ResponseBodyEncoding: respBodyEnc,
		ResponseSize:         respCap.Total(),
		ResponseTruncated:    respCap.Truncated(),
		RuleMatches:          allMatches,
		Redacted:             !p.cfg.NoRedact,
	})
}

func parseConnectTarget(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("empty CONNECT target")
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		host = strings.Trim(host, "[]")
		if host == "" {
			return "", "", errors.New("missing host in CONNECT target")
		}
		p, pErr := strconv.Atoi(port)
		if pErr != nil || p < 1 || p > 65535 {
			return "", "", fmt.Errorf("invalid port %q in CONNECT target", port)
		}
		return host, port, nil
	}
	// Allow bare hostname or [ipv6] without port, defaulting to 443.
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		h := strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
		if net.ParseIP(h) == nil {
			return "", "", fmt.Errorf("invalid CONNECT target %q", raw)
		}
		return h, "443", nil
	}
	if strings.Contains(raw, ":") && net.ParseIP(raw) == nil {
		return "", "", fmt.Errorf("invalid CONNECT target %q", raw)
	}
	return raw, "443", nil
}

var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Proxy-Connection":    true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func stripHopByHop(src http.Header) http.Header {
	dst := make(http.Header, len(src))
	connTokens := make(map[string]bool)
	for _, v := range src.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			tok = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(tok))
			if tok != "" {
				connTokens[tok] = true
			}
		}
	}
	for k, vals := range src {
		canon := textproto.CanonicalMIMEHeaderKey(k)
		if hopByHopHeaders[canon] || connTokens[canon] {
			continue
		}
		cp := make([]string, len(vals))
		copy(cp, vals)
		dst[k] = cp
	}
	return dst
}

func roundMS(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

type captureReader struct {
	rc        io.ReadCloser
	limit     int64
	buf       bytes.Buffer
	total     int64
	truncated bool
}

func newCaptureReader(rc io.ReadCloser, limit int64) *captureReader {
	if rc == nil {
		rc = http.NoBody
	}
	return &captureReader{rc: rc, limit: limit}
}

func (c *captureReader) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.total += int64(n)
		rem := c.limit - int64(c.buf.Len())
		if rem > 0 {
			toWrite := int64(n)
			if toWrite > rem {
				toWrite = rem
				c.truncated = true
			}
			c.buf.Write(p[:toWrite])
		} else {
			c.truncated = true
		}
	}
	return n, err
}

func (c *captureReader) Close() error    { return c.rc.Close() }
func (c *captureReader) Captured() []byte { return c.buf.Bytes() }
func (c *captureReader) Total() int64     { return c.total }
func (c *captureReader) Truncated() bool  { return c.truncated }

type captureWriter struct {
	w         io.Writer
	limit     int64
	buf       bytes.Buffer
	total     int64
	truncated bool
}

func newCaptureWriter(w io.Writer, limit int64) *captureWriter {
	return &captureWriter{w: w, limit: limit}
}

func (c *captureWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.total += int64(n)
		rem := c.limit - int64(c.buf.Len())
		if rem > 0 {
			toWrite := int64(n)
			if toWrite > rem {
				toWrite = rem
				c.truncated = true
			}
			c.buf.Write(p[:toWrite])
		} else {
			c.truncated = true
		}
	}
	return n, err
}

func (c *captureWriter) Captured() []byte { return c.buf.Bytes() }
func (c *captureWriter) Total() int64     { return c.total }
func (c *captureWriter) Truncated() bool  { return c.truncated }

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

type connQueueListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newConnQueueListener() *connQueueListener {
	return &connQueueListener{
		ch:     make(chan net.Conn, 64),
		closed: make(chan struct{}),
	}
}

func (l *connQueueListener) Push(c net.Conn) bool {
	select {
	case <-l.closed:
		return false
	default:
	}
	select {
	case l.ch <- c:
		return true
	case <-l.closed:
		return false
	}
}

func (l *connQueueListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connQueueListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		for {
			select {
			case c := <-l.ch:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return nil
}

func (l *connQueueListener) Addr() net.Addr {
	return dummyAddr{}
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "wirecut-mitm" }
