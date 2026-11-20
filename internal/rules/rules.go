package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
)

type Match struct {
	Host   string `json:"host,omitempty"`
	Path   string `json:"path,omitempty"`
	Method string `json:"method,omitempty"`
}

type Rule struct {
	Name                  string            `json:"name,omitempty"`
	Enabled               *bool             `json:"enabled,omitempty"`
	Match                 Match             `json:"match"`
	Action                string            `json:"action,omitempty"` // "block" or "rewrite"
	Status                int               `json:"status,omitempty"`
	Body                  string            `json:"body,omitempty"`
	SetRequestHeaders     map[string]string `json:"set_request_headers,omitempty"`
	RemoveRequestHeaders  []string          `json:"remove_request_headers,omitempty"`
	SetResponseHeaders    map[string]string `json:"set_response_headers,omitempty"`
	RemoveResponseHeaders []string          `json:"remove_response_headers,omitempty"`
}

func (r Rule) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

func (r Rule) Label() string {
	if r.Name != "" {
		return r.Name
	}
	action := r.Action
	if action == "" {
		action = "rewrite"
	}
	return fmt.Sprintf("%s(%s %s%s)", action, emptyStar(r.Match.Method), emptyStar(r.Match.Host), emptyStar(r.Match.Path))
}

func emptyStar(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

func (r *Rule) normalizeAndValidate() error {
	hasRewrite := len(r.SetRequestHeaders) > 0 || len(r.RemoveRequestHeaders) > 0 ||
		len(r.SetResponseHeaders) > 0 || len(r.RemoveResponseHeaders) > 0

	switch strings.ToLower(strings.TrimSpace(r.Action)) {
	case "":
		if hasRewrite {
			r.Action = "rewrite"
		} else {
			return errors.New("rule action is required (\"block\" or \"rewrite\")")
		}
	case "block":
		r.Action = "block"
		if r.Status == 0 {
			r.Status = http.StatusForbidden
		}
		if r.Status < 100 || r.Status > 599 {
			return fmt.Errorf("invalid block status %d", r.Status)
		}
		if r.Body == "" {
			r.Body = "Blocked by wirecut rule\n"
		}
	case "rewrite":
		r.Action = "rewrite"
		if !hasRewrite {
			return errors.New("rewrite rule must specify at least one header modification")
		}
	default:
		return fmt.Errorf("unknown rule action %q (expected \"block\" or \"rewrite\")", r.Action)
	}
	return nil
}

type Engine struct {
	rules []Rule
}

func NewEngine(rules []Rule) (*Engine, error) {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		if err := r.normalizeAndValidate(); err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i, r.Label(), err)
		}
		out[i] = r
	}
	return &Engine{rules: out}, nil
}

func LoadFile(filePath string) ([]Rule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read rules file %s: %w", filePath, err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}
	var list []Rule
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, fmt.Errorf("parse rules array in %s: %w", filePath, err)
		}
	} else {
		var wrapper struct {
			Rules []Rule `json:"rules"`
		}
		if err := json.Unmarshal(trimmed, &wrapper); err != nil {
			return nil, fmt.Errorf("parse rules object in %s: %w", filePath, err)
		}
		list = wrapper.Rules
	}
	for i := range list {
		if err := list[i].normalizeAndValidate(); err != nil {
			return nil, fmt.Errorf("rule %d in %s: %w", i, filePath, err)
		}
	}
	return list, nil
}

// ParseRule parses a single rule from JSON or shorthand syntax:
//   block:host=example.com,path=/admin/*,method=DELETE,status=403
func ParseRule(spec string) (Rule, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return Rule{}, errors.New("empty rule spec")
	}
	if strings.HasPrefix(trimmed, "{") {
		var r Rule
		if err := json.Unmarshal([]byte(trimmed), &r); err != nil {
			return Rule{}, fmt.Errorf("parse rule JSON: %w", err)
		}
		if err := r.normalizeAndValidate(); err != nil {
			return Rule{}, err
		}
		return r, nil
	}

	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		return Rule{}, fmt.Errorf("invalid rule spec %q: expected JSON or action:k=v,...", spec)
	}
	action := strings.ToLower(strings.TrimSpace(parts[0]))
	r := Rule{Action: action}
	for _, kv := range strings.Split(parts[1], ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		pair := strings.SplitN(kv, "=", 2)
		if len(pair) != 2 {
			return Rule{}, fmt.Errorf("invalid rule token %q: expected key=value", kv)
		}
		k := strings.ToLower(strings.TrimSpace(pair[0]))
		v := strings.TrimSpace(pair[1])
		switch k {
		case "name":
			r.Name = v
		case "host":
			r.Match.Host = v
		case "path":
			r.Match.Path = v
		case "method":
			r.Match.Method = v
		case "status":
			code, err := strconv.Atoi(v)
			if err != nil {
				return Rule{}, fmt.Errorf("invalid status %q: %w", v, err)
			}
			r.Status = code
		case "body":
			r.Body = v
		case "set-req-header":
			hk, hv, ok := strings.Cut(v, ":")
			if !ok {
				return Rule{}, fmt.Errorf("invalid header %q: expected Name:Value", v)
			}
			if r.SetRequestHeaders == nil {
				r.SetRequestHeaders = make(map[string]string)
			}
			r.SetRequestHeaders[strings.TrimSpace(hk)] = strings.TrimSpace(hv)
		case "del-req-header":
			r.RemoveRequestHeaders = append(r.RemoveRequestHeaders, v)
		case "set-resp-header":
			hk, hv, ok := strings.Cut(v, ":")
			if !ok {
				return Rule{}, fmt.Errorf("invalid header %q: expected Name:Value", v)
			}
			if r.SetResponseHeaders == nil {
				r.SetResponseHeaders = make(map[string]string)
			}
			r.SetResponseHeaders[strings.TrimSpace(hk)] = strings.TrimSpace(hv)
		case "del-resp-header":
			r.RemoveResponseHeaders = append(r.RemoveResponseHeaders, v)
		default:
			return Rule{}, fmt.Errorf("unknown rule key %q", k)
		}
	}
	if err := r.normalizeAndValidate(); err != nil {
		return Rule{}, err
	}
	return r, nil
}

func (e *Engine) Rules() []Rule {
	if e == nil {
		return nil
	}
	cp := make([]Rule, len(e.rules))
	copy(cp, e.rules)
	return cp
}

type RequestDecision struct {
	Blocked     bool
	Status      int
	Body        string
	MatchedRule string
	Applied     []string
}

func (e *Engine) ApplyRequest(method, host, reqPath string, headers http.Header) RequestDecision {
	if e == nil || len(e.rules) == 0 {
		return RequestDecision{}
	}
	var res RequestDecision
	for _, r := range e.rules {
		if !r.IsEnabled() || !matches(r.Match, method, host, reqPath) {
			continue
		}
		res.Applied = append(res.Applied, r.Label())
		if r.Action == "block" {
			res.Blocked = true
			res.Status = r.Status
			res.Body = r.Body
			res.MatchedRule = r.Label()
			return res
		}
		for _, h := range r.RemoveRequestHeaders {
			headers.Del(h)
		}
		for k, v := range r.SetRequestHeaders {
			headers.Set(k, v)
		}
	}
	return res
}

func (e *Engine) ApplyResponse(method, host, reqPath string, headers http.Header) []string {
	if e == nil || len(e.rules) == 0 {
		return nil
	}
	var applied []string
	for _, r := range e.rules {
		if !r.IsEnabled() || r.Action == "block" || !matches(r.Match, method, host, reqPath) {
			continue
		}
		changed := false
		for _, h := range r.RemoveResponseHeaders {
			if headers.Get(h) != "" || len(headers.Values(h)) > 0 {
				changed = true
			}
			headers.Del(h)
		}
		for k, v := range r.SetResponseHeaders {
			headers.Set(k, v)
			changed = true
		}
		if changed {
			applied = append(applied, r.Label())
		}
	}
	return applied
}

func matches(m Match, method, host, reqPath string) bool {
	if m.Method != "" && m.Method != "*" {
		if !strings.EqualFold(m.Method, method) {
			return false
		}
	}
	if !matchHost(m.Host, host) {
		return false
	}
	if !matchPath(m.Path, reqPath) {
		return false
	}
	return true
}

func matchHost(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" || pattern == "*" {
		return true
	}
	hostLower := strings.ToLower(strings.TrimSpace(host))
	// If pattern does not include a port, strip port from incoming host.
	if _, _, err := net.SplitHostPort(pattern); err != nil {
		if h, _, splitErr := net.SplitHostPort(hostLower); splitErr == nil {
			hostLower = h
		}
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(hostLower, suffix) && len(hostLower) > len(suffix)
	}
	return hostLower == pattern
}

func matchPath(pattern, reqPath string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(reqPath, prefix)
	}
	if matched, err := path.Match(pattern, reqPath); err == nil && matched {
		return true
	}
	return reqPath == pattern
}
