package session

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"
)

type Exchange struct {
	ID                   string      `json:"id"`
	Timestamp            time.Time   `json:"timestamp"`
	DurationMS           float64     `json:"duration_ms"`
	Scheme               string      `json:"scheme"`
	Method               string      `json:"method"`
	URL                  string      `json:"url"`
	Host                 string      `json:"host"`
	Path                 string      `json:"path"`
	StatusCode           int         `json:"status_code"`
	Status               string      `json:"status"`
	RequestHeaders       http.Header `json:"request_headers"`
	RequestBody          string      `json:"request_body,omitempty"`
	RequestBodyEncoding  string      `json:"request_body_encoding,omitempty"`
	RequestSize          int64       `json:"request_size"`
	RequestTruncated     bool        `json:"request_truncated,omitempty"`
	ResponseHeaders      http.Header `json:"response_headers"`
	ResponseBody         string      `json:"response_body,omitempty"`
	ResponseBodyEncoding string      `json:"response_body_encoding,omitempty"`
	ResponseSize         int64       `json:"response_size"`
	ResponseTruncated    bool        `json:"response_truncated,omitempty"`
	Blocked              bool        `json:"blocked,omitempty"`
	RuleMatches          []string    `json:"rule_matches,omitempty"`
	Error                string      `json:"error,omitempty"`
	Redacted             bool        `json:"redacted"`
}

func EncodeBody(data []byte) (string, string) {
	if len(data) == 0 {
		return "", ""
	}
	if utf8.Valid(data) && !bytes.ContainsRune(data, 0) {
		return string(data), "utf-8"
	}
	return base64.StdEncoding.EncodeToString(data), "base64"
}

type Writer struct {
	path string
	mu   sync.Mutex
	file *os.File
}

func NewWriter(path string) (*Writer, error) {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create session dir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open session file %s: %w", path, err)
	}
	return &Writer{
		path: path,
		file: f,
	}, nil
}

func (w *Writer) Path() string {
	return w.path
}

func (w *Writer) Write(ex Exchange) error {
	line, err := json.Marshal(ex)
	if err != nil {
		return fmt.Errorf("marshal exchange %s: %w", ex.ID, err)
	}
	line = append(line, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return fmt.Errorf("session writer %s is closed", w.path)
	}
	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("write exchange %s: %w", ex.ID, err)
	}
	return nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func ReadFile(path string) ([]Exchange, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open session file %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 32*1024*1024)

	var out []Exchange
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		var ex Exchange
		if err := json.Unmarshal(raw, &ex); err != nil {
			return nil, fmt.Errorf("parse session %s line %d: %w", path, lineNum, err)
		}
		out = append(out, ex)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan session %s: %w", path, err)
	}
	return out, nil
}
