package redact

import (
	"net/http"
	"strings"
)

const Placeholder = "[REDACTED]"

var sensitiveHeaders = map[string]bool{
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              true,
	"Set-Cookie":          true,
	"X-Api-Key":           true,
}

func IsSensitiveHeader(name string) bool {
	return sensitiveHeaders[http.CanonicalHeaderKey(strings.TrimSpace(name))]
}

func CloneHeaders(src http.Header, redact bool) http.Header {
	if src == nil {
		return nil
	}
	dst := make(http.Header, len(src))
	for k, vals := range src {
		if redact && IsSensitiveHeader(k) {
			redacted := make([]string, len(vals))
			for i := range redacted {
				redacted[i] = Placeholder
			}
			dst[k] = redacted
			continue
		}
		cp := make([]string, len(vals))
		copy(cp, vals)
		dst[k] = cp
	}
	return dst
}
