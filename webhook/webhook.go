// Package webhook sets rate-limit key headers for Appmixer webhook requests.
package webhook

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

const (
	fieldFlowID    = "flowId"
	fieldTriggerID = "triggerId"
)

var (
	flowComponentPath = regexp.MustCompile(`^/flows/([a-f0-9-]+)/components/([a-zA-Z0-9_-]+)`)
	aliasPath         = regexp.MustCompile(`^/invoke/webhook/([^/]+)/([^/]+)$`)
)

// Config the plugin configuration.
type Config struct {
	// Headers maps a header name to the value it carries: "flowId" or "triggerId".
	Headers map[string]string `json:"headers,omitempty"`
	// IPDepth selects the client IP used as the fallback key: 0 uses the TCP
	// peer, N takes the Nth X-Forwarded-For entry from the right.
	IPDepth int `json:"ipDepth,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Headers: make(map[string]string),
	}
}

// Webhook a webhook plugin.
type Webhook struct {
	next    http.Handler
	headers map[string]string
	name    string
	ipDepth int
}

// New creates a new webhook plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	headers := config.Headers
	if len(headers) == 0 {
		headers = map[string]string{"X-Flow-Id": fieldFlowID, "X-Trigger-Id": fieldTriggerID}
	}
	for header, field := range headers {
		if field != fieldFlowID && field != fieldTriggerID {
			return nil, fmt.Errorf("header %s: unknown value %q, expected %q or %q", header, field, fieldFlowID, fieldTriggerID)
		}
	}
	if config.IPDepth < 0 {
		return nil, fmt.Errorf("ipDepth cannot be negative")
	}

	return &Webhook{
		headers: headers,
		next:    next,
		name:    name,
		ipDepth: config.IPDepth,
	}, nil
}

// ServeHTTP sets the configured headers. The trigger key is "<flowId>/<componentId>"
// for /flows/{flowId}/components/{componentId}, "alias:<aliasId>/<alias>" for
// /invoke/webhook/{aliasId}/{alias}, and "ip:<client ip>" otherwise. The flow ID is
// only set for the first form. Client-supplied values are always removed.
func (a *Webhook) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var flowID, triggerID string

	if matches := flowComponentPath.FindStringSubmatch(req.URL.Path); matches != nil {
		flowID = matches[1]
		triggerID = matches[1] + "/" + matches[2]
	} else if matches := aliasPath.FindStringSubmatch(req.URL.Path); matches != nil {
		triggerID = "alias:" + matches[1] + "/" + matches[2]
	} else {
		triggerID = "ip:" + clientIP(req, a.ipDepth)
	}

	for header, field := range a.headers {
		req.Header.Del(header)
		switch {
		case field == fieldFlowID && flowID != "":
			req.Header.Set(header, flowID)
		case field == fieldTriggerID:
			req.Header.Set(header, triggerID)
		}
	}

	a.next.ServeHTTP(rw, req)
}

func clientIP(req *http.Request, depth int) string {
	if depth > 0 {
		var ips []string
		for _, value := range req.Header.Values("X-Forwarded-For") {
			for _, ip := range strings.Split(value, ",") {
				if ip = strings.TrimSpace(ip); ip != "" {
					ips = append(ips, ip)
				}
			}
		}
		if len(ips) >= depth {
			return ips[len(ips)-depth]
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}

	return host
}
