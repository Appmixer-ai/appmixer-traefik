// Package webhook a webhook plugin.
package webhook

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
)

var flowComponentPath = regexp.MustCompile(`/flows/([a-f0-9-]+)/components/([a-zA-Z0-9_-]+)`)

// Config the plugin configuration.
type Config struct {
	Headers map[string]string `json:"headers,omitempty"`
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
}

// New creates a new webhook plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Headers) == 0 {
		return nil, fmt.Errorf("headers cannot be empty")
	}

	return &Webhook{
		headers: config.Headers,
		next:    next,
		name:    name,
	}, nil
}

func (a *Webhook) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	matches := flowComponentPath.FindStringSubmatch(req.URL.Path)

	if matches == nil {
		a.next.ServeHTTP(rw, req)
		return
	}

	req.Header.Set("X-Flow-Id", matches[1])
	req.Header.Set("X-Trigger-Id", matches[2])

	a.next.ServeHTTP(rw, req)
}
