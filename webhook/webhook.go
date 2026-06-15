// Package webhook a webhook plugin.
package webhook

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"text/template"
)

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

// Demo a Demo plugin.
type Demo struct {
	next     http.Handler
	headers  map[string]string
	name     string
	template *template.Template
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Headers) == 0 {
		return nil, fmt.Errorf("headers cannot be empty")
	}

	return &Demo{
		headers:  config.Headers,
		next:     next,
		name:     name,
		template: template.New("demo").Delims("[[", "]]"),
	}, nil
}

func (a *Demo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	re := regexp.MustCompile(`/flows/([a-f0-9-]+)/components/([a-zA-Z0-9_-]+)`)
	matches := re.FindStringSubmatch(req.URL.String())

	if matches == nil {
		a.next.ServeHTTP(rw, req)
		return
	}

	flowId := matches[1]
	triggerId := matches[2]

	req.Header.Set("X-Flow-Id", flowId)
	req.Header.Set("X-Trigger-Id", triggerId)

	for key, values := range req.Header {
		fmt.Printf("%s: %s\n", key, values[0])
	}

	a.next.ServeHTTP(rw, req)
}
