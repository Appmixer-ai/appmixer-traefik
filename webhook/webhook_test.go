package webhook_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/traefik/webhook"
)

func TestDemo(t *testing.T) {
	cfg := webhook.CreateConfig()
	cfg.Headers["X-Host"] = "[[.Host]]"
	cfg.Headers["X-Method"] = "[[.Method]]"
	cfg.Headers["X-URL"] = "[[.URL]]"
	cfg.Headers["X-URL"] = "[[.URL]]"
	cfg.Headers["X-Demo"] = "test"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := webhook.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:2200/flows/123/components/abc", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "X-Flow-Id", "123")
	assertHeader(t, req, "X-Trigger-Id", "abc")
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
