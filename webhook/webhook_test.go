package webhook_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/traefik/webhook"
)

func newHandler(t *testing.T, cfg *webhook.Config) http.Handler {
	t.Helper()

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := webhook.New(context.Background(), next, cfg, "webhook-plugin")
	if err != nil {
		t.Fatal(err)
	}

	return handler
}

func serve(t *testing.T, cfg *webhook.Config, target string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, target, nil)
	req.RemoteAddr = "10.0.0.5:12345"
	req.Header.Set("X-Flow-Id", "spoofed")
	req.Header.Set("X-Trigger-Id", "spoofed")

	newHandler(t, cfg).ServeHTTP(httptest.NewRecorder(), req)

	return req
}

func chartConfig() *webhook.Config {
	cfg := webhook.CreateConfig()
	cfg.Headers["X-Flow-Id"] = "flowId"
	cfg.Headers["X-Trigger-Id"] = "triggerId"
	return cfg
}

func TestFlowComponent(t *testing.T) {
	req := serve(t, chartConfig(), "http://localhost:2200/flows/123/components/abc?x=1")

	assertHeader(t, req, "X-Flow-Id", "123")
	assertHeader(t, req, "X-Trigger-Id", "123/abc")
}

func TestAlias(t *testing.T) {
	req := serve(t, chartConfig(), "http://localhost:2200/invoke/webhook/a1b2/my-hook")

	assertHeader(t, req, "X-Flow-Id", "")
	assertHeader(t, req, "X-Trigger-Id", "alias:a1b2/my-hook")
}

func TestOtherPathFallsBackToIP(t *testing.T) {
	req := serve(t, chartConfig(), "http://localhost:2200/something/else")

	assertHeader(t, req, "X-Flow-Id", "")
	assertHeader(t, req, "X-Trigger-Id", "ip:10.0.0.5")
}

func TestPathMustStartWithFlows(t *testing.T) {
	req := serve(t, chartConfig(), "http://localhost:2200/x/flows/123/components/abc")

	assertHeader(t, req, "X-Trigger-Id", "ip:10.0.0.5")
}

func TestIPDepth(t *testing.T) {
	cfg := chartConfig()
	cfg.IPDepth = 1

	req := httptest.NewRequest(http.MethodPost, "http://localhost:2200/other", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 1.1.1.1")
	newHandler(t, cfg).ServeHTTP(httptest.NewRecorder(), req)

	assertHeader(t, req, "X-Trigger-Id", "ip:1.1.1.1")
}

func TestDefaultHeaders(t *testing.T) {
	req := serve(t, webhook.CreateConfig(), "http://localhost:2200/flows/123/components/abc")

	assertHeader(t, req, "X-Flow-Id", "123")
	assertHeader(t, req, "X-Trigger-Id", "123/abc")
}

func TestCustomHeaderNames(t *testing.T) {
	cfg := webhook.CreateConfig()
	cfg.Headers["X-Key"] = "triggerId"

	req := serve(t, cfg, "http://localhost:2200/flows/123/components/abc")

	assertHeader(t, req, "X-Key", "123/abc")
	// Not configured, so left untouched.
	assertHeader(t, req, "X-Flow-Id", "spoofed")
}

func TestInvalidConfig(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	cfg := webhook.CreateConfig()
	cfg.Headers["X-Demo"] = "test"
	if _, err := webhook.New(context.Background(), next, cfg, "webhook-plugin"); err == nil {
		t.Error("expected an error for an unknown header value")
	}

	if _, err := webhook.New(context.Background(), next, &webhook.Config{IPDepth: -1}, "webhook-plugin"); err == nil {
		t.Error("expected an error for negative ipDepth")
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("header %s: expected %q, got %q", key, expected, req.Header.Get(key))
	}
}
