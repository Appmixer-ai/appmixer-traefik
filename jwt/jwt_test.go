package jwt_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/traefik/jwt"
)

// makeToken builds a fake JWT with the given claims (no real signature).
func makeToken(claims map[string]interface{}) string {
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)

	h := base64.RawURLEncoding.EncodeToString(header)
	p := base64.RawURLEncoding.EncodeToString(payload)

	return h + "." + p + ".fakesignature"
}

func newHandler(t *testing.T, cfg *jwt.Config) http.Handler {
	t.Helper()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := jwt.New(ctx, next, cfg, "jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	return handler
}

func Test(t *testing.T) {

    token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIzMjRiOWQ0OC0zNTkyLTQ2YzctYWI5My02MzU2MDkxZGUwNGIiLCJuYmYiOjAsImlzcyI6Imh0dHBzOi8vYXBwbWl4ZXIuY29tIiwiYXVkIjoiYXBwbWl4ZXItdXNlciIsImlkIjoiNjlhZmY0ZmI2MzM3ZmVlMjE5NmRhZWY3Iiwic3ViIjoiNjlhZmY0ZmI2MzM3ZmVlMjE5NmRhZWY3IiwidHlwIjoiQmVhcmVyIiwic2NvcGUiOlsiYWRtaW4iXSwib3JpZ2luYWxVc2VySWQiOiI2OTk0ODA5NjBmMGE0YjQxZTIwNThiMzIiLCJjb250ZXh0VHlwZSI6Imdyb3VwIiwiZ3JvdXBJZCI6IjY5YWZmNGZiNjMzN2ZlZTIxOTZkYWVmOCIsImlhdCI6MTc3NTg0ODU1MiwiZXhwIjoxNzc4NDQwNTUyfQ.dmkp3kY9WY97fZQJt1LWzzsxDN7pOX3VvxLAiOax5R0"

    handler := newHandler(t, jwt.CreateConfig())
	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("Authorization", "Bearer "+ token)

	handler.ServeHTTP(recorder, req)

	if req.Header.Get("X-User-Id") != "699480960f0a4b41e2058b32" {
		t.Errorf("expected no X-User-Id header, got: %s", req.Header.Get("X-User-Id"))
	}

}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("header %s: expected %q, got %q", key, expected, req.Header.Get(key))
	}
}

