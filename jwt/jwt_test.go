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

func newRequest(authorization string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/flows", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return req
}

func serve(t *testing.T, cfg *jwt.Config, req *http.Request) {
	t.Helper()
	newHandler(t, cfg).ServeHTTP(httptest.NewRecorder(), req)
}

func Test(t *testing.T) {
	// Real group-context token: id/sub is the group user, originalUserId the member.
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIzMjRiOWQ0OC0zNTkyLTQ2YzctYWI5My02MzU2MDkxZGUwNGIiLCJuYmYiOjAsImlzcyI6Imh0dHBzOi8vYXBwbWl4ZXIuY29tIiwiYXVkIjoiYXBwbWl4ZXItdXNlciIsImlkIjoiNjlhZmY0ZmI2MzM3ZmVlMjE5NmRhZWY3Iiwic3ViIjoiNjlhZmY0ZmI2MzM3ZmVlMjE5NmRhZWY3IiwidHlwIjoiQmVhcmVyIiwic2NvcGUiOlsiYWRtaW4iXSwib3JpZ2luYWxVc2VySWQiOiI2OTk0ODA5NjBmMGE0YjQxZTIwNThiMzIiLCJjb250ZXh0VHlwZSI6Imdyb3VwIiwiZ3JvdXBJZCI6IjY5YWZmNGZiNjMzN2ZlZTIxOTZkYWVmOCIsImlhdCI6MTc3NTg0ODU1MiwiZXhwIjoxNzc4NDQwNTUyfQ.dmkp3kY9WY97fZQJt1LWzzsxDN7pOX3VvxLAiOax5R0"

	req := newRequest("Bearer " + token)
	serve(t, jwt.CreateConfig(), req)

	assertHeader(t, req, "X-User-Id", "699480960f0a4b41e2058b32|10.0.0.5")
}

func TestNormalTokenUsesId(t *testing.T) {
	req := newRequest("Bearer " + makeToken(map[string]interface{}{"id": "u1", "sub": "u1"}))
	serve(t, jwt.CreateConfig(), req)

	assertHeader(t, req, "X-User-Id", "u1|10.0.0.5")
}

func TestLowercaseBearer(t *testing.T) {
	req := newRequest("bearer " + makeToken(map[string]interface{}{"id": "u1"}))
	serve(t, jwt.CreateConfig(), req)

	assertHeader(t, req, "X-User-Id", "u1|10.0.0.5")
}

func TestLegacyUserIdClaim(t *testing.T) {
	req := newRequest("Bearer " + makeToken(map[string]interface{}{"id": "u1", "userId": "legacy"}))
	serve(t, &jwt.Config{UserIdClaim: "userId"}, req)

	assertHeader(t, req, "X-User-Id", "legacy|10.0.0.5")
}

func TestUserIdClaimsTakePrecedence(t *testing.T) {
	req := newRequest("Bearer " + makeToken(map[string]interface{}{"id": "u1", "sub": "s1", "originalUserId": "o1"}))
	serve(t, &jwt.Config{UserIdClaim: "originalUserId", UserIdClaims: []string{"sub"}}, req)

	assertHeader(t, req, "X-User-Id", "s1|10.0.0.5")
}

func TestNumericClaim(t *testing.T) {
	req := newRequest("Bearer " + makeToken(map[string]interface{}{"id": 42}))
	serve(t, jwt.CreateConfig(), req)

	assertHeader(t, req, "X-User-Id", "42|10.0.0.5")
}

func TestNoTokenFallsBackToIP(t *testing.T) {
	req := newRequest("")
	serve(t, jwt.CreateConfig(), req)

	assertHeader(t, req, "X-User-Id", "ip:10.0.0.5")
}

func TestInvalidTokensFallBackToIP(t *testing.T) {
	for _, auth := range []string{
		"Basic dXNlcjpwYXNz",
		"Bearer not-a-jwt",
		"Bearer a.!!!.c",
		"Bearer " + base64.RawURLEncoding.EncodeToString([]byte("{}")) + "." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig",
		"Bearer " + makeToken(map[string]interface{}{"email": "no-id@example.com"}),
		"Bearer " + makeToken(map[string]interface{}{"id": ""}),
	} {
		req := newRequest(auth)
		serve(t, jwt.CreateConfig(), req)

		assertHeader(t, req, "X-User-Id", "ip:10.0.0.5")
	}
}

func TestClientSuppliedHeaderIsReplaced(t *testing.T) {
	req := newRequest("")
	req.Header.Set("X-User-Id", "victim")
	serve(t, jwt.CreateConfig(), req)

	assertHeader(t, req, "X-User-Id", "ip:10.0.0.5")
}

func TestIPDepth(t *testing.T) {
	tests := []struct {
		name  string
		depth int
		xff   []string
		want  string
	}{
		{"depth 0 ignores XFF", 0, []string{"1.1.1.1"}, "ip:10.0.0.5"},
		{"depth 1 takes rightmost", 1, []string{"6.6.6.6, 1.1.1.1"}, "ip:1.1.1.1"},
		{"depth 2 takes second from right", 2, []string{"6.6.6.6, 1.1.1.1", "2.2.2.2"}, "ip:1.1.1.1"},
		{"XFF shorter than depth falls back", 3, []string{"1.1.1.1"}, "ip:10.0.0.5"},
		{"no XFF falls back", 1, nil, "ip:10.0.0.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newRequest("")
			for _, v := range tt.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			serve(t, &jwt.Config{IPDepth: tt.depth}, req)

			assertHeader(t, req, "X-User-Id", tt.want)
		})
	}
}

func TestNegativeIPDepth(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	if _, err := jwt.New(context.Background(), next, &jwt.Config{IPDepth: -1}, "jwt-plugin"); err == nil {
		t.Error("expected an error for negative ipDepth")
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("header %s: expected %q, got %q", key, expected, req.Header.Get(key))
	}
}
