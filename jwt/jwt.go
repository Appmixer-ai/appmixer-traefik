// Package jwt sets a rate-limit key header from the Appmixer access token.
package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

const userIDHeader = "X-User-Id"

var defaultUserIDClaims = []string{"originalUserId", "id", "sub"}

// Config the plugin configuration.
type Config struct {
	// UserIdClaim is the legacy single-claim option, used when UserIdClaims is empty.
	UserIdClaim string `json:"userIdClaim,omitempty"`
	// UserIdClaims are tried in order; the first claim present in the token wins.
	UserIdClaims []string `json:"userIdClaims,omitempty"`
	// IPDepth selects the client IP: 0 uses the TCP peer, N takes the Nth
	// X-Forwarded-For entry from the right (like Traefik's ipStrategy.depth).
	IPDepth int `json:"ipDepth,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// JWT a JWT plugin.
type JWT struct {
	next         http.Handler
	name         string
	userIDClaims []string
	ipDepth      int
}

// New creates a new JWT plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	claims := config.UserIdClaims
	if len(claims) == 0 && config.UserIdClaim != "" {
		claims = []string{config.UserIdClaim}
	}
	if len(claims) == 0 {
		claims = defaultUserIDClaims
	}
	if config.IPDepth < 0 {
		return nil, fmt.Errorf("ipDepth cannot be negative")
	}

	return &JWT{
		next:         next,
		name:         name,
		userIDClaims: claims,
		ipDepth:      config.IPDepth,
	}, nil
}

// ServeHTTP sets X-User-Id to "<userId>|<client ip>" when the request carries a
// decodable token, otherwise to "ip:<client ip>". The token signature is not
// verified; binding the key to the client IP keeps a forged token from
// exhausting another user's bucket. A client-supplied X-User-Id is always replaced.
func (j *JWT) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip := clientIP(req, j.ipDepth)

	if userID := j.userID(req); userID != "" {
		req.Header.Set(userIDHeader, userID+"|"+ip)
	} else {
		req.Header.Set(userIDHeader, "ip:"+ip)
	}

	j.next.ServeHTTP(rw, req)
}

func (j *JWT) userID(req *http.Request) string {
	authHeader := req.Header.Get("Authorization")
	if len(authHeader) < 7 || !strings.EqualFold(authHeader[:7], "bearer ") {
		return ""
	}

	parts := strings.Split(authHeader[7:], ".")
	if len(parts) != 3 {
		return ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	for _, claim := range j.userIDClaims {
		switch v := claims[claim].(type) {
		case string:
			if v != "" {
				return v
			}
		case float64:
			return fmt.Sprintf("%v", v)
		}
	}

	return ""
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
