package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	UserIdClaim string `json:"userIdClaim,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		UserIdClaim: "originalUserId",
	}
}

// JWT a JWT plugin.
type JWT struct {
	next        http.Handler
	name        string
	userIdClaim string
}

// New creates a new JWT plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	claim := config.UserIdClaim
	if claim == "" {
		claim = "userId"
	}

	return &JWT{
		next:        next,
		name:        name,
		userIdClaim: claim,
	}, nil
}

func (j *JWT) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		j.next.ServeHTTP(rw, req)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		j.next.ServeHTTP(rw, req)
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		j.next.ServeHTTP(rw, req)
		return
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		j.next.ServeHTTP(rw, req)
		return
	}

	if userId, ok := claims[j.userIdClaim]; ok {
		switch v := userId.(type) {
		case string:
			req.Header.Set("X-User-Id", v)
		case float64:
			req.Header.Set("X-User-Id", fmt.Sprintf("%v", v))
		}
	}

	j.next.ServeHTTP(rw, req)
}
