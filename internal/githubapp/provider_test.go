package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"agentbox/internal/domain"
)

type secrets map[string][]byte

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func (s secrets) Resolve(name string) ([]byte, bool) {
	value, ok := s[name]
	return append([]byte(nil), value...), ok
}

func source() domain.CredentialSource {
	return domain.CredentialSource{
		Name: "github-project", Provider: ProviderName,
		Parameters: map[string]string{
			"client-id": "Iv1.example", "installation-id": "12345",
			"repository-ids": "42,7", "permissions": "contents=write,pull_requests=write",
		},
		Secrets: map[string]string{PrivateKeyRole: "github-private-key"},
	}
}

func TestProviderSignsJWTAndNarrowsToken(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	expires := now.Add(time.Hour)
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/12345/access_tokens" {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != apiVersion {
			t.Errorf("headers=%v", r.Header)
		}
		jwt := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Errorf("JWT has %d parts", len(parts))
		} else {
			header, _ := base64.RawURLEncoding.DecodeString(parts[0])
			if string(header) != `{"alg":"RS256","typ":"JWT"}` {
				t.Errorf("JWT header=%s", header)
			}
			payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var payload struct {
				IssuedAt, ExpiresAt int64
				Issuer              string
			}
			var raw map[string]any
			if err := json.Unmarshal(payloadBytes, &raw); err != nil {
				t.Error(err)
			}
			payload.IssuedAt = int64(raw["iat"].(float64))
			payload.ExpiresAt = int64(raw["exp"].(float64))
			payload.Issuer = raw["iss"].(string)
			if payload.Issuer != "Iv1.example" || payload.IssuedAt != now.Add(-time.Minute).Unix() || payload.ExpiresAt != now.Add(9*time.Minute).Unix() {
				t.Errorf("JWT payload=%v", raw)
			}
			signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
				t.Errorf("verify JWT: %v", err)
			}
		}
		var body struct {
			RepositoryIDs []uint64          `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.RepositoryIDs) != 2 || body.RepositoryIDs[0] != 7 || body.RepositoryIDs[1] != 42 || body.Permissions["contents"] != "write" || body.Permissions["pull_requests"] != "write" {
			t.Errorf("body=%+v", body)
		}
		encoded, _ := json.Marshal(map[string]any{"token": "ghs_opaque.token_value", "expires_at": expires, "permissions": body.Permissions})
		return &http.Response{StatusCode: http.StatusCreated, Status: "201 Created", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(encoded))), Request: r}, nil
	})}
	provider, err := New(Options{Client: client, BaseURL: "https://api.github.test", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := provider.Issue(context.Background(), source(), secrets{"github-private-key": privatePEM})
	if err != nil {
		t.Fatal(err)
	}
	if string(lease.Value) != "ghs_opaque.token_value" || !lease.ExpiresAt.Equal(expires) {
		t.Fatalf("lease=%q expires=%s", lease.Value, lease.ExpiresAt)
	}
}

func TestProviderValidationIsStrict(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*domain.CredentialSource)
	}{
		{"unknown parameter", func(s *domain.CredentialSource) { s.Parameters["surprise"] = "x" }},
		{"bad installation", func(s *domain.CredentialSource) { s.Parameters["installation-id"] = "zero" }},
		{"both repository selectors", func(s *domain.CredentialSource) { s.Parameters["repositories"] = "repo" }},
		{"bad permission", func(s *domain.CredentialSource) { s.Parameters["permissions"] = "contents=admin" }},
		{"unknown secret", func(s *domain.CredentialSource) { s.Secrets["client-secret"] = "other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := source()
			test.mutate(&candidate)
			if _, err := ParseConfig(candidate); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestProviderFailsWithoutLeakingGitHubResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("UPSTREAM_RESPONSE_SECRET")), Request: r}, nil
	})}
	provider, _ := New(Options{Client: client, BaseURL: "https://api.github.test"})
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	_, err := provider.Issue(context.Background(), source(), secrets{"github-private-key": privatePEM})
	if err == nil || strings.Contains(err.Error(), "UPSTREAM_RESPONSE_SECRET") {
		t.Fatalf("unsafe error=%v", err)
	}
}

func TestProviderRejectsInvalidPrivateKey(t *testing.T) {
	provider, _ := New(Options{})
	_, err := provider.Issue(context.Background(), source(), secrets{"github-private-key": []byte("not a PEM")})
	if err == nil {
		t.Fatalf("invalid key error=%v", err)
	}
}
