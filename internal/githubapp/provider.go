// Package githubapp implements renewable GitHub App installation credentials.
// GitHub's JWT exchange is deliberately contained here; the credential broker
// only understands provider-neutral leases.
package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"agentbox/internal/credential"
	"agentbox/internal/domain"
)

const (
	ProviderName   = "github-app"
	PrivateKeyRole = "private-key"
	apiVersion     = "2026-03-10"
	maxResponse    = 4 << 20
)

var (
	clientIDRE   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	repositoryRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	permissionRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

type Config struct {
	ClientID       string
	InstallationID uint64
	Repositories   []string
	RepositoryIDs  []uint64
	Permissions    map[string]string
	PrivateKey     string
}

type Options struct {
	Client  *http.Client
	BaseURL string
	Now     func() time.Time
}

type Provider struct {
	client  *http.Client
	baseURL string
	now     func() time.Time
}

func New(options Options) (*Provider, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.BaseURL == "" {
		options.BaseURL = "https://api.github.com"
	}
	base, err := url.Parse(options.BaseURL)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Path != "" {
		return nil, fmt.Errorf("invalid GitHub API base URL %q", options.BaseURL)
	}
	if options.Client == nil {
		transport := &http.Transport{
			Proxy:             nil,
			DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout: 90 * time.Second,
		}
		options.Client = &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("GitHub credential endpoint redirected")
			},
		}
	}
	return &Provider{client: options.Client, baseURL: options.BaseURL, now: options.Now}, nil
}

func MustDefault() *Provider {
	provider, err := New(Options{})
	if err != nil {
		panic(err)
	}
	return provider
}

func (p *Provider) Name() string { return ProviderName }

func (p *Provider) Validate(source domain.CredentialSource) error {
	_, err := ParseConfig(source)
	return err
}

func ParseConfig(source domain.CredentialSource) (Config, error) {
	if source.Provider != ProviderName {
		return Config{}, fmt.Errorf("provider must be %q", ProviderName)
	}
	allowedParameters := map[string]bool{
		"client-id": true, "installation-id": true, "repositories": true,
		"repository-ids": true, "permissions": true,
	}
	for name := range source.Parameters {
		if !allowedParameters[name] {
			return Config{}, fmt.Errorf("unknown parameter %q", name)
		}
	}
	for role := range source.Secrets {
		if role != PrivateKeyRole {
			return Config{}, fmt.Errorf("unknown secret role %q", role)
		}
	}
	config := Config{ClientID: source.Parameters["client-id"], PrivateKey: source.Secrets[PrivateKeyRole]}
	if !clientIDRE.MatchString(config.ClientID) {
		return Config{}, errors.New("client-id is required and must contain only letters, digits, '.', '_', or '-'")
	}
	installationID, err := strconv.ParseUint(source.Parameters["installation-id"], 10, 64)
	if err != nil || installationID == 0 {
		return Config{}, errors.New("installation-id must be a positive decimal integer")
	}
	config.InstallationID = installationID
	if !domain.ValidKeyName(config.PrivateKey) {
		return Config{}, errors.New("private-key must reference a valid encrypted key name")
	}
	config.Repositories, err = parseNames(source.Parameters["repositories"])
	if err != nil {
		return Config{}, err
	}
	config.RepositoryIDs, err = parseIDs(source.Parameters["repository-ids"])
	if err != nil {
		return Config{}, err
	}
	if len(config.Repositories) != 0 && len(config.RepositoryIDs) != 0 {
		return Config{}, errors.New("repositories and repository-ids are mutually exclusive")
	}
	config.Permissions, err = parsePermissions(source.Parameters["permissions"])
	if err != nil {
		return Config{}, err
	}
	return config, nil
}

func (p *Provider) Issue(ctx context.Context, source domain.CredentialSource, secrets credential.SecretResolver) (credential.Lease, error) {
	config, err := ParseConfig(source)
	if err != nil {
		return credential.Lease{}, err
	}
	privatePEM, ok := secrets.Resolve(config.PrivateKey)
	if !ok {
		return credential.Lease{}, fmt.Errorf("private key %q is not installed", config.PrivateKey)
	}
	defer clear(privatePEM)
	privateKey, err := parsePrivateKey(privatePEM)
	if err != nil {
		return credential.Lease{}, fmt.Errorf("parse private key %q: %w", config.PrivateKey, err)
	}
	jwt, err := signJWT(privateKey, config.ClientID, p.now().UTC())
	if err != nil {
		return credential.Lease{}, errors.New("sign GitHub App JWT")
	}
	body := struct {
		Repositories  []string          `json:"repositories,omitempty"`
		RepositoryIDs []uint64          `json:"repository_ids,omitempty"`
		Permissions   map[string]string `json:"permissions,omitempty"`
	}{Repositories: config.Repositories, RepositoryIDs: config.RepositoryIDs, Permissions: config.Permissions}
	encoded, err := json.Marshal(body)
	if err != nil {
		return credential.Lease{}, err
	}
	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.baseURL, config.InstallationID)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return credential.Lease{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+jwt)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "agentboxd")
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	response, err := p.client.Do(request)
	if err != nil {
		return credential.Lease{}, errors.New("GitHub installation token request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return credential.Lease{}, fmt.Errorf("GitHub installation token request returned status %d", response.StatusCode)
	}
	var payload struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	responseData, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(responseData) > maxResponse {
		clear(responseData)
		return credential.Lease{}, errors.New("read GitHub installation token response")
	}
	defer clear(responseData)
	decoder := json.NewDecoder(bytes.NewReader(responseData))
	if err := decoder.Decode(&payload); err != nil {
		return credential.Lease{}, errors.New("decode GitHub installation token response")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return credential.Lease{}, errors.New("decode GitHub installation token response")
	}
	if len(payload.Token) == 0 || len(payload.Token) > maxResponse || payload.ExpiresAt.IsZero() {
		return credential.Lease{}, errors.New("GitHub returned an invalid installation token response")
	}
	return credential.Lease{Value: []byte(payload.Token), ExpiresAt: payload.ExpiresAt.UTC()}, nil
}

func signJWT(key *rsa.PrivateKey, issuer string, now time.Time) (string, error) {
	header, _ := json.Marshal(struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}{Algorithm: "RS256", Type: "JWT"})
	payload, _ := json.Marshal(struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}{IssuedAt: now.Add(-60 * time.Second).Unix(), ExpiresAt: now.Add(9 * time.Minute).Unix(), Issuer: issuer})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func parsePrivateKey(value []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(value)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected exactly one PEM block")
	}
	var key *rsa.PrivateKey
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			err = parseErr
			break
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			err = errors.New("PKCS#8 key is not RSA")
		}
	default:
		err = fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("RSA key is smaller than 2048 bits")
	}
	return key, nil
}

func parseNames(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, name := range strings.Split(value, ",") {
		if !repositoryRE.MatchString(name) {
			return nil, fmt.Errorf("invalid repository name %q", name)
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			return nil, fmt.Errorf("duplicate repository name %q", name)
		}
		seen[lower] = true
		out = append(out, name)
	}
	if len(out) > 500 {
		return nil, errors.New("at most 500 repositories may be requested")
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out, nil
}

func parseIDs(value string) ([]uint64, error) {
	if value == "" {
		return nil, nil
	}
	seen := map[uint64]bool{}
	var out []uint64
	for _, item := range strings.Split(value, ",") {
		id, err := strconv.ParseUint(item, 10, 64)
		if err != nil || id == 0 {
			return nil, fmt.Errorf("invalid repository ID %q", item)
		}
		if seen[id] {
			return nil, fmt.Errorf("duplicate repository ID %d", id)
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) > 500 {
		return nil, errors.New("at most 500 repository IDs may be requested")
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func parsePermissions(value string) (map[string]string, error) {
	if value == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, item := range strings.Split(value, ",") {
		name, level, ok := strings.Cut(item, "=")
		if !ok || !permissionRE.MatchString(name) || (level != "read" && level != "write") {
			return nil, fmt.Errorf("invalid permission %q (want name=read or name=write)", item)
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("duplicate permission %q", name)
		}
		out[name] = level
	}
	return out, nil
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
