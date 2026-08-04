package credential

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"agentbox/internal/domain"
)

type secretMap map[string][]byte

func (s secretMap) Resolve(name string) ([]byte, bool) {
	value, ok := s[name]
	return append([]byte(nil), value...), ok
}

type fakeProvider struct {
	mu      sync.Mutex
	calls   int
	now     func() time.Time
	fail    bool
	started chan struct{}
	release chan struct{}
}

func (p *fakeProvider) Name() string { return "fake" }
func (p *fakeProvider) Validate(source domain.CredentialSource) error {
	if source.Provider != p.Name() {
		return errors.New("wrong provider")
	}
	return nil
}
func (p *fakeProvider) Issue(ctx context.Context, _ domain.CredentialSource, _ SecretResolver) (Lease, error) {
	p.mu.Lock()
	p.calls++
	call := p.calls
	fail := p.fail
	started, release := p.started, p.release
	p.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-ctx.Done():
			return Lease{}, ctx.Err()
		case <-release:
		}
	}
	if fail {
		return Lease{}, errors.New("issuer failed")
	}
	return Lease{Value: []byte(fmt.Sprintf("token-%d", call)), ExpiresAt: p.now().Add(time.Hour)}, nil
}

func (p *fakeProvider) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func brokerState() domain.State {
	state := domain.NewState()
	state.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Unix(1, 0)}}
	state.CredentialSources = []domain.CredentialSource{{Name: "source", Provider: "fake", Parameters: map[string]string{}, Secrets: map[string]string{"root": "root-key"}}}
	state.CredentialGrants = []domain.CredentialGrant{{Container: "dev", Credential: "api", Source: "source"}}
	return state
}

func TestBrokerCachesRefreshesAndFallsBackToUnexpiredLease(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	provider := &fakeProvider{now: func() time.Time { return now }}
	broker, err := NewBroker(secretMap{"root-key": []byte("root")}, []Provider{provider}, Options{Now: func() time.Time { return now }, RefreshBefore: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	if err := broker.Configure(brokerState()); err != nil {
		t.Fatal(err)
	}
	first, err := broker.Acquire(context.Background(), "dev", "api")
	if err != nil || string(first.Value) != "token-1" {
		t.Fatalf("first lease=%q err=%v", first.Value, err)
	}
	second, err := broker.Acquire(context.Background(), "dev", "api")
	if err != nil || string(second.Value) != "token-1" || provider.Calls() != 1 {
		t.Fatalf("cached lease=%q calls=%d err=%v", second.Value, provider.Calls(), err)
	}

	now = now.Add(56 * time.Minute)
	provider.mu.Lock()
	provider.fail = true
	provider.mu.Unlock()
	stale, err := broker.Acquire(context.Background(), "dev", "api")
	if err != nil || string(stale.Value) != "token-1" {
		t.Fatalf("unexpired fallback=%q err=%v", stale.Value, err)
	}
	now = now.Add(5 * time.Minute)
	if _, err := broker.Acquire(context.Background(), "dev", "api"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expired fallback error=%v", err)
	}
	if _, err := broker.Acquire(context.Background(), "dev", "api"); !errors.Is(err, ErrUnavailable) || provider.Calls() != 3 {
		t.Fatalf("retry backoff error=%v calls=%d", err, provider.Calls())
	}

	provider.mu.Lock()
	provider.fail = false
	provider.mu.Unlock()
	now = now.Add(16 * time.Second)
	refreshed, err := broker.Acquire(context.Background(), "dev", "api")
	if err != nil || string(refreshed.Value) != "token-4" {
		t.Fatalf("refreshed lease=%q calls=%d err=%v", refreshed.Value, provider.Calls(), err)
	}
}

func TestBrokerCoalescesConcurrentIssue(t *testing.T) {
	now := time.Now().UTC()
	provider := &fakeProvider{now: func() time.Time { return now }, started: make(chan struct{}, 1), release: make(chan struct{})}
	broker, err := NewBroker(secretMap{}, []Provider{provider}, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	if err := broker.Configure(brokerState()); err != nil {
		t.Fatal(err)
	}
	const count = 24
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		go func() {
			lease, err := broker.Acquire(context.Background(), "dev", "api")
			if err == nil && string(lease.Value) != "token-1" {
				err = fmt.Errorf("unexpected lease %q", lease.Value)
			}
			results <- err
		}()
	}
	<-provider.started
	close(provider.release)
	for i := 0; i < count; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if provider.Calls() != 1 {
		t.Fatalf("provider calls=%d want 1", provider.Calls())
	}
}

func TestBrokerEnforcesGrantsAndInvalidatesSecret(t *testing.T) {
	now := time.Now().UTC()
	provider := &fakeProvider{now: func() time.Time { return now }}
	broker, _ := NewBroker(secretMap{}, []Provider{provider}, Options{Now: func() time.Time { return now }})
	defer broker.Close()
	if err := broker.Configure(brokerState()); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Acquire(context.Background(), "other", "api"); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("wrong principal error=%v", err)
	}
	if _, err := broker.Acquire(context.Background(), "dev", "other"); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("wrong alias error=%v", err)
	}
	if _, err := broker.Acquire(context.Background(), "dev", "api"); err != nil {
		t.Fatal(err)
	}
	broker.InvalidateSecret("root-key")
	lease, err := broker.Acquire(context.Background(), "dev", "api")
	if err != nil || string(lease.Value) != "token-2" {
		t.Fatalf("after invalidation=%q calls=%d err=%v", lease.Value, provider.Calls(), err)
	}
}

func TestBrokerInvalidatesChangedAndUngrantedSources(t *testing.T) {
	now := time.Now().UTC()
	provider := &fakeProvider{now: func() time.Time { return now }}
	broker, _ := NewBroker(secretMap{}, []Provider{provider}, Options{Now: func() time.Time { return now }})
	defer broker.Close()
	state := brokerState()
	if err := broker.Configure(state); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Acquire(context.Background(), "dev", "api"); err != nil {
		t.Fatal(err)
	}
	state.CredentialSources[0].Parameters["revision"] = "2"
	if err := broker.Configure(state); err != nil {
		t.Fatal(err)
	}
	lease, err := broker.Acquire(context.Background(), "dev", "api")
	if err != nil || string(lease.Value) != "token-2" {
		t.Fatalf("changed source lease=%q calls=%d err=%v", lease.Value, provider.Calls(), err)
	}
	state.CredentialGrants = nil
	if err := broker.Configure(state); err != nil {
		t.Fatal(err)
	}
	state.CredentialGrants = []domain.CredentialGrant{{Container: "dev", Credential: "api", Source: "source"}}
	if err := broker.Configure(state); err != nil {
		t.Fatal(err)
	}
	lease, err = broker.Acquire(context.Background(), "dev", "api")
	if err != nil || string(lease.Value) != "token-3" {
		t.Fatalf("regranted source lease=%q calls=%d err=%v", lease.Value, provider.Calls(), err)
	}
}

func TestBrokerRejectsUnknownProvider(t *testing.T) {
	broker, _ := NewBroker(secretMap{}, nil, Options{})
	state := brokerState()
	if err := broker.Configure(state); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

func TestRefreshTimeAdaptsToShortLease(t *testing.T) {
	now := time.Unix(100, 0)
	lease := Lease{Value: []byte("token"), ExpiresAt: now.Add(2 * time.Minute)}
	if got, want := refreshTime(lease, now, 5*time.Minute), now.Add(time.Minute); !got.Equal(want) {
		t.Fatalf("refresh=%s want %s", got, want)
	}
}
