// Package credential resolves container-bound logical credentials. Providers
// issue leases; Broker supplies provider-neutral caching, refresh coalescing,
// configuration invalidation, and fail-closed grant enforcement.
package credential

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"agentbox/internal/domain"
)

const maxCredentialBytes = 64 << 10

var (
	ErrNotGranted  = errors.New("credential is not granted")
	ErrUnavailable = errors.New("credential is unavailable")
)

type Lease struct {
	Value     []byte
	ExpiresAt time.Time
}

type SecretResolver interface {
	Resolve(string) ([]byte, bool)
}

// Provider validates public/source-secret configuration and issues a fresh
// lease. The returned byte slice becomes Broker's property. Returned errors
// must be safe to log: they must not contain root material, issued credentials,
// authorization headers, or upstream response bodies.
type Provider interface {
	Name() string
	Validate(domain.CredentialSource) error
	Issue(context.Context, domain.CredentialSource, SecretResolver) (Lease, error)
}

type sourceRuntime struct {
	spec       domain.CredentialSource
	provider   Provider
	generation uint64
}

type cacheEntry struct {
	lease           Lease
	refreshAt       time.Time
	retryAt         time.Time
	issuing         bool
	issueGeneration uint64
	done            chan struct{}
}

type Broker struct {
	secrets       SecretResolver
	providers     map[string]Provider
	now           func() time.Time
	refreshBefore time.Duration
	retryDelay    time.Duration

	mu         sync.Mutex
	sources    map[string]sourceRuntime
	grants     map[string]string
	cache      map[string]*cacheEntry
	generation uint64
}

type Options struct {
	Now           func() time.Time
	RefreshBefore time.Duration
	RetryDelay    time.Duration
}

func NewBroker(secrets SecretResolver, providers []Provider, options Options) (*Broker, error) {
	if secrets == nil {
		return nil, errors.New("secret resolver is required")
	}
	registered := make(map[string]Provider, len(providers))
	for _, provider := range providers {
		if provider == nil || !domain.ValidName(provider.Name()) {
			return nil, errors.New("provider has an invalid name")
		}
		if registered[provider.Name()] != nil {
			return nil, fmt.Errorf("duplicate credential provider %q", provider.Name())
		}
		registered[provider.Name()] = provider
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.RefreshBefore == 0 {
		options.RefreshBefore = 5 * time.Minute
	}
	if options.RefreshBefore < 0 {
		return nil, errors.New("refresh-before must not be negative")
	}
	if options.RetryDelay == 0 {
		options.RetryDelay = 15 * time.Second
	}
	if options.RetryDelay < 0 {
		return nil, errors.New("retry-delay must not be negative")
	}
	return &Broker{
		secrets: secrets, providers: registered, now: options.Now, refreshBefore: options.RefreshBefore, retryDelay: options.RetryDelay,
		sources: map[string]sourceRuntime{}, grants: map[string]string{}, cache: map[string]*cacheEntry{},
	}, nil
}

func (b *Broker) Validate(state domain.State) error {
	if err := domain.ValidateState(state); err != nil {
		return err
	}
	for _, source := range state.CredentialSources {
		provider := b.providers[source.Provider]
		if provider == nil {
			return fmt.Errorf("credential source %q: unknown provider %q", source.Name, source.Provider)
		}
		if err := provider.Validate(source); err != nil {
			return fmt.Errorf("credential source %q: %w", source.Name, err)
		}
	}
	return nil
}

// Configure atomically changes source/grant lookup. Leases survive unrelated
// edits but are cleared when their source definition changes.
func (b *Broker) Configure(state domain.State) error {
	if err := b.Validate(state); err != nil {
		return err
	}
	state = domain.CloneState(state)
	b.mu.Lock()
	defer b.mu.Unlock()

	nextSources := make(map[string]sourceRuntime, len(state.CredentialSources))
	for _, source := range state.CredentialSources {
		previous, ok := b.sources[source.Name]
		if ok && reflect.DeepEqual(previous.spec, source) {
			nextSources[source.Name] = previous
			continue
		}
		b.generation++
		nextSources[source.Name] = sourceRuntime{spec: source, provider: b.providers[source.Provider], generation: b.generation}
	}
	for name, entry := range b.cache {
		next, exists := nextSources[name]
		previous, existed := b.sources[name]
		if !exists || !existed || next.generation != previous.generation {
			resetEntry(entry)
		}
	}
	nextGrants := make(map[string]string, len(state.CredentialGrants))
	grantedSources := make(map[string]bool, len(state.CredentialGrants))
	for _, grant := range state.CredentialGrants {
		nextGrants[grantKey(grant.Container, grant.Credential)] = grant.Source
		grantedSources[grant.Source] = true
	}
	for name, entry := range b.cache {
		if !grantedSources[name] {
			resetEntry(entry)
		}
	}
	b.sources = nextSources
	b.grants = nextGrants
	return nil
}

func (b *Broker) Acquire(ctx context.Context, principal, name string) (Lease, error) {
	for {
		b.mu.Lock()
		sourceName, ok := b.grants[grantKey(principal, name)]
		if !ok {
			b.mu.Unlock()
			return Lease{}, fmt.Errorf("%w: %q for container %q", ErrNotGranted, name, principal)
		}
		source, ok := b.sources[sourceName]
		if !ok {
			b.mu.Unlock()
			return Lease{}, fmt.Errorf("%w: source %q", ErrUnavailable, sourceName)
		}
		entry := b.cache[sourceName]
		if entry == nil {
			entry = &cacheEntry{}
			b.cache[sourceName] = entry
		}
		now := b.now().UTC()
		if leaseFresh(entry.lease, entry.refreshAt, now) {
			lease := cloneLease(entry.lease)
			b.mu.Unlock()
			return lease, nil
		}
		if now.Before(entry.retryAt) {
			if leaseUsable(entry.lease, now) {
				lease := cloneLease(entry.lease)
				b.mu.Unlock()
				return lease, nil
			}
			b.mu.Unlock()
			return Lease{}, fmt.Errorf("%w: source %q is waiting to retry", ErrUnavailable, sourceName)
		}
		if entry.issuing {
			if leaseUsable(entry.lease, now) {
				lease := cloneLease(entry.lease)
				b.mu.Unlock()
				return lease, nil
			}
			done := entry.done
			b.mu.Unlock()
			select {
			case <-ctx.Done():
				return Lease{}, ctx.Err()
			case <-done:
				continue
			}
		}
		entry.issuing = true
		entry.issueGeneration = source.generation
		entry.done = make(chan struct{})
		b.mu.Unlock()

		issued, issueErr := source.provider.Issue(ctx, source.spec, b.secrets)
		now = b.now().UTC()
		if issueErr == nil {
			issueErr = validateLease(issued, now)
		}

		b.mu.Lock()
		entry.issuing = false
		close(entry.done)
		current, stillCurrent := b.sources[sourceName]
		stillGranted := b.grants[grantKey(principal, name)] == sourceName
		if !stillCurrent || current.generation != entry.issueGeneration || !stillGranted {
			clearLease(&issued)
			b.mu.Unlock()
			continue
		}
		if issueErr != nil {
			clearLease(&issued)
			if ctx.Err() != nil {
				b.mu.Unlock()
				return Lease{}, ctx.Err()
			}
			entry.retryAt = now.Add(b.retryDelay)
			if leaseUsable(entry.lease, now) {
				lease := cloneLease(entry.lease)
				b.mu.Unlock()
				return lease, nil
			}
			b.mu.Unlock()
			return Lease{}, fmt.Errorf("%w: source %q: %v", ErrUnavailable, sourceName, issueErr)
		}
		clearLease(&entry.lease)
		entry.lease = issued
		entry.refreshAt = refreshTime(issued, now, b.refreshBefore)
		entry.retryAt = time.Time{}
		lease := cloneLease(entry.lease)
		b.mu.Unlock()
		return lease, nil
	}
}

// InvalidateSecret clears all leases derived from a rotated secret.
func (b *Broker) InvalidateSecret(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for sourceName, source := range b.sources {
		for _, keyName := range source.spec.Secrets {
			if keyName != name {
				continue
			}
			b.generation++
			source.generation = b.generation
			b.sources[sourceName] = source
			if entry := b.cache[sourceName]; entry != nil {
				resetEntry(entry)
			}
			break
		}
	}
}

func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, entry := range b.cache {
		resetEntry(entry)
	}
}

func grantKey(principal, name string) string { return principal + "\x00" + name }

func leaseUsable(lease Lease, now time.Time) bool {
	return len(lease.Value) != 0 && (lease.ExpiresAt.IsZero() || now.Before(lease.ExpiresAt))
}

func leaseFresh(lease Lease, refreshAt, now time.Time) bool {
	return leaseUsable(lease, now) && (lease.ExpiresAt.IsZero() || now.Before(refreshAt))
}

func refreshTime(lease Lease, issuedAt time.Time, refreshBefore time.Duration) time.Time {
	if lease.ExpiresAt.IsZero() {
		return time.Time{}
	}
	lifetime := lease.ExpiresAt.Sub(issuedAt)
	if refreshBefore >= lifetime {
		refreshBefore = lifetime / 2
	}
	return lease.ExpiresAt.Add(-refreshBefore)
}

func validateLease(lease Lease, now time.Time) error {
	if len(lease.Value) == 0 {
		return errors.New("provider returned an empty credential")
	}
	if len(lease.Value) > maxCredentialBytes {
		return fmt.Errorf("provider returned a credential exceeding %d bytes", maxCredentialBytes)
	}
	if !lease.ExpiresAt.IsZero() && !now.Before(lease.ExpiresAt) {
		return errors.New("provider returned an expired credential")
	}
	for _, value := range lease.Value {
		if value < 0x21 || value > 0x7e {
			return errors.New("provider returned a credential containing an invalid byte")
		}
	}
	return nil
}

func cloneLease(lease Lease) Lease {
	return Lease{Value: append([]byte(nil), lease.Value...), ExpiresAt: lease.ExpiresAt}
}

func clearLease(lease *Lease) {
	for i := range lease.Value {
		lease.Value[i] = 0
	}
	lease.Value = nil
	lease.ExpiresAt = time.Time{}
}

func resetEntry(entry *cacheEntry) {
	clearLease(&entry.lease)
	entry.refreshAt = time.Time{}
	entry.retryAt = time.Time{}
}
