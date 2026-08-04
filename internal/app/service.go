// Package app is the transport-independent control plane. HTTP handlers and
// CLI commands are adapters around this typed service; persistence, runtime
// snapshots, and listener changes commit here as one serialized operation.
package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"agentbox/internal/credential"
	"agentbox/internal/domain"
	"agentbox/internal/engine"
	"agentbox/internal/githubapp"
	"agentbox/internal/secret"
	"agentbox/internal/state"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type ListenerReconciler interface {
	Reconcile([]domain.Container) error
}

type Service struct {
	stateStore  state.Store
	keys        *secret.Store
	credentials *credential.Broker

	mu        sync.Mutex
	state     domain.State
	listeners ListenerReconciler
	snapshot  atomic.Pointer[engine.Snapshot]
}

type Health struct {
	Status            string `json:"status"`
	Routes            int    `json:"routes"`
	Keys              int    `json:"keys"`
	Containers        int    `json:"containers"`
	CredentialSources int    `json:"credential_sources"`
	CredentialGrants  int    `json:"credential_grants"`
}

func Open(stateStore state.Store, keys *secret.Store) (*Service, error) {
	return OpenWithProviders(stateStore, keys, []credential.Provider{githubapp.MustDefault()}, credential.Options{})
}

// OpenWithProviders is the composition seam used by tests and future provider
// adapters. Production Open registers only explicitly supported providers.
func OpenWithProviders(stateStore state.Store, keys *secret.Store, providers []credential.Provider, options credential.Options) (*Service, error) {
	current, err := stateStore.Load()
	if err != nil {
		return nil, err
	}
	snapshot, err := engine.Compile(current)
	if err != nil {
		return nil, err
	}
	broker, err := credential.NewBroker(keys, providers, options)
	if err != nil {
		return nil, err
	}
	if err := broker.Configure(current); err != nil {
		return nil, err
	}
	s := &Service{stateStore: stateStore, keys: keys, credentials: broker, state: current}
	s.snapshot.Store(snapshot)
	return s, nil
}

// AttachListeners starts the data-plane sockets represented by persisted
// state. It is separate from Open to avoid a construction cycle between the
// service, proxy, and listener manager.
func (s *Service) AttachListeners(listeners ListenerReconciler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listeners != nil {
		return errors.New("listeners already attached")
	}
	if err := listeners.Reconcile(s.state.Containers); err != nil {
		return err
	}
	s.listeners = listeners
	return nil
}

func (s *Service) Snapshot() *engine.Snapshot { return s.snapshot.Load() }

func (s *Service) Close() { s.credentials.Close() }

func (s *Service) Resolve(ctx context.Context, principal string, ref domain.MaterialReference) ([]byte, error) {
	switch ref.Kind {
	case domain.MaterialSecret:
		value, ok := s.keys.Resolve(ref.Name)
		if !ok {
			return nil, fmt.Errorf("secret %q is not installed", ref.Name)
		}
		return value, nil
	case domain.MaterialCredential:
		lease, err := s.credentials.Acquire(ctx, principal, ref.Name)
		if err != nil {
			return nil, err
		}
		return lease.Value, nil
	default:
		return nil, fmt.Errorf("unknown material kind %q", ref.Kind)
	}
}

func (s *Service) Health(context.Context) Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Health{Status: "ok", Routes: len(s.state.Routes), Keys: len(s.keys.List()), Containers: len(s.state.Containers),
		CredentialSources: len(s.state.CredentialSources), CredentialGrants: len(s.state.CredentialGrants)}
}

func (s *Service) Routes(context.Context) []domain.Route {
	s.mu.Lock()
	defer s.mu.Unlock()
	return domain.CloneState(s.state).Routes
}

func (s *Service) PutRoute(_ context.Context, route domain.Route) error {
	return s.change(func(next *domain.State) error {
		for i := range next.Routes {
			if next.Routes[i].Name == route.Name {
				next.Routes[i] = route
				return nil
			}
		}
		next.Routes = append(next.Routes, route)
		return nil
	})
}

func (s *Service) ReplaceRoutes(_ context.Context, routes []domain.Route) error {
	return s.change(func(next *domain.State) error { next.Routes = append([]domain.Route(nil), routes...); return nil })
}

func (s *Service) DeleteRoute(_ context.Context, name string) error {
	return s.change(func(next *domain.State) error {
		for i, route := range next.Routes {
			if route.Name == name {
				next.Routes = append(next.Routes[:i], next.Routes[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("%w: route %q", ErrNotFound, name)
	})
}

func (s *Service) Keys(context.Context) []domain.KeyInfo { return s.keys.List() }
func (s *Service) SetKey(_ context.Context, name string, value []byte) error {
	if err := s.keys.Set(name, value); err != nil {
		return err
	}
	s.credentials.InvalidateSecret(name)
	return nil
}

func (s *Service) DeleteKey(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, route := range s.state.Routes {
		refs, err := domain.ReferencedKeys([]domain.Route{route})
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if ref == name {
				return fmt.Errorf("%w: key %q is referenced by route %q", ErrConflict, name, route.Name)
			}
		}
	}
	for _, source := range s.state.CredentialSources {
		for role, ref := range source.Secrets {
			if ref == name {
				return fmt.Errorf("%w: key %q is referenced by credential source %q as %q", ErrConflict, name, source.Name, role)
			}
		}
	}
	if !s.keys.Has(name) {
		return fmt.Errorf("%w: key %q", ErrNotFound, name)
	}
	return s.keys.Delete(name)
}

func (s *Service) CredentialSources(context.Context) []domain.CredentialSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	return domain.CloneState(s.state).CredentialSources
}

func (s *Service) PutCredentialSource(_ context.Context, source domain.CredentialSource) error {
	return s.change(func(next *domain.State) error {
		for i := range next.CredentialSources {
			if next.CredentialSources[i].Name == source.Name {
				next.CredentialSources[i] = source
				return nil
			}
		}
		next.CredentialSources = append(next.CredentialSources, source)
		return nil
	})
}

func (s *Service) DeleteCredentialSource(_ context.Context, name string) error {
	return s.change(func(next *domain.State) error {
		for _, grant := range next.CredentialGrants {
			if grant.Source == name {
				return fmt.Errorf("%w: credential source %q is referenced by grant %q for container %q", ErrConflict, name, grant.Credential, grant.Container)
			}
		}
		for i, source := range next.CredentialSources {
			if source.Name == name {
				next.CredentialSources = append(next.CredentialSources[:i], next.CredentialSources[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("%w: credential source %q", ErrNotFound, name)
	})
}

func (s *Service) CredentialGrants(context.Context) []domain.CredentialGrant {
	s.mu.Lock()
	defer s.mu.Unlock()
	return domain.CloneState(s.state).CredentialGrants
}

func (s *Service) PutCredentialGrant(_ context.Context, grant domain.CredentialGrant) error {
	return s.change(func(next *domain.State) error {
		for i := range next.CredentialGrants {
			if next.CredentialGrants[i].Container == grant.Container && next.CredentialGrants[i].Credential == grant.Credential {
				next.CredentialGrants[i] = grant
				return nil
			}
		}
		next.CredentialGrants = append(next.CredentialGrants, grant)
		return nil
	})
}

func (s *Service) DeleteCredentialGrant(_ context.Context, container, name string) error {
	return s.change(func(next *domain.State) error {
		for i, grant := range next.CredentialGrants {
			if grant.Container == container && grant.Credential == name {
				next.CredentialGrants = append(next.CredentialGrants[:i], next.CredentialGrants[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("%w: credential %q for container %q", ErrNotFound, name, container)
	})
}

func (s *Service) Containers(context.Context) []domain.Container {
	s.mu.Lock()
	defer s.mu.Unlock()
	return domain.CloneState(s.state).Containers
}

func (s *Service) AddContainer(_ context.Context, container domain.Container) (domain.Container, error) {
	if container.CreatedAt.IsZero() {
		container.CreatedAt = time.Now().UTC()
	}
	err := s.change(func(next *domain.State) error {
		for _, existing := range next.Containers {
			if existing.Name == container.Name {
				return fmt.Errorf("%w: container %q", ErrConflict, container.Name)
			}
		}
		next.Containers = append(next.Containers, container)
		return nil
	})
	return container, err
}

func (s *Service) SetContainerBlocked(_ context.Context, name string, blocked bool) error {
	return s.change(func(next *domain.State) error {
		for i := range next.Containers {
			if next.Containers[i].Name == name {
				next.Containers[i].Blocked = blocked
				return nil
			}
		}
		return fmt.Errorf("%w: container %q", ErrNotFound, name)
	})
}

func (s *Service) DeleteContainer(_ context.Context, name string) error {
	return s.change(func(next *domain.State) error {
		for i, container := range next.Containers {
			if container.Name == name {
				next.Containers = append(next.Containers[:i], next.Containers[i+1:]...)
				grants := next.CredentialGrants[:0]
				for _, grant := range next.CredentialGrants {
					if grant.Container != name {
						grants = append(grants, grant)
					}
				}
				next.CredentialGrants = grants
				return nil
			}
		}
		return fmt.Errorf("%w: container %q", ErrNotFound, name)
	})
}

func (s *Service) change(mutator func(*domain.State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := domain.CloneState(s.state)
	next := domain.CloneState(s.state)
	if err := mutator(&next); err != nil {
		return err
	}
	next = domain.NormalizeState(next)
	compiled, err := engine.Compile(next)
	if err != nil {
		return err
	}
	if err := s.credentials.Validate(next); err != nil {
		return err
	}
	if s.listeners != nil {
		if err := s.listeners.Reconcile(next.Containers); err != nil {
			rollbackErr := s.listeners.Reconcile(previous.Containers)
			return fmt.Errorf("reconcile listeners: %w (rollback listeners: %v)", err, rollbackErr)
		}
	}
	if err := s.credentials.Configure(next); err != nil {
		if s.listeners != nil {
			_ = s.listeners.Reconcile(previous.Containers)
		}
		return fmt.Errorf("configure credentials: %w", err)
	}
	if err := s.stateStore.Save(next); err != nil {
		_ = s.credentials.Configure(previous)
		if s.listeners != nil {
			rollbackErr := s.listeners.Reconcile(previous.Containers)
			return fmt.Errorf("persist state: %w (rollback listeners: %v)", err, rollbackErr)
		}
		return err
	}
	s.state = next
	s.snapshot.Store(compiled)
	return nil
}
