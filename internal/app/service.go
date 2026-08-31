// Package app is the transport-independent control plane. HTTP handlers and
// CLI commands are adapters around this typed service; persistence, runtime
// snapshots, and listener changes commit here as one serialized operation.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("conflict")
	ErrForbidden = errors.New("forbidden")
)

const maxHostSessionsPerUser = 16

type ListenerReconciler interface {
	Reconcile([]domain.Container) error
}

type Service struct {
	stateStore  state.Store
	keys        *secret.Store
	credentials *credential.Broker

	mu        sync.Mutex
	state     domain.State
	hosts     []domain.Container
	listeners ListenerReconciler
	snapshot  atomic.Pointer[engine.Snapshot]
}

type Health struct {
	Status             string `json:"status"`
	Profiles           int    `json:"profiles"`
	Routes             int    `json:"routes"`
	Keys               int    `json:"keys"`
	Containers         int    `json:"containers"`
	CredentialSources  int    `json:"credential_sources"`
	CredentialBindings int    `json:"credential_bindings"`
	HostSessions       int    `json:"host_sessions"`
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
	if err := listeners.Reconcile(s.runtimeState(s.state).Containers); err != nil {
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
	bindings := 0
	for _, profile := range s.state.Profiles {
		bindings += len(profile.Credentials)
	}
	return Health{Status: "ok", Profiles: len(s.state.Profiles), Routes: len(domain.AllRoutes(s.state)), Keys: len(s.keys.List()), Containers: len(s.state.Containers),
		CredentialSources: len(s.state.CredentialSources), CredentialBindings: bindings, HostSessions: len(s.hosts)}
}

func (s *Service) Routes(_ context.Context, profileName string) ([]domain.Route, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, profile := range s.state.Profiles {
		if profile.Name == profileName {
			return domain.AllRoutes(domain.State{Profiles: []domain.Profile{profile}}), nil
		}
	}
	return nil, fmt.Errorf("%w: profile %q", ErrNotFound, profileName)
}

func (s *Service) PutRoute(_ context.Context, profileName string, route domain.Route) error {
	return s.change(func(next *domain.State) error {
		for p := range next.Profiles {
			if next.Profiles[p].Name != profileName {
				continue
			}
			for i := range next.Profiles[p].Routes {
				if next.Profiles[p].Routes[i].Name == route.Name {
					next.Profiles[p].Routes[i] = route
					return nil
				}
			}
			next.Profiles[p].Routes = append(next.Profiles[p].Routes, route)
			return nil
		}
		return fmt.Errorf("%w: profile %q", ErrNotFound, profileName)
	})
}

func (s *Service) ReplaceRoutes(_ context.Context, profileName string, routes []domain.Route) error {
	return s.change(func(next *domain.State) error {
		for i := range next.Profiles {
			if next.Profiles[i].Name == profileName {
				next.Profiles[i].Routes = append([]domain.Route(nil), routes...)
				return nil
			}
		}
		return fmt.Errorf("%w: profile %q", ErrNotFound, profileName)
	})
}

func (s *Service) DeleteRoute(_ context.Context, profile, name string) error {
	return s.change(func(next *domain.State) error {
		for p := range next.Profiles {
			if next.Profiles[p].Name != profile {
				continue
			}
			for i, route := range next.Profiles[p].Routes {
				if route.Name == name {
					next.Profiles[p].Routes = append(next.Profiles[p].Routes[:i], next.Profiles[p].Routes[i+1:]...)
					return nil
				}
			}
		}
		return fmt.Errorf("%w: route %q in profile %q", ErrNotFound, name, profile)
	})
}

func (s *Service) Profiles(context.Context) []domain.Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return domain.CloneState(s.state).Profiles
}

// UserProfiles returns only the public launch configuration for profiles
// explicitly granted to uid. It deliberately excludes routes, key references,
// and credential-source bindings.
func (s *Service) UserProfiles(_ context.Context, uid uint32) []domain.UserProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	allowed := make(map[string]bool)
	for _, grant := range s.state.ProfileGrants {
		if grant.UID == uid {
			allowed[grant.Profile] = true
		}
	}
	var out []domain.UserProfile
	for _, profile := range s.state.Profiles {
		if allowed[profile.Name] {
			out = append(out, domain.UserProfile{Name: profile.Name, Environment: cloneStrings(profile.Environment)})
		}
	}
	return out
}

func (s *Service) ProfileGrants(context.Context) []domain.ProfileGrant {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]domain.ProfileGrant(nil), s.state.ProfileGrants...)
}

func (s *Service) PutProfileGrant(_ context.Context, grant domain.ProfileGrant) error {
	return s.change(func(next *domain.State) error {
		for _, existing := range next.ProfileGrants {
			if existing == grant {
				return nil
			}
		}
		next.ProfileGrants = append(next.ProfileGrants, grant)
		return nil
	})
}

func (s *Service) DeleteProfileGrant(_ context.Context, uid uint32, profile string) error {
	return s.change(func(next *domain.State) error {
		for i, grant := range next.ProfileGrants {
			if grant.UID == uid && grant.Profile == profile {
				next.ProfileGrants = append(next.ProfileGrants[:i], next.ProfileGrants[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("%w: profile %q is not granted to uid %d", ErrNotFound, profile, uid)
	})
}

func (s *Service) PutProfile(_ context.Context, profile domain.Profile) error {
	return s.change(func(next *domain.State) error {
		for i := range next.Profiles {
			if next.Profiles[i].Name == profile.Name {
				next.Profiles[i] = profile
				return nil
			}
		}
		next.Profiles = append(next.Profiles, profile)
		return nil
	})
}

func (s *Service) DeleteProfile(_ context.Context, name string) error {
	return s.change(func(next *domain.State) error {
		for _, host := range s.hosts {
			if host.Profile == name {
				return fmt.Errorf("%w: profile %q is used by host session %q", ErrConflict, name, host.Name)
			}
		}
		for _, container := range next.Containers {
			if container.Profile == name {
				return fmt.Errorf("%w: profile %q is used by container %q", ErrConflict, name, container.Name)
			}
		}
		for _, grant := range next.ProfileGrants {
			if grant.Profile == name {
				return fmt.Errorf("%w: profile %q is granted to uid %d", ErrConflict, name, grant.UID)
			}
		}
		for i, profile := range next.Profiles {
			if profile.Name == name {
				next.Profiles = append(next.Profiles[:i], next.Profiles[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("%w: profile %q", ErrNotFound, name)
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
	for _, route := range domain.AllRoutes(s.state) {
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
		for _, profile := range next.Profiles {
			for credential, source := range profile.Credentials {
				if source == name {
					return fmt.Errorf("%w: credential source %q is bound as %q by profile %q", ErrConflict, name, credential, profile.Name)
				}
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

func (s *Service) Containers(context.Context) []domain.Container {
	s.mu.Lock()
	defer s.mu.Unlock()
	return domain.CloneState(s.state).Containers
}

func (s *Service) AddContainer(_ context.Context, container domain.Container) (domain.Container, error) {
	container.Host = false
	container.OwnerUID = 0
	if container.CreatedAt.IsZero() {
		container.CreatedAt = time.Now().UTC()
	}
	err := s.change(func(next *domain.State) error {
		for _, existing := range s.hosts {
			if existing.Name == container.Name {
				return fmt.Errorf("%w: identity %q", ErrConflict, container.Name)
			}
		}
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

// AddHostSession registers an in-memory data-plane identity owned by uid. The
// name and owner are server-derived, and the selected profile must be granted
// to that uid. Host sessions are deliberately not persisted.
func (s *Service) AddHostSession(_ context.Context, uid uint32, profile string) (domain.HostSession, error) {
	name, err := randomHostName(uid)
	if err != nil {
		return domain.HostSession{}, err
	}
	host := domain.Container{Name: name, Profile: profile, CreatedAt: time.Now().UTC(), Host: true, OwnerUID: uid}
	err = s.changeHosts(func(next *[]domain.Container) error {
		if !profileGranted(s.state, uid, profile) {
			return fmt.Errorf("%w: profile %q is not granted to uid %d", ErrForbidden, profile, uid)
		}
		owned := 0
		for _, existing := range *next {
			if existing.OwnerUID == uid {
				owned++
			}
		}
		if owned >= maxHostSessionsPerUser {
			return fmt.Errorf("%w: uid %d already has %d host sessions", ErrConflict, uid, maxHostSessionsPerUser)
		}
		for _, existing := range s.state.Containers {
			if existing.Name == host.Name {
				return fmt.Errorf("%w: identity %q", ErrConflict, host.Name)
			}
		}
		for _, existing := range *next {
			if existing.Name == host.Name {
				return fmt.Errorf("%w: host session %q", ErrConflict, host.Name)
			}
		}
		*next = append(*next, host)
		return nil
	})
	return domain.HostSession{Name: host.Name, Profile: host.Profile, CreatedAt: host.CreatedAt}, err
}

func (s *Service) DeleteHostSession(_ context.Context, uid uint32, name string) error {
	return s.changeHosts(func(next *[]domain.Container) error {
		for i, host := range *next {
			if host.Name == name && host.OwnerUID == uid {
				*next = append((*next)[:i], (*next)[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("%w: host session %q", ErrNotFound, name)
	})
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
	nextHosts := authorizedHosts(s.hosts, next)
	previousRuntime := s.runtimeState(previous)
	nextRuntime := runtimeState(next, nextHosts)
	compiled, err := engine.Compile(nextRuntime)
	if err != nil {
		return err
	}
	if err := s.credentials.Validate(nextRuntime); err != nil {
		return err
	}
	if s.listeners != nil {
		if err := s.listeners.Reconcile(nextRuntime.Containers); err != nil {
			rollbackErr := s.listeners.Reconcile(previousRuntime.Containers)
			return fmt.Errorf("reconcile listeners: %w (rollback listeners: %v)", err, rollbackErr)
		}
	}
	if err := s.credentials.Configure(nextRuntime); err != nil {
		if s.listeners != nil {
			_ = s.listeners.Reconcile(previousRuntime.Containers)
		}
		return fmt.Errorf("configure credentials: %w", err)
	}
	if err := s.stateStore.Save(next); err != nil {
		_ = s.credentials.Configure(previousRuntime)
		if s.listeners != nil {
			rollbackErr := s.listeners.Reconcile(previousRuntime.Containers)
			return fmt.Errorf("persist state: %w (rollback listeners: %v)", err, rollbackErr)
		}
		return err
	}
	s.state = next
	s.hosts = nextHosts
	s.snapshot.Store(compiled)
	return nil
}

func (s *Service) changeHosts(mutator func(*[]domain.Container) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := append([]domain.Container(nil), s.hosts...)
	next := append([]domain.Container(nil), s.hosts...)
	if err := mutator(&next); err != nil {
		return err
	}
	nextRuntime := domain.CloneState(s.state)
	nextRuntime.Containers = append(nextRuntime.Containers, next...)
	nextRuntime = domain.NormalizeState(nextRuntime)
	compiled, err := engine.Compile(nextRuntime)
	if err != nil {
		return err
	}
	if err := s.credentials.Validate(nextRuntime); err != nil {
		return err
	}
	previousRuntime := domain.CloneState(s.state)
	previousRuntime.Containers = append(previousRuntime.Containers, previous...)
	previousRuntime = domain.NormalizeState(previousRuntime)
	if s.listeners != nil {
		if err := s.listeners.Reconcile(nextRuntime.Containers); err != nil {
			rollbackErr := s.listeners.Reconcile(previousRuntime.Containers)
			return fmt.Errorf("reconcile listeners: %w (rollback listeners: %v)", err, rollbackErr)
		}
	}
	if err := s.credentials.Configure(nextRuntime); err != nil {
		if s.listeners != nil {
			_ = s.listeners.Reconcile(previousRuntime.Containers)
		}
		return fmt.Errorf("configure credentials: %w", err)
	}
	s.hosts = next
	s.snapshot.Store(compiled)
	return nil
}

func (s *Service) runtimeState(persisted domain.State) domain.State {
	return runtimeState(persisted, s.hosts)
}

func runtimeState(persisted domain.State, hosts []domain.Container) domain.State {
	runtime := domain.CloneState(persisted)
	runtime.Containers = append(runtime.Containers, hosts...)
	return domain.NormalizeState(runtime)
}

func profileGranted(state domain.State, uid uint32, profile string) bool {
	for _, grant := range state.ProfileGrants {
		if grant.UID == uid && grant.Profile == profile {
			return true
		}
	}
	return false
}

func authorizedHosts(hosts []domain.Container, state domain.State) []domain.Container {
	out := make([]domain.Container, 0, len(hosts))
	for _, host := range hosts {
		if profileGranted(state, host.OwnerUID, host.Profile) {
			out = append(out, host)
		}
	}
	return out
}

func cloneStrings(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func randomHostName(uid uint32) (string, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate host session name: %w", err)
	}
	return fmt.Sprintf("host-%d-%s", uid, hex.EncodeToString(random[:])), nil
}
