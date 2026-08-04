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

	"agentbox/internal/domain"
	"agentbox/internal/engine"
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
	stateStore state.Store
	keys       *secret.Store

	mu        sync.Mutex
	state     domain.State
	listeners ListenerReconciler
	snapshot  atomic.Pointer[engine.Snapshot]
}

type Health struct {
	Status     string `json:"status"`
	Routes     int    `json:"routes"`
	Keys       int    `json:"keys"`
	Containers int    `json:"containers"`
}

func Open(stateStore state.Store, keys *secret.Store) (*Service, error) {
	current, err := stateStore.Load()
	if err != nil {
		return nil, err
	}
	snapshot, err := engine.Compile(current)
	if err != nil {
		return nil, err
	}
	s := &Service{stateStore: stateStore, keys: keys, state: current}
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

func (s *Service) Snapshot() *engine.Snapshot         { return s.snapshot.Load() }
func (s *Service) Resolve(name string) ([]byte, bool) { return s.keys.Resolve(name) }

func (s *Service) Health(context.Context) Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Health{Status: "ok", Routes: len(s.state.Routes), Keys: len(s.keys.List()), Containers: len(s.state.Containers)}
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
	return s.keys.Set(name, value)
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
	if !s.keys.Has(name) {
		return fmt.Errorf("%w: key %q", ErrNotFound, name)
	}
	return s.keys.Delete(name)
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
	if s.listeners != nil {
		if err := s.listeners.Reconcile(next.Containers); err != nil {
			rollbackErr := s.listeners.Reconcile(previous.Containers)
			return fmt.Errorf("reconcile listeners: %w (rollback listeners: %v)", err, rollbackErr)
		}
	}
	if err := s.stateStore.Save(next); err != nil {
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
