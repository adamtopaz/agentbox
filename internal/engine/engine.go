// Package engine compiles domain routes into an immutable matching snapshot.
// Snapshots can be atomically replaced while in-flight requests retain the
// exact configuration with which they started.
package engine

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"agentbox/internal/domain"
)

type Header struct {
	Name     string
	Template domain.Template
}
type Route struct {
	domain.Route
	Profile string
	Target  *url.URL
	Headers []Header
}

type Snapshot struct {
	routes     []Route
	containers map[string]domain.Container
}

func Compile(state domain.State) (*Snapshot, error) {
	if err := domain.ValidateState(state); err != nil {
		return nil, err
	}
	s := &Snapshot{containers: map[string]domain.Container{}}
	for _, c := range state.Containers {
		s.containers[c.Name] = c
	}
	for _, profile := range state.Profiles {
		for _, source := range profile.Routes {
			target, err := url.Parse(source.Upstream)
			if err != nil {
				return nil, err
			}
			r := Route{Route: source, Profile: profile.Name, Target: target}
			for _, h := range source.SetHeaders {
				t, err := domain.ParseTemplate(h.Value)
				if err != nil {
					return nil, fmt.Errorf("route %q in profile %q: %w", source.Name, profile.Name, err)
				}
				r.Headers = append(r.Headers, Header{Name: h.Name, Template: t})
			}
			s.routes = append(s.routes, r)
		}
	}
	// Hosts beat paths and longer path prefixes beat shorter ones. Names make
	// the remaining order deterministic.
	sort.Slice(s.routes, func(i, j int) bool {
		a, b := s.routes[i], s.routes[j]
		if (a.Match.Host != "") != (b.Match.Host != "") {
			return a.Match.Host != ""
		}
		if len(a.Match.PathPrefix) != len(b.Match.PathPrefix) {
			return len(a.Match.PathPrefix) > len(b.Match.PathPrefix)
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		return a.Name < b.Name
	})
	return s, nil
}

func (s *Snapshot) Container(name string) (domain.Container, bool) {
	c, ok := s.containers[name]
	return c, ok
}

func (s *Snapshot) Containers() []domain.Container {
	out := make([]domain.Container, 0, len(s.containers))
	for _, c := range s.containers {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Snapshot) Match(profile, host, requestPath string) (*Route, string, bool) {
	host = domain.Hostname(host)
	for i := range s.routes {
		r := &s.routes[i]
		if r.Profile != profile {
			continue
		}
		if r.Match.Host != "" {
			if !strings.EqualFold(r.Match.Host, host) {
				continue
			}
			return r, requestPath, true
		}
		prefix := r.Match.PathPrefix
		if prefix != "/" && requestPath != prefix && !strings.HasPrefix(requestPath, prefix+"/") {
			continue
		}
		path := requestPath
		if r.StripPrefix {
			if prefix != "/" {
				path = strings.TrimPrefix(requestPath, prefix)
			}
			if path == "" {
				path = "/"
			}
		}
		return r, path, true
	}
	return nil, "", false
}
