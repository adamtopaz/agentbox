// Package state persists the non-secret daemon state as strict JSON.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"agentbox/internal/atomicfile"
	"agentbox/internal/domain"
)

const legacyUniversalScope = "*"

type Store struct{ Path string }

func (s Store) Load() (domain.State, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return domain.NewState(), nil
	}
	if err != nil {
		return domain.State{}, err
	}
	state, err := decodeState(data)
	if err != nil {
		return domain.State{}, fmt.Errorf("parse %s: %w", s.Path, err)
	}
	if err := domain.ValidateState(state); err != nil {
		return domain.State{}, fmt.Errorf("validate %s: %w", s.Path, err)
	}
	return domain.NormalizeState(state), nil
}

func decodeState(data []byte) (domain.State, error) {
	var version struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &version); err != nil {
		return domain.State{}, err
	}
	switch version.Version {
	case domain.StateVersion:
		var current domain.State
		if err := decodeStrict(data, &current); err != nil {
			return domain.State{}, err
		}
		return current, nil
	case 2:
		return migrateV2(data)
	case 1:
		return migrateV1(data)
	default:
		return domain.State{}, fmt.Errorf("unsupported state version %d (want %d)", version.Version, domain.StateVersion)
	}
}

// Version 1 briefly supported path, query, and JSON-body transformations.
// Version 2 deliberately removes them: Agentbox is an authentication proxy and
// must preserve the provider request. A transforming route is omitted instead
// of being migrated with changed semantics; provider profiles safely recreate
// their routes against transparent, provider-native endpoints.
func migrateV1(data []byte) (domain.State, error) {
	type legacyRoute struct {
		Name        string               `json:"name"`
		Scope       string               `json:"scope"`
		Match       domain.Match         `json:"match"`
		Upstream    string               `json:"upstream"`
		StripPrefix bool                 `json:"strip_prefix,omitempty"`
		DropQuery   bool                 `json:"drop_query,omitempty"`
		PathMap     []json.RawMessage    `json:"path_map,omitempty"`
		RequestJSON json.RawMessage      `json:"request_json,omitempty"`
		SetHeaders  []domain.HeaderValue `json:"set_headers,omitempty"`
	}
	type legacyState struct {
		Version           int                       `json:"version"`
		Routes            []legacyRoute             `json:"routes"`
		Containers        []legacyContainer         `json:"containers"`
		CredentialSources []domain.CredentialSource `json:"credential_sources"`
		CredentialGrants  []domain.CredentialGrant  `json:"credential_grants"`
	}
	var old legacyState
	if err := decodeStrict(data, &old); err != nil {
		return domain.State{}, err
	}

	var routes []legacyScopedRoute
	for _, route := range old.Routes {
		requestJSON := bytes.TrimSpace(route.RequestJSON)
		transformsBody := len(requestJSON) != 0 && !bytes.Equal(requestJSON, []byte("null"))
		if route.DropQuery || len(route.PathMap) != 0 || transformsBody {
			continue
		}
		routes = append(routes, legacyScopedRoute{Scope: route.Scope, Route: domain.Route{
			Name: route.Name, Match: route.Match,
			Upstream: route.Upstream, StripPrefix: route.StripPrefix,
			SetHeaders: route.SetHeaders,
		}})
	}
	return migrateLegacy(routes, old.Containers, old.CredentialSources, old.CredentialGrants)
}

type legacyContainer struct {
	Name      string    `json:"name"`
	Scope     string    `json:"scope"`
	Blocked   bool      `json:"blocked,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type legacyScopedRoute struct {
	Scope string
	Route domain.Route
}

type legacyRouteV2 struct {
	Name        string               `json:"name"`
	Scope       string               `json:"scope"`
	Match       domain.Match         `json:"match"`
	Upstream    string               `json:"upstream"`
	StripPrefix bool                 `json:"strip_prefix,omitempty"`
	SetHeaders  []domain.HeaderValue `json:"set_headers,omitempty"`
}

type legacyStateV2 struct {
	Version           int                       `json:"version"`
	Routes            []legacyRouteV2           `json:"routes"`
	Containers        []legacyContainer         `json:"containers"`
	CredentialSources []domain.CredentialSource `json:"credential_sources"`
	CredentialGrants  []domain.CredentialGrant  `json:"credential_grants"`
}

func migrateV2(data []byte) (domain.State, error) {
	var old legacyStateV2
	if err := decodeStrict(data, &old); err != nil {
		return domain.State{}, err
	}
	routes := make([]legacyScopedRoute, len(old.Routes))
	for i, route := range old.Routes {
		routes[i] = legacyScopedRoute{Scope: route.Scope, Route: domain.Route{
			Name: route.Name, Match: route.Match, Upstream: route.Upstream,
			StripPrefix: route.StripPrefix, SetHeaders: route.SetHeaders,
		}}
	}
	return migrateLegacy(routes, old.Containers, old.CredentialSources, old.CredentialGrants)
}

func migrateLegacy(routes []legacyScopedRoute, containers []legacyContainer, sources []domain.CredentialSource, grants []domain.CredentialGrant) (domain.State, error) {
	next := domain.NewState()
	next.CredentialSources = sources
	profiles := map[string]*domain.Profile{}
	ensureProfile := func(name string) *domain.Profile {
		if profiles[name] == nil {
			profiles[name] = &domain.Profile{Name: name, Routes: []domain.Route{}, Credentials: map[string]string{}, Environment: map[string]string{}}
		}
		return profiles[name]
	}
	for _, container := range containers {
		ensureProfile(container.Scope)
		next.Containers = append(next.Containers, domain.Container{
			Name: container.Name, Profile: container.Scope, Blocked: container.Blocked, CreatedAt: container.CreatedAt,
		})
	}
	for _, route := range routes {
		if route.Scope != legacyUniversalScope {
			ensureProfile(route.Scope).Routes = append(ensureProfile(route.Scope).Routes, route.Route)
		}
	}
	if len(profiles) == 0 && len(routes) != 0 {
		ensureProfile("default")
	}

	profileContainers := map[string][]string{}
	containerProfiles := map[string]string{}
	for _, container := range containers {
		profileContainers[container.Scope] = append(profileContainers[container.Scope], container.Name)
		containerProfiles[container.Name] = container.Scope
	}
	sourceNames := map[string]bool{}
	for _, source := range sources {
		sourceNames[source.Name] = true
	}
	perContainer := map[string]map[string]string{}
	for _, grant := range grants {
		if err := domain.ValidateCredentialGrant(grant); err != nil {
			return domain.State{}, err
		}
		if containerProfiles[grant.Container] == "" {
			return domain.State{}, fmt.Errorf("legacy credential grant references unknown container %q", grant.Container)
		}
		if !sourceNames[grant.Source] {
			return domain.State{}, fmt.Errorf("legacy credential grant references unknown source %q", grant.Source)
		}
		if perContainer[grant.Container] == nil {
			perContainer[grant.Container] = map[string]string{}
		}
		if perContainer[grant.Container][grant.Credential] != "" {
			return domain.State{}, fmt.Errorf("duplicate legacy credential %q for container %q", grant.Credential, grant.Container)
		}
		perContainer[grant.Container][grant.Credential] = grant.Source
	}
	for profileName, names := range profileContainers {
		if len(names) == 0 {
			continue
		}
		first := perContainer[names[0]]
		for _, name := range names[1:] {
			if !mapsEqual(first, perContainer[name]) {
				return domain.State{}, fmt.Errorf("cannot migrate scope %q to one profile: containers have different credential grants", profileName)
			}
		}
		for credential, source := range first {
			profiles[profileName].Credentials[credential] = source
		}
	}
	for _, route := range routes {
		if route.Scope != legacyUniversalScope {
			continue
		}
		for _, profile := range profiles {
			refs, err := domain.ReferencedCredentials([]domain.Route{route.Route})
			if err != nil {
				return domain.State{}, err
			}
			allowed := true
			for _, ref := range refs {
				if profile.Credentials[ref] == "" {
					allowed = false
					break
				}
			}
			if !allowed {
				continue
			}
			profile.Routes = append(profile.Routes, route.Route)
		}
	}
	for _, profile := range profiles {
		base := "http://127.0.0.1:8787/cloudflare/" + profile.Name
		for name, value := range map[string]string{
			"AGENTBOX_PROFILE":   profile.Name,
			"ANTHROPIC_BASE_URL": base + "/anthropic",
			"OPENAI_BASE_URL":    base + "/openai",
			"ANTHROPIC_API_KEY":  "agentbox-dummy",
			"OPENAI_API_KEY":     "agentbox-dummy",
			"GH_TOKEN":           "agentbox-dummy",
		} {
			profile.Environment[name] = value
		}
		next.Profiles = append(next.Profiles, *profile)
	}
	return domain.NormalizeState(next), nil
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func decodeStrict(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return ensureEOF(dec)
}

func (s Store) Save(state domain.State) error {
	state = domain.NormalizeState(state)
	if err := domain.ValidateState(state); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(s.Path, append(data, '\n'), 0o600)
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("trailing JSON data")
}
