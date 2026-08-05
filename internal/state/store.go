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

	"agentbox/internal/atomicfile"
	"agentbox/internal/domain"
)

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
		Containers        []domain.Container        `json:"containers"`
		CredentialSources []domain.CredentialSource `json:"credential_sources"`
		CredentialGrants  []domain.CredentialGrant  `json:"credential_grants"`
	}
	var old legacyState
	if err := decodeStrict(data, &old); err != nil {
		return domain.State{}, err
	}

	migrated := domain.NewState()
	migrated.Containers = old.Containers
	migrated.CredentialSources = old.CredentialSources
	migrated.CredentialGrants = old.CredentialGrants
	for _, route := range old.Routes {
		requestJSON := bytes.TrimSpace(route.RequestJSON)
		transformsBody := len(requestJSON) != 0 && !bytes.Equal(requestJSON, []byte("null"))
		if route.DropQuery || len(route.PathMap) != 0 || transformsBody {
			continue
		}
		migrated.Routes = append(migrated.Routes, domain.Route{
			Name: route.Name, Scope: route.Scope, Match: route.Match,
			Upstream: route.Upstream, StripPrefix: route.StripPrefix,
			SetHeaders: route.SetHeaders,
		})
	}
	return migrated, nil
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
