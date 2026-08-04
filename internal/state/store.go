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
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var state domain.State
	if err := dec.Decode(&state); err != nil {
		return domain.State{}, fmt.Errorf("parse %s: %w", s.Path, err)
	}
	if err := ensureEOF(dec); err != nil {
		return domain.State{}, fmt.Errorf("parse %s: %w", s.Path, err)
	}
	if err := domain.ValidateState(state); err != nil {
		return domain.State{}, fmt.Errorf("validate %s: %w", s.Path, err)
	}
	return domain.NormalizeState(state), nil
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
