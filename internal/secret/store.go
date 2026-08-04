// Package secret implements an encrypted-at-rest key store. A single 256-bit
// master key is supplied to the daemon at startup (normally by systemd-creds);
// individual keys can then be changed without restarting the service.
package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"agentbox/internal/atomicfile"
	"agentbox/internal/domain"
)

const maxValueBytes = 64 << 10

type envelope struct {
	Version    int       `json:"version"`
	Name       string    `json:"name"`
	UpdatedAt  time.Time `json:"updated_at"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
}

type entry struct {
	value     []byte
	updatedAt time.Time
}

type Store struct {
	dir     string
	aead    cipher.AEAD
	mu      sync.RWMutex
	entries map[string]entry
}

func Open(dir string, masterKey []byte) (*Store, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be exactly 32 bytes, got %d", len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, aead: aead, entries: map[string]entry{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	loaded := false
	defer func() {
		if !loaded {
			for _, item := range s.entries {
				clearBytes(item.value)
			}
		}
	}()
	items, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, item.Name()))
		if err != nil {
			return err
		}
		var env envelope
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&env); err != nil {
			return fmt.Errorf("parse encrypted key %s: %w", item.Name(), err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return fmt.Errorf("parse encrypted key %s: trailing JSON data", item.Name())
		}
		if env.Version != 1 || !domain.ValidKeyName(env.Name) || item.Name() != env.Name+".json" || env.UpdatedAt.IsZero() {
			return fmt.Errorf("invalid encrypted key envelope %s", item.Name())
		}
		value, err := s.decrypt(env)
		if err != nil {
			return fmt.Errorf("decrypt key %q: %w", env.Name, err)
		}
		s.entries[env.Name] = entry{value: value, updatedAt: env.UpdatedAt}
	}
	loaded = true
	return nil
}

func (s *Store) Set(name string, value []byte) error {
	if !domain.ValidKeyName(name) {
		return fmt.Errorf("invalid key name %q", name)
	}
	if len(value) == 0 {
		return errors.New("key value must not be empty")
	}
	if len(value) > maxValueBytes {
		return fmt.Errorf("key exceeds %d bytes", maxValueBytes)
	}
	value = append([]byte(nil), value...)
	committed := false
	defer func() {
		if !committed {
			clearBytes(value)
		}
	}()
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	updated := time.Now().UTC()
	env := envelope{
		Version: 1, Name: name, UpdatedAt: updated,
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(s.aead.Seal(nil, nonce, value, additionalData(name))),
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := atomicfile.Write(s.path(name), append(data, '\n'), 0o600); err != nil {
		return err
	}
	if previous, ok := s.entries[name]; ok {
		clearBytes(previous.value)
	}
	s.entries[name] = entry{value: value, updatedAt: updated}
	committed = true
	return nil
}

func (s *Store) Delete(name string) error {
	if !domain.ValidKeyName(name) {
		return fmt.Errorf("invalid key name %q", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := atomicfile.Remove(s.path(name)); err != nil {
		return err
	}
	if previous, ok := s.entries[name]; ok {
		clearBytes(previous.value)
	}
	delete(s.entries, name)
	return nil
}

func (s *Store) Has(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.entries[name]
	return ok
}

func (s *Store) Resolve(name string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[name]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), e.value...), true
}

func (s *Store) List() []domain.KeyInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.KeyInfo, 0, len(s.entries))
	for name, e := range s.entries {
		out = append(out, domain.KeyInfo{Name: name, UpdatedAt: e.updatedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) decrypt(env envelope) ([]byte, error) {
	nonce, err := base64.RawStdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	if len(nonce) != s.aead.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	return s.aead.Open(nil, nonce, ciphertext, additionalData(env.Name))
}

func (s *Store) path(name string) string { return filepath.Join(s.dir, name+".json") }
func additionalData(name string) []byte  { return []byte("agentbox-key-v1\x00" + name) }

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
