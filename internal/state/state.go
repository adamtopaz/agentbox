// Package state persists the set of agentbox-managed containers as one JSON
// file per container under <base>/containers.d/. The files are the source of
// truth the Caddyfile is rendered from; they are written by the CLI and read
// by every reconcile cycle.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ReservedName is used by `agentbox build-image` for its scratch container and
// must never be a managed container.
const ReservedName = "agentbox-build"

// nameRE matches incus's own instance-name rule (letters, digits and dashes;
// no leading digit or dash, no trailing dash, ≤63 chars) so a name agentbox
// accepts is never rejected later by `incus launch` — after the state file
// has been written and Caddy reloaded. Lowercase only, since the name also
// becomes a unix socket path and rendered Caddyfile text.
var nameRE = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidName reports whether s is acceptable as a container name.
func ValidName(s string) bool {
	return s != ReservedName && nameRE.MatchString(s)
}

// Container is the persisted per-container record.
type Container struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Blocked bool      `json:"blocked"`
}

// Dir manages the containers.d directory under a base path.
type Dir struct {
	path string
}

// Open ensures <base>/containers.d exists and returns a handle to it.
func Open(base string) (*Dir, error) {
	p := filepath.Join(base, "containers.d")
	if err := os.MkdirAll(p, 0o775); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	return &Dir{path: p}, nil
}

// Path returns the containers.d directory path.
func (d *Dir) Path() string { return d.path }

// List returns all containers, sorted by name. Files that are not
// <valid-name>.json, or that fail to parse, are skipped with a warning —
// a stray editor temp file must never take the whole proxy config down.
func (d *Dir) List() ([]Container, error) {
	entries, err := os.ReadDir(d.path)
	if err != nil {
		return nil, fmt.Errorf("read state dir: %w", err)
	}
	var out []Container
	for _, e := range entries {
		if e.IsDir() {
			slog.Warn("state: ignoring unexpected directory", "name", e.Name())
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue // our own .tmp-* and .reconcile.lock; not worth a warning
		}
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidName(name) {
			slog.Warn("state: ignoring unexpected file", "name", e.Name())
			continue
		}
		c, found, err := d.Get(name)
		if err != nil || !found {
			slog.Warn("state: skipping unreadable state file", "name", e.Name(), "err", err)
			continue
		}
		if c.Name != name {
			slog.Warn("state: skipping state file whose content disagrees with its filename",
				"file", e.Name(), "content-name", c.Name)
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get returns the container record for name, with found=false when no state
// file exists.
func (d *Dir) Get(name string) (Container, bool, error) {
	if !ValidName(name) {
		return Container{}, false, fmt.Errorf("invalid container name %q", name)
	}
	data, err := os.ReadFile(filepath.Join(d.path, name+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return Container{}, false, nil
	}
	if err != nil {
		return Container{}, false, err
	}
	var c Container
	if err := json.Unmarshal(data, &c); err != nil {
		return Container{}, false, fmt.Errorf("parse state file for %q: %w", name, err)
	}
	return c, true, nil
}

// Put atomically writes the container record (temp file + rename). Mode 0664:
// the CLI is run by different users sharing the agentbox group.
func (d *Dir) Put(c Container) error {
	if !ValidName(c.Name) {
		return fmt.Errorf("invalid container name %q", c.Name)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(d.path, ".tmp-*")
	if err != nil {
		return fmt.Errorf("write state file: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o664); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(d.path, c.Name+".json"))
}

// Remove deletes the state file; removing an absent one is not an error.
func (d *Dir) Remove(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid container name %q", name)
	}
	err := os.Remove(filepath.Join(d.path, name+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
