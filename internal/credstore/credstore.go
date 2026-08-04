// Package credstore wraps systemd-creds, which encrypts each secret at rest
// so no plaintext credential is ever written to disk. Ciphertext lives in
// /etc/agentbox/secrets/<name>.cred and is handed to Caddy by systemd's
// LoadCredentialEncrypted=, which decrypts it into the service's private
// /run/credentials ramfs at start (unswappable, per man systemd-creds).
//
// What this does and does not buy is worth being precise about. Caddy needs
// plaintext at request time and must start unattended, so the decryption key
// is necessarily reachable by the machine: root on a running host can always
// recover the secrets, under any scheme. The protection is against the disk
// being read *outside* the running system — a stolen or decommissioned drive,
// a backup, a copied snapshot. On a host with a TPM that is a strong
// boundary; agentbox uses the host key
// (/var/lib/systemd/credential.secret), which is weaker — key and ciphertext
// sit on the same disk — but predictable. See docs/runbook.md.
package credstore

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Ext is the on-disk suffix for an encrypted credential.
const Ext = ".cred"

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)

// Store encrypts and decrypts credentials in a directory.
type Store struct {
	Dir string // /etc/agentbox/secrets
	Bin string // systemd-creds binary; default "systemd-creds"
}

func (s Store) bin() string {
	if s.Bin == "" {
		return "systemd-creds"
	}
	return s.Bin
}

// Path returns the ciphertext path for a credential name.
func (s Store) Path(name string) string {
	return filepath.Join(s.Dir, name+Ext)
}

// ValidName reports whether name is usable as a credential ID. systemd binds
// the name into the ciphertext, so it must round-trip exactly.
func ValidName(name string) bool {
	return name != "" && len(name) <= 64 && nameRE.MatchString(name)
}

// Put encrypts value under name and writes it atomically, 0600. The value
// never touches the filesystem in plaintext: it is piped to systemd-creds on
// stdin, and only ciphertext is written.
func (s Store) Put(name string, value []byte) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid credential name %q", name)
	}
	// Normalise and validate here rather than in each caller: add-secret and
	// the plaintext migration both land on this path, and having the rules in
	// only one of them is how they drift.
	value = bytes.TrimSpace(value)
	if len(value) == 0 {
		return fmt.Errorf("refusing to store an empty value for %q", name)
	}
	// The value ends up verbatim in an HTTP header. Go rewrites embedded
	// newlines to spaces when writing headers, so a value containing them
	// would be silently corrupted and fail upstream with nothing pointing at
	// the cause.
	for _, b := range value {
		if b < 0x20 || b > 0x7e {
			return fmt.Errorf("value for %q contains a non-printable or non-ASCII byte (0x%02x)", name, b)
		}
	}
	tmp, err := os.CreateTemp(s.Dir, ".cred-*")
	if err != nil {
		return fmt.Errorf("create temp credential: %w", err)
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName) // no-op once renamed

	// --with-key=host, explicitly. The default (auto) binds to the TPM *and*
	// the host key when a TPM is present — man systemd-creds: "both need to
	// be available to decrypt the credential again" — so losing either one
	// destroys every credential, and decryption failure is fatal to unit
	// activation. Since no plaintext copy is kept, that would mean re-issuing
	// every token. The host key alone is predictable, survives firmware and
	// Secure Boot changes, and still makes the ciphertext useless off this
	// host, which is the property this is for. A TPM-backed deployment can
	// opt into stronger binding deliberately; it should not arrive by
	// accident with the brittleness attached.
	//
	// (An earlier revision passed --tpm2-pcrs= and --tpm2-public-key= to tame
	// the auto path. The first is real; the second is a no-op — an empty
	// value parses to "unset", which is exactly what triggers the
	// tpm2-pcr-public-key.pem auto-discovery it was meant to suppress. Both
	// are moot with an explicit key choice.)
	cmd := exec.Command(s.bin(), "encrypt",
		"--name="+name, "--with-key=host", "-", tmpName)
	cmd.Stdin = bytes.NewReader(value)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemd-creds encrypt %q: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	// Verify before installing. Callers delete the operator's only plaintext
	// copy on the strength of this succeeding, so an encrypt that "worked"
	// but does not round-trip must not be allowed to look like success.
	got, err := s.decryptFile(tmpName, name)
	if err != nil {
		return fmt.Errorf("stored credential %q does not decrypt; refusing to install it: %w", name, err)
	}
	if !bytes.Equal(got, value) {
		return fmt.Errorf("stored credential %q did not round-trip intact; refusing to install it", name)
	}
	return os.Rename(tmpName, s.Path(name))
}

// Get decrypts the named credential. Callers must not write the result to
// disk; it exists so setup can derive companions (see config's {basic:...}
// template) without asking the operator to re-enter a token.
func (s Store) Get(name string) ([]byte, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("invalid credential name %q", name)
	}
	return s.decryptFile(s.Path(name), name)
}

// decryptFile decrypts an arbitrary ciphertext path under the given
// credential name. The name is bound into the ciphertext by systemd, so a
// mismatch fails rather than silently returning the value.
func (s Store) decryptFile(path, name string) ([]byte, error) {
	cmd := exec.Command(s.bin(), "decrypt", "--name="+name, path, "-")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("systemd-creds decrypt %q: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Has reports whether a ciphertext file exists for name.
func (s Store) Has(name string) bool {
	if !ValidName(name) {
		return false
	}
	_, err := os.Stat(s.Path(name))
	return err == nil
}

// List returns the names of all stored credentials, sorted, derived from the
// ciphertext filenames. Names only — nothing is decrypted.
func (s Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		name, ok := strings.CutSuffix(e.Name(), Ext)
		if ok && ValidName(name) {
			out = append(out, name)
		}
	}
	sortStrings(out)
	return out, nil
}

// Available reports whether systemd-creds can be used at all.
func (s Store) Available() error {
	if _, err := exec.LookPath(s.bin()); err != nil {
		return fmt.Errorf("%s not found; systemd 250+ is required for encrypted credentials: %w", s.bin(), err)
	}
	return nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
