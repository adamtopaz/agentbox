// Package fakebin provides a generic argv-recording fake executable for
// tests, standing in for the real `incus` and `caddy` binaries. It records
// every invocation and can be scripted to fail or emit stdout for calls whose
// argv matches a prefix.
package fakebin

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type Fake struct {
	t     *testing.T
	bin   string
	calls string
	rules string
}

// New creates a fake executable named name in a temp dir.
func New(t *testing.T, name string) *Fake {
	t.Helper()
	dir := t.TempDir()
	f := &Fake{
		t:     t,
		bin:   filepath.Join(dir, name),
		calls: filepath.Join(dir, "calls.log"),
		rules: filepath.Join(dir, "rules.txt"),
	}
	script := `#!/bin/sh
CALLS='` + f.calls + `'
RULES='` + f.rules + `'
{
  first=1
  for a in "$@"; do
    if [ $first -eq 1 ]; then first=0; printf '%s' "$a"; else printf '\t%s' "$a"; fi
  done
  printf '\n'
} >> "$CALLS"
if [ -f "$RULES" ]; then
  while IFS='|' read -r match code out errout; do
    case "$*" in
      "$match"*)
        if [ -n "$out" ]; then printf '%s' "$out" | base64 -d; fi
        if [ -n "$errout" ]; then printf '%s' "$errout" | base64 -d >&2; fi
        exit "$code"
        ;;
    esac
  done < "$RULES"
fi
exit 0
`
	if err := os.WriteFile(f.bin, []byte(script), 0o755); err != nil {
		t.Fatalf("fakebin: %v", err)
	}
	return f
}

// Bin returns the path of the fake executable.
func (f *Fake) Bin() string { return f.bin }

// Respond makes invocations whose space-joined argv starts with match exit
// with code after printing stdout. Rules are consulted in the order added;
// unmatched calls succeed silently.
func (f *Fake) Respond(match string, code int, stdout string) {
	f.RespondStderr(match, code, stdout, "")
}

// RespondStderr is Respond with stderr output as well.
func (f *Fake) RespondStderr(match string, code int, stdout, stderr string) {
	f.t.Helper()
	enc := func(s string) string {
		if s == "" {
			return ""
		}
		return base64.StdEncoding.EncodeToString([]byte(s))
	}
	line := fmt.Sprintf("%s|%d|%s|%s\n", match, code, enc(stdout), enc(stderr))
	fh, err := os.OpenFile(f.rules, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		f.t.Fatalf("fakebin: %v", err)
	}
	defer fh.Close()
	if _, err := fh.WriteString(line); err != nil {
		f.t.Fatalf("fakebin: %v", err)
	}
}

// Calls returns the argv (excluding argv[0]) of every invocation so far.
func (f *Fake) Calls() [][]string {
	f.t.Helper()
	data, err := os.ReadFile(f.calls)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		f.t.Fatalf("fakebin: %v", err)
	}
	var out [][]string
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			out = append(out, []string{})
			continue
		}
		out = append(out, strings.Split(line, "\t"))
	}
	return out
}

// Reset clears recorded calls (rules are kept).
func (f *Fake) Reset() {
	f.t.Helper()
	if err := os.Remove(f.calls); err != nil && !os.IsNotExist(err) {
		f.t.Fatalf("fakebin: %v", err)
	}
}

// SystemdCreds writes a stand-in for systemd-creds that reversibly wraps a
// value instead of encrypting it, so tests can exercise the credential flow
// without root or a TPM. It binds the --name= into the wrapper exactly as the
// real tool binds it into the ciphertext, so a credential cannot be decrypted
// under the wrong name.
func SystemdCreds(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "systemd-creds")
	// Sets its own PATH: callers null out PATH to keep LookPath deterministic.
	// Format is a header line naming the credential, then the value, so the
	// name binding can be checked exactly rather than by pattern.
	script := `#!/bin/sh
PATH=/usr/bin:/bin
op=$1; shift
name=""; args=""
for a in "$@"; do
  case "$a" in
    --name=*) name=${a#--name=} ;;
    --*) ;;
    *) args="$args $a" ;;
  esac
done
set -- $args
case "$op" in
  encrypt) { printf 'ENC(%s)\n' "$name"; cat; } > "$2" ;;
  decrypt)
    read -r hdr < "$1"
    if [ "$hdr" != "ENC($name)" ]; then
      echo "credential name mismatch: file has $hdr, asked for $name" >&2
      exit 1
    fi
    tail -n +2 "$1"
    ;;
  *) echo "unknown op $op" >&2; exit 2 ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("fakebin: %v", err)
	}
	return bin
}
