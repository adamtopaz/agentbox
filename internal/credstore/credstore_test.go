package credstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentbox/internal/fakebin"
)

func newStore(t *testing.T) Store {
	t.Helper()
	return Store{Dir: t.TempDir(), Bin: fakebin.SystemdCreds(t)}
}

func TestPutGetRoundTrip(t *testing.T) {
	s := newStore(t)
	if err := s.Put("cf-aig-token", []byte("dummy-value")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("cf-aig-token")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "dummy-value" {
		t.Fatalf("round trip = %q", got)
	}
}

// TestNoPlaintextOnDisk is the point of the whole package.
func TestNoPlaintextOnDisk(t *testing.T) {
	s := newStore(t)
	const secret = "super-secret-value-9f2a"
	if err := s.Put("tok", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one file (no temp left behind), got %v", entries)
	}
	if entries[0].Name() != "tok"+Ext {
		t.Fatalf("unexpected filename %q", entries[0].Name())
	}
	fi, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("ciphertext mode = %v, want 0600", fi.Mode().Perm())
	}
	// The fake wraps rather than encrypts, so assert on the wrapper marker:
	// with a real systemd-creds the value would be ciphertext. What matters
	// here is that Put never wrote the raw value to a file of its own.
	data, err := os.ReadFile(s.Path("tok"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "ENC(tok)\n") {
		t.Fatalf("value was not passed through systemd-creds: %q", data)
	}
}

func TestNameBinding(t *testing.T) {
	s := newStore(t)
	if err := s.Put("a", []byte("v")); err != nil {
		t.Fatal(err)
	}
	// The name is bound into the ciphertext; decrypting under another name
	// must not silently yield the value.
	if err := os.Rename(s.Path("a"), s.Path("b")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("b")
	if err == nil && string(got) == "v" {
		t.Fatal("a credential decrypted under the wrong name")
	}
}

func TestPutRejects(t *testing.T) {
	s := newStore(t)
	if err := s.Put("", []byte("v")); err == nil {
		t.Error("empty name accepted")
	}
	if err := s.Put("Bad Name", []byte("v")); err == nil {
		t.Error("invalid name accepted")
	}
	if err := s.Put("ok", nil); err == nil {
		t.Error("empty value accepted")
	}
}

func TestHasAndList(t *testing.T) {
	s := newStore(t)
	for _, n := range []string{"zeta", "alpha", "gh-pat.basic"} {
		if err := s.Put(n, []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	// Junk in the directory must not surface as a credential.
	if err := os.WriteFile(filepath.Join(s.Dir, "README"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "gh-pat.basic", "zeta"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("List = %v, want %v", got, want)
	}
	if !s.Has("alpha") || s.Has("nope") {
		t.Fatal("Has is wrong")
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"a", "cf-aig-token", "gh-pat.basic", "x9"} {
		if !ValidName(n) {
			t.Errorf("ValidName(%q) = false", n)
		}
	}
	for _, n := range []string{"", "-a", ".a", "A", "a b", "a/b", strings.Repeat("a", 65)} {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true", n)
		}
	}
}
