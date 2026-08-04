package credstore

import (
	"os"
	"path/filepath"
	"slices"
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
	// The fake encodes rather than encrypts, but it does not write the value
	// verbatim — so this assertion is real: no file anywhere under the store
	// may contain the plaintext.
	data, err := os.ReadFile(s.Path("tok"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("plaintext value written to disk: %q", data)
	}
	if !strings.HasPrefix(string(data), "ENC(tok)\n") {
		t.Fatalf("value was not passed through systemd-creds: %q", data)
	}
}

// TestNameIsBoundToTheCredentialID pins the contract the whole scheme rests
// on: systemd looks the credential up by the ID in LoadCredentialEncrypted=,
// and refuses it if the --name= baked into the ciphertext differs. Passing
// anything but the bare name here (the filename, say) would pass every other
// test and break every real boot.
func TestNameIsBoundToTheCredentialID(t *testing.T) {
	rec := fakebin.New(t, "systemd-creds")
	s := Store{Dir: t.TempDir(), Bin: rec.Bin()}
	_ = s.Put("gh-pat", []byte("v")) // fake records argv; the verify read fails, fine

	var encrypt []string
	for _, c := range rec.Calls() {
		if len(c) > 0 && c[0] == "encrypt" {
			encrypt = c
		}
	}
	if encrypt == nil {
		t.Fatal("no encrypt invocation recorded")
	}
	if !slices.Contains(encrypt, "--name=gh-pat") {
		t.Errorf("encrypt argv must bind the bare credential ID, got %v", encrypt)
	}
	// Sealing to the default PCR 7 would make every credential undecryptable
	// after an unrelated firmware or Secure Boot change, with no plaintext
	// copy left to recover from.
	if !slices.Contains(encrypt, "--tpm2-pcrs=") {
		t.Errorf("encrypt must pin an empty PCR set, got %v", encrypt)
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

// TestPutRefusesToInstallWhatDoesNotDecrypt is the guarantee the plaintext
// migration relies on when it deletes the operator's only copy.
func TestPutRefusesToInstallWhatDoesNotDecrypt(t *testing.T) {
	dir := t.TempDir()
	// A fake that "encrypts" but produces something its own decrypt rejects.
	bin := filepath.Join(t.TempDir(), "systemd-creds")
	script := "#!/bin/sh\nPATH=/usr/bin:/bin\ncase \"$1\" in\n  encrypt) shift; for a in \"$@\"; do case \"$a\" in --*) ;; *) last=$a;; esac; done; cat > /dev/null; echo corrupt > \"$last\" ;;\n  decrypt) echo 'cannot decrypt' >&2; exit 1 ;;\nesac\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	s := Store{Dir: dir, Bin: bin}

	const secret = "irreplaceable-token"
	err := s.Put("tok", []byte(secret))
	if err == nil {
		t.Fatal("Put must fail when the ciphertext does not decrypt")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error message leaks the secret value: %v", err)
	}
	if s.Has("tok") {
		t.Error("a credential that does not decrypt was installed anyway")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("temp file left behind: %v", entries)
	}
}

func TestPutRejectsUnusableValues(t *testing.T) {
	s := newStore(t)
	for _, bad := range [][]byte{
		[]byte("tok\nwith-newline"), // Go rewrites these to spaces in headers
		[]byte("tok\twith-tab"),
		[]byte("tök-non-ascii"),
		[]byte("   "),
	} {
		if err := s.Put("tok", bad); err == nil {
			t.Errorf("Put(%q) should have been rejected", bad)
		}
	}
	// Surrounding whitespace is trimmed rather than rejected.
	if err := s.Put("tok", []byte("  padded-token \n")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("tok")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "padded-token" {
		t.Fatalf("stored %q, want the trimmed value", got)
	}
}
