package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{7}, 32)
	s, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("plain-secret-value")
	if err := s.Set("token", plaintext); err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, "token.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, plaintext) {
		t.Fatal("plaintext appeared on disk")
	}
	loaded, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := loaded.Resolve("token")
	if !ok || !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, %v", got, ok)
	}
	got[0] = 'X'
	again, _ := loaded.Resolve("token")
	if again[0] == 'X' {
		t.Fatal("Resolve exposed internal memory")
	}
	if err := loaded.Delete("token"); err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Resolve("token"); ok {
		t.Fatal("deleted key remains")
	}
}

func TestWrongKeyAndTamperingFail(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{1}, 32)
	s, _ := Open(dir, key)
	if err := s.Set("token", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Fatal("wrong key decrypted store")
	}
	path := filepath.Join(dir, "token.json")
	data, _ := os.ReadFile(path)
	data[len(data)/2] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, key); err == nil {
		t.Fatal("tampered envelope loaded")
	}
}
