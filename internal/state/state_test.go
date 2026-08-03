package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidName(t *testing.T) {
	valid := []string{"a", "foo", "foo-bar", "x1", "a1-b2"}
	// Rejections marked (incus) would be accepted by agentbox but refused by
	// `incus launch` afterwards — after the state file was written and Caddy
	// reloaded — so they must fail here instead.
	invalid := []string{"", "-a", "A", "foo_bar", "foo.bar", "foo bar", ReservedName,
		"0abc", // (incus) no leading digit
		"foo-", // (incus) no trailing dash
		"averyveryveryveryveryveryveryveryveryveryveryverylongname-over63chars"}
	for _, n := range valid {
		if !ValidName(n) {
			t.Errorf("ValidName(%q) = false, want true", n)
		}
	}
	for _, n := range invalid {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true, want false", n)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := Container{Name: "foo", Created: time.Now().UTC().Truncate(time.Second)}
	if err := d.Put(c); err != nil {
		t.Fatal(err)
	}
	got, found, err := d.Get("foo")
	if err != nil || !found {
		t.Fatalf("Get: %v found=%v", err, found)
	}
	if got != c {
		t.Fatalf("got %+v want %+v", got, c)
	}

	got.Blocked = true
	if err := d.Put(got); err != nil {
		t.Fatal(err)
	}
	got2, _, _ := d.Get("foo")
	if !got2.Blocked {
		t.Fatal("blocked flag lost")
	}

	if err := d.Remove("foo"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := d.Get("foo"); found {
		t.Fatal("still found after Remove")
	}
	if err := d.Remove("foo"); err != nil {
		t.Fatalf("Remove must be idempotent: %v", err)
	}
}

func TestListSkipsGarbage(t *testing.T) {
	base := t.TempDir()
	d, err := Open(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Put(Container{Name: "good", Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// Garbage that must never surface as containers (or worse, sockets):
	junk := map[string]string{
		"README":               "hi",
		".tmp-1234":            "partial",
		"Bad_Name.json":        `{"name":"Bad_Name"}`,
		"notjson.json":         "{{{{",
		"mismatch.json":        `{"name":"other"}`,
		ReservedName + ".json": `{"name":"` + ReservedName + `"}`,
	}
	for name, content := range junk {
		if err := os.WriteFile(filepath.Join(d.Path(), name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	list, err := d.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "good" {
		t.Fatalf("List = %+v, want just 'good'", list)
	}
}

func TestListSorted(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"zeta", "alpha", "mid"} {
		if err := d.Put(Container{Name: n, Created: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := d.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].Name != "alpha" || list[1].Name != "mid" || list[2].Name != "zeta" {
		t.Fatalf("not sorted: %+v", list)
	}
}
