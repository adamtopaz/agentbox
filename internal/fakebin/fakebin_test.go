package fakebin

import (
	"os/exec"
	"reflect"
	"testing"
)

func TestRecordsAndResponds(t *testing.T) {
	f := New(t, "fake")

	out, err := exec.Command(f.Bin(), "list", "--format", "json").Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "" {
		t.Fatalf("default stdout should be empty, got %q", out)
	}

	f.Respond("version", 0, "v1.2.3\n")
	f.RespondStderr("boom now", 3, "", "it broke\n")

	out, err = exec.Command(f.Bin(), "version").Output()
	if err != nil || string(out) != "v1.2.3\n" {
		t.Fatalf("scripted stdout: out=%q err=%v", out, err)
	}

	cmd := exec.Command(f.Bin(), "boom", "now", "please")
	stderr, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected scripted failure")
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 3 {
		t.Fatalf("exit code: %v", err)
	}
	if string(stderr) != "it broke\n" {
		t.Fatalf("stderr = %q", stderr)
	}

	want := [][]string{
		{"list", "--format", "json"},
		{"version"},
		{"boom", "now", "please"},
	}
	if got := f.Calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Calls = %v, want %v", got, want)
	}

	f.Reset()
	if got := f.Calls(); got != nil {
		t.Fatalf("Calls after Reset = %v", got)
	}
}
