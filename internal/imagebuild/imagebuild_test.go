package imagebuild

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

type recordedCall struct {
	kind  string
	args  []string
	input string
}

type incusFake struct {
	instances map[string]instance
	calls     []recordedCall
	failMatch string
}

func newIncusFake() *incusFake { return &incusFake{instances: map[string]instance{}} }

func (f *incusFake) Run(args ...string) error {
	f.record("run", "", args)
	if f.fails(args) {
		return errors.New("injected Incus failure")
	}
	if len(args) >= 3 && args[0] == "delete" {
		delete(f.instances, args[len(args)-1])
	}
	if len(args) >= 4 && args[0] == "config" && args[1] == "unset" {
		item := f.instances[args[2]]
		delete(item.Config, args[3])
		f.instances[args[2]] = item
	}
	return nil
}

func (f *incusFake) RunInput(input string, args ...string) error {
	f.record("input", input, args)
	if len(args) >= 3 && args[0] == "init" {
		f.instances[args[2]] = instance{Name: args[2], Status: "Stopped", Config: map[string]string{
			BuilderTag: "true", "cloud-init.user-data": "present",
		}}
	}
	if f.fails(args) {
		return errors.New("injected Incus failure")
	}
	return nil
}

func (f *incusFake) RunStreaming(args ...string) error {
	f.record("stream", "", args)
	if f.fails(args) {
		return errors.New("injected Incus failure")
	}
	if len(args) >= 2 && args[0] == "start" {
		item := f.instances[args[1]]
		item.Status = "Running"
		f.instances[args[1]] = item
	}
	if len(args) >= 2 && args[0] == "stop" {
		item := f.instances[args[1]]
		item.Status = "Stopped"
		f.instances[args[1]] = item
	}
	return nil
}

func (f *incusFake) Output(args ...string) ([]byte, error) {
	f.record("output", "", args)
	return nil, errors.New("unexpected Output call")
}

func (f *incusFake) JSON(dst any, args ...string) error {
	f.record("json", "", args)
	items := make([]instance, 0, len(f.instances))
	for _, item := range f.instances {
		items = append(items, item)
	}
	data, err := json.Marshal(items)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

func (f *incusFake) record(kind, input string, args []string) {
	f.calls = append(f.calls, recordedCall{kind: kind, input: input, args: append([]string(nil), args...)})
}
func (f *incusFake) fails(args []string) bool {
	return f.failMatch != "" && strings.Contains(strings.Join(args, " "), f.failMatch)
}

func TestBuildUsesIncusCloudInitWorkflowAndCleansBuilder(t *testing.T) {
	fake := newIncusFake()
	definition := []byte("config:\n  cloud-init.user-data: test\n")
	err := Run(Options{Alias: "test-image", Source: "images:test/cloud", Incus: fake, Definition: definition, Out: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := fake.instances[BuilderName]; exists {
		t.Fatal("builder survived successful build")
	}

	wantStages := []string{"init", "start", "cloud-init", "verify", "unset", "clean", "stop", "publish", "delete"}
	var gotStages []string
	for _, call := range fake.calls {
		joined := strings.Join(call.args, " ")
		switch {
		case len(call.args) > 0 && call.args[0] == "init":
			gotStages = append(gotStages, "init")
			if call.input != string(definition) {
				t.Fatal("embedded definition was not passed to incus init")
			}
			if !reflect.DeepEqual(call.args, []string{"init", "images:test/cloud", BuilderName}) {
				t.Fatalf("init args: %v", call.args)
			}
		case len(call.args) > 0 && call.args[0] == "start":
			gotStages = append(gotStages, "start")
		case strings.Contains(joined, "cloud-init status"):
			gotStages = append(gotStages, "cloud-init")
		case strings.Contains(joined, "missing expected command"):
			gotStages = append(gotStages, "verify")
		case strings.HasPrefix(joined, "config unset"):
			gotStages = append(gotStages, "unset")
		case strings.Contains(joined, "cloud-init clean"):
			gotStages = append(gotStages, "clean")
		case len(call.args) > 0 && call.args[0] == "stop":
			gotStages = append(gotStages, "stop")
		case len(call.args) > 0 && call.args[0] == "publish":
			gotStages = append(gotStages, "publish")
			if !strings.Contains(joined, "--alias test-image --reuse") {
				t.Fatalf("publish did not reuse requested alias: %v", call.args)
			}
		case len(call.args) > 0 && call.args[0] == "delete":
			gotStages = append(gotStages, "delete")
		}
	}
	if !reflect.DeepEqual(gotStages, wantStages) {
		t.Fatalf("stages = %v, want %v", gotStages, wantStages)
	}
}

func TestIndependentVerificationExecutesPinnedAgentCLIs(t *testing.T) {
	for _, required := range []string{
		`test "$(node --version)" = 'v24.19.0'`,
		`test "$(npm --version)" = '11.17.0'`,
		`test "$(readlink "$(command -v fd)")" = '/usr/bin/fdfind'`,
		`dpkg-query --show fd-find`,
		`fd --version`,
		`claude --version | grep -F '2.1.220'`,
		`codex --version | grep -F '0.145.0'`,
		`pi --version | grep -F '0.82.1'`,
		`system URL rewrites must not change canonical repository metadata`,
		`test -x /usr/local/lib/agentbox/git-core/git-remote-https`,
		`GIT_EXEC_PATH=/usr/local/lib/agentbox/git-core git --exec-path`,
	} {
		if !strings.Contains(verifyScript, required) {
			t.Fatalf("verification script does not execute %q", required)
		}
	}
}

func TestBuildRefusesForeignBuilder(t *testing.T) {
	fake := newIncusFake()
	fake.instances[BuilderName] = instance{Name: BuilderName, Config: map[string]string{}}
	err := Run(Options{Incus: fake, Definition: []byte("config: {}\n"), Out: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "not an agentbox image builder") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 1 || fake.calls[0].kind != "json" {
		t.Fatalf("foreign instance was mutated: %+v", fake.calls)
	}
}

func TestBuildDeletesStaleOwnedBuilderAndFailureResult(t *testing.T) {
	fake := newIncusFake()
	fake.instances[BuilderName] = instance{Name: BuilderName, Config: map[string]string{BuilderTag: "true"}}
	fake.failMatch = "cloud-init status"
	err := Run(Options{Incus: fake, Definition: []byte("config: {}\n"), Out: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "cloud-init provisioning failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, exists := fake.instances[BuilderName]; exists {
		t.Fatal("failed build was not cleaned up")
	}
	deletes := 0
	for _, call := range fake.calls {
		if len(call.args) > 0 && call.args[0] == "delete" {
			deletes++
		}
	}
	if deletes != 2 {
		t.Fatalf("delete calls = %d, want stale + failed builders", deletes)
	}
}

func TestInitFailureAfterCreationStillCleansOwnedBuilder(t *testing.T) {
	fake := newIncusFake()
	fake.failMatch = "init images:test/cloud"
	err := Run(Options{Source: "images:test/cloud", Incus: fake, Definition: []byte("config: {}\n"), Out: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "create builder") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, exists := fake.instances[BuilderName]; exists {
		t.Fatal("partially created builder was not cleaned up")
	}
}

func TestKeepBuilderIsExplicit(t *testing.T) {
	fake := newIncusFake()
	if err := Run(Options{Incus: fake, Definition: []byte("config: {}\n"), Keep: true, Out: io.Discard}); err != nil {
		t.Fatal(err)
	}
	if item, exists := fake.instances[BuilderName]; !exists || item.Status != "Stopped" {
		t.Fatalf("builder was not retained stopped: %+v, exists=%v", item, exists)
	}
}
