package incus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"agentbox/internal/domain"
)

type controlFake struct {
	containers []domain.Container
	events     *[]string
}

func (c *controlFake) Containers(context.Context) ([]domain.Container, error) {
	return append([]domain.Container(nil), c.containers...), nil
}
func (c *controlFake) AddContainer(_ context.Context, value domain.Container) (domain.Container, error) {
	c.containers = append(c.containers, value)
	return value, nil
}
func (c *controlFake) SetContainerBlocked(_ context.Context, name string, blocked bool) error {
	for i := range c.containers {
		if c.containers[i].Name == name {
			c.containers[i].Blocked = blocked
			if c.events != nil {
				*c.events = append(*c.events, fmt.Sprintf("blocked=%v", blocked))
			}
			return nil
		}
	}
	return errors.New("not found")
}
func (c *controlFake) DeleteContainer(_ context.Context, name string) error {
	for i := range c.containers {
		if c.containers[i].Name == name {
			c.containers = append(c.containers[:i], c.containers[i+1:]...)
			return nil
		}
	}
	return errors.New("not found")
}

type commanderFake struct {
	instances      []instance
	devices        string
	calls          [][]string
	events         *[]string
	failLaunch     bool
	createThenFail bool
	failDevice     bool
}

func (f *commanderFake) Run(args ...string) error {
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(args) >= 4 && args[0] == "config" && args[1] == "device" {
		if f.events != nil {
			*f.events = append(*f.events, "device")
		}
		if f.failDevice {
			return errors.New("device failure")
		}
	}
	if len(args) >= 3 && args[0] == "delete" {
		for i := range f.instances {
			if f.instances[i].Name == args[len(args)-1] {
				f.instances = append(f.instances[:i], f.instances[i+1:]...)
				break
			}
		}
	}
	return nil
}
func (f *commanderFake) RunInput(_ string, args ...string) error { return f.Run(args...) }
func (f *commanderFake) RunStreaming(args ...string) error {
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(args) > 0 && args[0] == "launch" {
		if f.failLaunch {
			if f.createThenFail {
				f.instances = append(f.instances, instance{Name: args[2], Status: "Running", Config: map[string]string{ManagedTag: "true"}})
			}
			return errors.New("launch failure")
		}
		f.instances = append(f.instances, instance{Name: args[2], Status: "Running", Config: map[string]string{ManagedTag: "true"}})
	}
	return nil
}
func (f *commanderFake) Output(args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	return []byte(f.devices), nil
}
func (f *commanderFake) JSON(dst any, _ ...string) error {
	data, err := json.Marshal(f.instances)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

func TestCreateRegistersBeforeLaunchAndRollsBack(t *testing.T) {
	control := &controlFake{}
	commands := &commanderFake{failLaunch: true}
	manager := &Manager{
		Incus: commands, Control: control, SocketDir: "/run/test", SocketWait: time.Millisecond,
		SocketReady: func(path string) bool { return path == "/run/test/dev.sock" },
	}
	err := manager.Create(context.Background(), CreateOptions{Name: "dev", Profile: "prod"})
	if err == nil || !strings.Contains(err.Error(), "launch failure") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(control.containers) != 0 {
		t.Fatalf("registration was not rolled back: %+v", control.containers)
	}
	if len(commands.calls) == 0 || commands.calls[0][0] != "launch" {
		t.Fatalf("launch was not attempted: %v", commands.calls)
	}
}

func TestCreateAppliesDefaultResourceLimits(t *testing.T) {
	control := &controlFake{}
	commands := &commanderFake{}
	manager := &Manager{
		Incus: commands, Control: control, SocketDir: "/run/test",
		SocketReady: func(string) bool { return true },
	}
	if err := manager.Create(context.Background(), CreateOptions{Name: "dev", Profile: "prod"}); err != nil {
		t.Fatal(err)
	}
	if len(commands.calls) == 0 {
		t.Fatal("Incus was not called")
	}
	launch := strings.Join(commands.calls[0], " ")
	for _, expected := range []string{
		"limits.cpu=4", "limits.memory=8GiB", "limits.processes=2048", "root,size=50GiB",
	} {
		if !strings.Contains(launch, expected) {
			t.Fatalf("launch missing %q: %s", expected, launch)
		}
	}
}

func TestCreateCanOmitResourceLimits(t *testing.T) {
	control := &controlFake{}
	commands := &commanderFake{}
	manager := &Manager{
		Incus: commands, Control: control, SocketDir: "/run/test",
		SocketReady: func(string) bool { return true },
	}
	if err := manager.Create(context.Background(), CreateOptions{
		Name: "dev", Profile: "prod", NoResourceLimits: true,
	}); err != nil {
		t.Fatal(err)
	}
	if len(commands.calls) == 0 {
		t.Fatal("Incus was not called")
	}
	launch := strings.Join(commands.calls[0], " ")
	for _, unexpected := range []string{
		"limits.cpu=", "limits.memory=", "limits.processes=", "root,size=",
	} {
		if strings.Contains(launch, unexpected) {
			t.Fatalf("launch unexpectedly contains %q: %s", unexpected, launch)
		}
	}
}

func TestCreateRejectsInvalidResourceLimitsBeforeMutation(t *testing.T) {
	control := &controlFake{}
	commands := &commanderFake{}
	manager := &Manager{Incus: commands, Control: control}
	if err := manager.Create(context.Background(), CreateOptions{Name: "dev", Profile: "prod", Memory: "everything"}); err == nil {
		t.Fatal("invalid memory limit accepted")
	}
	if len(commands.calls) != 0 || len(control.containers) != 0 {
		t.Fatalf("invalid limits mutated state: calls=%v containers=%v", commands.calls, control.containers)
	}
}

func TestCreateRollsBackInstanceCreatedBeforeLaunchError(t *testing.T) {
	control := &controlFake{}
	commands := &commanderFake{failLaunch: true, createThenFail: true}
	manager := &Manager{
		Incus: commands, Control: control, SocketDir: "/run/test", SocketWait: time.Millisecond,
		SocketReady: func(string) bool { return true },
	}
	if err := manager.Create(context.Background(), CreateOptions{Name: "dev", Profile: "prod"}); err == nil {
		t.Fatal("launch failure was accepted")
	}
	if len(commands.instances) != 0 || len(control.containers) != 0 {
		t.Fatalf("rollback left instance=%v containers=%v", commands.instances, control.containers)
	}
}

func TestUnblockRestoresDevicesBeforePublishingState(t *testing.T) {
	var events []string
	control := &controlFake{containers: []domain.Container{{Name: "dev", Profile: "prod", Blocked: true, CreatedAt: time.Now()}}, events: &events}
	commands := &commanderFake{events: &events}
	manager := &Manager{Incus: commands, Control: control, SocketDir: "/run/test"}
	if err := manager.Unblock(context.Background(), "dev"); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0] != "device" || events[1] != "device" || events[2] != "blocked=false" {
		t.Fatalf("unsafe unblock order: %v", events)
	}

	events = nil
	control.containers[0].Blocked = true
	commands.failDevice = true
	if err := manager.Unblock(context.Background(), "dev"); err == nil {
		t.Fatal("device failure was accepted")
	}
	if !control.containers[0].Blocked {
		t.Fatal("device failure published an unblocked state")
	}
}

func TestDestroyRefusesUnmanagedInstance(t *testing.T) {
	commands := &commanderFake{instances: []instance{{Name: "foreign", Config: map[string]string{}}}}
	manager := &Manager{Incus: commands, Control: &controlFake{}}
	if err := manager.Destroy(context.Background(), "foreign"); err == nil {
		t.Fatal("unmanaged instance deletion was accepted")
	}
	for _, call := range commands.calls {
		if len(call) != 0 && call[0] == "delete" {
			t.Fatalf("delete was attempted: %v", call)
		}
	}
}
