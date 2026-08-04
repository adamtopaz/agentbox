package incus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"agentbox/internal/domain"
)

const (
	DefaultImage  = "agentbox-base"
	TCPDevice     = "agentbox-proxy"
	UnixDevice    = "agentbox-socket"
	ContainerTCP  = "tcp:127.0.0.1:8787"
	ContainerUnix = "/run/agentbox.sock"
	ManagedTag    = "user.agentbox"
)

type Control interface {
	Containers(context.Context) ([]domain.Container, error)
	AddContainer(context.Context, domain.Container) (domain.Container, error)
	SetContainerBlocked(context.Context, string, bool) error
	DeleteContainer(context.Context, string) error
}

type Manager struct {
	Incus       Commander
	Control     Control
	SocketDir   string
	Image       string
	SocketWait  time.Duration
	SocketReady func(string) bool
	Out         io.Writer
}

type CreateOptions struct{ Name, Scope, ConfigureScript string }

func (m *Manager) Create(ctx context.Context, options CreateOptions) error {
	container := domain.Container{Name: options.Name, Scope: options.Scope, CreatedAt: time.Now().UTC()}
	if err := domain.ValidateContainer(container); err != nil {
		return err
	}
	managed, exists, err := m.instanceManaged(options.Name)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("incus instance %q already exists (managed=%v)", options.Name, managed)
	}
	if _, err := m.Control.AddContainer(ctx, container); err != nil {
		return err
	}
	rollback := func(cause error) error {
		// A CLI launch can fail after Incus created the instance (for example,
		// if the client loses its connection while waiting for the operation).
		// Re-query ownership instead of trusting the command's exit status.
		managed, exists, lookupErr := m.instanceManaged(options.Name)
		if lookupErr != nil {
			fmt.Fprintf(m.out(), "warning: rollback could not inspect %s: %v\n", options.Name, lookupErr)
		} else if exists && managed {
			if err := m.Incus.Run("delete", "--force", options.Name); err != nil {
				fmt.Fprintf(m.out(), "warning: rollback could not delete %s: %v\n", options.Name, err)
			}
		} else if exists {
			fmt.Fprintf(m.out(), "warning: rollback found non-agentbox instance %s and left it untouched\n", options.Name)
		}
		if err := m.Control.DeleteContainer(ctx, options.Name); err != nil {
			fmt.Fprintf(m.out(), "warning: rollback could not unregister %s: %v\n", options.Name, err)
		}
		return cause
	}
	if err := m.waitForSocket(options.Name); err != nil {
		return rollback(err)
	}
	image := m.Image
	if image == "" {
		image = DefaultImage
	}
	if err := m.Incus.RunStreaming("launch", image, options.Name, "-c", ManagedTag+"=true", "-c", "boot.autostart=true"); err != nil {
		return rollback(err)
	}
	for _, args := range m.deviceArgs(options.Name) {
		if err := m.Incus.Run(args...); err != nil {
			return rollback(err)
		}
	}
	if options.ConfigureScript != "" {
		if err := m.Incus.RunInput(options.ConfigureScript, "exec", options.Name, "--", "sh", "-s"); err != nil {
			return rollback(err)
		}
	}
	fmt.Fprintf(m.out(), "container %q ready in scope %q; enter it with: agentbox container shell %s\n", options.Name, options.Scope, options.Name)
	return nil
}

func (m *Manager) Destroy(ctx context.Context, name string) error {
	if !domain.ValidName(name) {
		return fmt.Errorf("invalid container name %q", name)
	}
	containers, err := m.Control.Containers(ctx)
	if err != nil {
		return err
	}
	tracked := false
	for _, c := range containers {
		if c.Name == name {
			tracked = true
			break
		}
	}
	managed, exists, err := m.instanceManaged(name)
	if err != nil {
		return err
	}
	if exists && !managed {
		return fmt.Errorf("incus instance %q is not agentbox-managed; refusing to delete it", name)
	}
	if !tracked && !exists {
		return fmt.Errorf("unknown container %q", name)
	}
	if exists {
		if err := m.Incus.Run("delete", "--force", name); err != nil && !isNotFound(err) {
			return err
		}
	}
	if tracked {
		if err := m.Control.DeleteContainer(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Block(ctx context.Context, name string, hard bool) error {
	if err := m.Control.SetContainerBlocked(ctx, name, true); err != nil {
		return err
	}
	if !hard {
		fmt.Fprintf(m.out(), "blocked %q: new requests receive 403\n", name)
		return nil
	}
	var errs []error
	for _, device := range []string{TCPDevice, UnixDevice} {
		if err := m.Incus.Run("config", "device", "remove", name, device); err != nil && !isNotFound(err) {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return fmt.Errorf("container is blocked but a proxy device could not be removed: %w", errors.Join(errs...))
	}
	fmt.Fprintf(m.out(), "blocked %q and severed its proxy devices\n", name)
	return nil
}

func (m *Manager) Unblock(ctx context.Context, name string) error {
	containers, err := m.Control.Containers(ctx)
	if err != nil {
		return err
	}
	tracked := false
	for _, container := range containers {
		if container.Name == name {
			tracked = true
			break
		}
	}
	if !tracked {
		return fmt.Errorf("unknown container %q", name)
	}
	// Restore the transport while the daemon still returns 403, then publish
	// the unblocked state last. A partial device failure therefore fails closed.
	devices, err := m.Incus.Output("config", "device", "list", name)
	if err != nil {
		return err
	}
	for _, args := range m.deviceArgs(name) {
		device := args[4]
		if containsLine(string(devices), device) {
			continue
		}
		if err := m.Incus.Run(args...); err != nil {
			return err
		}
	}
	if err := m.Control.SetContainerBlocked(ctx, name, false); err != nil {
		return err
	}
	fmt.Fprintf(m.out(), "unblocked %q\n", name)
	return nil
}

type Row struct {
	Name, Scope, Incus string
	Blocked, Socket    bool
	CreatedAt          time.Time
}

type instance struct {
	Name   string            `json:"name"`
	Status string            `json:"status"`
	Config map[string]string `json:"config"`
}

func (m *Manager) List(ctx context.Context) ([]Row, error) {
	containers, err := m.Control.Containers(ctx)
	if err != nil {
		return nil, err
	}
	var instances []instance
	if err := m.Incus.JSON(&instances, "list", "--format", "json"); err != nil {
		return nil, err
	}
	managed := map[string]instance{}
	for _, instance := range instances {
		if instance.Config[ManagedTag] == "true" {
			managed[instance.Name] = instance
		}
	}
	seen := map[string]bool{}
	var rows []Row
	for _, c := range containers {
		row := Row{Name: c.Name, Scope: c.Scope, Blocked: c.Blocked, CreatedAt: c.CreatedAt, Incus: "MISSING!", Socket: m.socketLive(c.Name)}
		if instance, ok := managed[c.Name]; ok {
			row.Incus = instance.Status
		}
		rows = append(rows, row)
		seen[c.Name] = true
	}
	for name, instance := range managed {
		if !seen[name] {
			rows = append(rows, Row{Name: name, Incus: instance.Status + " (untracked!)"})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

func (m *Manager) deviceArgs(name string) [][]string {
	socket := m.socketPath(name)
	return [][]string{
		{"config", "device", "add", name, TCPDevice, "proxy", "listen=" + ContainerTCP, "connect=unix:" + socket, "bind=instance"},
		{"config", "device", "add", name, UnixDevice, "proxy", "listen=unix:" + ContainerUnix, "connect=unix:" + socket, "bind=instance", "mode=0666"},
	}
}

func (m *Manager) socketPath(name string) string {
	return strings.TrimSuffix(m.SocketDir, "/") + "/" + name + ".sock"
}
func (m *Manager) waitForSocket(name string) error {
	timeout := m.SocketWait
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		if m.socketReady(m.socketPath(name)) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("daemon did not serve %s within %s", m.socketPath(name), timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func (m *Manager) socketReady(path string) bool {
	if m.SocketReady != nil {
		return m.SocketReady(path)
	}
	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
func (m *Manager) socketLive(name string) bool {
	return m.socketReady(m.socketPath(name))
}
func (m *Manager) out() io.Writer {
	if m.Out != nil {
		return m.Out
	}
	return os.Stdout
}

func (m *Manager) instanceManaged(name string) (bool, bool, error) {
	var instances []instance
	if err := m.Incus.JSON(&instances, "list", "--format", "json"); err != nil {
		return false, false, err
	}
	for _, instance := range instances {
		if instance.Name == name {
			return instance.Config[ManagedTag] == "true", true, nil
		}
	}
	return false, false, nil
}

func containsLine(value, want string) bool {
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}
func isNotFound(err error) bool {
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "not found") || strings.Contains(value, "doesn't exist") || strings.Contains(value, "does not exist")
}
