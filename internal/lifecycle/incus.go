package lifecycle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Incus is a thin wrapper over the incus CLI. Errors always carry incus's
// stderr text.
type Incus struct {
	Bin string // default "incus"
}

func (i Incus) bin() string {
	if i.Bin == "" {
		return "incus"
	}
	return i.Bin
}

// Run executes incus with the given args, discarding stdout.
func (i Incus) Run(args ...string) error {
	cmd := exec.Command(i.bin(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("incus %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// RunStreaming executes incus with stdout/stderr attached to the operator's
// terminal (image builds, long launches).
func (i Incus) RunStreaming(args ...string) error {
	cmd := exec.Command(i.bin(), args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("incus %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// Output executes incus and returns stdout.
func (i Incus) Output(args ...string) ([]byte, error) {
	cmd := exec.Command(i.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("incus %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// JSON executes incus and unmarshals its stdout into v.
func (i Incus) JSON(v any, args ...string) error {
	out, err := i.Output(args...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("incus %s: bad JSON: %w", strings.Join(args, " "), err)
	}
	return nil
}
