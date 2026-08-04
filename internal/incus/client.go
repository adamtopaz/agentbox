// Package incus contains the privileged lifecycle adapter. It runs in the CLI
// process, not agentboxd, so the network-facing daemon never receives Incus
// administrative authority.
package incus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type Client struct {
	Bin      string
	Out, Err io.Writer
}

// Commander is the narrow Incus boundary used by lifecycle orchestration.
// Client is the production CLI adapter; tests and future native adapters can
// implement the same operations without changing lifecycle policy.
type Commander interface {
	Run(...string) error
	RunInput(string, ...string) error
	RunStreaming(...string) error
	Output(...string) ([]byte, error)
	JSON(any, ...string) error
}

func (c Client) binary() string {
	if c.Bin != "" {
		return c.Bin
	}
	return "incus"
}
func (c Client) stderr() io.Writer {
	if c.Err != nil {
		return c.Err
	}
	return os.Stderr
}
func (c Client) stdout() io.Writer {
	if c.Out != nil {
		return c.Out
	}
	return os.Stdout
}

func (c Client) Run(args ...string) error {
	cmd := exec.Command(c.binary(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("incus %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (c Client) RunInput(input string, args ...string) error {
	cmd := exec.Command(c.binary(), args...)
	cmd.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("incus %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (c Client) RunStreaming(args ...string) error {
	cmd := exec.Command(c.binary(), args...)
	cmd.Stdout = c.stdout()
	cmd.Stderr = c.stderr()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("incus %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func (c Client) Output(args ...string) ([]byte, error) {
	cmd := exec.Command(c.binary(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("incus %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (c Client) JSON(dst any, args ...string) error {
	data, err := c.Output(args...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("incus %s returned invalid JSON: %w", strings.Join(args, " "), err)
	}
	return nil
}
