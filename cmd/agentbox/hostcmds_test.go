package main

import (
	"context"
	"strings"
	"testing"
)

func TestHostAgentUsage(t *testing.T) {
	for _, agent := range []string{"claude", "codex", "pi"} {
		err := cmdHost(context.Background(), nil, "", []string{agent})
		if err == nil || !strings.Contains(err.Error(), "--"+agent+"-bin PATH") {
			t.Errorf("%s usage error = %v", agent, err)
		}
	}
}

func TestHostRejectsUnknownAgent(t *testing.T) {
	err := cmdHost(context.Background(), nil, "", []string{"other"})
	if err == nil || !strings.Contains(err.Error(), "unknown host agent") {
		t.Fatalf("unexpected error: %v", err)
	}
}
