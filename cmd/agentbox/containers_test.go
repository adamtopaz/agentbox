package main

import (
	"context"
	"strings"
	"testing"
)

func TestContainerCreateRejectsNoLimitsWithIndividualLimit(t *testing.T) {
	err := cmdContainer(context.Background(), nil, []string{
		"create", "--scope", "test", "--configure", "none",
		"--no-resource-limits", "--cpus", "2", "dev",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined with --cpus") {
		t.Fatalf("unexpected error: %v", err)
	}
}
