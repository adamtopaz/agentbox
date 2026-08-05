package main

import (
	"context"
	"strings"
	"testing"
)

func TestContainerCreateRejectsNoLimitsWithIndividualLimit(t *testing.T) {
	err := cmdContainer(context.Background(), nil, []string{
		"create", "--profile", "test",
		"--no-resource-limits", "--cpus", "2", "dev",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined with --cpus") {
		t.Fatalf("unexpected error: %v", err)
	}
}
