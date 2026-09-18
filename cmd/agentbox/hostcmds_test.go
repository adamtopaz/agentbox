package main

import (
	"context"
	"slices"
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

func TestHostRunUsage(t *testing.T) {
	for _, args := range [][]string{{"run"}, {"run", "--profile", "prod"}, {"run", "--profile", "prod", "--"}, {"run", "--profile", "prod", ""}} {
		_, err := parseHostArgs(args)
		if err == nil || !strings.Contains(err.Error(), "COMMAND [ARGS...]") {
			t.Errorf("%q usage error = %v", args, err)
		}
	}
}

func TestParseHostArgs(t *testing.T) {
	cases := []struct {
		args    []string
		program string
		rest    []string
		gitBin  string
	}{
		{[]string{"run", "--profile", "prod", "--", "python3", "agent.py"}, "python3", []string{"agent.py"}, "git"},
		{[]string{"run", "--profile", "prod", "python3", "agent.py"}, "python3", []string{"agent.py"}, "git"},
		{[]string{"run", "--profile", "prod", "prog", "--profile", "other", "--git-bin", "x"}, "prog", []string{"--profile", "other", "--git-bin", "x"}, "git"},
		{[]string{"run", "--profile", "prod", "--", "--dashed", "a"}, "--dashed", []string{"a"}, "git"},
		{[]string{"run", "--profile", "prod", "--", "prog", "--", "b"}, "prog", []string{"--", "b"}, "git"},
		{[]string{"run", "--git-bin", "/opt/git", "--profile", "prod", "prog"}, "prog", nil, "/opt/git"},
		{[]string{"claude", "--profile", "prod", "--", "-p", "hi"}, "claude", []string{"-p", "hi"}, "git"},
		{[]string{"codex", "--profile", "prod", "--codex-bin", "/opt/codex", "exec", "x"}, "/opt/codex", []string{"exec", "x"}, "git"},
	}
	for _, tc := range cases {
		got, err := parseHostArgs(tc.args)
		if err != nil {
			t.Errorf("%q: %v", tc.args, err)
			continue
		}
		if got.profile != "prod" || got.program != tc.program || !slices.Equal(got.args, tc.rest) || got.gitBin != tc.gitBin {
			t.Errorf("%q: got %+v", tc.args, got)
		}
	}
}

func TestParseHostArgsExplainsDashedProgram(t *testing.T) {
	_, err := parseHostArgs([]string{"run", "--profile", "prod", "--dashed"})
	if err == nil || !strings.Contains(err.Error(), "must follow '--'") {
		t.Fatalf("unexpected error: %v", err)
	}
}
