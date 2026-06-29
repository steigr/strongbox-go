package main

import (
	"testing"
)

// TestCommandStructure verifies the top-level command names after the
// ssh/ssh-agent refactor: `ssh` is now the direct run command and
// `ssh-agent` is a sibling top-level command (not a sub-sub-command).
func TestCommandStructure_SSHIsTopLevel(t *testing.T) {
	if sshCmd.Use != "ssh [ssh-flags] user@host [command]" {
		t.Errorf("sshCmd.Use = %q, expected ssh as top-level run command", sshCmd.Use)
	}
	// sshCmd must not have subcommands (it IS the run command).
	if len(sshCmd.Commands()) != 0 {
		names := make([]string, 0, len(sshCmd.Commands()))
		for _, c := range sshCmd.Commands() {
			names = append(names, c.Use)
		}
		t.Errorf("sshCmd should have no subcommands, got: %v", names)
	}
}

func TestCommandStructure_SSHAgentIsTopLevel(t *testing.T) {
	if sshAgentCmd.Use != "ssh-agent" {
		t.Errorf("sshAgentCmd.Use = %q, want ssh-agent", sshAgentCmd.Use)
	}
	// ssh-agent must have exactly the load-key subcommand.
	cmds := sshAgentCmd.Commands()
	if len(cmds) != 1 {
		t.Fatalf("ssh-agent should have 1 subcommand, got %d", len(cmds))
	}
	if cmds[0].Use != "load-key <entry-name>" {
		t.Errorf("ssh-agent subcommand Use = %q, want load-key <entry-name>", cmds[0].Use)
	}
}

func TestCommandStructure_SSHAgentHasNoSSHParent(t *testing.T) {
	// sshAgentCmd must NOT be a child of sshCmd.
	for _, sub := range sshCmd.Commands() {
		if sub == sshAgentCmd {
			t.Error("sshAgentCmd must not be a subcommand of sshCmd")
		}
	}
}
