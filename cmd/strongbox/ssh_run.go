package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/steigr/strongbox-go/pkg/strongbox"
)

var sshCmd = &cobra.Command{
	Use:   "ssh [ssh-flags] user@host [command]",
	Short: "Run ssh with the password fetched from Strongbox",
	Long: `Look up the password for user@host in Strongbox and invoke ssh with it.

All arguments are forwarded to ssh unchanged. Strongbox's own flags (--unlock,
etc.) must be placed before the "ssh" subcommand so they are parsed before
flag parsing is handed over to ssh.

The password is injected via SSH_ASKPASS; it never appears in the process
argument list or in a temp file on disk.`,
	Example: `  strongbox ssh user@host
  strongbox ssh -p 2222 user@host
  strongbox --unlock true ssh user@host ls /tmp`,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		for _, a := range args {
			if a == "--help" || a == "-h" {
				return cmd.Help()
			}
		}

		user, host := findUserHost(args)
		if user == "" || host == "" {
			return fmt.Errorf("no <user>@<host> argument found in: %s", strings.Join(args, " "))
		}

		ensureAutoFillDatabase(client, unlockBehavior)

		result, err := client.Search(host, 0, 100)
		if err != nil {
			fatal("searching Strongbox: %v", err)
		}

		matches := matchCredentials(result.Results, user, host)
		if len(matches) == 0 {
			fatal("no credentials found in Strongbox for %s@%s", user, host)
		}

		best := pickCredential(matches)

		if err := executeSSHWithPassword(args, best.Password); err != nil {
			fatal("%v", err)
		}
		return nil
	},
}


// handleAskpassMode is called at program startup. When the binary is invoked
// as an SSH_ASKPASS helper (signalled by STRONGBOX_SSH_PASSWORD being set) it
// writes the password to w and returns true; the caller should exit 0.
func handleAskpassMode(w io.Writer) bool {
	if p := os.Getenv("STRONGBOX_SSH_PASSWORD"); p != "" {
		fmt.Fprint(w, p)
		return true
	}
	return false
}

// userHostRe matches tokens of the form user@host.
var userHostRe = regexp.MustCompile(`^([^@]+)@([^@]+)$`)

// findUserHost scans args for the first token that matches user@host.
func findUserHost(args []string) (user, host string) {
	for _, arg := range args {
		if m := userHostRe.FindStringSubmatch(arg); m != nil {
			return m[1], m[2]
		}
	}
	return "", ""
}

// matchCredentials returns the subset of creds whose username matches user
// and whose URL or title references host.
func matchCredentials(creds []strongbox.AutoFillCredential, user, host string) []strongbox.AutoFillCredential {
	sshURL := "ssh://" + strings.ToLower(host)
	hostL := strings.ToLower(host)
	var out []strongbox.AutoFillCredential
	for _, c := range creds {
		if !strings.EqualFold(c.Username, user) {
			continue
		}
		urlL := strings.ToLower(c.URL)
		titleL := strings.ToLower(c.Title)
		if strings.Contains(urlL, hostL) ||
			strings.Contains(urlL, sshURL) ||
			strings.Contains(titleL, hostL) {
			out = append(out, c)
		}
	}
	return out
}

// pickCredential returns the most recently modified entry from matches.
func pickCredential(matches []strongbox.AutoFillCredential) strongbox.AutoFillCredential {
	sort.Slice(matches, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339, matches[i].Modified)
		tj, _ := time.Parse(time.RFC3339, matches[j].Modified)
		return ti.After(tj)
	})
	return matches[0]
}

// executeSSHWithPassword runs ssh with args, injecting password via the
// SSH_ASKPASS mechanism. The current binary re-invokes itself as the askpass
// helper when STRONGBOX_SSH_PASSWORD is set, so no temp files are created.
func executeSSHWithPassword(args []string, password string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	cmd := exec.Command("ssh", args...)
	cmd.Env = append(os.Environ(),
		"STRONGBOX_SSH_PASSWORD="+password,
		"SSH_ASKPASS="+exe,
		"DISPLAY=:0",               // required by some ssh versions to use SSH_ASKPASS
		"SSH_ASKPASS_REQUIRE=force", // override TTY detection in OpenSSH ≥ 8.4
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("executing ssh: %w", err)
	}
	return nil
}
