package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [ssh-args...] <user>@<host>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s user@host\n", os.Args[0])
		os.Exit(1)
	}

	// 1. Find <user>@<host> in arguments
	user, host := findUserHost(os.Args[1:])
	if user == "" || host == "" {
		log.Fatal("Could not find <user>@<host> in arguments")
	}

	// 2. Initialize Strongbox client
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatalf("Error creating Strongbox client: %v", err)
	}

	// 3. Search for credentials
	// We search for the host as it's more specific usually
	searchResult, err := client.Search(host, 0, 100)
	if err != nil {
		log.Fatalf("Error searching Strongbox: %v", err)
	}

	// 4. Filter and pick the newest match
	var matches []strongbox.AutoFillCredential
	hostWithProtocol := "ssh://" + host
	for _, cred := range searchResult.Results {
		// Match user and host (case-insensitive for host)
		if cred.Username == user && (strings.Contains(strings.ToLower(cred.URL), strings.ToLower(host)) || strings.Contains(strings.ToLower(cred.URL), strings.ToLower(hostWithProtocol)) || strings.Contains(strings.ToLower(cred.Title), strings.ToLower(host))) {
			matches = append(matches, cred)
		}
	}

	if len(matches) == 0 {
		log.Fatalf("No credentials found for %s@%s", user, host)
	}

	// Sort by Modified date (descending)
	sort.Slice(matches, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339, matches[i].Modified)
		tj, _ := time.Parse(time.RFC3339, matches[j].Modified)
		return ti.After(tj)
	})

	password := matches[0].Password

	// 5. Execute ssh and provide password
	// sshpass-like behavior: we'll use a pipe for simple cases,
	// but note that real sshpass uses a pty to handle ssh's requirement for a TTY.
	// For this example, we'll use a simple approach that works if the command accepts password from stdin
	// or we can try to use a more sophisticated approach if needed.
	// However, standard 'ssh' DOES NOT take password from stdin unless some flags/env are set.

	if err := executeSSH(os.Args[1:], password); err != nil {
		log.Fatal(err)
	}
}

func findUserHost(args []string) (string, string) {
	re := regexp.MustCompile(`^([^@]+)@([^@]+)$`)
	for _, arg := range args {
		matches := re.FindStringSubmatch(arg)
		if len(matches) == 3 {
			return matches[1], matches[2]
		}
	}
	return "", ""
}

func executeSSH(args []string, password string) error {
	// To actually work like sshpass with 'ssh', we need a PTY.
	// Since we want to keep examples simple and without extra dependencies,
	// let's see if we can use a trick or just provide the password via environment
	// variable if the command supports it, but the requirement said "instead of
	// providing the password via argument or environment variable".

	// Wait, if I'm supposed to "work like sshpass", I should probably use a PTY.
	// But adding a PTY dependency might be too much for a simple example.
	// Let's look at how other tools do it.

	// If I can't use a PTY, I'll at least implement the searching logic correctly.
	// For 'ssh', one can use SSH_ASKPASS.

	fmt.Fprintf(os.Stderr, "Found password for match, executing ssh...\n")

	// Set up SSH_ASKPASS trick
	// We create a temporary script that prints the password
	tmpScript, err := os.CreateTemp("", "strongsshpass-askpass")
	if err != nil {
		return fmt.Errorf("error creating temp script: %v", err)
	}
	defer os.Remove(tmpScript.Name())

	fmt.Fprintf(tmpScript, "#!/bin/sh\necho '%s'\n", strings.ReplaceAll(password, "'", "'\\''"))
	tmpScript.Close()
	os.Chmod(tmpScript.Name(), 0700)

	cmd := exec.Command("ssh", args...)
	cmd.Env = append(os.Environ(),
		"SSH_ASKPASS="+tmpScript.Name(),
		"DISPLAY=:0",                // Required for SSH_ASKPASS to be used in some versions
		"SSH_ASKPASS_REQUIRE=force", // Force it even if we have a TTY
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			os.Remove(tmpScript.Name()) // Explicitly remove before exit
			os.Exit(exitError.ExitCode())
		}
		return fmt.Errorf("error executing ssh: %v", err)
	}
	return nil
}
