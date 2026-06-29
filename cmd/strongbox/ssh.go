package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"github.com/spf13/cobra"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

var sshAgentCmd = &cobra.Command{
	Use:   "ssh-agent",
	Short: "Interact with the running SSH agent",
}

var sshAgentLoadKeyCmd = &cobra.Command{
	Use:   "load-key <entry-name>",
	Short: "Load an SSH private key into the SSH agent",
	Long: `Retrieve an SSH private key from a Strongbox entry and add it to the running SSH agent.

If --field is not specified, the following fields are tried in order and the first
one containing a valid SSH private key is used: id_ed25519, id_rsa, id_ecdsa, password.

For passphrase-protected keys the passphrase is resolved in priority order:
  1. SSH_KEY_PASSPHRASE environment variable
  2. The entry's password field (when --field is not "password")
  3. Interactive prompt (when stdin is a terminal)`,
	Example: `  strongbox ssh-agent load-key "My SSH Key"
  strongbox ssh-agent load-key "My SSH Key" --field id_ed25519`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fieldName, _ := cmd.Flags().GetString("field")
		name := args[0]

		ensureAutoFillDatabase(client, unlockBehavior)

		result, err := client.Search(searchTerm(name), 0, -1)
		if err != nil {
			fatal("searching: %v", err)
		}
		if len(result.Results) == 0 {
			fatal("no entry found matching '%s'", name)
		}

		entry := *resolveEntry(result.Results, name)

		var keyPEM string
		var keyField string
		if fieldName != "" {
			keyPEM = entryField(entry, fieldName)
			if keyPEM == "" {
				fatal("field '%s' is empty or not found in entry '%s'", fieldName, entry.Title)
			}
			if !isSSHPrivateKey(keyPEM) {
				fatal("field '%s' in entry '%s' does not contain a valid SSH private key", fieldName, entry.Title)
			}
			keyField = fieldName
		} else {
			keyField, keyPEM = findSSHKeyField(entry)
			if keyPEM == "" {
				fatal("no valid SSH private key found in entry '%s' (tried: id_ed25519, id_rsa, id_ecdsa, password)", entry.Title)
			}
		}

		if err := loadKeyIntoAgent(entry, keyField, []byte(keyPEM)); err != nil {
			fatal("%v", err)
		}

		fmt.Fprintf(os.Stderr, "loaded key from '%s' (field: %s) into SSH agent\n", entry.Title, keyField)
	},
}

func init() {
	sshAgentLoadKeyCmd.Flags().StringP("field", "f", "", "Field containing the SSH private key")
	sshAgentCmd.AddCommand(sshAgentLoadKeyCmd)
}

// entryField returns the value of the named field from an entry,
// checking standard fields first and then custom fields.
func entryField(entry strongbox.AutoFillCredential, field string) string {
	switch field {
	case "password":
		return entry.Password
	case "username":
		return entry.Username
	case "url":
		return entry.URL
	case "notes":
		return entry.Notes
	}
	for _, cf := range entry.CustomFields {
		if cf.Key == field {
			return cf.Value
		}
	}
	return ""
}

// candidateKeyFields are tried in order when no --field flag is given.
var candidateKeyFields = []string{"id_ed25519", "id_rsa", "id_ecdsa", "password"}

// findSSHKeyField returns the first (fieldName, value) pair from candidateKeyFields
// that holds a valid SSH private key.
func findSSHKeyField(entry strongbox.AutoFillCredential) (string, string) {
	for _, field := range candidateKeyFields {
		val := entryField(entry, field)
		if val != "" && isSSHPrivateKey(val) {
			return field, val
		}
	}
	return "", ""
}

// isSSHPrivateKey returns true if s is a valid (possibly passphrase-protected)
// PEM-encoded SSH private key.
func isSSHPrivateKey(s string) bool {
	_, err := gossh.ParseRawPrivateKey([]byte(s))
	if err == nil {
		return true
	}
	var ppErr *gossh.PassphraseMissingError
	return errors.As(err, &ppErr)
}

// loadKeyIntoAgent decrypts keyPEM (resolving any passphrase) and adds the
// resulting key to the SSH agent at SSH_AUTH_SOCK.
func loadKeyIntoAgent(entry strongbox.AutoFillCredential, keyField string, keyPEM []byte) error {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return fmt.Errorf("SSH_AUTH_SOCK is not set — is the SSH agent running?")
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return fmt.Errorf("connecting to SSH agent: %w", err)
	}
	defer conn.Close()

	ag := agent.NewClient(conn)

	privKey, err := gossh.ParseRawPrivateKey(keyPEM)
	if err == nil {
		return ag.Add(agent.AddedKey{PrivateKey: privKey, Comment: entry.Title})
	}

	var ppErr *gossh.PassphraseMissingError
	if !errors.As(err, &ppErr) {
		return fmt.Errorf("parsing SSH private key: %w", err)
	}

	// tryPassphrase attempts to decrypt keyPEM with pp, updating privKey on success.
	tryPassphrase := func(pp []byte) bool {
		key, e := gossh.ParseRawPrivateKeyWithPassphrase(keyPEM, pp)
		if e != nil {
			return false
		}
		privKey = key
		return true
	}

	// 1. SSH_KEY_PASSPHRASE environment variable.
	if pp := os.Getenv("SSH_KEY_PASSPHRASE"); pp != "" {
		if tryPassphrase([]byte(pp)) {
			return ag.Add(agent.AddedKey{PrivateKey: privKey, Comment: entry.Title})
		}
	}

	// 2. Entry password field (only when the key itself is not from the password field).
	if keyField != "password" && entry.Password != "" {
		if tryPassphrase([]byte(entry.Password)) {
			return ag.Add(agent.AddedKey{PrivateKey: privKey, Comment: entry.Title})
		}
	}

	// 3. Interactive passphrase prompt.
	if isInputTerminal() {
		fmt.Fprintf(os.Stderr, "Enter passphrase for SSH key '%s': ", entry.Title)
		pp, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if e == nil && len(pp) > 0 {
			if tryPassphrase(pp) {
				return ag.Add(agent.AddedKey{PrivateKey: privKey, Comment: entry.Title})
			}
			return fmt.Errorf("wrong passphrase for SSH private key")
		}
	}

	return fmt.Errorf("SSH key is passphrase-protected but no valid passphrase was found " +
		"(set SSH_KEY_PASSPHRASE, store the passphrase in the entry's password field, " +
		"or run in an interactive terminal)")
}
