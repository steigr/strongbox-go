package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

// ---------------------------------------------------------------------------
// Key generation helpers
// ---------------------------------------------------------------------------

func marshalKey(t *testing.T, key interface{}) string {
	t.Helper()
	block, err := gossh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

func marshalKeyEncrypted(t *testing.T, key interface{}, passphrase string) string {
	t.Helper()
	block, err := gossh.MarshalPrivateKeyWithPassphrase(key, "test", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

func newEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ---------------------------------------------------------------------------
// In-process SSH agent backed by a unix socket
// ---------------------------------------------------------------------------

type testAgentServer struct {
	keyring  agent.Agent
	sockPath string
}

func startTestAgent(t *testing.T) *testAgentServer {
	t.Helper()
	// Use os.MkdirTemp with an empty base so the path lands under os.TempDir()
	// (/tmp on macOS), keeping the socket path well under the 104-char unix limit.
	dir, err := os.MkdirTemp("", "t")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "a.sock")

	keyring := agent.NewKeyring()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })

	return &testAgentServer{keyring: keyring, sockPath: sockPath}
}

func (s *testAgentServer) keyCount(t *testing.T) int {
	t.Helper()
	keys, err := s.keyring.List()
	if err != nil {
		t.Fatal(err)
	}
	return len(keys)
}

// ---------------------------------------------------------------------------
// TestEntryField
// ---------------------------------------------------------------------------

func TestEntryField(t *testing.T) {
	entry := strongbox.AutoFillCredential{
		Password: "p@ssw0rd",
		Username: "user@example.com",
		URL:      "https://example.com",
		Notes:    "some notes",
		CustomFields: []strongbox.CustomField{
			{Key: "id_ed25519", Value: "keydata"},
			{Key: "secret", Value: "s3cret"},
		},
	}

	cases := []struct{ field, want string }{
		{"password", "p@ssw0rd"},
		{"username", "user@example.com"},
		{"url", "https://example.com"},
		{"notes", "some notes"},
		{"id_ed25519", "keydata"},
		{"secret", "s3cret"},
		{"nonexistent", ""},
	}
	for _, c := range cases {
		if got := entryField(entry, c.field); got != c.want {
			t.Errorf("entryField(%q) = %q, want %q", c.field, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// TestIsSSHPrivateKey
// ---------------------------------------------------------------------------

func TestIsSSHPrivateKey(t *testing.T) {
	ed := newEd25519Key(t)
	rsaKey := newRSAKey(t)
	ecKey := newECDSAKey(t)

	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"ed25519 unencrypted", marshalKey(t, ed), true},
		{"ed25519 encrypted", marshalKeyEncrypted(t, ed, "pw"), true},
		{"rsa unencrypted", marshalKey(t, rsaKey), true},
		{"ecdsa unencrypted", marshalKey(t, ecKey), true},
		{"empty", "", false},
		{"random text", "not a key at all", false},
		{"malformed pem", "-----BEGIN OPENSSH PRIVATE KEY-----\ngarbage\n-----END OPENSSH PRIVATE KEY-----\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isSSHPrivateKey(c.input); got != c.want {
				t.Errorf("isSSHPrivateKey = %v, want %v", got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestFindSSHKeyField
// ---------------------------------------------------------------------------

func TestFindSSHKeyField(t *testing.T) {
	keyPEM := marshalKey(t, newEd25519Key(t))
	keyPEM2 := marshalKey(t, newEd25519Key(t))

	t.Run("id_ed25519 wins over id_rsa", func(t *testing.T) {
		entry := strongbox.AutoFillCredential{
			CustomFields: []strongbox.CustomField{
				{Key: "id_rsa", Value: keyPEM2},
				{Key: "id_ed25519", Value: keyPEM},
			},
		}
		field, val := findSSHKeyField(entry)
		if field != "id_ed25519" || val != keyPEM {
			t.Errorf("got field=%q", field)
		}
	})

	t.Run("falls back to id_rsa", func(t *testing.T) {
		entry := strongbox.AutoFillCredential{
			CustomFields: []strongbox.CustomField{
				{Key: "id_rsa", Value: keyPEM},
			},
		}
		field, _ := findSSHKeyField(entry)
		if field != "id_rsa" {
			t.Errorf("got field=%q, want id_rsa", field)
		}
	})

	t.Run("falls back to id_ecdsa", func(t *testing.T) {
		entry := strongbox.AutoFillCredential{
			CustomFields: []strongbox.CustomField{
				{Key: "id_ecdsa", Value: keyPEM},
			},
		}
		field, _ := findSSHKeyField(entry)
		if field != "id_ecdsa" {
			t.Errorf("got field=%q, want id_ecdsa", field)
		}
	})

	t.Run("falls back to password field", func(t *testing.T) {
		entry := strongbox.AutoFillCredential{Password: keyPEM}
		field, val := findSSHKeyField(entry)
		if field != "password" || val != keyPEM {
			t.Errorf("got field=%q", field)
		}
	})

	t.Run("skips non-key custom field value", func(t *testing.T) {
		entry := strongbox.AutoFillCredential{
			CustomFields: []strongbox.CustomField{
				{Key: "id_ed25519", Value: "not a key"},
				{Key: "id_rsa", Value: keyPEM},
			},
		}
		field, _ := findSSHKeyField(entry)
		if field != "id_rsa" {
			t.Errorf("got field=%q, want id_rsa", field)
		}
	})

	t.Run("no key found", func(t *testing.T) {
		entry := strongbox.AutoFillCredential{Password: "hunter2"}
		field, val := findSSHKeyField(entry)
		if field != "" || val != "" {
			t.Errorf("got field=%q val=%q, want empty", field, val)
		}
	})
}

// ---------------------------------------------------------------------------
// TestLoadKeyIntoAgent – infrastructure / error paths
// ---------------------------------------------------------------------------

func TestLoadKeyIntoAgent_NoSSHAuthSock(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	keyPEM := marshalKey(t, newEd25519Key(t))
	err := loadKeyIntoAgent(strongbox.AutoFillCredential{Title: "t"}, "id_ed25519", []byte(keyPEM))
	if err == nil || !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Fatalf("expected SSH_AUTH_SOCK error, got: %v", err)
	}
}

func TestLoadKeyIntoAgent_ConnectFailure(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/nonexistent/path/agent.sock")
	keyPEM := marshalKey(t, newEd25519Key(t))
	err := loadKeyIntoAgent(strongbox.AutoFillCredential{Title: "t"}, "id_ed25519", []byte(keyPEM))
	if err == nil {
		t.Fatal("expected connection error")
	}
}

func TestLoadKeyIntoAgent_InvalidKeyData(t *testing.T) {
	ta := startTestAgent(t)
	t.Setenv("SSH_AUTH_SOCK", ta.sockPath)
	err := loadKeyIntoAgent(strongbox.AutoFillCredential{Title: "t"}, "id_ed25519", []byte("not a key"))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

// ---------------------------------------------------------------------------
// TestLoadKeyIntoAgent – successful loads
// ---------------------------------------------------------------------------

func TestLoadKeyIntoAgent_Unencrypted(t *testing.T) {
	ta := startTestAgent(t)
	t.Setenv("SSH_AUTH_SOCK", ta.sockPath)

	keyPEM := marshalKey(t, newEd25519Key(t))
	entry := strongbox.AutoFillCredential{Title: "my ssh key"}
	if err := loadKeyIntoAgent(entry, "id_ed25519", []byte(keyPEM)); err != nil {
		t.Fatal(err)
	}

	keys, _ := ta.keyring.List()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in agent, got %d", len(keys))
	}
	if keys[0].Comment != "my ssh key" {
		t.Errorf("comment = %q, want %q", keys[0].Comment, "my ssh key")
	}
}

func TestLoadKeyIntoAgent_Unencrypted_RSA(t *testing.T) {
	ta := startTestAgent(t)
	t.Setenv("SSH_AUTH_SOCK", ta.sockPath)

	keyPEM := marshalKey(t, newRSAKey(t))
	if err := loadKeyIntoAgent(strongbox.AutoFillCredential{Title: "rsa"}, "id_rsa", []byte(keyPEM)); err != nil {
		t.Fatal(err)
	}
	if ta.keyCount(t) != 1 {
		t.Fatal("key not added")
	}
}

func TestLoadKeyIntoAgent_Unencrypted_ECDSA(t *testing.T) {
	ta := startTestAgent(t)
	t.Setenv("SSH_AUTH_SOCK", ta.sockPath)

	keyPEM := marshalKey(t, newECDSAKey(t))
	if err := loadKeyIntoAgent(strongbox.AutoFillCredential{Title: "ec"}, "id_ecdsa", []byte(keyPEM)); err != nil {
		t.Fatal(err)
	}
	if ta.keyCount(t) != 1 {
		t.Fatal("key not added")
	}
}

// ---------------------------------------------------------------------------
// TestLoadKeyIntoAgent – passphrase resolution
// ---------------------------------------------------------------------------

func TestLoadKeyIntoAgent_Encrypted_EnvVar(t *testing.T) {
	ta := startTestAgent(t)
	t.Setenv("SSH_AUTH_SOCK", ta.sockPath)
	t.Setenv("SSH_KEY_PASSPHRASE", "correct")

	keyPEM := marshalKeyEncrypted(t, newEd25519Key(t), "correct")
	if err := loadKeyIntoAgent(strongbox.AutoFillCredential{Title: "t"}, "id_ed25519", []byte(keyPEM)); err != nil {
		t.Fatal(err)
	}
	if ta.keyCount(t) != 1 {
		t.Fatal("key not added")
	}
}

func TestLoadKeyIntoAgent_Encrypted_WrongEnvVar_PasswordFieldSucceeds(t *testing.T) {
	ta := startTestAgent(t)
	t.Setenv("SSH_AUTH_SOCK", ta.sockPath)
	t.Setenv("SSH_KEY_PASSPHRASE", "wrong")

	keyPEM := marshalKeyEncrypted(t, newEd25519Key(t), "correct")
	entry := strongbox.AutoFillCredential{Title: "t", Password: "correct"}
	if err := loadKeyIntoAgent(entry, "id_ed25519", []byte(keyPEM)); err != nil {
		t.Fatal(err)
	}
	if ta.keyCount(t) != 1 {
		t.Fatal("key not added")
	}
}

func TestLoadKeyIntoAgent_Encrypted_PasswordField(t *testing.T) {
	ta := startTestAgent(t)
	t.Setenv("SSH_AUTH_SOCK", ta.sockPath)
	t.Setenv("SSH_KEY_PASSPHRASE", "") // ensure env var is not used

	keyPEM := marshalKeyEncrypted(t, newEd25519Key(t), "secret")
	entry := strongbox.AutoFillCredential{Title: "t", Password: "secret"}
	if err := loadKeyIntoAgent(entry, "id_ed25519", []byte(keyPEM)); err != nil {
		t.Fatal(err)
	}
	if ta.keyCount(t) != 1 {
		t.Fatal("key not added")
	}
}

func TestLoadKeyIntoAgent_Encrypted_KeyFromPasswordField_DoesNotSelfUnlock(t *testing.T) {
	// When the key itself came from the password field, the password field must
	// NOT be tried as a passphrase — that would be circular.
	ta := startTestAgent(t)
	t.Setenv("SSH_AUTH_SOCK", ta.sockPath)
	t.Setenv("SSH_KEY_PASSPHRASE", "")

	keyPEM := marshalKeyEncrypted(t, newEd25519Key(t), "secret")
	// Password field holds the passphrase, but keyField == "password" → skip it.
	entry := strongbox.AutoFillCredential{Title: "t", Password: "secret"}
	err := loadKeyIntoAgent(entry, "password", []byte(keyPEM))
	if err == nil {
		t.Fatal("expected error: circular passphrase use should be prevented")
	}
}

func TestLoadKeyIntoAgent_Encrypted_NoPassphraseAvailable(t *testing.T) {
	ta := startTestAgent(t)
	t.Setenv("SSH_AUTH_SOCK", ta.sockPath)
	t.Setenv("SSH_KEY_PASSPHRASE", "")

	keyPEM := marshalKeyEncrypted(t, newEd25519Key(t), "secret")
	entry := strongbox.AutoFillCredential{Title: "t", Password: ""}
	err := loadKeyIntoAgent(entry, "id_ed25519", []byte(keyPEM))
	if err == nil {
		t.Fatal("expected error when no passphrase is available")
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error message should mention passphrase, got: %v", err)
	}
}

func TestLoadKeyIntoAgent_Encrypted_WrongPassphraseEverywhere(t *testing.T) {
	ta := startTestAgent(t)
	t.Setenv("SSH_AUTH_SOCK", ta.sockPath)
	t.Setenv("SSH_KEY_PASSPHRASE", "wrong-env")

	keyPEM := marshalKeyEncrypted(t, newEd25519Key(t), "correct")
	entry := strongbox.AutoFillCredential{Title: "t", Password: "wrong-field"}
	err := loadKeyIntoAgent(entry, "id_ed25519", []byte(keyPEM))
	if err == nil {
		t.Fatal("expected error when all passphrases are wrong")
	}
}

// ---------------------------------------------------------------------------
// TestCandidateKeyFields – ordering is contractual
// ---------------------------------------------------------------------------

func TestCandidateKeyFieldsOrder(t *testing.T) {
	want := []string{"id_ed25519", "id_rsa", "id_ecdsa", "password"}
	if len(candidateKeyFields) != len(want) {
		t.Fatalf("len=%d, want %d", len(candidateKeyFields), len(want))
	}
	for i, f := range want {
		if candidateKeyFields[i] != f {
			t.Errorf("[%d] = %q, want %q", i, candidateKeyFields[i], f)
		}
	}
}
