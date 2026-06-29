package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

// ---------------------------------------------------------------------------
// handleAskpassMode
// ---------------------------------------------------------------------------

func TestHandleAskpassMode_NotSet(t *testing.T) {
	t.Setenv("STRONGBOX_SSH_PASSWORD", "")
	var buf bytes.Buffer
	if handleAskpassMode(&buf) {
		t.Fatal("expected false when env var is empty")
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no output, got %q", buf.String())
	}
}

func TestHandleAskpassMode_Set(t *testing.T) {
	t.Setenv("STRONGBOX_SSH_PASSWORD", "s3cr3t")
	var buf bytes.Buffer
	if !handleAskpassMode(&buf) {
		t.Fatal("expected true when env var is set")
	}
	if buf.String() != "s3cr3t" {
		t.Fatalf("got %q, want s3cr3t", buf.String())
	}
}

func TestHandleAskpassMode_SpecialChars(t *testing.T) {
	pass := "p@$$w0rd!\"'\\n\t"
	t.Setenv("STRONGBOX_SSH_PASSWORD", pass)
	var buf bytes.Buffer
	handleAskpassMode(&buf)
	if buf.String() != pass {
		t.Fatalf("password round-trip failed: got %q", buf.String())
	}
}

// ---------------------------------------------------------------------------
// findUserHost
// ---------------------------------------------------------------------------

func TestFindUserHost(t *testing.T) {
	cases := []struct {
		args             []string
		wantUser, wantHost string
	}{
		{[]string{"user@host"}, "user", "host"},
		{[]string{"-p", "22", "user@host"}, "user", "host"},
		{[]string{"user@host", "ls", "/tmp"}, "user", "host"},
		{[]string{"-i", "~/.ssh/id_rsa", "admin@server.example.com"}, "admin", "server.example.com"},
		{[]string{"-l", "alice", "host"}, "", ""},  // no user@host form
		{[]string{"noatsign"}, "", ""},
		{[]string{}, "", ""},
		// two @ — the regex anchors to ^ and $ so this must not match
		{[]string{"a@b@c"}, "", ""},
	}
	for _, c := range cases {
		u, h := findUserHost(c.args)
		if u != c.wantUser || h != c.wantHost {
			t.Errorf("findUserHost(%v) = (%q,%q), want (%q,%q)",
				c.args, u, h, c.wantUser, c.wantHost)
		}
	}
}

// ---------------------------------------------------------------------------
// matchCredentials
// ---------------------------------------------------------------------------

func sshCred(username, url, title string) strongbox.AutoFillCredential {
	return strongbox.AutoFillCredential{Username: username, URL: url, Title: title}
}

func TestMatchCredentials(t *testing.T) {
	pool := []strongbox.AutoFillCredential{
		sshCred("alice", "ssh://server.example.com", "server"),
		sshCred("bob", "ssh://server.example.com", "server"),
		sshCred("alice", "https://web.example.com", "web"),
		sshCred("alice", "", "server.example.com"),         // match via title
		sshCred("alice", "ssh://other.host.com", "other"),
		sshCred("alice", "ssh://example.com", "example"),   // partial URL — should match
	}

	t.Run("matches URL and username", func(t *testing.T) {
		got := matchCredentials(pool, "alice", "server.example.com")
		// should match: ssh URL, title
		if len(got) != 2 {
			t.Errorf("got %d matches, want 2", len(got))
		}
	})

	t.Run("different username excluded", func(t *testing.T) {
		got := matchCredentials(pool, "bob", "server.example.com")
		if len(got) != 1 || got[0].Username != "bob" {
			t.Errorf("unexpected: %+v", got)
		}
	})

	t.Run("unknown host returns nothing", func(t *testing.T) {
		if n := len(matchCredentials(pool, "alice", "unknown.host")); n != 0 {
			t.Errorf("expected 0, got %d", n)
		}
	})

	t.Run("case-insensitive username", func(t *testing.T) {
		got := matchCredentials(pool, "ALICE", "server.example.com")
		if len(got) == 0 {
			t.Error("expected case-insensitive username match")
		}
	})

	t.Run("case-insensitive host", func(t *testing.T) {
		got := matchCredentials(pool, "alice", "Server.Example.Com")
		if len(got) == 0 {
			t.Error("expected case-insensitive host match")
		}
	})

	t.Run("title-based match included", func(t *testing.T) {
		got := matchCredentials(pool, "alice", "server.example.com")
		hasTitleMatch := false
		for _, c := range got {
			if c.URL == "" && c.Title == "server.example.com" {
				hasTitleMatch = true
			}
		}
		if !hasTitleMatch {
			t.Error("title-based match not found")
		}
	})

	t.Run("empty pool", func(t *testing.T) {
		if n := len(matchCredentials(nil, "alice", "host")); n != 0 {
			t.Errorf("expected 0, got %d", n)
		}
	})
}

// ---------------------------------------------------------------------------
// pickCredential
// ---------------------------------------------------------------------------

func TestPickCredential_NewestWins(t *testing.T) {
	now := time.Now()
	matches := []strongbox.AutoFillCredential{
		{Title: "old", Modified: now.Add(-24 * time.Hour).Format(time.RFC3339)},
		{Title: "newest", Modified: now.Format(time.RFC3339)},
		{Title: "middle", Modified: now.Add(-1 * time.Hour).Format(time.RFC3339)},
	}
	if got := pickCredential(matches).Title; got != "newest" {
		t.Errorf("got %q, want newest", got)
	}
}

func TestPickCredential_InvalidDateTreatedAsZero(t *testing.T) {
	now := time.Now()
	matches := []strongbox.AutoFillCredential{
		{Title: "valid", Modified: now.Format(time.RFC3339)},
		{Title: "bad-date", Modified: "not-a-date"},
	}
	if got := pickCredential(matches).Title; got != "valid" {
		t.Errorf("got %q, want valid", got)
	}
}

func TestPickCredential_AllInvalidDates(t *testing.T) {
	matches := []strongbox.AutoFillCredential{
		{Title: "a", Modified: "bad"},
		{Title: "b", Modified: "also-bad"},
	}
	// Should not panic; just return first after sort (both zero time, stable not required).
	_ = pickCredential(matches)
}

func TestPickCredential_SingleEntry(t *testing.T) {
	matches := []strongbox.AutoFillCredential{{Title: "only"}}
	if got := pickCredential(matches).Title; got != "only" {
		t.Errorf("got %q", got)
	}
}
