package main

import (
	"context"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/steigr/strongbox-go/pkg/strongbox"
)

func listMCPTools(t *testing.T, readOnly bool) []string {
	t.Helper()
	ctx := context.Background()
	server := (&mcpServer{}).build(readOnly)

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer session.Close()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

func TestMCPTools(t *testing.T) {
	want := []string{"copy_field", "create_entry", "generate_password", "get", "get_url", "groups", "lock", "password_strength", "search", "status", "unlock"}
	if got := listMCPTools(t, false); !slices.Equal(got, want) {
		t.Errorf("tools = %v, want %v", got, want)
	}
}

func TestMCPToolsReadOnly(t *testing.T) {
	got := listMCPTools(t, true)
	for _, name := range []string{"create_entry", "lock", "unlock"} {
		if slices.Contains(got, name) {
			t.Errorf("read-only server exposes %q", name)
		}
	}
	if !slices.Contains(got, "search") {
		t.Errorf("read-only server is missing search: %v", got)
	}
}

func testCredential() strongbox.AutoFillCredential {
	return strongbox.AutoFillCredential{
		Title:    "GitHub",
		Username: "octocat",
		Password: "hunter2",
		TOTP:     "123456",
		Icon:     "data:image/png;base64,AAAA",
		CustomFields: []strongbox.CustomField{
			{Key: "api-key", Value: "secret", Concealable: true},
			{Key: "region", Value: "eu"},
		},
	}
}

func TestMCPCredentialRedactsSecrets(t *testing.T) {
	cred := testCredential()
	got := (&mcpServer{}).mcpCredential(cred)

	if got.Password != redacted || got.TOTP != redacted {
		t.Errorf("password/totp not redacted: %q / %q", got.Password, got.TOTP)
	}
	if got.CustomFields[0].Value != redacted {
		t.Errorf("concealable custom field not redacted: %q", got.CustomFields[0].Value)
	}
	if got.CustomFields[1].Value != "eu" || got.Username != "octocat" {
		t.Errorf("non-secret fields changed: %+v", got)
	}
	if got.Icon != "" {
		t.Errorf("icon not dropped")
	}
	if cred.Password != "hunter2" || cred.CustomFields[0].Value != "secret" {
		t.Errorf("input credential was modified")
	}
}

func TestMCPCredentialRevealSecrets(t *testing.T) {
	got := (&mcpServer{revealSecrets: true}).mcpCredential(testCredential())
	if got.Password != "hunter2" || got.TOTP != "123456" || got.CustomFields[0].Value != "secret" {
		t.Errorf("secrets redacted despite revealSecrets: %+v", got)
	}
	if got.Icon != "" {
		t.Errorf("icon not dropped")
	}
}

func TestIsSecretField(t *testing.T) {
	cred := testCredential()
	for field, want := range map[string]bool{
		"password": true,
		"totp":     true,
		"api-key":  true,
		"region":   false,
		"username": false,
		"url":      false,
	} {
		if got := isSecretField(cred, field); got != want {
			t.Errorf("isSecretField(%q) = %v, want %v", field, got, want)
		}
	}
}
