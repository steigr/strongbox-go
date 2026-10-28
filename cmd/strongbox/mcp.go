package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
	"github.com/steigr/strongbox-go/pkg/strongbox"
)

const (
	mcpDefaultTake = 50
	redacted       = "***"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run an MCP server on stdio",
	Long: `Run a Model Context Protocol (MCP) server that talks JSON-RPC over stdin/stdout.

Secrets (passwords, TOTP codes and concealable custom fields) are redacted
from all tool results unless --reveal-secrets is given. Without it, the
copy_field tool still lets a client put a secret on the clipboard without
ever seeing its value.

Use --read-only to omit tools that change Strongbox state (create_entry,
lock, unlock).`,
	Example: `  # Claude Code
  claude mcp add strongbox -- strongbox mcp

  # Claude Desktop / other clients (mcpServers entry)
  {"command": "strongbox", "args": ["mcp"]}`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		revealSecrets, _ := cmd.Flags().GetBool("reveal-secrets")
		readOnly, _ := cmd.Flags().GetBool("read-only")

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		s := &mcpServer{client: client, unlockBehavior: unlockBehavior, revealSecrets: revealSecrets}
		return s.build(readOnly).Run(ctx, &mcp.StdioTransport{})
	},
}

func init() {
	mcpCmd.Flags().Bool("reveal-secrets", false, "Include passwords, TOTP codes and concealable custom fields in tool results")
	mcpCmd.Flags().Bool("read-only", false, "Omit tools that create entries or lock/unlock databases")
}

type mcpServer struct {
	client         *strongbox.Client
	unlockBehavior string
	revealSecrets  bool
}

func mcpVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "dev"
}

func boolPtr(b bool) *bool { return &b }

// build returns an MCP server with all tools registered. When readOnly is
// set, tools that modify Strongbox state are left out.
func (s *mcpServer) build(readOnly bool) *mcp.Server {
	instructions := "Access credentials stored in the Strongbox password manager. " +
		"Only AutoFill-enabled databases are searchable. Entries can be addressed by title or by group path (\"group/sub/title\")."
	if !s.revealSecrets {
		instructions += " Secret values are redacted as \"" + redacted + "\"; use copy_field to place one on the user's clipboard."
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "strongbox", Version: mcpVersion()}, &mcp.ServerOptions{
		Instructions: instructions,
	})

	readOnlyHint := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "status",
		Description: "Show the Strongbox version and the known databases with their lock and AutoFill state.",
		Annotations: readOnlyHint,
	}, s.status)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "search",
		Description: "Search entries across all unlocked AutoFill-enabled databases.",
		Annotations: readOnlyHint,
	}, s.search)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get",
		Description: "Get a single entry by title or group path (\"group/sub/title\"), optionally just one field.",
		Annotations: readOnlyHint,
	}, s.get)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_url",
		Description: "Find entries whose URL matches the given URL.",
		Annotations: readOnlyHint,
	}, s.getURL)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "groups",
		Description: "List the groups of a database, e.g. to pick a group for create_entry.",
		Annotations: readOnlyHint,
	}, s.groups)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "generate_password",
		Description: "Generate a password (plus alternatives) with Strongbox's password generator, including a strength estimate.",
		Annotations: readOnlyHint,
	}, s.generatePassword)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "password_strength",
		Description: "Estimate the strength of a password.",
		Annotations: readOnlyHint,
	}, s.passwordStrength)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "copy_field",
		Description: "Copy an entry's username, password or TOTP code to the clipboard without returning its value.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
	}, s.copyField)

	if readOnly {
		return server
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "create_entry",
		Description: "Create a new entry in a database. Omit password to let the caller pick one from generate_password first.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(false)},
	}, s.createEntry)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "lock",
		Description: "Lock a database.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
	}, s.lock)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "unlock",
		Description: "Ask Strongbox to unlock a database. The user is prompted in the Strongbox app.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
	}, s.unlock)

	return server
}

// mcpCredential prepares a credential for a tool result: icons are dropped
// (large and useless to a model) and secrets are redacted unless revealed.
func (s *mcpServer) mcpCredential(cred strongbox.AutoFillCredential) strongbox.AutoFillCredential {
	res := cred
	res.Icon = ""
	if s.revealSecrets {
		return res
	}
	if res.Password != "" {
		res.Password = redacted
	}
	if res.TOTP != "" {
		res.TOTP = redacted
	}
	res.CustomFields = make([]strongbox.CustomField, len(cred.CustomFields))
	for i, f := range cred.CustomFields {
		if f.Concealable && f.Value != "" {
			f.Value = redacted
		}
		res.CustomFields[i] = f
	}
	return res
}

func (s *mcpServer) mcpCredentials(creds []strongbox.AutoFillCredential) []strongbox.AutoFillCredential {
	res := make([]strongbox.AutoFillCredential, len(creds))
	for i, c := range creds {
		res[i] = s.mcpCredential(c)
	}
	return res
}

// isSecretField reports whether fieldName holds a secret in entry.
func isSecretField(entry strongbox.AutoFillCredential, fieldName string) bool {
	switch fieldName {
	case "password", "totp":
		return true
	}
	for _, f := range entry.CustomFields {
		if f.Key == fieldName {
			return f.Concealable
		}
	}
	return false
}

func mcpTake(take int) int {
	if take == 0 {
		return mcpDefaultTake
	}
	return take
}

// resolveDatabase resolves a database UUID or nickname after making sure
// Strongbox is reachable and a database is unlocked.
func (s *mcpServer) resolveDatabase(idOrNickname string) (string, error) {
	status, err := unlockedStatus(s.client, s.unlockBehavior)
	if err != nil {
		return "", err
	}
	return lookupDatabase(status, idOrNickname)
}

// findEntry searches for name (a title or group path) and returns the best match.
func (s *mcpServer) findEntry(name string) (*strongbox.AutoFillCredential, error) {
	status, err := autoFillStatus(s.client, s.unlockBehavior)
	if err != nil {
		return nil, err
	}
	result, err := s.client.Search(searchTerm(name), 0, -1)
	if err != nil {
		return nil, fmt.Errorf("searching: %v", err)
	}
	if len(result.Results) == 0 {
		if hint := unlockedNonAutoFillHint(status); hint != "" {
			return nil, fmt.Errorf("no entry found matching '%s'\n%s", name, hint)
		}
		return nil, fmt.Errorf("no entry found matching '%s'", name)
	}
	return resolveEntry(result.Results, name), nil
}

type mcpStatusOutput struct {
	ServerVersionInfo string                      `json:"serverVersionInfo"`
	Databases         []strongbox.DatabaseSummary `json:"databases"`
}

func (s *mcpServer) status(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, mcpStatusOutput, error) {
	status, err := s.client.GetStatus()
	if err != nil {
		return nil, mcpStatusOutput{}, fmt.Errorf("getting status: %v", err)
	}
	return nil, mcpStatusOutput{ServerVersionInfo: status.ServerVersionInfo, Databases: status.Databases}, nil
}

type mcpSearchInput struct {
	Query string `json:"query" jsonschema:"search term matched against entry titles, usernames, URLs and tags"`
	Skip  int    `json:"skip,omitempty" jsonschema:"number of results to skip"`
	Take  int    `json:"take,omitempty" jsonschema:"maximum number of results (default 50, -1 for all)"`
}

type mcpCredentialsOutput struct {
	Results []strongbox.AutoFillCredential `json:"results"`
}

func (s *mcpServer) search(_ context.Context, _ *mcp.CallToolRequest, in mcpSearchInput) (*mcp.CallToolResult, mcpCredentialsOutput, error) {
	if _, err := autoFillStatus(s.client, s.unlockBehavior); err != nil {
		return nil, mcpCredentialsOutput{}, err
	}
	result, err := s.client.Search(in.Query, in.Skip, mcpTake(in.Take))
	if err != nil {
		return nil, mcpCredentialsOutput{}, fmt.Errorf("searching: %v", err)
	}
	return nil, mcpCredentialsOutput{Results: s.mcpCredentials(result.Results)}, nil
}

type mcpGetInput struct {
	Name  string `json:"name" jsonschema:"entry title or group path such as \"work/github\""`
	Field string `json:"field,omitempty" jsonschema:"return only this field: username, password, url, totp, notes, uuid, database, modified or a custom field name"`
}

type mcpGetOutput struct {
	Entry *strongbox.AutoFillCredential `json:"entry,omitempty"`
	Field string                        `json:"field,omitempty"`
	Value *string                       `json:"value,omitempty"`
}

func (s *mcpServer) get(_ context.Context, _ *mcp.CallToolRequest, in mcpGetInput) (*mcp.CallToolResult, mcpGetOutput, error) {
	entry, err := s.findEntry(in.Name)
	if err != nil {
		return nil, mcpGetOutput{}, err
	}
	if in.Field == "" {
		cred := s.mcpCredential(*entry)
		return nil, mcpGetOutput{Entry: &cred}, nil
	}
	if !s.revealSecrets && isSecretField(*entry, in.Field) {
		return nil, mcpGetOutput{}, fmt.Errorf("field '%s' is secret; use copy_field to put it on the clipboard (or start the server with --reveal-secrets)", in.Field)
	}
	val, err := fieldValue(*entry, in.Field)
	if err != nil {
		return nil, mcpGetOutput{}, err
	}
	return nil, mcpGetOutput{Field: in.Field, Value: &val}, nil
}

type mcpGetURLInput struct {
	URL  string `json:"url" jsonschema:"URL to match, e.g. https://github.com/login"`
	Skip int    `json:"skip,omitempty" jsonschema:"number of results to skip"`
	Take int    `json:"take,omitempty" jsonschema:"maximum number of results (default 50, -1 for all)"`
}

func (s *mcpServer) getURL(_ context.Context, _ *mcp.CallToolRequest, in mcpGetURLInput) (*mcp.CallToolResult, mcpCredentialsOutput, error) {
	if _, err := autoFillStatus(s.client, s.unlockBehavior); err != nil {
		return nil, mcpCredentialsOutput{}, err
	}
	result, err := s.client.CredentialsForURL(in.URL, in.Skip, mcpTake(in.Take))
	if err != nil {
		return nil, mcpCredentialsOutput{}, fmt.Errorf("getting credentials for URL: %v", err)
	}
	return nil, mcpCredentialsOutput{Results: s.mcpCredentials(result.Results)}, nil
}

type mcpDatabaseInput struct {
	Database string `json:"database" jsonschema:"database UUID or (part of) its nickname"`
}

type mcpGroupsOutput struct {
	Groups []strongbox.GroupSummary `json:"groups"`
}

func (s *mcpServer) groups(_ context.Context, _ *mcp.CallToolRequest, in mcpDatabaseInput) (*mcp.CallToolResult, mcpGroupsOutput, error) {
	dbID, err := s.resolveDatabase(in.Database)
	if err != nil {
		return nil, mcpGroupsOutput{}, err
	}
	result, err := s.client.GetGroups(dbID)
	if err != nil {
		return nil, mcpGroupsOutput{}, fmt.Errorf("getting groups: %v", err)
	}
	if result.Error != nil && *result.Error != "" {
		return nil, mcpGroupsOutput{}, fmt.Errorf("getting groups: %s", *result.Error)
	}
	return nil, mcpGroupsOutput{Groups: result.Groups}, nil
}

func (s *mcpServer) generatePassword(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, *strongbox.GeneratePasswordV2Response, error) {
	result, err := s.client.GeneratePasswordV2()
	if err != nil {
		return nil, nil, fmt.Errorf("generating password: %v", err)
	}
	return nil, result, nil
}

type mcpPasswordInput struct {
	Password string `json:"password" jsonschema:"password to evaluate"`
}

func (s *mcpServer) passwordStrength(_ context.Context, _ *mcp.CallToolRequest, in mcpPasswordInput) (*mcp.CallToolResult, *strongbox.PasswordStrengthData, error) {
	result, err := s.client.GetPasswordStrength(in.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("getting password strength: %v", err)
	}
	return nil, &result.Strength, nil
}

type mcpCopyFieldInput struct {
	Name  string `json:"name" jsonschema:"entry title or group path such as \"work/github\""`
	Field string `json:"field" jsonschema:"username, password or totp"`
}

type mcpSuccessOutput struct {
	Success bool `json:"success"`
}

func (s *mcpServer) copyField(_ context.Context, _ *mcp.CallToolRequest, in mcpCopyFieldInput) (*mcp.CallToolResult, mcpSuccessOutput, error) {
	var field strongbox.WellKnownField
	switch strings.ToLower(in.Field) {
	case "username":
		field = strongbox.FieldUsername
	case "password":
		field = strongbox.FieldPassword
	case "totp":
		field = strongbox.FieldTOTP
	default:
		return nil, mcpSuccessOutput{}, fmt.Errorf("unknown field: %s (use username, password, or totp)", in.Field)
	}
	entry, err := s.findEntry(in.Name)
	if err != nil {
		return nil, mcpSuccessOutput{}, err
	}
	result, err := s.client.CopyField(entry.DatabaseID, entry.UUID, field, field == strongbox.FieldTOTP)
	if err != nil {
		return nil, mcpSuccessOutput{}, fmt.Errorf("copying field: %v", err)
	}
	return nil, mcpSuccessOutput{Success: result.Success}, nil
}

type mcpCreateEntryInput struct {
	Database string `json:"database" jsonschema:"database UUID or (part of) its nickname"`
	Title    string `json:"title,omitempty" jsonschema:"entry title"`
	Username string `json:"username,omitempty" jsonschema:"username"`
	Password string `json:"password,omitempty" jsonschema:"password"`
	URL      string `json:"url,omitempty" jsonschema:"URL"`
	Group    string `json:"group,omitempty" jsonschema:"group UUID from the groups tool"`
}

type mcpCreateEntryOutput struct {
	UUID       string                        `json:"uuid"`
	Credential *strongbox.AutoFillCredential `json:"credential,omitempty"`
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (s *mcpServer) createEntry(_ context.Context, _ *mcp.CallToolRequest, in mcpCreateEntryInput) (*mcp.CallToolResult, mcpCreateEntryOutput, error) {
	dbID, err := s.resolveDatabase(in.Database)
	if err != nil {
		return nil, mcpCreateEntryOutput{}, err
	}
	result, err := s.client.CreateEntry(&strongbox.CreateEntryRequest{
		DatabaseID: dbID,
		GroupID:    optional(in.Group),
		Title:      optional(in.Title),
		Username:   optional(in.Username),
		Password:   optional(in.Password),
		URL:        optional(in.URL),
	})
	if err != nil {
		return nil, mcpCreateEntryOutput{}, fmt.Errorf("creating entry: %v", err)
	}
	if result.Error != nil && *result.Error != "" {
		return nil, mcpCreateEntryOutput{}, fmt.Errorf("creating entry: %s", *result.Error)
	}
	var out mcpCreateEntryOutput
	if result.UUID != nil {
		out.UUID = *result.UUID
	}
	if result.Credential != nil {
		cred := s.mcpCredential(*result.Credential)
		out.Credential = &cred
	}
	return nil, out, nil
}

func (s *mcpServer) lock(_ context.Context, _ *mcp.CallToolRequest, in mcpDatabaseInput) (*mcp.CallToolResult, *strongbox.LockResponse, error) {
	status, err := s.client.GetStatus()
	if err != nil {
		return nil, nil, fmt.Errorf("getting status: %v", err)
	}
	dbID, err := lookupDatabase(status, in.Database)
	if err != nil {
		return nil, nil, err
	}
	result, err := s.client.LockDatabase(dbID)
	if err != nil {
		return nil, nil, fmt.Errorf("locking database: %v", err)
	}
	return nil, result, nil
}

func (s *mcpServer) unlock(_ context.Context, _ *mcp.CallToolRequest, in mcpDatabaseInput) (*mcp.CallToolResult, *strongbox.UnlockResponse, error) {
	status, err := s.client.GetStatus()
	if err != nil {
		return nil, nil, fmt.Errorf("getting status: %v", err)
	}
	dbID, err := lookupDatabase(status, in.Database)
	if err != nil {
		return nil, nil, err
	}
	result, err := s.client.UnlockDatabase(dbID)
	if err != nil {
		return nil, nil, fmt.Errorf("unlocking database: %v", err)
	}
	return nil, result, nil
}
