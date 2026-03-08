package strongbox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"

	"golang.org/x/crypto/nacl/box"
)

// defaultProxyPath is the standard installation path for the Strongbox native messaging host (afproxy)
// on macOS. This binary is used to communicate with the Strongbox Password Manager application.
const defaultProxyPath = "/Applications/Strongbox.app/Contents/MacOS/afproxy"

// transport is the internal interface for sending a raw native-messaging request.
// The default implementation spawns an afproxy process. Tests can substitute a mock
// via WithTransport.
type transport interface {
	sendRaw(request any) (*EncryptedResponse, error)
}

// Client communicates with the Strongbox native messaging host (afproxy) using the browser
// extension protocol. It handles encryption/decryption of messages using NaCl box encryption
// and manages the lifecycle of afproxy processes.
//
// The Client is safe for concurrent use. Each request spawns a new afproxy process,
// The Client is safe for concurrent use. Each request spawns a new afproxy process,
// matching the behavior of browser native messaging.
type Client struct {
	// proxyPath is the filesystem path to the afproxy binary
	proxyPath string

	// transport is the pluggable I/O backend (defaults to afproxyTransport)
	transport transport

	// mu protects the client's cryptographic state (keys)
	mu sync.Mutex
	// publicKey is the client's Curve25519 public key for encryption
	publicKey *[32]byte
	// privateKey is the client's Curve25519 private key for decryption
	privateKey *[32]byte
	// serverPublicKey is the Strongbox server's public key, obtained during the initial handshake
	serverPublicKey *[32]byte
}

// Option is a functional option for configuring a Client.
type Option func(*Client)

// WithProxyPath sets a custom path to the afproxy binary.
// This is useful when Strongbox is installed in a non-standard location or when testing.
//
// Example:
//
//	client, err := strongbox.NewClient(strongbox.WithProxyPath("/custom/path/to/afproxy"))
func WithProxyPath(path string) Option {
	return func(c *Client) { c.proxyPath = path }
}

// WithTransport sets a custom transport for the client.
// This is primarily useful for testing, allowing you to mock the afproxy communication.
func WithTransport(t transport) Option {
	return func(c *Client) { c.transport = t }
}

// NewClient creates a new Strongbox client with the specified options.
// It generates an ephemeral Curve25519 keypair for encrypting communication with the server.
//
// By default, it uses the standard afproxy path at /Applications/Strongbox.app/Contents/MacOS/afproxy.
// Use WithProxyPath to specify a custom location.
//
// Example:
//
//	// Create a client with default settings
//	client, err := strongbox.NewClient()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create a client with a custom proxy path
//	client, err := strongbox.NewClient(strongbox.WithProxyPath("/custom/path/to/afproxy"))
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewClient(opts ...Option) (*Client, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating keypair: %w", err)
	}
	c := &Client{
		proxyPath:  defaultProxyPath,
		publicKey:  pub,
		privateKey: priv,
	}
	for _, o := range opts {
		o(c)
	}
	// Default transport: spawn afproxy processes
	if c.transport == nil {
		c.transport = &afproxyTransport{proxyPath: c.proxyPath}
	}
	return c, nil
}

// SendRaw sends a single native-messaging request and returns the raw encrypted response.
// Each call spawns a new afproxy process (matching browser native messaging behavior).
//
// This is a low-level method that doesn't handle decryption. Most users should use the
// higher-level methods like GetStatus, Search, etc. This method is exposed for advanced
// use cases where you need direct control over the request/response cycle.
//
// The request is marshaled to JSON and sent using the native messaging protocol
// (4-byte little-endian length prefix followed by the JSON payload).
func (c *Client) SendRaw(request any) (*EncryptedResponse, error) {
	return c.sendRaw(request)
}

func (c *Client) sendRaw(request any) (*EncryptedResponse, error) {
	return c.transport.sendRaw(request)
}

// afproxyTransport is the default transport that spawns an afproxy process for each request.
type afproxyTransport struct {
	proxyPath string
}

func (t *afproxyTransport) sendRaw(request any) (*EncryptedResponse, error) {
	reqBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	cmd := exec.Command(t.proxyPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting afproxy: %w", err)
	}

	// Write length-prefixed message (4-byte little-endian + JSON)
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(reqBytes)))
	if _, err := stdin.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("writing length: %w", err)
	}
	if _, err := stdin.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("writing message: %w", err)
	}
	stdin.Close()

	// Read length-prefixed response
	if _, err := io.ReadFull(stdout, lenBuf); err != nil {
		return nil, fmt.Errorf("reading response length: %w", err)
	}
	respLen := binary.LittleEndian.Uint32(lenBuf)
	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(stdout, respBytes); err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		// afproxy may exit non-zero after responding; ignore if we got data
	}

	var resp EncryptedResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("unmarshaling response: %w", err)
	}
	return &resp, nil
}

// decryptResponse decrypts an EncryptedResponse from the server and unmarshals the result.
// It uses NaCl box encryption (Curve25519, XSalsa20, and Poly1305) to decrypt the message
// using the server's public key and the client's private key.
//
// The server's public key is cached after the first successful decryption. If decryption fails,
// the cached key is cleared to force a fresh handshake on the next request.
func (c *Client) decryptResponse(resp *EncryptedResponse, result any) error {
	if !resp.Success {
		return fmt.Errorf("server error: %s", resp.ErrorMessage)
	}

	msgBytes, err := base64.StdEncoding.DecodeString(resp.Message)
	if err != nil {
		return fmt.Errorf("decoding message: %w", err)
	}
	nonceBytes, err := base64.StdEncoding.DecodeString(resp.Nonce)
	if err != nil {
		return fmt.Errorf("decoding nonce: %w", err)
	}
	serverPKBytes, err := base64.StdEncoding.DecodeString(resp.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("decoding server public key: %w", err)
	}

	var nonce [24]byte
	copy(nonce[:], nonceBytes)
	var serverPK [32]byte
	copy(serverPK[:], serverPKBytes)

	c.mu.Lock()
	c.serverPublicKey = &serverPK
	c.mu.Unlock()

	decrypted, ok := box.Open(nil, msgBytes, &nonce, &serverPK, c.privateKey)
	if !ok {
		c.mu.Lock()
		c.serverPublicKey = nil
		c.mu.Unlock()
		return fmt.Errorf("decryption failed")
	}

	return json.Unmarshal(decrypted, result)
}

// ensureServerPublicKey ensures that the client has the server's public key.
// If the key is not yet cached, it performs a GetStatus request to establish
// the initial handshake and obtain the key.
func (c *Client) ensureServerPublicKey() error {
	c.mu.Lock()
	hasPK := c.serverPublicKey != nil
	c.mu.Unlock()
	if hasPK {
		return nil
	}
	_, err := c.GetStatus()
	return err
}

// BuildEncryptedRequest constructs an encrypted request envelope for the given payload.
// This is a low-level method exposed for advanced use cases. Most users should use
// the higher-level methods like Search, CreateEntry, etc.
//
// The method ensures the server's public key is available (performing a handshake if needed),
// generates a random nonce, encrypts the inner request using NaCl box encryption,
// and returns a fully constructed EncryptedRequest ready to be sent via SendRaw.
func (c *Client) BuildEncryptedRequest(innerRequest any, msgType AutoFillMessageType) (*EncryptedRequest, error) {
	return c.buildEncryptedRequest(innerRequest, msgType)
}

func (c *Client) buildEncryptedRequest(innerRequest any, msgType AutoFillMessageType) (*EncryptedRequest, error) {
	if err := c.ensureServerPublicKey(); err != nil {
		return nil, fmt.Errorf("ensuring server public key: %w", err)
	}

	innerJSON, err := json.Marshal(innerRequest)
	if err != nil {
		return nil, fmt.Errorf("marshaling inner request: %w", err)
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	c.mu.Lock()
	serverPK := c.serverPublicKey
	c.mu.Unlock()

	encrypted := box.Seal(nil, innerJSON, &nonce, serverPK, c.privateKey)

	return &EncryptedRequest{
		MessageType:     msgType,
		ClientPublicKey: base64.StdEncoding.EncodeToString(c.publicKey[:]),
		Nonce:           base64.StdEncoding.EncodeToString(nonce[:]),
		Message:         base64.StdEncoding.EncodeToString(encrypted),
	}, nil
}

// SendEncrypted sends an encrypted request and decrypts the response into the result parameter.
// This is a low-level method exposed for advanced use cases. Most users should use
// the higher-level methods like Search, CreateEntry, etc.
//
// The method builds an encrypted request, sends it via SendRaw, and decrypts the response
// into the provided result parameter. The result parameter should be a pointer to the
// expected response type.
func (c *Client) SendEncrypted(innerRequest any, msgType AutoFillMessageType, result any) error {
	return c.sendEncrypted(innerRequest, msgType, result)
}

func (c *Client) sendEncrypted(innerRequest any, msgType AutoFillMessageType, result any) error {
	req, err := c.buildEncryptedRequest(innerRequest, msgType)
	if err != nil {
		return err
	}
	resp, err := c.sendRaw(req)
	if err != nil {
		return err
	}
	return c.decryptResponse(resp, result)
}

// GetStatus retrieves the status of the Strongbox server, including the list of databases.
//
// This method performs the initial handshake with the server if needed, establishing
// the encrypted communication channel. It returns information about all databases
// known to Strongbox, their lock state, and global server settings.
//
// Example:
//
//	status, err := client.GetStatus()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Strongbox version: %s\n", status.ServerVersionInfo)
//	for _, db := range status.Databases {
//	    fmt.Printf("Database: %s (locked: %t)\n", db.NickName, db.Locked)
//	}
func (c *Client) GetStatus() (*GetStatusResponse, error) {
	req := &EncryptedRequest{
		MessageType:     MessageTypeStatus,
		ClientPublicKey: base64.StdEncoding.EncodeToString(c.publicKey[:]),
	}
	resp, err := c.sendRaw(req)
	if err != nil {
		return nil, err
	}
	var status GetStatusResponse
	if err := c.decryptResponse(resp, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// Search searches for credentials matching the query across all unlocked databases.
//
// The query parameter is matched against credential titles, usernames, URLs, and other fields.
// The skip and take parameters provide pagination support. Set take to -1 to fetch all results
// (the method will automatically paginate through all available results).
//
// Example:
//
//	// Search for GitHub credentials, get first 10 results
//	results, err := client.Search("github", 0, 10)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, cred := range results.Results {
//	    fmt.Printf("%s: %s\n", cred.Title, cred.Username)
//	}
//
//	// Fetch all results matching "example.com"
//	allResults, err := client.Search("example.com", 0, -1)
func (c *Client) Search(query string, skip, take int) (*SearchResponse, error) {
	if take == -1 {
		return c.searchAll(query, skip)
	}
	var result SearchResponse
	err := c.sendEncrypted(&SearchRequest{Query: query, Skip: skip, Take: take}, MessageTypeSearch, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) searchAll(query string, skip int) (*SearchResponse, error) {
	const chunkSize = 100
	var allResults []AutoFillCredential
	currentSkip := skip

	for {
		result, err := c.Search(query, currentSkip, chunkSize)
		if err != nil {
			return nil, err
		}
		if len(result.Results) == 0 {
			break
		}
		allResults = append(allResults, result.Results...)
		if len(result.Results) < chunkSize {
			// If we got fewer than requested, we've likely hit the end or an internal limit
			// To be sure, we check if the next page is empty in the next iteration.
			// However, some APIs might always return fewer than chunkSize if they have a hard internal limit.
			// Let's assume len < chunkSize means we are done or close to it.
		}
		currentSkip += len(result.Results)

		// Strongbox afproxy seems to have a limit around 64 or 100.
		// If we get 0 results, we are definitely done.
	}

	return &SearchResponse{Results: allResults}, nil
}

// CredentialsForURL retrieves credentials that match the given URL.
//
// This method uses Strongbox's URL matching logic to find credentials associated with
// the specified URL. The matching may be fuzzy (e.g., matching subdomains or paths).
// The skip and take parameters provide pagination support. Set take to -1 to fetch all results.
//
// Example:
//
//	// Get credentials for a specific URL
//	results, err := client.CredentialsForURL("https://github.com", 0, 10)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d credentials in %d unlocked databases\n",
//	    len(results.Results), results.UnlockedDatabaseCount)
func (c *Client) CredentialsForURL(url string, skip, take int) (*CredentialsForURLResponse, error) {
	if take == -1 {
		return c.credentialsForURLAll(url, skip)
	}
	var result CredentialsForURLResponse
	err := c.sendEncrypted(&CredentialsForURLRequest{URL: url, Skip: skip, Take: take}, MessageTypeGetCredentialsForURL, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) credentialsForURLAll(url string, skip int) (*CredentialsForURLResponse, error) {
	const chunkSize = 100
	var allResults []AutoFillCredential
	var lastResponse *CredentialsForURLResponse
	currentSkip := skip

	for {
		result, err := c.CredentialsForURL(url, currentSkip, chunkSize)
		if err != nil {
			return nil, err
		}
		lastResponse = result
		if len(result.Results) == 0 {
			break
		}
		allResults = append(allResults, result.Results...)
		currentSkip += len(result.Results)
	}

	if lastResponse == nil {
		return &CredentialsForURLResponse{Results: allResults}, nil
	}
	lastResponse.Results = allResults
	return lastResponse, nil
}

// CopyField copies a specific field of a credential entry to the system clipboard.
//
// This method instructs Strongbox to copy the specified field (username, password, or TOTP)
// to the clipboard. The field parameter should be one of FieldUsername, FieldPassword, or FieldTOTP.
// When copying a TOTP code, set explicitTOTP to true to ensure a fresh code is generated.
//
// Example:
//
//	// Copy a password to the clipboard
//	result, err := client.CopyField(databaseID, nodeID, strongbox.FieldPassword, false)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.Success {
//	    fmt.Println("Password copied to clipboard")
//	}
func (c *Client) CopyField(databaseID, nodeID string, field WellKnownField, explicitTOTP bool) (*CopyFieldResponse, error) {
	var result CopyFieldResponse
	err := c.sendEncrypted(&CopyFieldRequest{
		DatabaseID: databaseID, NodeID: nodeID, Field: field, ExplicitTOTP: explicitTOTP,
	}, MessageTypeCopyField, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// LockDatabase locks the specified database, preventing access until it is unlocked.
//
// Example:
//
//	result, err := client.LockDatabase(databaseID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Database %s is now locked\n", result.DatabaseID)
func (c *Client) LockDatabase(databaseID string) (*LockResponse, error) {
	var result LockResponse
	err := c.sendEncrypted(&LockRequest{DatabaseID: databaseID}, MessageTypeLock, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// UnlockDatabase requests Strongbox to unlock the specified database.
// This typically triggers a prompt in the Strongbox app for the user to enter credentials.
//
// Example:
//
//	result, err := client.UnlockDatabase(databaseID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.Success {
//	    fmt.Println("Database unlocked successfully")
//	}
func (c *Client) UnlockDatabase(databaseID string) (*UnlockResponse, error) {
	var result UnlockResponse
	err := c.sendEncrypted(&UnlockRequest{DatabaseID: databaseID}, MessageTypeUnlock, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// CreateEntry creates a new credential entry in the specified database.
//
// All fields in the request except DatabaseID are optional. Use the Get NewEntryDefaults
// methods to retrieve suggested default values before creating an entry.
//
// Example:
//
//	title := "My GitHub Account"
//	username := "myuser"
//	password := "secret123"
//	url := "https://github.com"
//
//	result, err := client.CreateEntry(&strongbox.CreateEntryRequest{
//	    DatabaseID: databaseID,
//	    Title:      &title,
//	    Username:   &username,
//	    Password:   &password,
//	    URL:        &url,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.Error != nil {
//	    log.Fatalf("Failed to create entry: %s", *result.Error)
//	}
//	fmt.Printf("Created entry with UUID: %s\n", *result.UUID)
func (c *Client) CreateEntry(req *CreateEntryRequest) (*CreateEntryResponse, error) {
	var result CreateEntryResponse
	err := c.sendEncrypted(req, MessageTypeCreateEntry, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetGroups retrieves the group structure for a database.
//
// Groups are used to organize entries hierarchically within a database.
// This method returns a flat list of all groups with their UUIDs and titles.
//
// Example:
//
//	groups, err := client.GetGroups(databaseID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if groups.Error != nil {
//	    log.Fatalf("Error getting groups: %s", *groups.Error)
//	}
//	for _, group := range groups.Groups {
//	    fmt.Printf("Group: %s (UUID: %s)\n", group.Title, group.UUID)
//	}
func (c *Client) GetGroups(databaseID string) (*GetGroupsResponse, error) {
	var result GetGroupsResponse
	err := c.sendEncrypted(&GetGroupsRequest{DatabaseID: databaseID}, MessageTypeGetGroups, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetNewEntryDefaults retrieves default values for a new entry in a database.
//
// This method returns suggested defaults such as commonly used usernames and
// a generated password. Use these defaults when creating new entries to maintain
// consistency with user preferences.
//
// Example:
//
//	defaults, err := client.GetNewEntryDefaults(databaseID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if defaults.Error != nil {
//	    log.Fatalf("Error getting defaults: %s", *defaults.Error)
//	}
//	if defaults.Username != nil {
//	    fmt.Printf("Suggested username: %s\n", *defaults.Username)
//	}
//	if defaults.Password != nil {
//	    fmt.Printf("Generated password: %s\n", *defaults.Password)
//	}
func (c *Client) GetNewEntryDefaults(databaseID string) (*GetNewEntryDefaultsResponse, error) {
	var result GetNewEntryDefaultsResponse
	err := c.sendEncrypted(&GetNewEntryDefaultsRequest{DatabaseID: databaseID}, MessageTypeGetNewEntryDefaults, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetNewEntryDefaultsV2 retrieves defaults (v2) for creating a new entry.
//
// This is an enhanced version of GetNewEntryDefaults that includes password strength
// information along with the generated password. Use this method when you need detailed
// information about password quality.
//
// Example:
//
//	defaults, err := client.GetNewEntryDefaultsV2(databaseID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if defaults.Password != nil {
//	    fmt.Printf("Password: %s (Strength: %s, Entropy: %.2f bits)\n",
//	        defaults.Password.Password,
//	        defaults.Password.Strength.Category,
//	        defaults.Password.Strength.Entropy)
//	}
func (c *Client) GetNewEntryDefaultsV2(databaseID string) (*GetNewEntryDefaultsResponseV2, error) {
	var result GetNewEntryDefaultsResponseV2
	err := c.sendEncrypted(&GetNewEntryDefaultsRequest{DatabaseID: databaseID}, MessageTypeGetNewEntryDefaultsV2, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GeneratePassword generates a random password using Strongbox.
//
// This method uses Strongbox's password generator with the current user's preferences
// (length, character sets, etc.). It returns a primary password and several alternatives.
//
// Example:
//
//	result, err := client.GeneratePassword()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Generated password: %s\n", result.Password)
//	fmt.Printf("Alternatives: %v\n", result.Alternatives)
func (c *Client) GeneratePassword() (*GeneratePasswordResponse, error) {
	var result GeneratePasswordResponse
	err := c.sendEncrypted(struct{}{}, MessageTypeGeneratePassword, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GeneratePasswordV2 generates passwords with strength info.
//
// This is an enhanced version of GeneratePassword that includes detailed strength
// analysis (entropy, category, summary) for the generated password. The alternatives
// are provided as strings without strength info.
//
// Example:
//
//	result, err := client.GeneratePasswordV2()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	pwd := result.Password
//	fmt.Printf("Password: %s\n", pwd.Password)
//	fmt.Printf("Strength: %s (%.2f bits entropy)\n",
//	    pwd.Strength.Category, pwd.Strength.Entropy)
//	fmt.Printf("Summary: %s\n", pwd.Strength.SummaryString)
func (c *Client) GeneratePasswordV2() (*GeneratePasswordV2Response, error) {
	var result GeneratePasswordV2Response
	err := c.sendEncrypted(struct{}{}, MessageTypeGeneratePasswordV2, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetIcon retrieves the icon for an entry.
//
// The icon is returned as a base64-encoded image. Icons may be custom images
// uploaded by the user or favicons automatically fetched for the entry's URL.
//
// Example:
//
//	iconData, err := client.GetIcon(databaseID, nodeID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// iconData.Icon is base64-encoded image data
//	imgBytes, _ := base64.StdEncoding.DecodeString(iconData.Icon)
func (c *Client) GetIcon(databaseID, nodeID string) (*GetIconResponse, error) {
	var result GetIconResponse
	err := c.sendEncrypted(&GetIconRequest{DatabaseID: databaseID, NodeID: nodeID}, MessageTypeGetIcon, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPasswordStrength checks the strength of a password.
//
// This method analyzes a password and returns detailed strength information including
// entropy (in bits), a category classification (e.g., "weak", "medium", "strong"),
// and a human-readable summary string.
//
// Example:
//
//	result, err := client.GetPasswordStrength("MyP@ssw0rd123")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Entropy: %.2f bits\n", result.Strength.Entropy)
//	fmt.Printf("Category: %s\n", result.Strength.Category)
//	fmt.Printf("Summary: %s\n", result.Strength.SummaryString)
func (c *Client) GetPasswordStrength(password string) (*GetPasswordAndStrengthResponse, error) {
	var result GetPasswordAndStrengthResponse
	err := c.sendEncrypted(&GetPasswordAndStrengthRequest{Password: password}, MessageTypeGetPasswordStrength, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// CopyString copies an arbitrary string to the clipboard via Strongbox.
//
// Unlike CopyField which copies a specific field from a credential entry, this method
// copies any string you provide. This is useful when you want to use Strongbox's
// clipboard management features for custom data.
//
// Example:
//
//	result, err := client.CopyString("my custom text")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.Success {
//	    fmt.Println("String copied to clipboard")
//	}
func (c *Client) CopyString(value string) (*CopyStringResponse, error) {
	var result CopyStringResponse
	err := c.sendEncrypted(&CopyStringRequest{Value: value}, MessageTypeCopyString, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
