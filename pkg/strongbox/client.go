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

const defaultProxyPath = "/Applications/Strongbox.app/Contents/MacOS/afproxy"

// Client communicates with the Strongbox native messaging host.
type Client struct {
	proxyPath string

	mu              sync.Mutex
	publicKey       *[32]byte
	privateKey      *[32]byte
	serverPublicKey *[32]byte
}

// Option configures a Client.
type Option func(*Client)

// WithProxyPath sets a custom path to the afproxy binary.
func WithProxyPath(path string) Option {
	return func(c *Client) { c.proxyPath = path }
}

// NewClient creates a new Strongbox client.
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
	return c, nil
}

// sendRaw sends a single native-messaging request and returns the raw response.
// Each call spawns a new afproxy process (matching browser native messaging behavior).
func (c *Client) SendRaw(request any) (*EncryptedResponse, error) {
	return c.sendRaw(request)
}

func (c *Client) sendRaw(request any) (*EncryptedResponse, error) {
	reqBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	cmd := exec.Command(c.proxyPath)
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

// Search searches for credentials matching the query.
// skip and take are used for pagination.
func (c *Client) Search(query string, skip, take int) (*SearchResponse, error) {
	var result SearchResponse
	err := c.sendEncrypted(&SearchRequest{Query: query, Skip: skip, Take: take}, MessageTypeSearch, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// CredentialsForURL retrieves credentials matching the given URL.
func (c *Client) CredentialsForURL(url string, skip, take int) (*CredentialsForURLResponse, error) {
	var result CredentialsForURLResponse
	err := c.sendEncrypted(&CredentialsForURLRequest{URL: url, Skip: skip, Take: take}, MessageTypeGetCredentialsForURL, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// CopyField copies a specific field of an entry to the clipboard.
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

// LockDatabase locks the specified database.
func (c *Client) LockDatabase(databaseID string) (*LockResponse, error) {
	var result LockResponse
	err := c.sendEncrypted(&LockRequest{DatabaseID: databaseID}, MessageTypeLock, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// UnlockDatabase requests Strongbox to unlock the specified database.
// This typically triggers a prompt in the Strongbox app.
func (c *Client) UnlockDatabase(databaseID string) (*UnlockResponse, error) {
	var result UnlockResponse
	err := c.sendEncrypted(&UnlockRequest{DatabaseID: databaseID}, MessageTypeUnlock, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// CreateEntry creates a new entry in the specified database.
func (c *Client) CreateEntry(req *CreateEntryRequest) (*CreateEntryResponse, error) {
	var result CreateEntryResponse
	err := c.sendEncrypted(req, MessageTypeCreateEntry, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetGroups retrieves the group structure for a database.
func (c *Client) GetGroups(databaseID string) (*GetGroupsResponse, error) {
	var result GetGroupsResponse
	err := c.sendEncrypted(&GetGroupsRequest{DatabaseID: databaseID}, MessageTypeGetGroups, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetNewEntryDefaults retrieves default values for a new entry in a database.
func (c *Client) GetNewEntryDefaults(databaseID string) (*GetNewEntryDefaultsResponse, error) {
	var result GetNewEntryDefaultsResponse
	err := c.sendEncrypted(&GetNewEntryDefaultsRequest{DatabaseID: databaseID}, MessageTypeGetNewEntryDefaults, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetNewEntryDefaultsV2 retrieves defaults (v2) for creating a new entry.
func (c *Client) GetNewEntryDefaultsV2(databaseID string) (*GetNewEntryDefaultsResponseV2, error) {
	var result GetNewEntryDefaultsResponseV2
	err := c.sendEncrypted(&GetNewEntryDefaultsRequest{DatabaseID: databaseID}, MessageTypeGetNewEntryDefaultsV2, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GeneratePassword generates a random password using Strongbox.
func (c *Client) GeneratePassword() (*GeneratePasswordResponse, error) {
	var result GeneratePasswordResponse
	err := c.sendEncrypted(struct{}{}, MessageTypeGeneratePassword, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GeneratePasswordV2 generates passwords with strength info.
func (c *Client) GeneratePasswordV2() (*GeneratePasswordV2Response, error) {
	var result GeneratePasswordV2Response
	err := c.sendEncrypted(struct{}{}, MessageTypeGeneratePasswordV2, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetIcon retrieves the icon for an entry.
func (c *Client) GetIcon(databaseID, nodeID string) (*GetIconResponse, error) {
	var result GetIconResponse
	err := c.sendEncrypted(&GetIconRequest{DatabaseID: databaseID, NodeID: nodeID}, MessageTypeGetIcon, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPasswordStrength checks the strength of a password.
func (c *Client) GetPasswordStrength(password string) (*GetPasswordAndStrengthResponse, error) {
	var result GetPasswordAndStrengthResponse
	err := c.sendEncrypted(&GetPasswordAndStrengthRequest{Password: password}, MessageTypeGetPasswordStrength, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// CopyString copies an arbitrary string to the clipboard via Strongbox.
func (c *Client) CopyString(value string) (*CopyStringResponse, error) {
	var result CopyStringResponse
	err := c.sendEncrypted(&CopyStringRequest{Value: value}, MessageTypeCopyString, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
