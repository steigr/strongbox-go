package strongbox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// ---------------------------------------------------------------------------
// mockTransport simulates a Strongbox afproxy server.  It owns a NaCl
// keypair, decrypts incoming encrypted requests, routes them by message type,
// and encrypts the response back to the client.
// ---------------------------------------------------------------------------

type mockTransport struct {
	mu         sync.Mutex
	publicKey  *[32]byte
	privateKey *[32]byte

	// handlers maps message type → handler func.
	// The handler receives the decrypted inner JSON payload and returns the
	// response object to be encrypted back to the client, or an error.
	handlers map[AutoFillMessageType]func(raw json.RawMessage) (any, error)

	// calls records every (messageType, rawInnerJSON) pair received.
	calls []mockCall
}

type mockCall struct {
	MessageType AutoFillMessageType
	InnerJSON   json.RawMessage
}

func newMockTransport() *mockTransport {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &mockTransport{
		publicKey:  pub,
		privateKey: priv,
		handlers:   make(map[AutoFillMessageType]func(json.RawMessage) (any, error)),
	}
}

func (m *mockTransport) sendRaw(request any) (*EncryptedResponse, error) {
	reqBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	var req EncryptedRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("mock: unmarshal request: %w", err)
	}

	// For the status handshake the client sends an unencrypted request
	// (Message field is empty).
	handler, ok := m.handlers[req.MessageType]
	if !ok {
		return &EncryptedResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("mock: no handler for message type %d", req.MessageType),
		}, nil
	}

	var innerJSON json.RawMessage

	if req.Message != "" {
		// Decrypt the inner payload.
		clientPKBytes, err := base64.StdEncoding.DecodeString(req.ClientPublicKey)
		if err != nil {
			return nil, fmt.Errorf("mock: decode client public key: %w", err)
		}
		nonceBytes, err := base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			return nil, fmt.Errorf("mock: decode nonce: %w", err)
		}
		msgBytes, err := base64.StdEncoding.DecodeString(req.Message)
		if err != nil {
			return nil, fmt.Errorf("mock: decode message: %w", err)
		}

		var clientPK [32]byte
		copy(clientPK[:], clientPKBytes)
		var nonce [24]byte
		copy(nonce[:], nonceBytes)

		decrypted, ok := box.Open(nil, msgBytes, &nonce, &clientPK, m.privateKey)
		if !ok {
			return nil, fmt.Errorf("mock: decryption failed")
		}
		innerJSON = decrypted
	}

	m.mu.Lock()
	m.calls = append(m.calls, mockCall{MessageType: req.MessageType, InnerJSON: innerJSON})
	m.mu.Unlock()

	// Call handler to get response payload.
	respPayload, err := handler(innerJSON)
	if err != nil {
		return &EncryptedResponse{
			Success:      false,
			ErrorMessage: err.Error(),
		}, nil
	}

	// Encrypt the response back to the client.
	respJSON, err := json.Marshal(respPayload)
	if err != nil {
		return nil, fmt.Errorf("mock: marshal response: %w", err)
	}

	clientPKBytes, _ := base64.StdEncoding.DecodeString(req.ClientPublicKey)
	var clientPK [32]byte
	copy(clientPK[:], clientPKBytes)

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	encrypted := box.Seal(nil, respJSON, &nonce, &clientPK, m.privateKey)

	return &EncryptedResponse{
		Success:         true,
		ServerPublicKey: base64.StdEncoding.EncodeToString(m.publicKey[:]),
		Nonce:           base64.StdEncoding.EncodeToString(nonce[:]),
		Message:         base64.StdEncoding.EncodeToString(encrypted),
	}, nil
}

// ---------------------------------------------------------------------------
// Test helper: create a client wired to a mock transport
// ---------------------------------------------------------------------------

func newTestClient(t *testing.T, mock *mockTransport) *Client {
	t.Helper()
	c, err := NewClient(WithTransport(mock))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// setupStatusHandler registers a status handler on the mock that returns the
// given databases.  Almost every test needs this because the client performs a
// status handshake to obtain the server public key before sending encrypted
// requests.
func setupStatusHandler(mock *mockTransport, databases []DatabaseSummary) {
	mock.handlers[MessageTypeStatus] = func(_ json.RawMessage) (any, error) {
		return &GetStatusResponse{
			ServerVersionInfo: "Strongbox Mock v1.0",
			Databases:         databases,
		}, nil
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestGetStatus(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, []DatabaseSummary{
		{UUID: "db-1", NickName: "Work", Locked: false, AutoFillEnabled: true},
		{UUID: "db-2", NickName: "Personal", Locked: true, AutoFillEnabled: false},
	})

	client := newTestClient(t, mock)
	status, err := client.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}

	if status.ServerVersionInfo != "Strongbox Mock v1.0" {
		t.Errorf("ServerVersionInfo = %q, want %q", status.ServerVersionInfo, "Strongbox Mock v1.0")
	}
	if len(status.Databases) != 2 {
		t.Fatalf("len(Databases) = %d, want 2", len(status.Databases))
	}
	if status.Databases[0].UUID != "db-1" {
		t.Errorf("Databases[0].UUID = %q, want %q", status.Databases[0].UUID, "db-1")
	}
	if status.Databases[0].NickName != "Work" {
		t.Errorf("Databases[0].NickName = %q, want %q", status.Databases[0].NickName, "Work")
	}
	if status.Databases[0].Locked {
		t.Error("Databases[0].Locked = true, want false")
	}
	if status.Databases[1].Locked != true {
		t.Error("Databases[1].Locked = false, want true")
	}
}

func TestSearch(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeSearch] = func(raw json.RawMessage) (any, error) {
		var req SearchRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.Query != "github" {
			return &SearchResponse{}, nil
		}
		return &SearchResponse{
			Results: []AutoFillCredential{
				{UUID: "cred-1", Title: "GitHub", Username: "user@example.com", URL: "https://github.com"},
				{UUID: "cred-2", Title: "GitHub Enterprise", Username: "admin", URL: "https://github.example.com"},
			},
		}, nil
	}

	client := newTestClient(t, mock)

	t.Run("basic search", func(t *testing.T) {
		result, err := client.Search("github", 0, 10)
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		if len(result.Results) != 2 {
			t.Fatalf("len(Results) = %d, want 2", len(result.Results))
		}
		if result.Results[0].Title != "GitHub" {
			t.Errorf("Results[0].Title = %q, want %q", result.Results[0].Title, "GitHub")
		}
		if result.Results[1].Username != "admin" {
			t.Errorf("Results[1].Username = %q, want %q", result.Results[1].Username, "admin")
		}
	})

	t.Run("no results", func(t *testing.T) {
		result, err := client.Search("nonexistent", 0, 10)
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		if len(result.Results) != 0 {
			t.Errorf("len(Results) = %d, want 0", len(result.Results))
		}
	})
}

func TestSearchAll(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	// Return results in pages: first 100, then 50, then 0.
	callCount := 0
	mock.handlers[MessageTypeSearch] = func(raw json.RawMessage) (any, error) {
		var req SearchRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		callCount++
		switch {
		case req.Skip == 0:
			creds := make([]AutoFillCredential, 100)
			for i := range creds {
				creds[i] = AutoFillCredential{UUID: fmt.Sprintf("cred-%d", i), Title: fmt.Sprintf("Entry %d", i)}
			}
			return &SearchResponse{Results: creds}, nil
		case req.Skip == 100:
			creds := make([]AutoFillCredential, 50)
			for i := range creds {
				creds[i] = AutoFillCredential{UUID: fmt.Sprintf("cred-%d", 100+i), Title: fmt.Sprintf("Entry %d", 100+i)}
			}
			return &SearchResponse{Results: creds}, nil
		default:
			return &SearchResponse{}, nil
		}
	}

	client := newTestClient(t, mock)
	result, err := client.Search("all", 0, -1)
	if err != nil {
		t.Fatalf("Search(take=-1): %v", err)
	}
	if len(result.Results) != 150 {
		t.Errorf("len(Results) = %d, want 150", len(result.Results))
	}
}

func TestCredentialsForURL(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeGetCredentialsForURL] = func(raw json.RawMessage) (any, error) {
		var req CredentialsForURLRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return &CredentialsForURLResponse{
			UnlockedDatabaseCount: 1,
			Results: []AutoFillCredential{
				{UUID: "cred-url-1", Title: "GitHub Login", URL: req.URL, Username: "user"},
			},
		}, nil
	}

	client := newTestClient(t, mock)
	result, err := client.CredentialsForURL("https://github.com", 0, 10)
	if err != nil {
		t.Fatalf("CredentialsForURL: %v", err)
	}
	if result.UnlockedDatabaseCount != 1 {
		t.Errorf("UnlockedDatabaseCount = %d, want 1", result.UnlockedDatabaseCount)
	}
	if len(result.Results) != 1 {
		t.Fatalf("len(Results) = %d, want 1", len(result.Results))
	}
	if result.Results[0].URL != "https://github.com" {
		t.Errorf("Results[0].URL = %q, want %q", result.Results[0].URL, "https://github.com")
	}
}

func TestCredentialsForURLAll(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	callCount := 0
	mock.handlers[MessageTypeGetCredentialsForURL] = func(raw json.RawMessage) (any, error) {
		var req CredentialsForURLRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		callCount++
		if req.Skip == 0 {
			return &CredentialsForURLResponse{
				UnlockedDatabaseCount: 2,
				Results: []AutoFillCredential{
					{UUID: "c1", Title: "Entry 1"},
					{UUID: "c2", Title: "Entry 2"},
				},
			}, nil
		}
		return &CredentialsForURLResponse{UnlockedDatabaseCount: 2}, nil
	}

	client := newTestClient(t, mock)
	result, err := client.CredentialsForURL("https://example.com", 0, -1)
	if err != nil {
		t.Fatalf("CredentialsForURL(take=-1): %v", err)
	}
	if len(result.Results) != 2 {
		t.Errorf("len(Results) = %d, want 2", len(result.Results))
	}
	if result.UnlockedDatabaseCount != 2 {
		t.Errorf("UnlockedDatabaseCount = %d, want 2", result.UnlockedDatabaseCount)
	}
}

func TestLockDatabase(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeLock] = func(raw json.RawMessage) (any, error) {
		var req LockRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return &LockResponse{DatabaseID: req.DatabaseID}, nil
	}

	client := newTestClient(t, mock)
	result, err := client.LockDatabase("db-42")
	if err != nil {
		t.Fatalf("LockDatabase: %v", err)
	}
	if result.DatabaseID != "db-42" {
		t.Errorf("DatabaseID = %q, want %q", result.DatabaseID, "db-42")
	}
}

func TestUnlockDatabase(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeUnlock] = func(raw json.RawMessage) (any, error) {
		var req UnlockRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.DatabaseID == "db-42" {
			return &UnlockResponse{Success: true}, nil
		}
		return &UnlockResponse{Success: false}, nil
	}

	client := newTestClient(t, mock)

	t.Run("success", func(t *testing.T) {
		result, err := client.UnlockDatabase("db-42")
		if err != nil {
			t.Fatalf("UnlockDatabase: %v", err)
		}
		if !result.Success {
			t.Error("Success = false, want true")
		}
	})

	t.Run("wrong database", func(t *testing.T) {
		result, err := client.UnlockDatabase("db-999")
		if err != nil {
			t.Fatalf("UnlockDatabase: %v", err)
		}
		if result.Success {
			t.Error("Success = true, want false")
		}
	})
}

func TestCreateEntry(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeCreateEntry] = func(raw json.RawMessage) (any, error) {
		var req CreateEntryRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		uuid := "new-entry-uuid"
		return &CreateEntryResponse{
			UUID: &uuid,
			Credential: &AutoFillCredential{
				DatabaseID: req.DatabaseID,
				UUID:       uuid,
				Title:      deref(req.Title),
				Username:   deref(req.Username),
				Password:   deref(req.Password),
				URL:        deref(req.URL),
			},
		}, nil
	}

	client := newTestClient(t, mock)

	title := "Test Account"
	username := "testuser"
	password := "s3cret!"
	url := "https://example.com"

	result, err := client.CreateEntry(&CreateEntryRequest{
		DatabaseID: "db-1",
		Title:      &title,
		Username:   &username,
		Password:   &password,
		URL:        &url,
	})
	if err != nil {
		t.Fatalf("CreateEntry: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("CreateEntry error: %s", *result.Error)
	}
	if result.UUID == nil || *result.UUID != "new-entry-uuid" {
		t.Errorf("UUID = %v, want %q", result.UUID, "new-entry-uuid")
	}
	if result.Credential == nil {
		t.Fatal("Credential is nil")
	}
	if result.Credential.Title != "Test Account" {
		t.Errorf("Credential.Title = %q, want %q", result.Credential.Title, "Test Account")
	}
	if result.Credential.Username != "testuser" {
		t.Errorf("Credential.Username = %q, want %q", result.Credential.Username, "testuser")
	}
	if result.Credential.URL != "https://example.com" {
		t.Errorf("Credential.URL = %q, want %q", result.Credential.URL, "https://example.com")
	}
}

func TestGetGroups(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeGetGroups] = func(raw json.RawMessage) (any, error) {
		var req GetGroupsRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return &GetGroupsResponse{
			Groups: []GroupSummary{
				{UUID: "group-1", Title: "Root"},
				{UUID: "group-2", Title: "Social"},
			},
		}, nil
	}

	client := newTestClient(t, mock)
	result, err := client.GetGroups("db-1")
	if err != nil {
		t.Fatalf("GetGroups: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("GetGroups error: %s", *result.Error)
	}
	if len(result.Groups) != 2 {
		t.Fatalf("len(Groups) = %d, want 2", len(result.Groups))
	}
	if result.Groups[0].Title != "Root" {
		t.Errorf("Groups[0].Title = %q, want %q", result.Groups[0].Title, "Root")
	}
}

func TestGetNewEntryDefaults(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeGetNewEntryDefaults] = func(raw json.RawMessage) (any, error) {
		user := "admin@example.com"
		pass := "generated-password"
		return &GetNewEntryDefaultsResponse{
			Username:             &user,
			MostPopularUsernames: []string{"admin@example.com", "user@example.com"},
			Password:             &pass,
		}, nil
	}

	client := newTestClient(t, mock)
	result, err := client.GetNewEntryDefaults("db-1")
	if err != nil {
		t.Fatalf("GetNewEntryDefaults: %v", err)
	}
	if result.Username == nil || *result.Username != "admin@example.com" {
		t.Errorf("Username = %v, want %q", result.Username, "admin@example.com")
	}
	if result.Password == nil || *result.Password != "generated-password" {
		t.Errorf("Password = %v, want %q", result.Password, "generated-password")
	}
	if len(result.MostPopularUsernames) != 2 {
		t.Errorf("len(MostPopularUsernames) = %d, want 2", len(result.MostPopularUsernames))
	}
}

func TestGetNewEntryDefaultsV2(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeGetNewEntryDefaultsV2] = func(raw json.RawMessage) (any, error) {
		user := "admin"
		return &GetNewEntryDefaultsResponseV2{
			Username: &user,
			Password: &PasswordAndStrength{
				Password: "Str0ng!P@ss",
				Strength: PasswordStrengthData{
					Entropy:       72.5,
					Category:      "strong",
					SummaryString: "Strong password",
				},
			},
		}, nil
	}

	client := newTestClient(t, mock)
	result, err := client.GetNewEntryDefaultsV2("db-1")
	if err != nil {
		t.Fatalf("GetNewEntryDefaultsV2: %v", err)
	}
	if result.Password == nil {
		t.Fatal("Password is nil")
	}
	if result.Password.Password != "Str0ng!P@ss" {
		t.Errorf("Password.Password = %q, want %q", result.Password.Password, "Str0ng!P@ss")
	}
	if result.Password.Strength.Category != "strong" {
		t.Errorf("Strength.Category = %q, want %q", result.Password.Strength.Category, "strong")
	}
	if result.Password.Strength.Entropy != 72.5 {
		t.Errorf("Strength.Entropy = %f, want 72.5", result.Password.Strength.Entropy)
	}
}

func TestGeneratePassword(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeGeneratePassword] = func(_ json.RawMessage) (any, error) {
		return &GeneratePasswordResponse{
			Password:     "xK9!mP2@qR",
			Alternatives: []string{"aB3#dE5$fG", "hI7&jK9*lM"},
		}, nil
	}

	client := newTestClient(t, mock)
	result, err := client.GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword: %v", err)
	}
	if result.Password != "xK9!mP2@qR" {
		t.Errorf("Password = %q, want %q", result.Password, "xK9!mP2@qR")
	}
	if len(result.Alternatives) != 2 {
		t.Errorf("len(Alternatives) = %d, want 2", len(result.Alternatives))
	}
}

func TestGeneratePasswordV2(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeGeneratePasswordV2] = func(_ json.RawMessage) (any, error) {
		return &GeneratePasswordV2Response{
			Password: PasswordAndStrength{
				Password: "SecurePass123!",
				Strength: PasswordStrengthData{
					Entropy:       65.3,
					Category:      "strong",
					SummaryString: "Good password",
				},
			},
			Alternatives: []string{"alt1", "alt2", "alt3"},
		}, nil
	}

	client := newTestClient(t, mock)
	result, err := client.GeneratePasswordV2()
	if err != nil {
		t.Fatalf("GeneratePasswordV2: %v", err)
	}
	if result.Password.Password != "SecurePass123!" {
		t.Errorf("Password.Password = %q, want %q", result.Password.Password, "SecurePass123!")
	}
	if result.Password.Strength.Category != "strong" {
		t.Errorf("Strength.Category = %q, want %q", result.Password.Strength.Category, "strong")
	}
	if len(result.Alternatives) != 3 {
		t.Errorf("len(Alternatives) = %d, want 3", len(result.Alternatives))
	}
}

func TestGetPasswordStrength(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeGetPasswordStrength] = func(raw json.RawMessage) (any, error) {
		var req GetPasswordAndStrengthRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		// Simple mock: longer passwords are "stronger".
		entropy := float64(len(req.Password)) * 4.0
		cat := "weak"
		if entropy > 40 {
			cat = "medium"
		}
		if entropy > 60 {
			cat = "strong"
		}
		return &GetPasswordAndStrengthResponse{
			Strength: PasswordStrengthData{
				Entropy:       entropy,
				Category:      cat,
				SummaryString: cat + " password",
			},
		}, nil
	}

	client := newTestClient(t, mock)

	t.Run("weak password", func(t *testing.T) {
		result, err := client.GetPasswordStrength("abc")
		if err != nil {
			t.Fatalf("GetPasswordStrength: %v", err)
		}
		if result.Strength.Category != "weak" {
			t.Errorf("Category = %q, want %q", result.Strength.Category, "weak")
		}
	})

	t.Run("strong password", func(t *testing.T) {
		result, err := client.GetPasswordStrength("ThisIsAVeryStrongPassword!")
		if err != nil {
			t.Fatalf("GetPasswordStrength: %v", err)
		}
		if result.Strength.Category != "strong" {
			t.Errorf("Category = %q, want %q", result.Strength.Category, "strong")
		}
	})
}

func TestCopyField(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeCopyField] = func(raw json.RawMessage) (any, error) {
		var req CopyFieldRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return &CopyFieldResponse{Success: true}, nil
	}

	client := newTestClient(t, mock)

	t.Run("copy password", func(t *testing.T) {
		result, err := client.CopyField("db-1", "node-1", FieldPassword, false)
		if err != nil {
			t.Fatalf("CopyField: %v", err)
		}
		if !result.Success {
			t.Error("Success = false, want true")
		}
	})

	t.Run("copy totp", func(t *testing.T) {
		result, err := client.CopyField("db-1", "node-1", FieldTOTP, true)
		if err != nil {
			t.Fatalf("CopyField: %v", err)
		}
		if !result.Success {
			t.Error("Success = false, want true")
		}
	})

	// Verify the requests were decoded correctly by the mock.
	mock.mu.Lock()
	defer mock.mu.Unlock()
	// Skip the status call(s); find the CopyField calls.
	var copyFieldCalls []mockCall
	for _, c := range mock.calls {
		if c.MessageType == MessageTypeCopyField {
			copyFieldCalls = append(copyFieldCalls, c)
		}
	}
	if len(copyFieldCalls) != 2 {
		t.Fatalf("expected 2 CopyField calls, got %d", len(copyFieldCalls))
	}

	var req1, req2 CopyFieldRequest
	json.Unmarshal(copyFieldCalls[0].InnerJSON, &req1)
	json.Unmarshal(copyFieldCalls[1].InnerJSON, &req2)

	if req1.Field != FieldPassword {
		t.Errorf("call 1 Field = %d, want %d (FieldPassword)", req1.Field, FieldPassword)
	}
	if req1.ExplicitTOTP {
		t.Error("call 1 ExplicitTOTP = true, want false")
	}
	if req2.Field != FieldTOTP {
		t.Errorf("call 2 Field = %d, want %d (FieldTOTP)", req2.Field, FieldTOTP)
	}
	if !req2.ExplicitTOTP {
		t.Error("call 2 ExplicitTOTP = false, want true")
	}
}

func TestCopyString(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeCopyString] = func(raw json.RawMessage) (any, error) {
		var req CopyStringRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return &CopyStringResponse{Success: true}, nil
	}

	client := newTestClient(t, mock)
	result, err := client.CopyString("hello clipboard")
	if err != nil {
		t.Fatalf("CopyString: %v", err)
	}
	if !result.Success {
		t.Error("Success = false, want true")
	}

	// Verify the inner request payload.
	mock.mu.Lock()
	defer mock.mu.Unlock()
	for _, c := range mock.calls {
		if c.MessageType == MessageTypeCopyString {
			var req CopyStringRequest
			json.Unmarshal(c.InnerJSON, &req)
			if req.Value != "hello clipboard" {
				t.Errorf("Value = %q, want %q", req.Value, "hello clipboard")
			}
			break
		}
	}
}

func TestGetIcon(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeGetIcon] = func(raw json.RawMessage) (any, error) {
		var req GetIconRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return &GetIconResponse{Icon: "iVBORw0KGgoAAAANSUhEUg=="}, nil
	}

	client := newTestClient(t, mock)
	result, err := client.GetIcon("db-1", "node-1")
	if err != nil {
		t.Fatalf("GetIcon: %v", err)
	}
	if result.Icon == "" {
		t.Error("Icon is empty")
	}
}

// ---------------------------------------------------------------------------
// Error handling tests
// ---------------------------------------------------------------------------

func TestServerError(t *testing.T) {
	mock := newMockTransport()
	// Status handler returns a server error.
	mock.handlers[MessageTypeStatus] = func(_ json.RawMessage) (any, error) {
		return nil, fmt.Errorf("database corruption detected")
	}

	client := newTestClient(t, mock)
	_, err := client.GetStatus()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "server error: database corruption detected" {
		t.Errorf("error = %q, want to contain %q", got, "database corruption detected")
	}
}

func TestTransportError(t *testing.T) {
	errTransport := &errorTransport{err: fmt.Errorf("connection refused")}
	client, err := NewClient(WithTransport(errTransport))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.GetStatus()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "connection refused" {
		t.Errorf("error = %q, want %q", got, "connection refused")
	}
}

// errorTransport always returns an error.
type errorTransport struct {
	err error
}

func (e *errorTransport) sendRaw(_ any) (*EncryptedResponse, error) {
	return nil, e.err
}

// ---------------------------------------------------------------------------
// Concurrency test
// ---------------------------------------------------------------------------

func TestConcurrentRequests(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)

	mock.handlers[MessageTypeSearch] = func(raw json.RawMessage) (any, error) {
		var req SearchRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return &SearchResponse{
			Results: []AutoFillCredential{
				{UUID: "c-" + req.Query, Title: req.Query},
			},
		}, nil
	}

	client := newTestClient(t, mock)

	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			query := fmt.Sprintf("query-%d", i)
			result, err := client.Search(query, 0, 10)
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", i, err)
				return
			}
			if len(result.Results) != 1 {
				errs <- fmt.Errorf("goroutine %d: got %d results, want 1", i, len(result.Results))
				return
			}
			if result.Results[0].Title != query {
				errs <- fmt.Errorf("goroutine %d: Title = %q, want %q", i, result.Results[0].Title, query)
				return
			}
			errs <- nil
		}(i)
	}

	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}

// ---------------------------------------------------------------------------
// Message type tests
// ---------------------------------------------------------------------------

func TestParseMessageType(t *testing.T) {
	tests := []struct {
		input string
		want  AutoFillMessageType
		ok    bool
	}{
		{"status", MessageTypeStatus, true},
		{"Status", MessageTypeStatus, true},
		{"search", MessageTypeSearch, true},
		{"get-url", MessageTypeGetCredentialsForURL, true},
		{"getcredentialsforurl", MessageTypeGetCredentialsForURL, true},
		{"copy-field", MessageTypeCopyField, true},
		{"lock", MessageTypeLock, true},
		{"unlock", MessageTypeUnlock, true},
		{"create-entry", MessageTypeCreateEntry, true},
		{"generate-password", MessageTypeGeneratePassword, true},
		{"generate-password-v2", MessageTypeGeneratePasswordV2, true},
		{"password-strength", MessageTypeGetPasswordStrength, true},
		{"copy-string", MessageTypeCopyString, true},
		{"nonexistent", MessageTypeUnknown, false},
		{"", MessageTypeUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := ParseMessageType(tt.input)
			if ok != tt.ok {
				t.Errorf("ParseMessageType(%q) ok = %v, want %v", tt.input, ok, tt.ok)
			}
			if got != tt.want {
				t.Errorf("ParseMessageType(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestMessageTypeString(t *testing.T) {
	if s := MessageTypeStatus.String(); s != "status" {
		t.Errorf("MessageTypeStatus.String() = %q, want %q", s, "status")
	}
	if s := MessageTypeUnknown.String(); s != "unknown" {
		t.Errorf("MessageTypeUnknown.String() = %q, want %q", s, "unknown")
	}
}

// ---------------------------------------------------------------------------
// WithProxyPath test
// ---------------------------------------------------------------------------

func TestWithProxyPath(t *testing.T) {
	client, err := NewClient(WithProxyPath("/custom/path"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.proxyPath != "/custom/path" {
		t.Errorf("proxyPath = %q, want %q", client.proxyPath, "/custom/path")
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
