package strongbox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// ---------------------------------------------------------------------------
// mockTransport simulates a Strongbox afproxy server with NaCl encryption.
// ---------------------------------------------------------------------------

type mockTransport struct {
	mu         sync.Mutex
	publicKey  *[32]byte
	privateKey *[32]byte
	handlers   map[AutoFillMessageType]func(raw json.RawMessage) (any, error)
	calls      []mockCall
}

type mockCall struct {
	MessageType AutoFillMessageType
	InnerJSON   json.RawMessage
}

func newMockTransport() *mockTransport {
	pub, priv, _ := box.GenerateKey(rand.Reader)
	return &mockTransport{publicKey: pub, privateKey: priv, handlers: make(map[AutoFillMessageType]func(json.RawMessage) (any, error))}
}

func (m *mockTransport) sendRaw(request any) (*EncryptedResponse, error) {
	reqBytes, _ := json.Marshal(request)
	var req EncryptedRequest
	json.Unmarshal(reqBytes, &req)

	handler, ok := m.handlers[req.MessageType]
	if !ok {
		return &EncryptedResponse{Success: false, ErrorMessage: fmt.Sprintf("no handler for %d", req.MessageType)}, nil
	}

	var innerJSON json.RawMessage
	if req.Message != "" {
		cpk, _ := base64.StdEncoding.DecodeString(req.ClientPublicKey)
		nb, _ := base64.StdEncoding.DecodeString(req.Nonce)
		mb, _ := base64.StdEncoding.DecodeString(req.Message)
		var clientPK [32]byte
		copy(clientPK[:], cpk)
		var nonce [24]byte
		copy(nonce[:], nb)
		dec, ok := box.Open(nil, mb, &nonce, &clientPK, m.privateKey)
		if !ok {
			return nil, fmt.Errorf("mock: decryption failed")
		}
		innerJSON = dec
	}

	m.mu.Lock()
	m.calls = append(m.calls, mockCall{req.MessageType, innerJSON})
	m.mu.Unlock()

	resp, err := handler(innerJSON)
	if err != nil {
		return &EncryptedResponse{Success: false, ErrorMessage: err.Error()}, nil
	}

	rj, _ := json.Marshal(resp)
	cpk, _ := base64.StdEncoding.DecodeString(req.ClientPublicKey)
	var clientPK [32]byte
	copy(clientPK[:], cpk)
	var nonce [24]byte
	rand.Read(nonce[:])
	enc := box.Seal(nil, rj, &nonce, &clientPK, m.privateKey)

	return &EncryptedResponse{
		Success: true, ServerPublicKey: base64.StdEncoding.EncodeToString(m.publicKey[:]),
		Nonce: base64.StdEncoding.EncodeToString(nonce[:]), Message: base64.StdEncoding.EncodeToString(enc),
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestClient(t *testing.T, mock *mockTransport) *Client {
	t.Helper()
	c, err := NewClient(WithTransport(mock))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func setupStatusHandler(mock *mockTransport, dbs []DatabaseSummary) {
	mock.handlers[MessageTypeStatus] = func(_ json.RawMessage) (any, error) {
		return &GetStatusResponse{ServerVersionInfo: "Mock v1", Databases: dbs}, nil
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

type errorTransport struct{ err error }

func (e *errorTransport) sendRaw(_ any) (*EncryptedResponse, error) { return nil, e.err }

type staticTransport struct{ resp *EncryptedResponse }

func (s *staticTransport) sendRaw(_ any) (*EncryptedResponse, error) { return s.resp, nil }

type callCountTransport struct {
	inner     *mockTransport
	failAfter int
	mu        sync.Mutex
	count     int
}

func (c *callCountTransport) sendRaw(req any) (*EncryptedResponse, error) {
	c.mu.Lock()
	c.count++
	n := c.count
	c.mu.Unlock()
	if n > c.failAfter {
		return nil, fmt.Errorf("transport error on call %d", n)
	}
	return c.inner.sendRaw(req)
}

// ---------------------------------------------------------------------------
// TestMain — subprocess pattern for afproxyTransport
// ---------------------------------------------------------------------------

func TestMain(m *testing.M) {
	if os.Getenv("STRONGBOX_TEST_HELPER_PROCESS") == "1" {
		runFakeAfproxy()
		return
	}
	os.Exit(m.Run())
}

func runFakeAfproxy() {
	mode := os.Getenv("STRONGBOX_TEST_HELPER_MODE")
	switch mode {
	case "echo":
		fakeAfproxyEcho(0)
	case "echo-fail":
		fakeAfproxyEcho(1)
	case "garbage":
		buf := make([]byte, 4)
		io.ReadFull(os.Stdin, buf)
		n := binary.LittleEndian.Uint32(buf)
		io.ReadAll(io.LimitReader(os.Stdin, int64(n)))
		g := []byte("not json!!!")
		binary.LittleEndian.PutUint32(buf, uint32(len(g)))
		os.Stdout.Write(buf)
		os.Stdout.Write(g)
		os.Exit(0)
	case "short":
		buf := make([]byte, 4)
		io.ReadFull(os.Stdin, buf)
		n := binary.LittleEndian.Uint32(buf)
		io.ReadAll(io.LimitReader(os.Stdin, int64(n)))
		binary.LittleEndian.PutUint32(buf, 9999)
		os.Stdout.Write(buf)
		os.Stdout.Write([]byte("short"))
		os.Exit(0)
	case "no-output":
		buf := make([]byte, 4)
		io.ReadFull(os.Stdin, buf)
		n := binary.LittleEndian.Uint32(buf)
		io.ReadAll(io.LimitReader(os.Stdin, int64(n)))
		os.Exit(0)
	case "close-stdin":
		buf := make([]byte, 4)
		io.ReadFull(os.Stdin, buf)
		os.Stdin.Close()
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

func fakeAfproxyEcho(exitCode int) {
	buf := make([]byte, 4)
	io.ReadFull(os.Stdin, buf)
	n := binary.LittleEndian.Uint32(buf)
	msg := make([]byte, n)
	io.ReadFull(os.Stdin, msg)
	var req EncryptedRequest
	json.Unmarshal(msg, &req)
	sPub, sPriv, _ := box.GenerateKey(rand.Reader)
	cpk, _ := base64.StdEncoding.DecodeString(req.ClientPublicKey)
	var clientPK [32]byte
	copy(clientPK[:], cpk)
	payload, _ := json.Marshal(&GetStatusResponse{
		ServerVersionInfo: "FakeAfproxy v1",
		Databases:         []DatabaseSummary{{UUID: "db-fake", NickName: "Fake DB"}},
	})
	var nonce [24]byte
	rand.Read(nonce[:])
	enc := box.Seal(nil, payload, &nonce, &clientPK, sPriv)
	resp, _ := json.Marshal(EncryptedResponse{
		Success: true, ServerPublicKey: base64.StdEncoding.EncodeToString(sPub[:]),
		Nonce: base64.StdEncoding.EncodeToString(nonce[:]), Message: base64.StdEncoding.EncodeToString(enc),
	})
	binary.LittleEndian.PutUint32(buf, uint32(len(resp)))
	os.Stdout.Write(buf)
	os.Stdout.Write(resp)
	os.Exit(exitCode)
}

func helperBinary(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func helperScript(t *testing.T, mode string) string {
	t.Helper()
	exe := helperBinary(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-afproxy")
	content := fmt.Sprintf("#!/bin/sh\nexport STRONGBOX_TEST_HELPER_PROCESS=1\nexport STRONGBOX_TEST_HELPER_MODE=%s\nexec %q -test.run=^$ \"$@\"\n", mode, exe)
	os.WriteFile(script, []byte(content), 0755)
	return script
}

// ===========================================================================
// TESTS
// ===========================================================================

func TestGetStatus(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, []DatabaseSummary{
		{UUID: "db-1", NickName: "Work", Locked: false},
		{UUID: "db-2", NickName: "Personal", Locked: true},
	})
	c := newTestClient(t, mock)
	s, err := c.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Databases) != 2 || s.Databases[0].Locked || !s.Databases[1].Locked {
		t.Errorf("unexpected: %+v", s)
	}
}

func TestSearch(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeSearch] = func(raw json.RawMessage) (any, error) {
		var req SearchRequest
		json.Unmarshal(raw, &req)
		if req.Query == "github" {
			return &SearchResponse{Results: []AutoFillCredential{{Title: "GitHub"}, {Title: "GHE"}}}, nil
		}
		return &SearchResponse{}, nil
	}
	c := newTestClient(t, mock)
	t.Run("basic", func(t *testing.T) {
		r, err := c.Search("github", 0, 10)
		if err != nil || len(r.Results) != 2 {
			t.Fatalf("err=%v len=%d", err, len(r.Results))
		}
	})
	t.Run("no results", func(t *testing.T) {
		r, _ := c.Search("none", 0, 10)
		if len(r.Results) != 0 {
			t.Errorf("got %d", len(r.Results))
		}
	})
	t.Run("with skip", func(t *testing.T) {
		_, err := c.Search("github", 5, 3)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestSearchAll(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeSearch] = func(raw json.RawMessage) (any, error) {
		var req SearchRequest
		json.Unmarshal(raw, &req)
		if req.Skip == 0 {
			creds := make([]AutoFillCredential, 100)
			for i := range creds {
				creds[i] = AutoFillCredential{UUID: fmt.Sprintf("c-%d", i)}
			}
			return &SearchResponse{Results: creds}, nil
		}
		if req.Skip == 100 {
			creds := make([]AutoFillCredential, 50)
			for i := range creds {
				creds[i] = AutoFillCredential{UUID: fmt.Sprintf("c-%d", 100+i)}
			}
			return &SearchResponse{Results: creds}, nil
		}
		return &SearchResponse{}, nil
	}
	c := newTestClient(t, mock)
	r, err := c.Search("all", 0, -1)
	if err != nil || len(r.Results) != 150 {
		t.Fatalf("err=%v len=%d", err, len(r.Results))
	}
}

func TestSearchAllFewerThanChunkSize(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	n := 0
	mock.handlers[MessageTypeSearch] = func(_ json.RawMessage) (any, error) {
		n++
		if n == 1 {
			creds := make([]AutoFillCredential, 50)
			for i := range creds {
				creds[i] = AutoFillCredential{UUID: fmt.Sprintf("c-%d", i)}
			}
			return &SearchResponse{Results: creds}, nil
		}
		return &SearchResponse{}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.Search("q", 0, -1)
	if len(r.Results) != 50 {
		t.Errorf("got %d", len(r.Results))
	}
}

func TestCredentialsForURL(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeGetCredentialsForURL] = func(raw json.RawMessage) (any, error) {
		return &CredentialsForURLResponse{UnlockedDatabaseCount: 1, Results: []AutoFillCredential{{UUID: "c1"}}}, nil
	}
	c := newTestClient(t, mock)
	r, err := c.CredentialsForURL("https://x.com", 0, 10)
	if err != nil || len(r.Results) != 1 {
		t.Fatal(err)
	}
}

func TestCredentialsForURLAll(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	n := 0
	mock.handlers[MessageTypeGetCredentialsForURL] = func(_ json.RawMessage) (any, error) {
		n++
		if n == 1 {
			return &CredentialsForURLResponse{UnlockedDatabaseCount: 2, Results: []AutoFillCredential{{UUID: "c1"}, {UUID: "c2"}}}, nil
		}
		return &CredentialsForURLResponse{UnlockedDatabaseCount: 2}, nil
	}
	c := newTestClient(t, mock)
	r, err := c.CredentialsForURL("https://x.com", 0, -1)
	if err != nil || len(r.Results) != 2 {
		t.Fatalf("err=%v len=%d", err, len(r.Results))
	}
}

func TestCredentialsForURLAllEmpty(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeGetCredentialsForURL] = func(_ json.RawMessage) (any, error) {
		return &CredentialsForURLResponse{}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.CredentialsForURL("https://x.com", 0, -1)
	if len(r.Results) != 0 {
		t.Errorf("got %d", len(r.Results))
	}
}

func TestLockDatabase(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeLock] = func(raw json.RawMessage) (any, error) {
		var req LockRequest
		json.Unmarshal(raw, &req)
		return &LockResponse{DatabaseID: req.DatabaseID}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.LockDatabase("db-42")
	if r.DatabaseID != "db-42" {
		t.Errorf("got %q", r.DatabaseID)
	}
}

func TestUnlockDatabase(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeUnlock] = func(raw json.RawMessage) (any, error) {
		var req UnlockRequest
		json.Unmarshal(raw, &req)
		return &UnlockResponse{Success: req.DatabaseID == "ok"}, nil
	}
	c := newTestClient(t, mock)
	r1, _ := c.UnlockDatabase("ok")
	r2, _ := c.UnlockDatabase("bad")
	if !r1.Success || r2.Success {
		t.Errorf("r1=%v r2=%v", r1.Success, r2.Success)
	}
}

func TestCreateEntry(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeCreateEntry] = func(_ json.RawMessage) (any, error) {
		u := "new"
		return &CreateEntryResponse{UUID: &u}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.CreateEntry(&CreateEntryRequest{DatabaseID: "db"})
	if r.UUID == nil || *r.UUID != "new" {
		t.Errorf("UUID=%v", r.UUID)
	}
}

func TestGetGroups(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeGetGroups] = func(_ json.RawMessage) (any, error) {
		return &GetGroupsResponse{Groups: []GroupSummary{{Title: "Root"}}}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.GetGroups("db")
	if len(r.Groups) != 1 {
		t.Errorf("got %d", len(r.Groups))
	}
}

func TestGetNewEntryDefaults(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeGetNewEntryDefaults] = func(_ json.RawMessage) (any, error) {
		u := "admin"
		return &GetNewEntryDefaultsResponse{Username: &u}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.GetNewEntryDefaults("db")
	if r.Username == nil {
		t.Fatal("nil")
	}
}

func TestGetNewEntryDefaultsV2(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeGetNewEntryDefaultsV2] = func(_ json.RawMessage) (any, error) {
		return &GetNewEntryDefaultsResponseV2{Password: &PasswordAndStrength{Password: "p"}}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.GetNewEntryDefaultsV2("db")
	if r.Password == nil {
		t.Fatal("nil")
	}
}

func TestGeneratePassword(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeGeneratePassword] = func(_ json.RawMessage) (any, error) {
		return &GeneratePasswordResponse{Password: "p"}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.GeneratePassword()
	if r.Password != "p" {
		t.Errorf("got %q", r.Password)
	}
}

func TestGeneratePasswordV2(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeGeneratePasswordV2] = func(_ json.RawMessage) (any, error) {
		return &GeneratePasswordV2Response{Password: PasswordAndStrength{Password: "p"}}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.GeneratePasswordV2()
	if r.Password.Password != "p" {
		t.Errorf("got %q", r.Password.Password)
	}
}

func TestGetPasswordStrength(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeGetPasswordStrength] = func(_ json.RawMessage) (any, error) {
		return &GetPasswordAndStrengthResponse{Strength: PasswordStrengthData{Category: "strong"}}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.GetPasswordStrength("pw")
	if r.Strength.Category != "strong" {
		t.Errorf("got %q", r.Strength.Category)
	}
}

func TestCopyField(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeCopyField] = func(_ json.RawMessage) (any, error) {
		return &CopyFieldResponse{Success: true}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.CopyField("db", "n", FieldPassword, false)
	if !r.Success {
		t.Error("not success")
	}
}

func TestCopyString(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeCopyString] = func(_ json.RawMessage) (any, error) {
		return &CopyStringResponse{Success: true}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.CopyString("v")
	if !r.Success {
		t.Error("not success")
	}
}

func TestGetIcon(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeGetIcon] = func(_ json.RawMessage) (any, error) {
		return &GetIconResponse{Icon: "data"}, nil
	}
	c := newTestClient(t, mock)
	r, _ := c.GetIcon("db", "n")
	if r.Icon == "" {
		t.Error("empty")
	}
}

// ---------------------------------------------------------------------------
// Error paths for every high-level method
// ---------------------------------------------------------------------------

func TestSearchError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.Search("q", 0, 10)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSearchAllError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	n := 0
	mock.handlers[MessageTypeSearch] = func(_ json.RawMessage) (any, error) {
		n++
		if n == 1 {
			creds := make([]AutoFillCredential, 100)
			for i := range creds {
				creds[i] = AutoFillCredential{UUID: fmt.Sprintf("c-%d", i)}
			}
			return &SearchResponse{Results: creds}, nil
		}
		return nil, fmt.Errorf("fail")
	}
	c := newTestClient(t, mock)
	_, err := c.Search("q", 0, -1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCredentialsForURLError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.CredentialsForURL("u", 0, 10)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCredentialsForURLAllError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	n := 0
	mock.handlers[MessageTypeGetCredentialsForURL] = func(_ json.RawMessage) (any, error) {
		n++
		if n == 1 {
			creds := make([]AutoFillCredential, 100)
			for i := range creds {
				creds[i] = AutoFillCredential{UUID: fmt.Sprintf("c-%d", i)}
			}
			return &CredentialsForURLResponse{Results: creds}, nil
		}
		return nil, fmt.Errorf("fail")
	}
	c := newTestClient(t, mock)
	_, err := c.CredentialsForURL("u", 0, -1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCopyFieldError(t *testing.T) {
	c := newTestClient(t, newMockTransport())
	setupStatusHandler(newMockTransport(), nil)
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c2 := newTestClient(t, mock)
	_, err := c2.CopyField("db", "n", FieldPassword, false)
	if err == nil {
		t.Fatal("expected error")
	}
	_ = c
}

func TestLockDatabaseError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.LockDatabase("db")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUnlockDatabaseError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.UnlockDatabase("db")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateEntryError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.CreateEntry(&CreateEntryRequest{DatabaseID: "db"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetGroupsError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.GetGroups("db")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetNewEntryDefaultsError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.GetNewEntryDefaults("db")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetNewEntryDefaultsV2Error(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.GetNewEntryDefaultsV2("db")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGeneratePasswordError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.GeneratePassword()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGeneratePasswordV2Error(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.GeneratePasswordV2()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetIconError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.GetIcon("db", "n")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetPasswordStrengthError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.GetPasswordStrength("pw")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCopyStringError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	_, err := c.CopyString("v")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetStatusTransportError(t *testing.T) {
	c, _ := NewClient(WithTransport(&errorTransport{err: fmt.Errorf("down")}))
	_, err := c.GetStatus()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetStatusDecryptError(t *testing.T) {
	c, _ := NewClient(WithTransport(&staticTransport{resp: &EncryptedResponse{
		Success: true, ServerPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Nonce:   base64.StdEncoding.EncodeToString(make([]byte, 24)),
		Message: base64.StdEncoding.EncodeToString([]byte("bad")),
	}}))
	_, err := c.GetStatus()
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// Public wrappers: SendRaw, BuildEncryptedRequest, SendEncrypted
// ---------------------------------------------------------------------------

func TestSendRaw(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	resp, err := c.SendRaw(&EncryptedRequest{
		MessageType: MessageTypeStatus, ClientPublicKey: base64.StdEncoding.EncodeToString(c.publicKey[:]),
	})
	if err != nil || !resp.Success {
		t.Fatalf("err=%v", err)
	}
}

func TestBuildEncryptedRequest(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	c.GetStatus()
	r, err := c.BuildEncryptedRequest(&SearchRequest{Query: "q"}, MessageTypeSearch)
	if err != nil || r.Message == "" {
		t.Fatalf("err=%v", err)
	}
}

func TestBuildEncryptedRequestNoServerKey(t *testing.T) {
	c, _ := NewClient(WithTransport(&errorTransport{err: fmt.Errorf("no")}))
	_, err := c.BuildEncryptedRequest(struct{}{}, MessageTypeSearch)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSendEncrypted(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeSearch] = func(_ json.RawMessage) (any, error) {
		return &SearchResponse{Results: []AutoFillCredential{{Title: "hit"}}}, nil
	}
	c := newTestClient(t, mock)
	var r SearchResponse
	if err := c.SendEncrypted(&SearchRequest{}, MessageTypeSearch, &r); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// decryptResponse error paths
// ---------------------------------------------------------------------------

func TestDecryptResponseServerError(t *testing.T) {
	c := newTestClient(t, newMockTransport())
	err := c.decryptResponse(&EncryptedResponse{Success: false, ErrorMessage: "boom"}, &GetStatusResponse{})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("err=%v", err)
	}
}

func TestDecryptResponseBadBase64Message(t *testing.T) {
	c := newTestClient(t, newMockTransport())
	err := c.decryptResponse(&EncryptedResponse{
		Success: true, ServerPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Nonce: base64.StdEncoding.EncodeToString(make([]byte, 24)), Message: "!!!",
	}, &GetStatusResponse{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptResponseBadBase64Nonce(t *testing.T) {
	c := newTestClient(t, newMockTransport())
	err := c.decryptResponse(&EncryptedResponse{
		Success: true, ServerPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Nonce: "!!!", Message: base64.StdEncoding.EncodeToString([]byte("x")),
	}, &GetStatusResponse{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptResponseBadBase64ServerPK(t *testing.T) {
	c := newTestClient(t, newMockTransport())
	err := c.decryptResponse(&EncryptedResponse{
		Success: true, ServerPublicKey: "!!!",
		Nonce:   base64.StdEncoding.EncodeToString(make([]byte, 24)),
		Message: base64.StdEncoding.EncodeToString([]byte("x")),
	}, &GetStatusResponse{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptResponseDecryptionFailure(t *testing.T) {
	c := newTestClient(t, newMockTransport())
	err := c.decryptResponse(&EncryptedResponse{
		Success: true, ServerPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Nonce:   base64.StdEncoding.EncodeToString(make([]byte, 24)),
		Message: base64.StdEncoding.EncodeToString([]byte("not-valid-nacl-ciphertext!!")),
	}, &GetStatusResponse{})
	if err == nil || err.Error() != "decryption failed" {
		t.Errorf("err=%v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.serverPublicKey != nil {
		t.Error("key should be nil")
	}
}

func TestDecryptResponseBadJSON(t *testing.T) {
	mock := newMockTransport()
	c := newTestClient(t, mock)
	var nonce [24]byte
	rand.Read(nonce[:])
	enc := box.Seal(nil, []byte("not json{"), &nonce, c.publicKey, mock.privateKey)
	err := c.decryptResponse(&EncryptedResponse{
		Success: true, ServerPublicKey: base64.StdEncoding.EncodeToString(mock.publicKey[:]),
		Nonce: base64.StdEncoding.EncodeToString(nonce[:]), Message: base64.StdEncoding.EncodeToString(enc),
	}, &GetStatusResponse{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// sendEncrypted error paths
// ---------------------------------------------------------------------------

func TestSendEncryptedBuildError(t *testing.T) {
	c, _ := NewClient(WithTransport(&errorTransport{err: fmt.Errorf("fail")}))
	var r SearchResponse
	if err := c.sendEncrypted(&SearchRequest{}, MessageTypeSearch, &r); err == nil {
		t.Fatal("expected error")
	}
}

func TestSendEncryptedTransportError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c, _ := NewClient(WithTransport(&callCountTransport{inner: mock, failAfter: 1}))
	var r SearchResponse
	if err := c.sendEncrypted(&SearchRequest{}, MessageTypeSearch, &r); err == nil {
		t.Fatal("expected error")
	}
}

func TestSendEncryptedDecryptError(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	c.GetStatus()
	np, ns, _ := box.GenerateKey(rand.Reader)
	mock.publicKey = np
	mock.privateKey = ns
	mock.handlers[MessageTypeSearch] = func(_ json.RawMessage) (any, error) {
		return &SearchResponse{}, nil
	}
	var r SearchResponse
	if err := c.sendEncrypted(&SearchRequest{}, MessageTypeSearch, &r); err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// ensureServerPublicKey, NewClient options, MessageType
// ---------------------------------------------------------------------------

func TestEnsureServerPublicKeyAlreadyCached(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	c := newTestClient(t, mock)
	c.GetStatus()
	delete(mock.handlers, MessageTypeStatus)
	if err := c.ensureServerPublicKey(); err != nil {
		t.Fatal(err)
	}
}

func TestServerError(t *testing.T) {
	mock := newMockTransport()
	mock.handlers[MessageTypeStatus] = func(_ json.RawMessage) (any, error) {
		return nil, fmt.Errorf("corruption")
	}
	c := newTestClient(t, mock)
	_, err := c.GetStatus()
	if err == nil || !strings.Contains(err.Error(), "corruption") {
		t.Errorf("err=%v", err)
	}
}

func TestTransportError(t *testing.T) {
	c, _ := NewClient(WithTransport(&errorTransport{err: fmt.Errorf("refused")}))
	_, err := c.GetStatus()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewClientDefaultTransport(t *testing.T) {
	c, _ := NewClient()
	at, ok := c.transport.(*afproxyTransport)
	if !ok || at.proxyPath != defaultProxyPath {
		t.Errorf("type=%T path=%v", c.transport, at)
	}
}

func TestWithProxyPath(t *testing.T) {
	c, _ := NewClient(WithProxyPath("/x"))
	if c.proxyPath != "/x" {
		t.Errorf("got %q", c.proxyPath)
	}
	at := c.transport.(*afproxyTransport)
	if at.proxyPath != "/x" {
		t.Errorf("transport path=%q", at.proxyPath)
	}
}

func TestConcurrentRequests(t *testing.T) {
	mock := newMockTransport()
	setupStatusHandler(mock, nil)
	mock.handlers[MessageTypeSearch] = func(raw json.RawMessage) (any, error) {
		var req SearchRequest
		json.Unmarshal(raw, &req)
		return &SearchResponse{Results: []AutoFillCredential{{Title: req.Query}}}, nil
	}
	c := newTestClient(t, mock)
	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			q := fmt.Sprintf("q-%d", i)
			r, err := c.Search(q, 0, 10)
			if err != nil || len(r.Results) != 1 || r.Results[0].Title != q {
				errs <- fmt.Errorf("g%d: err=%v r=%+v", i, err, r)
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

func TestParseMessageType(t *testing.T) {
	tests := []struct {
		in   string
		want AutoFillMessageType
		ok   bool
	}{
		{"status", MessageTypeStatus, true}, {"Status", MessageTypeStatus, true},
		{"search", MessageTypeSearch, true},
		{"get-url", MessageTypeGetCredentialsForURL, true}, {"getcredentialsforurl", MessageTypeGetCredentialsForURL, true},
		{"copy-field", MessageTypeCopyField, true}, {"copyfield", MessageTypeCopyField, true},
		{"lock", MessageTypeLock, true}, {"unlock", MessageTypeUnlock, true},
		{"create-entry", MessageTypeCreateEntry, true}, {"createentry", MessageTypeCreateEntry, true},
		{"get-groups", MessageTypeGetGroups, true}, {"getgroups", MessageTypeGetGroups, true},
		{"get-defaults", MessageTypeGetNewEntryDefaults, true}, {"getnewentrydefaults", MessageTypeGetNewEntryDefaults, true},
		{"generate-password", MessageTypeGeneratePassword, true}, {"generatepassword", MessageTypeGeneratePassword, true},
		{"get-icon", MessageTypeGetIcon, true}, {"geticon", MessageTypeGetIcon, true},
		{"generate-password-v2", MessageTypeGeneratePasswordV2, true}, {"generatepasswordv2", MessageTypeGeneratePasswordV2, true},
		{"password-strength", MessageTypeGetPasswordStrength, true}, {"getpasswordstrength", MessageTypeGetPasswordStrength, true},
		{"get-defaults-v2", MessageTypeGetNewEntryDefaultsV2, true}, {"getnewentrydefaultsv2", MessageTypeGetNewEntryDefaultsV2, true},
		{"get-favourites", MessageTypeGetFavourites, true}, {"getfavourites", MessageTypeGetFavourites, true},
		{"copy-string", MessageTypeCopyString, true}, {"copystring", MessageTypeCopyString, true},
		{"nonexistent", MessageTypeUnknown, false}, {"", MessageTypeUnknown, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := ParseMessageType(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Errorf("got (%d,%v) want (%d,%v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestMessageTypeStringAll(t *testing.T) {
	m := map[AutoFillMessageType]string{
		MessageTypeStatus: "status", MessageTypeSearch: "search",
		MessageTypeGetCredentialsForURL: "getcredentialsforurl", MessageTypeCopyField: "copyfield",
		MessageTypeLock: "lock", MessageTypeUnlock: "unlock",
		MessageTypeCreateEntry: "createentry", MessageTypeGetGroups: "getgroups",
		MessageTypeGetNewEntryDefaults: "getnewentrydefaults", MessageTypeGeneratePassword: "generatepassword",
		MessageTypeGetIcon: "geticon", MessageTypeGeneratePasswordV2: "generatepasswordv2",
		MessageTypeGetPasswordStrength: "getpasswordstrength", MessageTypeGetNewEntryDefaultsV2: "getnewentrydefaultsv2",
		MessageTypeGetFavourites: "getfavourites", MessageTypeCopyString: "copystring",
		MessageTypeUnknown: "unknown", AutoFillMessageType(999): "unknown",
	}
	for mt, want := range m {
		if got := mt.String(); got != want {
			t.Errorf("(%d).String()=%q want %q", mt, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// afproxyTransport tests
// ---------------------------------------------------------------------------

func TestAfproxyTransportStartError(t *testing.T) {
	tr := &afproxyTransport{proxyPath: "/nonexistent"}
	if _, err := tr.sendRaw(map[string]string{"a": "b"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestAfproxyTransportMarshalError(t *testing.T) {
	tr := &afproxyTransport{proxyPath: "/bin/echo"}
	if _, err := tr.sendRaw(make(chan int)); err == nil {
		t.Fatal("expected error")
	}
}

func TestAfproxyTransportEcho(t *testing.T) {
	script := helperScript(t, "echo")
	tr := &afproxyTransport{proxyPath: script}
	pub, _, _ := box.GenerateKey(rand.Reader)
	resp, err := tr.sendRaw(&EncryptedRequest{
		MessageType: MessageTypeStatus, ClientPublicKey: base64.StdEncoding.EncodeToString(pub[:]),
	})
	if err != nil || !resp.Success {
		t.Fatalf("err=%v", err)
	}
}

func TestAfproxyTransportGarbage(t *testing.T) {
	tr := &afproxyTransport{proxyPath: helperScript(t, "garbage")}
	if _, err := tr.sendRaw(&EncryptedRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestAfproxyTransportShortRead(t *testing.T) {
	tr := &afproxyTransport{proxyPath: helperScript(t, "short")}
	if _, err := tr.sendRaw(&EncryptedRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestAfproxyTransportNoOutput(t *testing.T) {
	tr := &afproxyTransport{proxyPath: helperScript(t, "no-output")}
	if _, err := tr.sendRaw(&EncryptedRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestAfproxyTransportWaitError(t *testing.T) {
	tr := &afproxyTransport{proxyPath: helperScript(t, "echo-fail")}
	pub, _, _ := box.GenerateKey(rand.Reader)
	resp, err := tr.sendRaw(&EncryptedRequest{
		MessageType: MessageTypeStatus, ClientPublicKey: base64.StdEncoding.EncodeToString(pub[:]),
	})
	if err != nil || !resp.Success {
		t.Fatalf("err=%v", err)
	}
}

func TestAfproxyTransportFullRoundTrip(t *testing.T) {
	c, _ := NewClient(WithProxyPath(helperScript(t, "echo")))
	s, err := c.GetStatus()
	if err != nil || s.ServerVersionInfo != "FakeAfproxy v1" {
		t.Fatalf("err=%v info=%q", err, s.ServerVersionInfo)
	}
}

func TestAfproxyTransportWriteError(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "exit-now")
	os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0755)
	tr := &afproxyTransport{proxyPath: script}
	if _, err := tr.sendRaw(&EncryptedRequest{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestAfproxyTransportWriteBodyError(t *testing.T) {
	tr := &afproxyTransport{proxyPath: helperScript(t, "close-stdin")}
	req := &EncryptedRequest{Message: string(make([]byte, 1024*1024))}
	if _, err := tr.sendRaw(req); err == nil {
		t.Fatal("expected error")
	}
}

// exhaustFDs lowers RLIMIT_NOFILE, then opens files until exactly `remaining`
// file descriptors are left.  It returns a cleanup function that closes the
// leaked files and restores the original limit.  The caller MUST defer the
// cleanup.
func exhaustFDs(t *testing.T, remaining int) func() {
	t.Helper()

	var origLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &origLimit); err != nil {
		t.Skipf("cannot get RLIMIT_NOFILE: %v", err)
	}

	// Choose a low soft limit that is still large enough for the test
	// framework itself.  The test infra needs stdin/stdout/stderr (3) plus a
	// few more for the runtime.  50 is a safe floor.
	const lowLimit = 50
	newLimit := syscall.Rlimit{Cur: lowLimit, Max: origLimit.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &newLimit); err != nil {
		t.Skipf("cannot set RLIMIT_NOFILE: %v", err)
	}

	// Consume FDs until we can't open any more.
	var leaked []*os.File
	for {
		f, err := os.Open(os.DevNull)
		if err != nil {
			break // hit the limit
		}
		leaked = append(leaked, f)
	}

	// Now release exactly `remaining` FDs so that the caller has that many
	// available.
	for i := 0; i < remaining && len(leaked) > 0; i++ {
		last := leaked[len(leaked)-1]
		last.Close()
		leaked = leaked[:len(leaked)-1]
	}

	return func() {
		for _, f := range leaked {
			f.Close()
		}
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &origLimit)
	}
}

func TestAfproxyTransportStdinPipeError(t *testing.T) {
	// StdinPipe() calls os.Pipe() which needs 2 FDs.
	// Leave 0 FDs available → StdinPipe fails with EMFILE.
	script := helperScript(t, "echo")
	tr := &afproxyTransport{proxyPath: script}

	cleanup := exhaustFDs(t, 0)
	defer cleanup()

	_, err := tr.sendRaw(map[string]string{"test": "value"})
	if err == nil {
		t.Fatal("expected error due to exhausted FDs")
	}
	if !strings.Contains(err.Error(), "stdin pipe") {
		t.Errorf("expected stdin pipe error, got: %q", err.Error())
	}
}

func TestAfproxyTransportStdoutPipeError(t *testing.T) {
	// StdinPipe() needs 2 FDs, StdoutPipe() needs 2 more.
	// Leave exactly 2 FDs → StdinPipe succeeds, StdoutPipe fails.
	script := helperScript(t, "echo")
	tr := &afproxyTransport{proxyPath: script}

	cleanup := exhaustFDs(t, 2)
	defer cleanup()

	_, err := tr.sendRaw(map[string]string{"test": "value"})
	if err == nil {
		t.Fatal("expected error due to exhausted FDs")
	}
	if !strings.Contains(err.Error(), "stdout pipe") {
		t.Errorf("expected stdout pipe error, got: %q", err.Error())
	}
}
