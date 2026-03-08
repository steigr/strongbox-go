// Package strongbox provides a Go client library for interacting with the Strongbox Password Manager
// through its native messaging host (afproxy). This library implements the browser extension protocol,
// allowing Go applications to:
//
//   - Search and retrieve credentials from unlocked Strongbox databases
//   - Create new password entries programmatically
//   - Generate secure passwords using Strongbox's password generator
//   - Copy credentials to the clipboard securely
//   - Lock and unlock databases
//   - Retrieve database status and metadata
//
// # Getting Started
//
// To use this library, you need Strongbox installed on macOS with the afproxy binary available.
// The default path is /Applications/Strongbox.app/Contents/MacOS/afproxy.
//
//	client, err := strongbox.NewClient()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get status and list of databases
//	status, err := client.GetStatus()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Search for credentials
//	results, err := client.Search("github", 0, 10)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Security
//
// The client uses NaCl box encryption (Curve25519, XSalsa20, and Poly1305) to secure all
// communication with the Strongbox native host. Each client generates an ephemeral keypair,
// and messages are encrypted using the server's public key obtained during the initial handshake.
//
// # Thread Safety
//
// The Client type is safe for concurrent use. Internal state (encryption keys) is protected
// by a mutex.
package strongbox

import "strings"

// AutoFillMessageType corresponds to the message type enum used by the browser extension.
type AutoFillMessageType int

const (
	// MessageTypeStatus is used to get the status of the Strongbox server and the list of available databases.
	MessageTypeStatus AutoFillMessageType = iota
	// MessageTypeSearch is used to search for entries across all unlocked databases.
	MessageTypeSearch
	// MessageTypeGetCredentialsForURL is used to retrieve credentials that match a specific URL.
	MessageTypeGetCredentialsForURL
	// MessageTypeCopyField is used to copy a field's value to the clipboard.
	MessageTypeCopyField
	// MessageTypeLock is used to lock a database.
	MessageTypeLock
	// MessageTypeUnlock is used to unlock a database.
	MessageTypeUnlock
	// MessageTypeCreateEntry is used to create a new entry in a database.
	MessageTypeCreateEntry
	// MessageTypeGetGroups is used to get the group structure of a database.
	MessageTypeGetGroups
	// MessageTypeGetNewEntryDefaults is used to get default values for a new entry.
	MessageTypeGetNewEntryDefaults
	// MessageTypeGeneratePassword is used to generate a random password.
	MessageTypeGeneratePassword
	// MessageTypeGetIcon is used to retrieve an entry's icon.
	MessageTypeGetIcon
	// MessageTypeGeneratePasswordV2 is a more detailed password generation message.
	MessageTypeGeneratePasswordV2
	// MessageTypeGetPasswordStrength is used to evaluate a password's strength.
	MessageTypeGetPasswordStrength
	// MessageTypeGetNewEntryDefaultsV2 is a more detailed version of GetNewEntryDefaults.
	MessageTypeGetNewEntryDefaultsV2
	// MessageTypeGetFavourites is used to get favourite entries.
	MessageTypeGetFavourites
	// MessageTypeCopyString is used to copy an arbitrary string to the clipboard via Strongbox.
	MessageTypeCopyString
	// MessageTypeUnknown represents an unknown message type.
	MessageTypeUnknown AutoFillMessageType = -1
)

// messageTypeNames maps each AutoFillMessageType to its canonical name and aliases.
// The first name in each slice is the canonical representation used by String().
var messageTypeNames = map[AutoFillMessageType][]string{
	MessageTypeStatus:                {"status"},
	MessageTypeSearch:                {"search"},
	MessageTypeGetCredentialsForURL:  {"getcredentialsforurl", "get-url"},
	MessageTypeCopyField:             {"copyfield", "copy-field"},
	MessageTypeLock:                  {"lock"},
	MessageTypeUnlock:                {"unlock"},
	MessageTypeCreateEntry:           {"createentry", "create-entry"},
	MessageTypeGetGroups:             {"getgroups", "get-groups"},
	MessageTypeGetNewEntryDefaults:   {"getnewentrydefaults", "get-defaults"},
	MessageTypeGeneratePassword:      {"generatepassword", "generate-password"},
	MessageTypeGetIcon:               {"geticon", "get-icon"},
	MessageTypeGeneratePasswordV2:    {"generatepasswordv2", "generate-password-v2"},
	MessageTypeGetPasswordStrength:   {"getpasswordstrength", "password-strength"},
	MessageTypeGetNewEntryDefaultsV2: {"getnewentrydefaultsv2", "get-defaults-v2"},
	MessageTypeGetFavourites:         {"getfavourites", "get-favourites"},
	MessageTypeCopyString:            {"copystring", "copy-string"},
}

// String returns the canonical name of the message type.
func (m AutoFillMessageType) String() string {
	if names, ok := messageTypeNames[m]; ok && len(names) > 0 {
		return names[0]
	}
	return "unknown"
}

// ParseMessageType parses a message type from its name (case-insensitive).
func ParseMessageType(name string) (AutoFillMessageType, bool) {
	name = strings.ToLower(name)
	for m, names := range messageTypeNames {
		for _, n := range names {
			if n == name {
				return m, true
			}
		}
	}
	return MessageTypeUnknown, false
}

// WellKnownField represents standard credential fields that can be accessed or copied.
// These fields correspond to the common attributes of password entries in Strongbox.
type WellKnownField int

const (
	// FieldUsername represents the username field.
	FieldUsername WellKnownField = iota
	// FieldPassword represents the password field.
	FieldPassword
	// FieldTOTP represents the TOTP (Time-based One-Time Password) field.
	FieldTOTP
)

// EncryptedRequest is the outer envelope sent to the native host (afproxy).
// It contains the NaCl box encrypted message along with the necessary cryptographic parameters
// for the server to decrypt it. The actual request data is encrypted and stored in the Message field.
type EncryptedRequest struct {
	// ClientPublicKey is the base64-encoded Curve25519 public key of the client.
	ClientPublicKey string `json:"clientPublicKey"`
	// Nonce is the base64-encoded 24-byte nonce used for encryption.
	Nonce string `json:"nonce"`
	// Message is the base64-encoded encrypted payload containing the actual request data.
	Message string `json:"message"`
	// MessageType indicates the type of operation being requested.
	MessageType AutoFillMessageType `json:"messageType"`
}

// EncryptedResponse is the outer envelope received from the native host (afproxy).
// It contains the encrypted response along with the server's public key and nonce needed for decryption.
type EncryptedResponse struct {
	// Success indicates whether the operation succeeded.
	Success bool `json:"success"`
	// ErrorMessage contains error details if Success is false.
	ErrorMessage string `json:"errorMessage,omitempty"`
	// ServerPublicKey is the base64-encoded Curve25519 public key of the server.
	ServerPublicKey string `json:"serverPublicKey,omitempty"`
	// Message is the base64-encoded encrypted response payload.
	Message string `json:"message,omitempty"`
	// Nonce is the base64-encoded 24-byte nonce used for encryption.
	Nonce string `json:"nonce,omitempty"`
}

// GetStatusResponse is the decrypted response for MessageTypeStatus.
type GetStatusResponse struct {
	// ServerVersionInfo contains the Strongbox version string.
	ServerVersionInfo string `json:"serverVersionInfo"`
	// Databases lists all databases currently known to the Strongbox instance.
	Databases []DatabaseSummary `json:"databases"`
	// ServerSettings contains the current global settings of the Strongbox server.
	ServerSettings *ServerSettings `json:"serverSettings,omitempty"`
}

// ServerSettings contains global Strongbox settings relevant for the client.
type ServerSettings struct {
	SupportsCreateNew bool `json:"supportsCreateNew"`
	MarkdownNotes     bool `json:"markdownNotes"`
	ColorizePasswords bool `json:"colorizePasswords"`
	ColorBlindPalette bool `json:"colorBlindPalette"`
}

// DatabaseSummary provides brief information about a Strongbox database.
// It includes the database's identity, lock state, and AutoFill configuration.
type DatabaseSummary struct {
	// UUID is the unique identifier for the database.
	UUID string `json:"uuid"`
	// NickName is the display name of the database.
	NickName string `json:"nickName"`
	// Locked indicates if the database is currently locked.
	Locked bool `json:"locked"`
	// AutoFillEnabled indicates if AutoFill is enabled for this database.
	AutoFillEnabled bool `json:"autoFillEnabled"`
	// IncludeFavIconForNewEntries indicates if new entries should include favicons.
	IncludeFavIconForNewEntries bool `json:"includeFavIconForNewEntries"`
}

// CustomField represents a custom field in a Strongbox entry.
// Custom fields allow storing additional key-value pairs beyond the standard
// username, password, and URL fields.
type CustomField struct {
	// Key is the name of the custom field.
	Key string `json:"key"`
	// Value is the content of the custom field.
	Value string `json:"value"`
	// Concealable indicates if the field should be hidden by default in the UI.
	Concealable bool `json:"concealable"`
}

// AutoFillCredential represents a single credential entry from Strongbox.
// It contains all the information about a password entry, including standard fields
// (username, password, URL) and additional metadata (tags, notes, custom fields).
type AutoFillCredential struct {
	// DatabaseID is the UUID of the database containing this credential.
	DatabaseID string `json:"databaseId"`
	// UUID is the unique identifier of this credential entry.
	UUID string `json:"uuid"`
	// Title is the display name of the credential entry.
	Title string `json:"title"`
	// Username is the username associated with this credential.
	Username string `json:"username"`
	// Password is the password for this credential.
	Password string `json:"password"`
	// URL is the associated URL for this credential.
	URL string `json:"url"`
	// TOTP is the current TOTP (Time-based One-Time Password) code if configured.
	TOTP string `json:"totp"`
	// Icon is a base64-encoded image representing the credential's icon.
	Icon string `json:"icon"`
	// CustomFields contains additional user-defined fields.
	CustomFields []CustomField `json:"customFields"`
	// DatabaseName is the display name of the containing database.
	DatabaseName string `json:"databaseName"`
	// Tags are user-defined labels for organizing credentials.
	Tags []string `json:"tags"`
	// Favourite indicates if this credential is marked as a favourite.
	Favourite bool `json:"favourite"`
	// Notes contains any additional notes for this credential.
	Notes string `json:"notes"`
	// Modified is the timestamp of the last modification.
	Modified string `json:"modified"`
}

// CredentialsForURLRequest is the request payload for retrieving credentials that match a specific URL.
// CredentialsForURLRequest is the request payload for retrieving credentials that match a specific URL.
type CredentialsForURLRequest struct {
	// URL is the URL to search for matching credentials.
	URL string `json:"url"`
	// Skip is the number of results to skip for pagination.
	Skip int `json:"skip"`
	// Take is the maximum number of results to return.
	Take int `json:"take"`
}

// CredentialsForURLResponse contains the credentials matching a URL query.
type CredentialsForURLResponse struct {
	// UnlockedDatabaseCount is the number of databases that are currently unlocked.
	UnlockedDatabaseCount int `json:"unlockedDatabaseCount"`
	// Results contains the matching credentials.
	Results []AutoFillCredential `json:"results"`
}

// SearchRequest is the request payload for searching credentials across all unlocked databases.
type SearchRequest struct {
	// Query is the search term to match against credential fields.
	Query string `json:"query"`
	// Skip is the number of results to skip for pagination.
	Skip int `json:"skip"`
	// Take is the maximum number of results to return.
	Take int `json:"take"`
}

// SearchResponse contains the results of a credential search.
type SearchResponse struct {
	// Results contains the matching credentials.
	Results []AutoFillCredential `json:"results"`
}

// CopyFieldRequest is the request payload for copying a specific field to the clipboard.
type CopyFieldRequest struct {
	// DatabaseID is the UUID of the database containing the entry.
	DatabaseID string `json:"databaseId"`
	// NodeID is the UUID of the credential entry.
	NodeID string `json:"nodeId"`
	// Field specifies which field to copy (username, password, or TOTP).
	Field WellKnownField `json:"field"`
	// ExplicitTOTP indicates if the TOTP code should be explicitly generated.
	ExplicitTOTP bool `json:"explicitTotp"`
}

// CopyFieldResponse indicates whether the field was successfully copied.
type CopyFieldResponse struct {
	// Success indicates whether the copy operation succeeded.
	Success bool `json:"success"`
}

// LockRequest is the request payload for locking a database.
type LockRequest struct {
	// DatabaseID is the UUID of the database to lock.
	DatabaseID string `json:"databaseId"`
}

// LockResponse confirms that a database has been locked.
type LockResponse struct {
	// DatabaseID is the UUID of the locked database.
	DatabaseID string `json:"databaseId"`
}

// UnlockRequest is the request payload for unlocking a database.
// This typically triggers a prompt in the Strongbox app for the user to enter credentials.
type UnlockRequest struct {
	// DatabaseID is the UUID of the database to unlock.
	DatabaseID string `json:"databaseId"`
}

// UnlockResponse indicates whether the unlock operation succeeded.
type UnlockResponse struct {
	// Success indicates whether the database was successfully unlocked.
	Success bool `json:"success"`
}

// CreateEntryRequest is the request payload for creating a new credential entry.
// All fields except DatabaseID are optional. If not provided, defaults may be used.
type CreateEntryRequest struct {
	// DatabaseID is the UUID of the database where the entry should be created.
	DatabaseID string `json:"databaseId"`
	// GroupID is the UUID of the group to place the entry in (optional).
	GroupID *string `json:"groupId"`
	// Icon is a base64-encoded image for the entry (optional).
	Icon *string `json:"icon"`
	// Title is the display name of the entry (optional).
	Title *string `json:"title"`
	// Username is the username for the credential (optional).
	Username *string `json:"username"`
	// Password is the password for the credential (optional).
	Password *string `json:"password"`
	// URL is the associated URL for the credential (optional).
	URL *string `json:"url"`
}

// CreateEntryResponse contains the result of creating a new credential entry.
type CreateEntryResponse struct {
	// UUID is the unique identifier of the newly created entry (nil on error).
	UUID *string `json:"uuid"`
	// Error contains error details if the creation failed.
	Error *string `json:"error"`
	// Credential contains the full credential data of the newly created entry.
	Credential *AutoFillCredential `json:"credential"`
}

// GetGroupsRequest is the request payload for retrieving the group structure of a database.
type GetGroupsRequest struct {
	// DatabaseID is the UUID of the database to query.
	DatabaseID string `json:"databaseId"`
}

// GroupSummary represents a single group within a database hierarchy.
type GroupSummary struct {
	// Title is the display name of the group.
	Title string `json:"title"`
	// UUID is the unique identifier of the group.
	UUID string `json:"uuid"`
}

// GetGroupsResponse contains the group structure of a database.
type GetGroupsResponse struct {
	// Error contains error details if the operation failed.
	Error *string `json:"error"`
	// Groups contains the list of groups in the database.
	Groups []GroupSummary `json:"groups"`
}

// GetNewEntryDefaultsRequest is the request payload for retrieving default values for new entries.
type GetNewEntryDefaultsRequest struct {
	// DatabaseID is the UUID of the database to query for defaults.
	DatabaseID string `json:"databaseId"`
}

// GetNewEntryDefaultsResponse contains suggested default values for creating a new entry.
type GetNewEntryDefaultsResponse struct {
	// Error contains error details if the operation failed.
	Error *string `json:"error"`
	// Username is the suggested default username (may be nil).
	Username *string `json:"username"`
	// MostPopularUsernames lists commonly used usernames in this database.
	MostPopularUsernames []string `json:"mostPopularUsernames"`
	// Password is a suggested default password (may be nil).
	Password *string `json:"password"`
}

// GeneratePasswordResponse contains a generated password and alternatives.
type GeneratePasswordResponse struct {
	// Password is the primary generated password.
	Password string `json:"password"`
	// Alternatives contains additional password suggestions.
	Alternatives []string `json:"alternatives"`
}

// PasswordAndStrength combines a password with its strength analysis.
type PasswordAndStrength struct {
	// Password is the password string.
	Password string `json:"password"`
	// Strength contains the strength analysis data.
	Strength PasswordStrengthData `json:"strength"`
}

// PasswordStrengthData contains detailed information about a password's strength.
type PasswordStrengthData struct {
	// Entropy is the password's entropy in bits.
	Entropy float64 `json:"entropy"`
	// Category is a human-readable strength category (e.g., "weak", "strong").
	Category string `json:"category"`
	// SummaryString is a user-friendly description of the password's strength.
	SummaryString string `json:"summaryString"`
}

// GeneratePasswordV2Response contains a generated password with strength information and alternatives.
type GeneratePasswordV2Response struct {
	// Password is the primary generated password with its strength analysis.
	Password PasswordAndStrength `json:"password"`
	// Alternatives contains additional password suggestions.
	Alternatives []string `json:"alternatives"`
}

// GetNewEntryDefaultsResponseV2 contains suggested default values with enhanced password information.
type GetNewEntryDefaultsResponseV2 struct {
	// Error contains error details if the operation failed.
	Error *string `json:"error"`
	// Username is the suggested default username (may be nil).
	Username *string `json:"username"`
	// MostPopularUsernames lists commonly used usernames in this database.
	MostPopularUsernames []string `json:"mostPopularUsernames"`
	// Password is a suggested default password with strength analysis (may be nil).
	Password *PasswordAndStrength `json:"password"`
}

// GetIconRequest is the request payload for retrieving an entry's icon.
type GetIconRequest struct {
	// DatabaseID is the UUID of the database containing the entry.
	DatabaseID string `json:"databaseId"`
	// NodeID is the UUID of the credential entry.
	NodeID string `json:"nodeId"`
}

// GetIconResponse contains the base64-encoded icon data.
type GetIconResponse struct {
	// Icon is the base64-encoded image data.
	Icon string `json:"icon"`
}

// GetPasswordAndStrengthRequest is the request payload for analyzing a password's strength.
type GetPasswordAndStrengthRequest struct {
	// Password is the password to analyze.
	Password string `json:"password"`
}

// GetPasswordAndStrengthResponse contains the strength analysis of a password.
type GetPasswordAndStrengthResponse struct {
	// Strength contains the detailed strength analysis.
	Strength PasswordStrengthData `json:"strength"`
}

// CopyStringRequest is the request payload for copying an arbitrary string to the clipboard.
type CopyStringRequest struct {
	// Value is the string to copy to the clipboard.
	Value string `json:"value"`
}

// CopyStringResponse indicates whether the string was successfully copied.
type CopyStringResponse struct {
	// Success indicates whether the copy operation succeeded.
	Success bool `json:"success"`
}
