package strongbox

import "encoding/json"

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
)

// WellKnownField corresponds to the standard credential fields.
type WellKnownField int

const (
	// FieldUsername represents the username field.
	FieldUsername WellKnownField = iota
	// FieldPassword represents the password field.
	FieldPassword
	// FieldTOTP represents the TOTP (Time-based One-Time Password) field.
	FieldTOTP
)

// EncryptedRequest is the outer envelope sent to the native host.
type EncryptedRequest struct {
	ClientPublicKey string              `json:"clientPublicKey"`
	Nonce           string              `json:"nonce"`
	Message         string              `json:"message"`
	MessageType     AutoFillMessageType `json:"messageType"`
}

// EncryptedResponse is the outer envelope received from the native host.
type EncryptedResponse struct {
	Success         bool   `json:"success"`
	ErrorMessage    string `json:"errorMessage,omitempty"`
	ServerPublicKey string `json:"serverPublicKey,omitempty"`
	Message         string `json:"message,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
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
type DatabaseSummary struct {
	// UUID is the unique identifier for the database.
	UUID string `json:"uuid"`
	// NickName is the display name of the database.
	NickName string `json:"nickName"`
	// Locked indicates if the database is currently locked.
	Locked bool `json:"locked"`
	// AutoFillEnabled indicates if AutoFill is enabled for this database.
	AutoFillEnabled             bool `json:"autoFillEnabled"`
	IncludeFavIconForNewEntries bool `json:"includeFavIconForNewEntries"`
}

// AutoFillCredential represents a single credential entry from Strongbox.
type AutoFillCredential struct {
	DatabaseID   string          `json:"databaseId"`
	UUID         string          `json:"uuid"`
	Title        string          `json:"title"`
	Username     string          `json:"username"`
	Password     string          `json:"password"`
	URL          string          `json:"url"`
	TOTP         string          `json:"totp"`
	Icon         string          `json:"icon"`
	CustomFields json.RawMessage `json:"customFields"`
	DatabaseName string          `json:"databaseName"`
	Tags         []string        `json:"tags"`
	Favourite    bool            `json:"favourite"`
	Notes        string          `json:"notes"`
	Modified     string          `json:"modified"`
}

type CredentialsForURLRequest struct {
	URL  string `json:"url"`
	Skip int    `json:"skip"`
	Take int    `json:"take"`
}

type CredentialsForURLResponse struct {
	UnlockedDatabaseCount int                  `json:"unlockedDatabaseCount"`
	Results               []AutoFillCredential `json:"results"`
}

type SearchRequest struct {
	Query string `json:"query"`
	Skip  int    `json:"skip"`
	Take  int    `json:"take"`
}

type SearchResponse struct {
	Results []AutoFillCredential `json:"results"`
}

type CopyFieldRequest struct {
	DatabaseID   string         `json:"databaseId"`
	NodeID       string         `json:"nodeId"`
	Field        WellKnownField `json:"field"`
	ExplicitTOTP bool           `json:"explicitTotp"`
}

type CopyFieldResponse struct {
	Success bool `json:"success"`
}

type LockRequest struct {
	DatabaseID string `json:"databaseId"`
}

type LockResponse struct {
	DatabaseID string `json:"databaseId"`
}

type UnlockRequest struct {
	DatabaseID string `json:"databaseId"`
}

type UnlockResponse struct {
	Success bool `json:"success"`
}

type CreateEntryRequest struct {
	DatabaseID string  `json:"databaseId"`
	GroupID    *string `json:"groupId"`
	Icon       *string `json:"icon"`
	Title      *string `json:"title"`
	Username   *string `json:"username"`
	Password   *string `json:"password"`
	URL        *string `json:"url"`
}

type CreateEntryResponse struct {
	UUID       *string             `json:"uuid"`
	Error      *string             `json:"error"`
	Credential *AutoFillCredential `json:"credential"`
}

type GetGroupsRequest struct {
	DatabaseID string `json:"databaseId"`
}

type GroupSummary struct {
	Title string `json:"title"`
	UUID  string `json:"uuid"`
}

type GetGroupsResponse struct {
	Error  *string        `json:"error"`
	Groups []GroupSummary `json:"groups"`
}

type GetNewEntryDefaultsRequest struct {
	DatabaseID string `json:"databaseId"`
}

type GetNewEntryDefaultsResponse struct {
	Error                *string  `json:"error"`
	Username             *string  `json:"username"`
	MostPopularUsernames []string `json:"mostPopularUsernames"`
	Password             *string  `json:"password"`
}

type GeneratePasswordResponse struct {
	Password     string   `json:"password"`
	Alternatives []string `json:"alternatives"`
}

type PasswordAndStrength struct {
	Password string               `json:"password"`
	Strength PasswordStrengthData `json:"strength"`
}

type PasswordStrengthData struct {
	Entropy       float64 `json:"entropy"`
	Category      string  `json:"category"`
	SummaryString string  `json:"summaryString"`
}

type GeneratePasswordV2Response struct {
	Password     PasswordAndStrength `json:"password"`
	Alternatives []string            `json:"alternatives"`
}

type GetNewEntryDefaultsResponseV2 struct {
	Error                *string              `json:"error"`
	Username             *string              `json:"username"`
	MostPopularUsernames []string             `json:"mostPopularUsernames"`
	Password             *PasswordAndStrength `json:"password"`
}

type GetIconRequest struct {
	DatabaseID string `json:"databaseId"`
	NodeID     string `json:"nodeId"`
}

type GetIconResponse struct {
	Icon string `json:"icon"`
}

type GetPasswordAndStrengthRequest struct {
	Password string `json:"password"`
}

type GetPasswordAndStrengthResponse struct {
	Strength PasswordStrengthData `json:"strength"`
}

type CopyStringRequest struct {
	Value string `json:"value"`
}

type CopyStringResponse struct {
	Success bool `json:"success"`
}
