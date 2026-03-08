# strongbox-go

A Go library and CLI for interfacing with [Strongbox](https://strongboxsafe.com) via its native messaging protocol, the same protocol used by the [browser autofill extension](https://github.com/strongbox-password-safe/browser-autofill).

## Features

- 🔐 **Secure Communication**: Uses NaCl box encryption (Curve25519, XSalsa20, Poly1305)
- 🔍 **Search & Retrieve**: Search credentials across all unlocked databases
- ➕ **Create Entries**: Programmatically create new password entries
- 🎲 **Password Generation**: Generate secure passwords using Strongbox's generator
- 📋 **Clipboard Integration**: Copy credentials securely to clipboard
- 🔒 **Database Management**: Lock and unlock databases
- 🔄 **Concurrent-Safe**: Thread-safe client for concurrent operations
- 📦 **Zero Dependencies**: Pure Go implementation with minimal external dependencies

## Requirements

- macOS with [Strongbox](https://strongboxsafe.com) installed (`/Applications/Strongbox.app`)
- Go 1.24+

## Installation

### As a Library

```bash
go get github.com/steigr/strongbox-go/pkg/strongbox
```

### CLI Tools

```bash
go install github.com/steigr/strongbox-go/cmd/strongbox@latest
go install github.com/steigr/strongbox-go/cmd/afproxy-cli@latest
```

Or build from source:

```bash
git clone https://github.com/steigr/strongbox-go.git
cd strongbox-go
go build -o bin/strongbox ./cmd/strongbox
go build -o bin/afproxy-cli ./cmd/afproxy-cli
```

## Library Usage

### Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/steigr/strongbox-go/pkg/strongbox"
)

func main() {
    // Create a new client
    client, err := strongbox.NewClient()
    if err != nil {
        log.Fatal(err)
    }

    // Get database status
    status, err := client.GetStatus()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Strongbox version: %s\n", status.ServerVersionInfo)
    fmt.Printf("Databases: %d\n", len(status.Databases))

    // Search for credentials
    results, err := client.Search("github", 0, 10)
    if err != nil {
        log.Fatal(err)
    }

    for _, cred := range results.Results {
        fmt.Printf("%s: %s@%s\n", cred.Title, cred.Username, cred.URL)
    }
}
```

### Common Operations

#### Searching for Credentials

```go
// Search with pagination
results, err := client.Search("example.com", 0, 10)

// Fetch all results (automatic pagination)
allResults, err := client.Search("example.com", 0, -1)
```

#### Getting Credentials by URL

```go
results, err := client.CredentialsForURL("https://github.com", 0, 10)
if err != nil {
    log.Fatal(err)
}

for _, cred := range results.Results {
    fmt.Printf("Username: %s\n", cred.Username)
    fmt.Printf("Password: %s\n", cred.Password)
}
```

#### Creating New Entries

```go
// Get default values first
defaults, err := client.GetNewEntryDefaultsV2(databaseID)
if err != nil {
    log.Fatal(err)
}

// Create the entry
title := "My New Account"
username := "user@example.com"
password := defaults.Password.Password  // Use generated password
url := "https://example.com"

result, err := client.CreateEntry(&strongbox.CreateEntryRequest{
    DatabaseID: databaseID,
    Title:      &title,
    Username:   &username,
    Password:   &password,
    URL:        &url,
})
```

#### Generating Passwords

```go
// Basic generation
pwd, err := client.GeneratePassword()

// With strength analysis
pwdV2, err := client.GeneratePasswordV2()
fmt.Printf("Password: %s (Strength: %s, %.2f bits)\n",
    pwdV2.Password.Password,
    pwdV2.Password.Strength.Category,
    pwdV2.Password.Strength.Entropy)
```

#### Copying to Clipboard

```go
// Copy password
result, err := client.CopyField(databaseID, nodeID, strongbox.FieldPassword, false)

// Copy TOTP code
result, err := client.CopyField(databaseID, nodeID, strongbox.FieldTOTP, true)
```

### Documentation

Full API documentation is available on [pkg.go.dev](https://pkg.go.dev/github.com/steigr/strongbox-go/pkg/strongbox).

View local documentation:

```bash
go doc -all github.com/steigr/strongbox-go/pkg/strongbox
```

## CLI Usage

### Status and Database Info

```bash
# Show status and databases
strongbox status

# afproxy-cli - direct interaction with afproxy
afproxy-cli --type status
afproxy-cli --type search --payload '{"query": "github", "skip": 0, "take": 10}'
```

# Search for credentials
strongbox search "github"

# Get credentials for a URL
strongbox get-url "https://github.com"
strongbox get-url "https://github.com" -f password

# Get an entry by name
strongbox get "My Entry"
strongbox get "My Entry" -f password
strongbox get ssh passphrase --field=password

# strongsshpass - sshpass-like tool using Strongbox
go run ./examples/strongsshpass user@host

# Lock/unlock a database
strongbox lock <database-id>
strongbox unlock <database-id>

# List groups
strongbox groups <database-id>

# Generate a password
strongbox generate-password
strongbox generate-password-v2

# Check password strength
strongbox password-strength "mypassword"

# Copy a field to clipboard
strongbox copy-field <db-id> <node-id> username
strongbox copy-field <db-id> <node-id> password
strongbox copy-field <db-id> <node-id> totp

# Copy arbitrary string to clipboard
strongbox copy-string "some value"

# Create a new entry
strongbox create-entry <db-id> --title "My Entry" --username "user" --password "pass" --url "https://example.com"

# Get new entry defaults
strongbox defaults <database-id>

# Get icon for an entry
strongbox icon <database-id> <node-id>
```

All commands support global flags:
- `-U, --unlock <true|false|try>`: Control automatic database unlocking (default: try).
- `-o, --output <pretty|wide|json|yaml|csv|tsv>`: Output format (default: pretty).

## Library Usage

See the `examples/` directory for standalone example applications, or the [Go Documentation](https://pkg.go.dev/github.com/steigr/strongbox-go/pkg/strongbox) for full API details.

```go
package main

import (
	"fmt"
	"log"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

func main() {
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	// Get status
	status, err := client.GetStatus()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Server: %s\n", status.ServerVersionInfo)
	for _, db := range status.Databases {
		fmt.Printf("  Database: %s (locked=%v)\n", db.NickName, db.Locked)
	}

	// Search
	results, err := client.Search("github", 0, 10)
	if err != nil {
		log.Fatal(err)
	}
	for _, cred := range results.Results {
		fmt.Printf("  %s - %s\n", cred.Title, cred.Username)
	}
}
```

## Protocol

Communication uses the [Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) protocol:

1. Messages are framed with a 4-byte little-endian length prefix followed by JSON
2. The client generates a NaCl (curve25519-xsalsa20-poly1305) keypair
3. The first `status` request is sent with only the client's public key to obtain the server's public key
4. Subsequent requests encrypt the inner JSON payload using NaCl `box` and send it as base64 in the outer envelope

## License

See the project license file.
