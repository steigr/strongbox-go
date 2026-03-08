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
// # Installation
//
// Install the package using go get:
//
//	go get github.com/steigr/strongbox-go/pkg/strongbox
//
// # Requirements
//
// This library requires Strongbox Password Manager to be installed on macOS with the afproxy
// binary available at /Applications/Strongbox.app/Contents/MacOS/afproxy. If Strongbox is
// installed in a different location, you can specify a custom path using the WithProxyPath option.
//
// # Quick Start
//
// Here's a simple example to get you started:
//
//	package main
//
//	import (

//	)
//
//	func main() {
//	    // Create a new client
//	    client, err := strongbox.NewClient()
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Get database status
//	    status, err := client.GetStatus()
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    fmt.Printf("Strongbox version: %s\n", status.ServerVersionInfo)
//	    fmt.Printf("Databases: %d\n", len(status.Databases))
//
//	    // Search for credentials
//	    results, err := client.Search("github", 0, 10)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    for _, cred := range results.Results {
//	        fmt.Printf("%s: %s@%s\n", cred.Title, cred.Username, cred.URL)
//	    }
//	}
//
// # Common Use Cases
//
// ## Searching for Credentials
//
// Search across all unlocked databases for credentials matching a query:
//
//	results, err := client.Search("example.com", 0, 10)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, cred := range results.Results {
//	    fmt.Printf("Found: %s (%s)\n", cred.Title, cred.Username)
//	}
//
// ## Getting Credentials by URL
//
// Retrieve credentials that match a specific URL using Strongbox's URL matching logic:
//
//	results, err := client.CredentialsForURL("https://github.com", 0, 10)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, cred := range results.Results {
//	    fmt.Printf("Username: %s\n", cred.Username)
//	    fmt.Printf("Password: %s\n", cred.Password)
//	    if cred.TOTP != "" {
//	        fmt.Printf("TOTP: %s\n", cred.TOTP)
//	    }
//	}
//
// ## Creating New Entries
//
// Create a new credential entry in a database:
//
//	// Get default values first
//	defaults, err := client.GetNewEntryDefaults(databaseID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create the entry
//	title := "My New Account"
//	username := "user@example.com"
//	password := *defaults.Password  // Use generated password
//	url := "https://example.com"
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
//
//	if result.Error != nil {
//	    log.Fatalf("Failed to create entry: %s", *result.Error)
//	}
//
//	fmt.Printf("Created entry with UUID: %s\n", *result.UUID)
//
// ## Generating Passwords
//
// Generate a secure password using Strongbox's password generator:
//
//	// Basic generation
//	pwd, err := client.GeneratePassword()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Generated password: %s\n", pwd.Password)
//
//	// Generation with strength analysis
//	pwdV2, err := client.GeneratePasswordV2()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Password: %s\n", pwdV2.Password.Password)
//	fmt.Printf("Strength: %s (%.2f bits)\n",
//	    pwdV2.Password.Strength.Category,
//	    pwdV2.Password.Strength.Entropy)
//
// ## Copying to Clipboard
//
// Copy a credential field to the system clipboard:
//
//	// Copy password
//	result, err := client.CopyField(databaseID, nodeID, strongbox.FieldPassword, false)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.Success {
//	    fmt.Println("Password copied to clipboard")
//	}
//
//	// Copy TOTP code
//	result, err = client.CopyField(databaseID, nodeID, strongbox.FieldTOTP, true)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// ## Managing Database Locks
//
// Lock and unlock databases:
//
//	// Unlock a database (prompts user in Strongbox)
//	unlockResult, err := client.UnlockDatabase(databaseID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if unlockResult.Success {
//	    fmt.Println("Database unlocked")
//	}
//
//	// Lock a database
//	lockResult, err := client.LockDatabase(databaseID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Database %s locked\n", lockResult.DatabaseID)
//
// # Pagination
//
// Many methods support pagination through skip and take parameters. You can fetch
// all results by setting take to -1:
//
//	// Get first 10 results
//	results, err := client.Search("example", 0, 10)
//
//	// Get all results (automatic pagination)
//	allResults, err := client.Search("example", 0, -1)
//
// # Security
//
// The client uses NaCl box encryption (Curve25519, XSalsa20, and Poly1305) to secure all
// communication with the Strongbox native host. Each client generates an ephemeral keypair,
// and messages are encrypted using the server's public key obtained during the initial handshake.
//
// The encryption happens automatically - you don't need to worry about the cryptographic
// details. Simply create a client and call the methods you need.
//
// # Thread Safety
//
// The Client type is safe for concurrent use. Internal state (encryption keys) is protected
// by a mutex. You can safely call methods from multiple goroutines:
//
//	client, err := strongbox.NewClient()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	var wg sync.WaitGroup
//	for i := 0; i < 10; i++ {
//	    wg.Add(1)
//	    go func(query string) {
//	        defer wg.Done()
//	        results, err := client.Search(query, 0, 10)
//	        if err != nil {
//	            log.Printf("Error: %v", err)
//	            return
//	        }
//	        fmt.Printf("Found %d results for %s\n", len(results.Results), query)
//	    }(fmt.Sprintf("query-%d", i))
//	}
//	wg.Wait()
//
// # Advanced Usage
//
// For advanced use cases, you can use the low-level methods:
//
//   - SendRaw: Send a raw request and get an encrypted response
//   - BuildEncryptedRequest: Build an encrypted request envelope
//   - SendEncrypted: Send an encrypted request and get a decrypted response
//
// These methods give you full control over the request/response cycle:
//
//	// Build and send a custom encrypted request
//	req, err := client.BuildEncryptedRequest(
//	    &strongbox.SearchRequest{Query: "test", Skip: 0, Take: 10},
//	    strongbox.MessageTypeSearch,
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	resp, err := client.SendRaw(req)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Error Handling
//
// Methods return errors for various failure conditions including:
//
//   - Network/communication errors with afproxy
//   - Encryption/decryption failures
//   - Server-side errors (database locked, entry not found, etc.)
//
// Always check for errors and handle them appropriately:
//
//	results, err := client.Search("example", 0, 10)
//	if err != nil {
//	    // Handle error - could be communication error, encryption error, etc.
//	    log.Printf("Search failed: %v", err)
//	    return
//	}
//
//	// Some methods return error information in the response
//	defaults, err := client.GetNewEntryDefaults(databaseID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if defaults.Error != nil {
//	    // Server-side error (e.g., database locked)
//	    log.Fatalf("Server error: %s", *defaults.Error)
//	}
//
// # Custom Proxy Path
//
// If Strongbox is installed in a non-standard location, specify a custom path:
//
//	client, err := strongbox.NewClient(
//	    strongbox.WithProxyPath("/custom/path/to/afproxy"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Complete Example
//
// Here's a more complete example showing various features:
//
//	package main
//
//	import (

// )
//
//	func main() {
//	    // Create client
//	    client, err := strongbox.NewClient()
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Get status and find an unlocked database
//	    status, err := client.GetStatus()
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    var unlockedDB *strongbox.DatabaseSummary
//	    for _, db := range status.Databases {
//	        if !db.Locked {
//	            unlockedDB = &db
//	            break
//	        }
//	    }
//
//	    if unlockedDB == nil {
//	        log.Fatal("No unlocked database found")
//	    }
//
//	    fmt.Printf("Using database: %s\n", unlockedDB.NickName)
//
//	    // Get default values for new entry
//	    defaults, err := client.GetNewEntryDefaultsV2(unlockedDB.UUID)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    if defaults.Error != nil {
//	        log.Fatalf("Error getting defaults: %s", *defaults.Error)
//	    }
//
//	    // Create a new entry
//	    title := "Test Entry"
//	    username := "testuser@example.com"
//	    password := defaults.Password.Password
//	    url := "https://example.com"
//
//	    entry, err := client.CreateEntry(&strongbox.CreateEntryRequest{
//	        DatabaseID: unlockedDB.UUID,
//	        Title:      &title,
//	        Username:   &username,
//	        Password:   &password,
//	        URL:        &url,
//	    })
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    if entry.Error != nil {
//	        log.Fatalf("Failed to create entry: %s", *entry.Error)
//	    }
//
//	    fmt.Printf("Created entry: %s (UUID: %s)\n", *entry.UUID, entry.Credential.Title)
//
//	    // Search for the entry we just created
//	    results, err := client.Search("Test Entry", 0, 10)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    fmt.Printf("Found %d entries matching 'Test Entry'\n", len(results.Results))
//	    for _, cred := range results.Results {
//	        fmt.Printf("  - %s: %s\n", cred.Title, cred.Username)
//	    }
//
//	    // Copy password to clipboard
//	    if len(results.Results) > 0 {
//	        cred := results.Results[0]
//	        result, err := client.CopyField(
//	            cred.DatabaseID,
//	            cred.UUID,
//	            strongbox.FieldPassword,
//	            false,
//	        )
//	        if err != nil {
//	            log.Fatal(err)
//	        }
//	        if result.Success {
//	            fmt.Println("Password copied to clipboard")
//	        }
//	    }
//	}
package strongbox
