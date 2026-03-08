package strongbox_test

import (
	"fmt"
	"log"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

// Example demonstrates basic usage of the strongbox client library.
func Example() {
	// Create a new client
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	// Get status and list databases
	status, err := client.GetStatus()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Strongbox version: %s\n", status.ServerVersionInfo)
	fmt.Printf("Number of databases: %d\n", len(status.Databases))

	// Search for credentials
	results, err := client.Search("github", 0, 10)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d credentials\n", len(results.Results))
}

// Example_search demonstrates searching for credentials.
func Example_search() {
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	// Search for credentials matching "github"
	results, err := client.Search("github", 0, 10)
	if err != nil {
		log.Fatal(err)
	}

	for _, cred := range results.Results {
		fmt.Printf("Title: %s\n", cred.Title)
		fmt.Printf("Username: %s\n", cred.Username)
		fmt.Printf("URL: %s\n", cred.URL)
		fmt.Println("---")
	}
}

// Example_credentialsForURL demonstrates retrieving credentials for a specific URL.
func Example_credentialsForURL() {
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	// Get credentials for a specific URL
	results, err := client.CredentialsForURL("https://github.com", 0, 10)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found credentials in %d unlocked databases\n", results.UnlockedDatabaseCount)
	for _, cred := range results.Results {
		fmt.Printf("%s: %s\n", cred.Title, cred.Username)
	}
}

// Example_generatePassword demonstrates password generation.
func Example_generatePassword() {
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	// Generate a password with strength information
	result, err := client.GeneratePasswordV2()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated password: %s\n", result.Password.Password)
	fmt.Printf("Strength: %s\n", result.Password.Strength.Category)
	fmt.Printf("Entropy: %.2f bits\n", result.Password.Strength.Entropy)
	fmt.Printf("Summary: %s\n", result.Password.Strength.SummaryString)
}

// Example_createEntry demonstrates creating a new credential entry.
func Example_createEntry() {
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	// Get status to find an unlocked database
	status, err := client.GetStatus()
	if err != nil {
		log.Fatal(err)
	}

	var databaseID string
	for _, db := range status.Databases {
		if !db.Locked {
			databaseID = db.UUID
			break
		}
	}

	if databaseID == "" {
		log.Fatal("No unlocked database found")
	}

	// Get default values
	defaults, err := client.GetNewEntryDefaultsV2(databaseID)
	if err != nil {
		log.Fatal(err)
	}

	if defaults.Error != nil {
		log.Fatalf("Error getting defaults: %s", *defaults.Error)
	}

	// Create a new entry
	title := "Example Account"
	username := "user@example.com"
	password := defaults.Password.Password
	url := "https://example.com"

	result, err := client.CreateEntry(&strongbox.CreateEntryRequest{
		DatabaseID: databaseID,
		Title:      &title,
		Username:   &username,
		Password:   &password,
		URL:        &url,
	})
	if err != nil {
		log.Fatal(err)
	}

	if result.Error != nil {
		log.Fatalf("Failed to create entry: %s", *result.Error)
	}

	fmt.Printf("Created entry with UUID: %s\n", *result.UUID)
}

// Example_copyField demonstrates copying a credential field to the clipboard.
func Example_copyField() {
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	// Search for a credential
	results, err := client.Search("example", 0, 1)
	if err != nil {
		log.Fatal(err)
	}

	if len(results.Results) == 0 {
		log.Fatal("No credentials found")
	}

	cred := results.Results[0]

	// Copy the password to clipboard
	result, err := client.CopyField(
		cred.DatabaseID,
		cred.UUID,
		strongbox.FieldPassword,
		false,
	)
	if err != nil {
		log.Fatal(err)
	}

	if result.Success {
		fmt.Println("Password copied to clipboard")
	}
}

// Example_lockUnlock demonstrates locking and unlocking a database.
func Example_lockUnlock() {
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	// Get status to find a database
	status, err := client.GetStatus()
	if err != nil {
		log.Fatal(err)
	}

	if len(status.Databases) == 0 {
		log.Fatal("No databases found")
	}

	databaseID := status.Databases[0].UUID

	// Lock the database
	lockResult, err := client.LockDatabase(databaseID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Database %s locked\n", lockResult.DatabaseID)

	// Unlock the database (prompts user in Strongbox)
	unlockResult, err := client.UnlockDatabase(databaseID)
	if err != nil {
		log.Fatal(err)
	}

	if unlockResult.Success {
		fmt.Println("Database unlocked successfully")
	}
}

// Example_pagination demonstrates fetching all results with automatic pagination.
func Example_pagination() {
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	// Fetch first 10 results
	results, err := client.Search("example", 0, 10)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("First page: %d results\n", len(results.Results))

	// Fetch all results with automatic pagination
	allResults, err := client.Search("example", 0, -1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("All results: %d credentials\n", len(allResults.Results))
}

// Example_passwordStrength demonstrates checking password strength.
func Example_passwordStrength() {
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	// Check strength of a password
	result, err := client.GetPasswordStrength("MyP@ssw0rd123!")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Entropy: %.2f bits\n", result.Strength.Entropy)
	fmt.Printf("Category: %s\n", result.Strength.Category)
	fmt.Printf("Summary: %s\n", result.Strength.SummaryString)
}

// Example_customProxyPath demonstrates using a custom afproxy path.
func Example_customProxyPath() {
	// Create a client with a custom afproxy path
	client, err := strongbox.NewClient(
		strongbox.WithProxyPath("/custom/path/to/afproxy"),
	)
	if err != nil {
		log.Fatal(err)
	}

	status, err := client.GetStatus()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Connected to Strongbox version: %s\n", status.ServerVersionInfo)
}
