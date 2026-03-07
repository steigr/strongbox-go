package main

import (
	"fmt"
	"log"
	"os"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

func main() {
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	url := "https://github.com"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}

	fmt.Printf("Getting credentials for: %s\n", url)

	// Get credentials for a specific URL
	results, err := client.CredentialsForURL(url, 0, 10)
	if err != nil {
		log.Fatalf("failed to get credentials: %v", err)
	}

	fmt.Printf("Found %d credentials\n", len(results.Results))
	for _, entry := range results.Results {
		fmt.Printf("Title: %s, User: %s\n", entry.Title, entry.Username)
	}
}
