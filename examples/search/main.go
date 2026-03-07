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

	query := "github"
	if len(os.Args) > 1 {
		query = os.Args[1]
	}

	fmt.Printf("Searching for: %s\n", query)

	// Search for entries matching the query
	results, err := client.Search(query, 0, 10)
	if err != nil {
		log.Fatalf("search failed: %v", err)
	}

	for _, entry := range results.Results {
		fmt.Printf("Found: %s (Username: %s)\n", entry.Title, entry.Username)
	}
}
