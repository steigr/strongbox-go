package main

import (
	"fmt"
	"log"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

func main() {
	// Create a new client with default options.
	// By default, it expects the afproxy binary at:
	// /Applications/Strongbox.app/Contents/MacOS/afproxy
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	// Use WithProxyPath to specify a different path to the afproxy binary.
	customClient, err := strongbox.NewClient(
		strongbox.WithProxyPath("/usr/local/bin/afproxy"),
	)
	if err != nil {
		log.Fatalf("failed to create custom client: %v", err)
	}

	_ = client
	_ = customClient
	fmt.Println("Clients created successfully")
}
