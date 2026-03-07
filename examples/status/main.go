package main

import (
	"fmt"
	"log"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

func main() {
	client, err := strongbox.NewClient()
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	status, err := client.GetStatus()
	if err != nil {
		log.Fatalf("could not get status: %v", err)
	}

	fmt.Printf("Server Version: %s\n", status.ServerVersionInfo)
	for _, db := range status.Databases {
		statusStr := "Unlocked"
		if db.Locked {
			statusStr = "Locked"
		}
		fmt.Printf("Database: %s (%s)\n", db.NickName, statusStr)
	}
}
