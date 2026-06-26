package main

import (
	"github.com/spf13/cobra"
	"github.com/steigr/strongbox-go/pkg/strongbox"
)

var createEntryCmd = &cobra.Command{
	Use:   "create-entry <db-id/nickname>",
	Short: "Create a new entry",
	Long:  `Create a new credential entry in the specified database.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idOrNickname := args[0]
		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)

		req := &strongbox.CreateEntryRequest{DatabaseID: dbID}

		if title, _ := cmd.Flags().GetString("title"); title != "" {
			req.Title = &title
		}
		if username, _ := cmd.Flags().GetString("username"); username != "" {
			req.Username = &username
		}
		if password, _ := cmd.Flags().GetString("password"); password != "" {
			req.Password = &password
		}
		if url, _ := cmd.Flags().GetString("url"); url != "" {
			req.URL = &url
		}
		if group, _ := cmd.Flags().GetString("group"); group != "" {
			req.GroupID = &group
		}

		result, err := client.CreateEntry(req)
		if err != nil {
			fatal("creating entry: %v", err)
		}
		printResult(result, false)
	},
}

func init() {
	createEntryCmd.Flags().String("title", "", "Entry title")
	createEntryCmd.Flags().String("username", "", "Username")
	createEntryCmd.Flags().String("password", "", "Password")
	createEntryCmd.Flags().String("url", "", "URL")
	createEntryCmd.Flags().String("group", "", "Group ID")
}