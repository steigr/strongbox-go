package main

import "github.com/spf13/cobra"

var defaultsCmd = &cobra.Command{
	Use:   "defaults <db-id/nickname>",
	Short: "Get new entry defaults",
	Long:  `Get suggested default values for creating a new entry in the specified database.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idOrNickname := args[0]
		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)
		result, err := client.GetNewEntryDefaults(dbID)
		if err != nil {
			fatal("getting defaults: %v", err)
		}
		printResult(result, false)
	},
}