package main

import "github.com/spf13/cobra"

var groupsCmd = &cobra.Command{
	Use:   "groups <db-id/nickname>",
	Short: "List groups in a database",
	Long:  `List all groups in the specified database.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idOrNickname := args[0]
		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)
		result, err := client.GetGroups(dbID)
		if err != nil {
			fatal("getting groups: %v", err)
		}
		printResult(result, false)
	},
}