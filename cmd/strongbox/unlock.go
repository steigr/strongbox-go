package main

import "github.com/spf13/cobra"

var unlockCmd = &cobra.Command{
	Use:   "unlock <db-id/nickname>",
	Short: "Unlock a database",
	Long:  `Request Strongbox to unlock the specified database. This will prompt in the Strongbox app.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idOrNickname := args[0]
		status, err := client.GetStatus()
		if err != nil {
			fatal("getting status: %v", err)
		}
		dbID := findDatabase(status, idOrNickname)
		result, err := client.UnlockDatabase(dbID)
		if err != nil {
			fatal("unlocking database: %v", err)
		}
		printResult(result, false)
	},
}