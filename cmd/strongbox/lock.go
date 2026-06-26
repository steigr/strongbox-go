package main

import "github.com/spf13/cobra"

var lockCmd = &cobra.Command{
	Use:   "lock <db-id/nickname>",
	Short: "Lock a database",
	Long:  `Lock the specified database by UUID or nickname.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idOrNickname := args[0]
		status, err := client.GetStatus()
		if err != nil {
			fatal("getting status: %v", err)
		}
		dbID := findDatabase(status, idOrNickname)
		result, err := client.LockDatabase(dbID)
		if err != nil {
			fatal("locking database: %v", err)
		}
		printResult(result, false)
	},
}