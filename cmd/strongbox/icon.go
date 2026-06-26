package main

import "github.com/spf13/cobra"

var iconCmd = &cobra.Command{
	Use:   "icon <db-id/nickname> <node-id>",
	Short: "Get icon for an entry",
	Long:  `Retrieve the icon for a specific entry.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		idOrNickname := args[0]
		nodeID := args[1]
		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)
		result, err := client.GetIcon(dbID, nodeID)
		if err != nil {
			fatal("getting icon: %v", err)
		}
		probeTerminal()
		if terminalImageSupport != ImageSupportNone {
			printIcon(result.Icon)
		} else {
			printResult(result, false)
		}
	},
}