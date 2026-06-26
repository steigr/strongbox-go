package main

import (
	"github.com/spf13/cobra"
	"github.com/steigr/strongbox-go/pkg/strongbox"
)

var copyFieldCmd = &cobra.Command{
	Use:   "copy-field <db-id/nickname> <node-id> <field>",
	Short: "Copy a field to clipboard",
	Long:  `Copy a specific field (username, password, or totp) from an entry to the clipboard.`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		idOrNickname := args[0]
		nodeID := args[1]
		fieldStr := args[2]

		var field strongbox.WellKnownField
		switch fieldStr {
		case "username":
			field = strongbox.FieldUsername
		case "password":
			field = strongbox.FieldPassword
		case "totp":
			field = strongbox.FieldTOTP
		default:
			fatal("unknown field: %s (use username, password, or totp)", fieldStr)
		}

		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)
		result, err := client.CopyField(dbID, nodeID, field, fieldStr == "totp")
		if err != nil {
			fatal("copying field: %v", err)
		}
		printResult(result, false)
	},
}