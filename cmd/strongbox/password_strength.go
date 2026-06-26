package main

import "github.com/spf13/cobra"

var passwordStrengthCmd = &cobra.Command{
	Use:   "password-strength <password>",
	Short: "Check password strength",
	Long:  `Analyze the strength of a password.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		password := args[0]
		result, err := client.GetPasswordStrength(password)
		if err != nil {
			fatal("checking password strength: %v", err)
		}
		printResult(result, false)
	},
}