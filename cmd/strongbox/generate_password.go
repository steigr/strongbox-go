package main

import "github.com/spf13/cobra"

var generatePasswordCmd = &cobra.Command{
	Use:   "generate-password",
	Short: "Generate a password",
	Long:  `Generate a secure password using Strongbox's password generator.`,
	Run: func(cmd *cobra.Command, args []string) {
		result, err := client.GeneratePassword()
		if err != nil {
			fatal("generating password: %v", err)
		}
		printResult(result, false)
	},
}