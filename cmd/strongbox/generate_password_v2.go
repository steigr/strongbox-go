package main

import "github.com/spf13/cobra"

var generatePasswordV2Cmd = &cobra.Command{
	Use:   "generate-password-v2",
	Short: "Generate passwords with strength info",
	Long:  `Generate secure passwords with detailed strength information.`,
	Run: func(cmd *cobra.Command, args []string) {
		result, err := client.GeneratePasswordV2()
		if err != nil {
			fatal("generating password: %v", err)
		}
		printResult(result, false)
	},
}