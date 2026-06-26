package main

import "github.com/spf13/cobra"

var copyStringCmd = &cobra.Command{
	Use:   "copy-string <value>",
	Short: "Copy a string to clipboard",
	Long:  `Copy an arbitrary string to the clipboard via Strongbox.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		value := args[0]
		result, err := client.CopyString(value)
		if err != nil {
			fatal("copying string: %v", err)
		}
		printResult(result, false)
	},
}