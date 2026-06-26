package main

import "github.com/spf13/cobra"

var searchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search for credentials",
	Long: `Search for credentials matching the query across all unlocked databases.

The query is matched against credential titles, usernames, URLs, and other fields.
Use --skip and --take for pagination.`,
	Example: `  strongbox search github
  strongbox search example.com --take 5
  strongbox search mypassword --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
 		ensureAutoFillDatabase(client, unlockBehavior)
		probeTerminal()
		query := args[0]
		result, err := client.Search(query, skip, take)
		if err != nil {
			fatal("searching: %v", err)
		}
		printResult(result, true)
	},
}