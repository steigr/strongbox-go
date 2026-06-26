package main

import (
	"github.com/spf13/cobra"
	"github.com/steigr/strongbox-go/pkg/strongbox"
)

var getURLCmd = &cobra.Command{
	Use:   "get-url <url>",
	Short: "Get credentials for a URL",
	Long:  `Retrieve credentials that match the given URL using Strongbox's URL matching logic.`,
	Example: `  strongbox get-url https://github.com
  strongbox get-url https://example.com --field password`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fieldName, _ := cmd.Flags().GetString("field")
		url := args[0]

		ensureUnlockedDatabase(client, unlockBehavior)
		result, err := client.CredentialsForURL(url, skip, take)
		if err != nil {
			fatal("getting credentials: %v", err)
		}

		if fieldName != "" {
			if len(result.Results) == 0 {
				fatal("no entry found for URL '%s'", url)
			}
			if len(result.Results) > 1 {
				fatal("multiple entries found for URL '%s', please be more specific", url)
			}
			entry := result.Results[0]
			printField(entry, fieldName)
		} else {
			probeTerminal()
			if len(result.Results) == 1 {
				printResult(result.Results[0], true)
			} else {
				printResult(result, true)
			}
		}
	},
}

func init() {
	getURLCmd.Flags().StringP("field", "f", "", "Field to extract (username/password/url/totp/notes/uuid/database/modified)")
	getURLCmd.RegisterFlagCompletionFunc("field", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return completeFieldForURL(args, toComplete)
	})
}

func completeFieldForURL(args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	fields := append([]string{}, standardFields...)

	if len(args) > 0 {
		c, err := strongbox.NewClient()
		if err == nil {
			result, err := c.CredentialsForURL(args[0], 0, 1)
			if err == nil && len(result.Results) == 1 {
				for _, cf := range result.Results[0].CustomFields {
					fields = append(fields, cf.Key)
				}
			}
		}
	}

	return fields, cobra.ShellCompDirectiveNoFileComp
}