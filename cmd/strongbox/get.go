package main

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/steigr/strongbox-go/pkg/strongbox"
)

var getCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get an entry by name or path",
	Long: `Get a credential entry by searching for its name or path.

If a field is specified with --field, only that field value is printed.`,
	Example: `  strongbox get "My Account"
  strongbox get github --field password
  strongbox get ssh passphrase --field password`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fieldName, _ := cmd.Flags().GetString("field")
		name := strings.Join(args, " ")

		ensureAutoFillDatabase(client, unlockBehavior)
		result, err := client.Search(name, 0, -1)
		if err != nil {
			fatal("searching: %v", err)
		}

		if len(result.Results) == 0 {
			fatal("no entry found matching '%s'", name)
		}

		var entry *strongbox.AutoFillCredential
		for i := range result.Results {
			if strings.EqualFold(result.Results[i].Title, name) {
				entry = &result.Results[i]
				break
			}
		}
		if entry == nil {
			entry = &result.Results[0]
		}

		if fieldName != "" {
			printField(*entry, fieldName)
		} else {
			probeTerminal()
			printResult(*entry, true)
		}
	},
}

func init() {
	getCmd.Flags().StringP("field", "f", "", "Field to extract (username/password/url/totp/notes/uuid/database/modified)")
	getCmd.RegisterFlagCompletionFunc("field", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return completeFieldForSearch(args, toComplete)
	})
}

var standardFields = []string{
	"username",
	"password",
	"url",
	"totp",
	"notes",
	"uuid",
	"database",
	"modified",
}

func completeFieldForSearch(args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	fields := append([]string{}, standardFields...)

	if len(args) > 0 {
		c, err := strongbox.NewClient()
		if err == nil {
			name := strings.Join(args, " ")
			result, err := c.Search(name, 0, -1)
			if err == nil && len(result.Results) > 0 {
				entry := result.Results[0]
				for _, r := range result.Results {
					if strings.EqualFold(r.Title, name) {
						entry = r
						break
					}
				}
				for _, cf := range entry.CustomFields {
					fields = append(fields, cf.Key)
				}
			}
		}
	}

	return fields, cobra.ShellCompDirectiveNoFileComp
}