package main

import (
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/steigr/strongbox-go/pkg/strongbox"
)

// Status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Strongbox status and databases",
	Long:  `Display the current status of Strongbox including all databases and their lock states.`,
	Run: func(cmd *cobra.Command, args []string) {
		probeTerminal()
		status, err := client.GetStatus()
		if err != nil {
			// Try to start Strongbox
			errStart := exec.Command("open", "-a", "Strongbox").Run()
			if errStart != nil {
				fatal("getting status: %v (failed to start Strongbox: %v)", err, errStart)
			}

			// Wait for Strongbox to start
			retries := 10
			for i := 0; i < retries; i++ {
				time.Sleep(500 * time.Millisecond)
				status, err = client.GetStatus()
				if err == nil {
					break
				}
			}

			if err != nil {
				fatal("getting status: %v (Strongbox did not respond after starting)", err)
			}
		}
		printResult(status, false)
	},
}

// Search command
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
		ensureUnlockedDatabase(client, unlockBehavior)
		probeTerminal()
		query := args[0]
		result, err := client.Search(query, skip, take)
		if err != nil {
			fatal("searching: %v", err)
		}
		printResult(result, true)
	},
}

// Get URL command
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

// Get command
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

		ensureUnlockedDatabase(client, unlockBehavior)
		result, err := client.Search(name, 0, -1)
		if err != nil {
			fatal("searching: %v", err)
		}

		if len(result.Results) == 0 {
			fatal("no entry found matching '%s'", name)
		}

		// Find exact or best match
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

// Lock command
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

// Unlock command
var unlockCmd = &cobra.Command{
	Use:   "unlock <db-id/nickname>",
	Short: "Unlock a database",
	Long:  `Request Strongbox to unlock the specified database. This will prompt in the Strongbox app.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idOrNickname := args[0]
		status, err := client.GetStatus()
		if err != nil {
			fatal("getting status: %v", err)
		}
		dbID := findDatabase(status, idOrNickname)
		result, err := client.UnlockDatabase(dbID)
		if err != nil {
			fatal("unlocking database: %v", err)
		}
		printResult(result, false)
	},
}

// Groups command
var groupsCmd = &cobra.Command{
	Use:   "groups <db-id/nickname>",
	Short: "List groups in a database",
	Long:  `List all groups in the specified database.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idOrNickname := args[0]
		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)
		result, err := client.GetGroups(dbID)
		if err != nil {
			fatal("getting groups: %v", err)
		}
		printResult(result, false)
	},
}

// Generate password command
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

// Generate password v2 command
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

// Password strength command
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

// Copy field command
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

// Copy string command
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

// Create entry command
var createEntryCmd = &cobra.Command{
	Use:   "create-entry <db-id/nickname>",
	Short: "Create a new entry",
	Long:  `Create a new credential entry in the specified database.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idOrNickname := args[0]
		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)

		req := &strongbox.CreateEntryRequest{DatabaseID: dbID}

		if title, _ := cmd.Flags().GetString("title"); title != "" {
			req.Title = &title
		}
		if username, _ := cmd.Flags().GetString("username"); username != "" {
			req.Username = &username
		}
		if password, _ := cmd.Flags().GetString("password"); password != "" {
			req.Password = &password
		}
		if url, _ := cmd.Flags().GetString("url"); url != "" {
			req.URL = &url
		}
		if group, _ := cmd.Flags().GetString("group"); group != "" {
			req.GroupID = &group
		}

		result, err := client.CreateEntry(req)
		if err != nil {
			fatal("creating entry: %v", err)
		}
		printResult(result, false)
	},
}

// Defaults command
var defaultsCmd = &cobra.Command{
	Use:   "defaults <db-id/nickname>",
	Short: "Get new entry defaults",
	Long:  `Get suggested default values for creating a new entry in the specified database.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		idOrNickname := args[0]
		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)
		result, err := client.GetNewEntryDefaults(dbID)
		if err != nil {
			fatal("getting defaults: %v", err)
		}
		printResult(result, false)
	},
}

// Icon command
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

func init() {
	// Add flags to commands
	getURLCmd.Flags().StringP("field", "f", "", "Field to extract (username/password/url/totp/notes/uuid/database/modified)")
	getCmd.Flags().StringP("field", "f", "", "Field to extract (username/password/url/totp/notes/uuid/database/modified)")

	createEntryCmd.Flags().String("title", "", "Entry title")
	createEntryCmd.Flags().String("username", "", "Username")
	createEntryCmd.Flags().String("password", "", "Password")
	createEntryCmd.Flags().String("url", "", "URL")
	createEntryCmd.Flags().String("group", "", "Group ID")

	// Dynamic completion for --field on "get"
	getCmd.RegisterFlagCompletionFunc("field", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return completeFieldForSearch(args, toComplete)
	})

	// Dynamic completion for --field on "get-url"
	getURLCmd.RegisterFlagCompletionFunc("field", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return completeFieldForURL(args, toComplete)
	})
}

// standardFields are the well-known fields available on every credential entry.
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

// completeFieldForSearch provides completions for the --field flag of "get".
// It always offers the standard fields and, when the entry name resolves to a
// single credential, also offers that entry's custom field keys.
func completeFieldForSearch(args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	fields := append([]string{}, standardFields...)

	if len(args) > 0 {
		c, err := strongbox.NewClient()
		if err == nil {
			name := strings.Join(args, " ")
			result, err := c.Search(name, 0, -1)
			if err == nil && len(result.Results) > 0 {
				// Find best match
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

// completeFieldForURL provides completions for the --field flag of "get-url".
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
