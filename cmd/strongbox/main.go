package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/steigr/strongbox-go/pkg/strongbox"
)

var (
	client               *strongbox.Client
	unlockBehavior       string
	skip                 int
	take                 int
	outputFormat         OutputFormat
	terminalImageSupport TerminalImageSupport
	helpMode             string
)

type TerminalImageSupport int

const (
	ImageSupportNone TerminalImageSupport = iota
	ImageSupportSixel
	ImageSupportIIP
)

type OutputFormat int

const (
	OutputFormatPretty OutputFormat = iota
	OutputFormatWide
	OutputFormatJSON
	OutputFormatYAML
	OutputFormatCSV
	OutputFormatTSV
)

func init() {
	terminalImageSupport = ImageSupportNone
	outputFormat = OutputFormatPretty
	helpMode = "short"
}

var rootCmd = &cobra.Command{
	Use:   "strongbox",
	Short: "Strongbox Password Manager CLI",
	Long:  "A command-line interface for interacting with Strongbox Password Manager.\n\nCommon commands:\n  search     Search for credentials\n  get        Get an entry by name or path",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		outputStr, _ := cmd.Flags().GetString("output")
		switch outputStr {
		case "pretty":
			outputFormat = OutputFormatPretty
		case "wide":
			outputFormat = OutputFormatWide
		case "json":
			outputFormat = OutputFormatJSON
		case "yaml":
			outputFormat = OutputFormatYAML
		case "csv":
			outputFormat = OutputFormatCSV
		case "tsv":
			outputFormat = OutputFormatTSV
		default:
			return fmt.Errorf("unknown output format: %s", outputStr)
		}

		var err error
		client, err = strongbox.NewClient()
		if err != nil {
			return fmt.Errorf("creating client: %v", err)
		}

		return nil
	},
}

func init() {

	rootCmd.PersistentFlags().StringVarP(&unlockBehavior, "unlock", "U", "try", "Control automatic database unlocking (true/false/try)")
	rootCmd.PersistentFlags().IntVar(&skip, "skip", 0, "Number of results to skip")
	rootCmd.PersistentFlags().IntVar(&take, "take", -1, "Number of results to take (-1 for all)")
	rootCmd.PersistentFlags().StringP("output", "o", "pretty", "Output format (pretty/wide/json/yaml/csv/tsv)")

	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(getURLCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(lockCmd)
	rootCmd.AddCommand(unlockCmd)
	rootCmd.AddCommand(groupsCmd)
	rootCmd.AddCommand(generatePasswordCmd)
	rootCmd.AddCommand(generatePasswordV2Cmd)
	rootCmd.AddCommand(passwordStrengthCmd)
	rootCmd.AddCommand(copyFieldCmd)
	rootCmd.AddCommand(copyStringCmd)
	rootCmd.AddCommand(createEntryCmd)
	rootCmd.AddCommand(defaultsCmd)
	rootCmd.AddCommand(iconCmd)
}

func main() {
	// Pre-process args to handle --help with a value parameter.
	// Cobra treats --help as a boolean flag, so we intercept "short" / "all"
	// before Cobra ever sees them.
	args := os.Args[1:]
	var newArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--help="):
			helpMode = strings.TrimPrefix(arg, "--help=")
			newArgs = append(newArgs, "--help")
		case arg == "--help" && i+1 < len(args) && (args[i+1] == "short" || args[i+1] == "all"):
			helpMode = args[i+1]
			newArgs = append(newArgs, "--help")
			i++
		case arg == "-h" && i+1 < len(args) && (args[i+1] == "short" || args[i+1] == "all"):
			helpMode = args[i+1]
			newArgs = append(newArgs, "-h")
			i++
		default:
			newArgs = append(newArgs, arg)
		}
	}

	// Apply help-mode filtering before Cobra runs.
	if helpMode == "short" {
		// Use a custom help function so we can hide commands at render time,
		// after Cobra has added its internal commands (completion, help).
		defaultHelp := rootCmd.HelpFunc()
		rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
			// Only apply the short template and hiding to the root command.
			if cmd == cmd.Root() {
				cmd.SetUsageTemplate(shortUsageTemplate)
				for _, sub := range cmd.Commands() {
					switch sub.Name() {
					case "search", "get", "help", "completion":
						// keep visible
					default:
						sub.Hidden = true
					}
				}
			}
			defaultHelp(cmd, args)
		})
	}

	os.Args = append([]string{os.Args[0]}, newArgs...)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// shortUsageTemplate is a custom Cobra usage template that shows only
// non-hidden (common) commands and adds a hint about --help all.
var shortUsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Common Commands:{{range .Commands}}{{if (not .Hidden)}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.
Use "{{.CommandPath}} --help all" to see all available commands.{{end}}
`
