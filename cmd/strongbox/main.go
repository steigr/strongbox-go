package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: strongbox <command> [arguments]

Commands:
  status                              Show Strongbox status and databases
  search <query> [skip] [take]        Search for credentials
  get <url> [skip] [take]             Get credentials for a URL
  lock <database-id>                  Lock a database
  unlock <database-id>                Unlock a database
  groups <database-id>                List groups in a database
  generate-password                   Generate a password
  generate-password-v2                Generate passwords with strength info
  password-strength <password>        Check password strength
  copy-field <db-id> <node-id> <field> Copy a field (username|password|totp)
  copy-string <value>                 Copy a string to clipboard
  create-entry <db-id> [--title T] [--username U] [--password P] [--url URL]
                                      Create a new entry
  defaults <database-id>              Get new entry defaults
  icon <database-id> <node-id>        Get icon for an entry
`)
	os.Exit(1)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func atoi(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		fatal("invalid number: %s", s)
	}
	return n
}

func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

func requireArg(args []string, i int, name string) string {
	if i >= len(args) {
		fatal("missing required argument: %s", name)
	}
	return args[i]
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	client, err := strongbox.NewClient()
	if err != nil {
		fatal("creating client: %v", err)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "status":
		status, err := client.GetStatus()
		if err != nil {
			fatal("getting status: %v", err)
		}
		printJSON(status)

	case "search":
		query := requireArg(args, 0, "query")
		skip := atoi(arg(args, 1), 0)
		take := atoi(arg(args, 2), 25)
		result, err := client.Search(query, skip, take)
		if err != nil {
			fatal("searching: %v", err)
		}
		printJSON(result)

	case "get":
		url := requireArg(args, 0, "url")
		skip := atoi(arg(args, 1), 0)
		take := atoi(arg(args, 2), 9)
		result, err := client.CredentialsForURL(url, skip, take)
		if err != nil {
			fatal("getting credentials: %v", err)
		}
		printJSON(result)

	case "lock":
		dbID := requireArg(args, 0, "database-id")
		result, err := client.LockDatabase(dbID)
		if err != nil {
			fatal("locking database: %v", err)
		}
		printJSON(result)

	case "unlock":
		dbID := requireArg(args, 0, "database-id")
		result, err := client.UnlockDatabase(dbID)
		if err != nil {
			fatal("unlocking database: %v", err)
		}
		printJSON(result)

	case "groups":
		dbID := requireArg(args, 0, "database-id")
		result, err := client.GetGroups(dbID)
		if err != nil {
			fatal("getting groups: %v", err)
		}
		printJSON(result)

	case "generate-password":
		result, err := client.GeneratePassword()
		if err != nil {
			fatal("generating password: %v", err)
		}
		printJSON(result)

	case "generate-password-v2":
		result, err := client.GeneratePasswordV2()
		if err != nil {
			fatal("generating password: %v", err)
		}
		printJSON(result)

	case "password-strength":
		pw := requireArg(args, 0, "password")
		result, err := client.GetPasswordStrength(pw)
		if err != nil {
			fatal("checking password strength: %v", err)
		}
		printJSON(result)

	case "copy-field":
		dbID := requireArg(args, 0, "database-id")
		nodeID := requireArg(args, 1, "node-id")
		fieldStr := requireArg(args, 2, "field")
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
		result, err := client.CopyField(dbID, nodeID, field, fieldStr == "totp")
		if err != nil {
			fatal("copying field: %v", err)
		}
		printJSON(result)

	case "copy-string":
		value := requireArg(args, 0, "value")
		result, err := client.CopyString(value)
		if err != nil {
			fatal("copying string: %v", err)
		}
		printJSON(result)

	case "create-entry":
		dbID := requireArg(args, 0, "database-id")
		req := &strongbox.CreateEntryRequest{DatabaseID: dbID}
		for i := 1; i < len(args)-1; i += 2 {
			v := args[i+1]
			switch args[i] {
			case "--title":
				req.Title = &v
			case "--username":
				req.Username = &v
			case "--password":
				req.Password = &v
			case "--url":
				req.URL = &v
			case "--group":
				req.GroupID = &v
			default:
				fatal("unknown flag: %s", args[i])
			}
		}
		result, err := client.CreateEntry(req)
		if err != nil {
			fatal("creating entry: %v", err)
		}
		printJSON(result)

	case "defaults":
		dbID := requireArg(args, 0, "database-id")
		result, err := client.GetNewEntryDefaults(dbID)
		if err != nil {
			fatal("getting defaults: %v", err)
		}
		printJSON(result)

	case "icon":
		dbID := requireArg(args, 0, "database-id")
		nodeID := requireArg(args, 1, "node-id")
		result, err := client.GetIcon(dbID, nodeID)
		if err != nil {
			fatal("getting icon: %v", err)
		}
		printJSON(result)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
	}
}
