package main

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/steigr/strongbox-go/pkg/strongbox"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: strongbox [global flags] <command> [arguments]

Global Flags:
  -U, --unlock <true|false|try>       Control automatic database unlocking (default: try)
  -o, --output <pretty|json|yaml|csv|tsv> Output format (default: pretty)

Commands:
  status                              Show Strongbox status and databases
  search <query> [skip] [take]        Search for credentials
  get-url <url> [-f/--field F]        Get credentials for a URL
  get <name> [-f/--field F]           Get an entry by name or path
  lock <db-id/nickname>               Lock a database
  unlock <db-id/nickname>             Unlock a database
  groups <db-id/nickname>             List groups in a database
  generate-password                   Generate a password
  generate-password-v2                Generate passwords with strength info
  password-strength <password>        Check password strength
  copy-field <db-id/nickname> <node-id> <field> Copy a field (username|password|totp)
  copy-string <value>                 Copy a string to clipboard
  create-entry <db-id/nickname> [--title T] [--username U] [--password P] [--url URL]
                                      Create a new entry
  defaults <db-id/nickname>           Get new entry defaults
  icon <db-id/nickname> <node-id>     Get icon for an entry
`)
	os.Exit(1)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func isTerminal() bool {
	fi, _ := os.Stdout.Stat()
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func isInputTerminal() bool {
	fi, _ := os.Stdin.Stat()
	return (fi.Mode() & os.ModeCharDevice) != 0
}

type TerminalImageSupport int

const (
	ImageSupportNone TerminalImageSupport = iota
	ImageSupportSixel
	ImageSupportIIP
)

var terminalImageSupport = ImageSupportNone

type OutputFormat int

const (
	OutputFormatPretty OutputFormat = iota
	OutputFormatJSON
	OutputFormatYAML
	OutputFormatCSV
	OutputFormatTSV
)

var outputFormat = OutputFormatPretty

func probeTerminal() {
	if !isTerminal() || !isInputTerminal() {
		return
	}

	// Put terminal in raw mode before sending probes
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return
	}
	defer term.Restore(fd, oldState)

	// Use a shared channel and goroutine for reading to avoid losing bytes
	ch := make(chan byte, 1024)
	done := make(chan struct{})
	go func() {
		defer close(ch)
		b := make([]byte, 1)
		for {
			select {
			case <-done:
				return
			default:
				n, err := os.Stdin.Read(b)
				if err != nil || n == 0 {
					return
				}
				select {
				case ch <- b[0]:
				case <-done:
					return
				}
			}
		}
	}()
	defer close(done)

	// Small delay after entering raw mode to allow terminal to settle
	time.Sleep(50 * time.Millisecond)

	readWithTimeout := func(timeout time.Duration, expectedEnd string) string {
		var resp []byte
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		for {
			select {
			case b, ok := <-ch:
				if !ok {
					return string(resp)
				}
				resp = append(resp, b)
				if expectedEnd != "" && strings.Contains(string(resp), expectedEnd) {
					return string(resp)
				}
				// Reset timer after each byte to allow for slow responses?
				// No, the original request was for total timeout.
			case <-timer.C:
				return string(resp)
			}
		}
	}

	// Probe IIP (iTerm2): XTerm secondary Device Attributes (DA) - ESC [ > q
	// iTerm2 responds with something like ESC [ > 0 ; 1 ; 2 c (iTerm2 3.4.5)
	// But it actually responds with a string containing "iTerm2" when probed this way?
	// The user's snippet: printf "\033[>q" && read -rt 0.1 -d 'c' res; if [[ "$res" == *'iTerm2'* ]];
	fmt.Print("\x1b[>q")
	os.Stdout.Sync()

	response := readWithTimeout(500*time.Millisecond, "c")
	if strings.Contains(response, "iTerm2") {
		terminalImageSupport = ImageSupportIIP
		return
	}

	// Also check ITERM_SESSION_ID as a fallback for iTerm2
	if os.Getenv("ITERM_SESSION_ID") != "" || os.Getenv("TERM_PROGRAM") == "iTerm.app" {
		terminalImageSupport = ImageSupportIIP
		return
	}

	// Probe Sixel: Primary Device Attributes (DA) - ESC [ c
	fmt.Print("\x1b[c")
	os.Stdout.Sync()
	response = readWithTimeout(1000*time.Millisecond, "c")
	// Match ESC [ ? ... ; 4 ... c
	if (strings.Contains(response, "\x1b[?") || strings.Contains(response, "[?")) &&
		(strings.Contains(response, ";4;") || strings.Contains(response, ";4c") || strings.Contains(response, "?4;") || strings.Contains(response, "?4c")) {
		terminalImageSupport = ImageSupportSixel
	}
}

func calculateEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func maskCredential(cred strongbox.AutoFillCredential) strongbox.AutoFillCredential {
	masked := cred
	masked.Password = "***"
	masked.TOTP = "***"
	if calculateEntropy(cred.Username) > 3.5 {
		masked.Username = "***"
	}
	masked.CustomFields = make([]strongbox.CustomField, len(cred.CustomFields))
	for i, f := range cred.CustomFields {
		maskedField := f
		if f.Concealable {
			maskedField.Value = "***"
		}
		masked.CustomFields[i] = maskedField
	}
	return masked
}

func getIconSequence(iconData string) string {
	if terminalImageSupport == ImageSupportNone || iconData == "" {
		return iconData
	}

	iconB64 := iconData
	if strings.HasPrefix(iconData, "data:image/") {
		parts := strings.SplitN(iconData, ",", 2)
		if len(parts) == 2 {
			iconB64 = parts[1]
		}
	}

	data, err := base64.StdEncoding.DecodeString(iconB64)
	if err != nil {
		return iconData
	}

	if terminalImageSupport == ImageSupportIIP {
		return fmt.Sprintf("\x1b]1337;File=inline=1;size=%d:%s\x07", len(data), iconB64)
	}

	if terminalImageSupport == ImageSupportSixel {
		img, _, err := image.Decode(base64.NewDecoder(base64.StdEncoding, strings.NewReader(iconB64)))
		if err != nil {
			return iconData
		}
		var buf strings.Builder
		encodeSixel(&buf, img)
		return buf.String()
	}

	return iconData
}

func printIcon(iconB64 string) {
	if seq := getIconSequence(iconB64); seq != iconB64 {
		fmt.Println(seq)
	}
}

func encodeSixel(w io.Writer, img image.Image) {
	bounds := img.Bounds()
	width, height := bounds.Max.X, bounds.Max.Y

	// Simplified Sixel encoding: DCS q p1 ; p2 ; p3 ; q <pixel data> ST
	// p1=pixel aspect ratio, p2=transparency, p3=horizontal grid size
	fmt.Fprintf(w, "\x1bPq")

	// Sixel color palette (map colors to registers)
	// For simplicity, we'll use a very limited set of colors or just grayscale if we want it really simple.
	// But let's try to map some colors.
	fmt.Fprintf(w, "#0;2;0;0;0")       // Black
	fmt.Fprintf(w, "#1;2;100;100;100") // White

	for y := 0; y < height; y += 6 {
		for x := 0; x < width; x++ {
			var sixel byte
			for i := 0; i < 6; i++ {
				if y+i < height {
					c := img.At(x, y+i)
					r, g, b, _ := c.RGBA()
					// Simple threshold for "on" pixel
					if (r+g+b)/3 > 0x7FFF {
						sixel |= 1 << i
					}
				}
			}
			fmt.Fprintf(w, "%c", sixel+63)
		}
		fmt.Fprintf(w, "-") // New line of sixels
	}
	fmt.Fprintf(w, "\x1b\\")
}

func processCredential(cred strongbox.AutoFillCredential, privacy bool) strongbox.AutoFillCredential {
	res := cred
	if privacy && isTerminal() {
		res = maskCredential(res)
	}
	if terminalImageSupport != ImageSupportNone {
		res.Icon = getIconSequence(res.Icon)
	}
	return res
}

func printResult(v any, privacy bool) {
	if outputFormat == OutputFormatPretty {
		if printPretty(v, privacy) {
			return
		}
		// fallback if pretty print not implemented for this type
	}

	switch outputFormat {
	case OutputFormatJSON:
		printJSON(v, privacy)
	case OutputFormatYAML:
		printYAML(v, privacy)
	case OutputFormatCSV, OutputFormatTSV:
		printCSV(v, privacy, outputFormat == OutputFormatTSV)
	default:
		printJSON(v, privacy)
	}
}

func printYAML(v any, privacy bool) {
	v = transformForOutput(v, privacy)
	yamlBytes, err := yaml.Marshal(v)
	if err != nil {
		fatal("marshaling YAML: %v", err)
	}
	fmt.Print(string(yamlBytes))
}

func printCSV(v any, privacy bool, tsv bool) {
	v = transformForOutput(v, privacy)
	var records [][]string

	switch res := v.(type) {
	case *strongbox.GetStatusResponse:
		records = append(records, []string{"UUID", "Nickname", "Locked", "AutoFill"})
		for _, db := range res.Databases {
			records = append(records, []string{db.UUID, db.NickName, strconv.FormatBool(db.Locked), strconv.FormatBool(db.AutoFillEnabled)})
		}
	case *strongbox.SearchResponse:
		records = append(records, []string{"Title", "Username", "URL", "UUID", "Database", "Modified"})
		for _, c := range res.Results {
			records = append(records, []string{c.Title, c.Username, c.URL, c.UUID, c.DatabaseName, c.Modified})
		}
	case *strongbox.CredentialsForURLResponse:
		records = append(records, []string{"Title", "Username", "URL", "UUID", "Database", "Modified"})
		for _, c := range res.Results {
			records = append(records, []string{c.Title, c.Username, c.URL, c.UUID, c.DatabaseName, c.Modified})
		}
	case *strongbox.AutoFillCredential:
		records = append(records, []string{"Title", "Username", "URL", "UUID", "Database", "Modified"})
		records = append(records, []string{res.Title, res.Username, res.URL, res.UUID, res.DatabaseName, res.Modified})
	default:
		// Just JSON if we can't CSV it
		printJSON(v, privacy)
		return
	}

	w := csv.NewWriter(os.Stdout)
	if tsv {
		w.Comma = '\t'
	}
	w.WriteAll(records)
}

func printPretty(v any, privacy bool) bool {
	v = transformForOutput(v, privacy)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	switch res := v.(type) {
	case *strongbox.GetStatusResponse:
		fmt.Fprintln(w, "DATABASE ID\tNICKNAME\tSTATUS\tAUTOFILL")
		for _, db := range res.Databases {
			status := "Unlocked"
			if db.Locked {
				status = "Locked"
			}
			autofill := ""
			if db.AutoFillEnabled {
				autofill = "Yes"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", db.UUID, db.NickName, status, autofill)
		}
		w.Flush()
		return true

	case *strongbox.SearchResponse:
		if len(res.Results) == 0 {
			fmt.Println("No results found.")
			return true
		}
		fmt.Fprintln(w, "TITLE\tUSERNAME\tURL\tDATABASE\tMODIFIED")
		for _, c := range res.Results {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", c.Title, c.Username, c.URL, c.DatabaseName, c.Modified)
		}
		w.Flush()
		return true

	case *strongbox.CredentialsForURLResponse:
		if len(res.Results) == 0 {
			fmt.Println("No results found.")
			return true
		}
		fmt.Fprintln(w, "TITLE\tUSERNAME\tURL\tDATABASE\tMODIFIED")
		for _, c := range res.Results {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", c.Title, c.Username, c.URL, c.DatabaseName, c.Modified)
		}
		w.Flush()
		return true

	case *strongbox.AutoFillCredential:
		return printPrettyCredential(*res, privacy, w)
	case strongbox.AutoFillCredential:
		return printPrettyCredential(res, privacy, w)
	}

	return false
}

func printPrettyCredential(res strongbox.AutoFillCredential, privacy bool, w *tabwriter.Writer) bool {
	fmt.Fprintf(w, "Title:\t%s\n", res.Title)
	fmt.Fprintf(w, "Username:\t%s\n", res.Username)
	fmt.Fprintf(w, "Password:\t%s\n", res.Password)
	fmt.Fprintf(w, "URL:\t%s\n", res.URL)
	fmt.Fprintf(w, "TOTP:\t%s\n", res.TOTP)
	fmt.Fprintf(w, "UUID:\t%s\n", res.UUID)
	fmt.Fprintf(w, "Database:\t%s\n", res.DatabaseName)
	fmt.Fprintf(w, "Modified:\t%s\n", res.Modified)
	if len(res.CustomFields) > 0 {
		fmt.Fprintln(w, "Custom Fields:")
		for _, f := range res.CustomFields {
			fmt.Fprintf(w, "  %s:\t%s\n", f.Key, f.Value)
		}
	}
	if len(res.Tags) > 0 {
		fmt.Fprintf(w, "Tags:\t%s\n", strings.Join(res.Tags, ", "))
	}
	if res.Notes != "" {
		fmt.Fprint(w, "Notes:")
		lines := strings.Split(res.Notes, "\n")
		if len(lines) == 1 {
			fmt.Fprintf(w, "\t%s\n", lines[0])
		} else {
			fmt.Fprint(w, "\n")
			for _, line := range lines {
				fmt.Fprintf(w, "  %s\n", line)
			}
		}
	}
	w.Flush()
	return true
}

func transformForOutput(v any, privacy bool) any {
	if !isTerminal() {
		return v
	}
	switch res := v.(type) {
	case *strongbox.AutoFillCredential:
		return processCredential(*res, privacy)
	case strongbox.AutoFillCredential:
		return processCredential(res, privacy)
	case *strongbox.SearchResponse:
		processedRes := *res
		processedRes.Results = make([]strongbox.AutoFillCredential, len(res.Results))
		for i, c := range res.Results {
			processedRes.Results[i] = processCredential(c, privacy)
		}
		return &processedRes
	case *strongbox.CredentialsForURLResponse:
		processedRes := *res
		processedRes.Results = make([]strongbox.AutoFillCredential, len(res.Results))
		for i, c := range res.Results {
			processedRes.Results[i] = processCredential(c, privacy)
		}
		return &processedRes
	}
	return v
}

func printJSON(v any, privacy bool) {
	v = transformForOutput(v, privacy)

	jsonBytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// Fallback to standard encoding if marshal fails
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(v)
		return
	}

	// Unescape \u001b (ESC), \u0007 (BEL), and \u001b\\ (ST) to allow terminal to interpret them
	output := string(jsonBytes)
	output = strings.ReplaceAll(output, `\u001b`, "\x1b")
	output = strings.ReplaceAll(output, `\u0007`, "\x07")

	fmt.Println(output)
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

func ensureUnlockedDatabase(client *strongbox.Client, unlockBehavior string) *strongbox.GetStatusResponse {
	status, err := client.GetStatus()
	if err != nil {
		errStart := exec.Command("open", "-a", "Strongbox").Run()
		if errStart != nil {
			fatal("getting status: %v (failed to start Strongbox: %v)", err, errStart)
		}

		// Wait for Strongbox to start and the API to become available
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
	if len(status.Databases) == 0 {
		fatal("no databases found in Strongbox")
	}

	checkUnlocked := func(databases []strongbox.DatabaseSummary) bool {
		for _, db := range databases {
			if !db.Locked {
				return true
			}
		}
		return false
	}

	if checkUnlocked(status.Databases) {
		return status
	}

	// No database is unlocked.
	if unlockBehavior == "false" {
		fmt.Fprintf(os.Stderr, "error: all databases are locked. Please unlock at least one database in Strongbox.\n")
		os.Exit(1)
	}

	// Try to unlock if only one database has autoFillEnabled
	autoFillDbs := 0
	var dbToUnlock string
	for _, db := range status.Databases {
		if db.AutoFillEnabled {
			autoFillDbs++
			dbToUnlock = db.UUID
		}
	}

	if autoFillDbs == 1 {
		_, err := client.UnlockDatabase(dbToUnlock)
		if err != nil {
			if unlockBehavior == "true" {
				fatal("auto-unlock failed: %v", err)
			}
			// if behavior is "try", we just continue and fail later if still locked
		}

		// Refresh status
		status, err = client.GetStatus()
		if err != nil {
			fatal("getting status after auto-unlock: %v", err)
		}

		if checkUnlocked(status.Databases) {
			return status
		}
	}

	fmt.Fprintf(os.Stderr, "error: all databases are locked. Please unlock at least one database in Strongbox.\n")
	os.Exit(1)
	return nil
}

func findDatabase(status *strongbox.GetStatusResponse, idOrNickname string) string {
	// Try UUID match first (case-insensitive)
	for _, db := range status.Databases {
		if strings.EqualFold(db.UUID, idOrNickname) {
			return db.UUID
		}
	}
	// Try Nickname match (case-insensitive substring)
	var matches []string
	for _, db := range status.Databases {
		if strings.Contains(strings.ToLower(db.NickName), strings.ToLower(idOrNickname)) {
			matches = append(matches, db.UUID)
		}
	}

	if len(matches) == 1 {
		return matches[0]
	} else if len(matches) > 1 {
		fatal("multiple databases match '%s', please use UUID", idOrNickname)
	}

	// If no match found, assume it's a UUID and let the API call fail if it's invalid
	return idOrNickname
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	client, err := strongbox.NewClient()
	if err != nil {
		fatal("creating client: %v", err)
	}

	unlockBehavior := "try"
	var cmd string
	var args []string

	// Global flag parsing
	rawArgs := os.Args[1:]
	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]
		if (arg == "-U" || arg == "--unlock") && i+1 < len(rawArgs) {
			unlockBehavior = rawArgs[i+1]
			i++
		} else if strings.HasPrefix(arg, "--unlock=") {
			unlockBehavior = strings.TrimPrefix(arg, "--unlock=")
		} else if (arg == "-o" || arg == "--output") && i+1 < len(rawArgs) {
			val := rawArgs[i+1]
			switch val {
			case "pretty":
				outputFormat = OutputFormatPretty
			case "json":
				outputFormat = OutputFormatJSON
			case "yaml":
				outputFormat = OutputFormatYAML
			case "csv":
				outputFormat = OutputFormatCSV
			case "tsv":
				outputFormat = OutputFormatTSV
			default:
				fatal("unknown output format: %s", val)
			}
			i++
		} else if strings.HasPrefix(arg, "--output=") {
			val := strings.TrimPrefix(arg, "--output=")
			switch val {
			case "pretty":
				outputFormat = OutputFormatPretty
			case "json":
				outputFormat = OutputFormatJSON
			case "yaml":
				outputFormat = OutputFormatYAML
			case "csv":
				outputFormat = OutputFormatCSV
			case "tsv":
				outputFormat = OutputFormatTSV
			default:
				fatal("unknown output format: %s", val)
			}
		} else if cmd == "" {
			cmd = arg
		} else {
			args = append(args, arg)
		}
	}

	if cmd == "" {
		usage()
	}

	switch cmd {
	case "status":
		probeTerminal()
		status, err := client.GetStatus()
		if err != nil {
			errStart := exec.Command("open", "-a", "Strongbox").Run()
			if errStart != nil {
				fatal("getting status: %v (failed to start Strongbox: %v)", err, errStart)
			}

			// Wait for Strongbox to start and the API to become available
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

	case "search":
		ensureUnlockedDatabase(client, unlockBehavior)
		probeTerminal()
		query := requireArg(args, 0, "query")
		skip := atoi(arg(args, 1), 0)
		take := atoi(arg(args, 2), 25)
		result, err := client.Search(query, skip, take)
		if err != nil {
			fatal("searching: %v", err)
		}
		printResult(result, true)

	case "get-url":
		var fieldName string
		var urlParts []string
		for i := 0; i < len(args); i++ {
			arg := args[i]
			if (arg == "-f" || arg == "--field") && i+1 < len(args) {
				fieldName = args[i+1]
				i++
			} else if strings.HasPrefix(arg, "--field=") {
				fieldName = strings.TrimPrefix(arg, "--field=")
			} else if strings.HasPrefix(arg, "-f=") {
				fieldName = strings.TrimPrefix(arg, "-f=")
			} else {
				urlParts = append(urlParts, arg)
			}
		}

		if len(urlParts) == 0 {
			fatal("missing required argument: url")
		}
		url := urlParts[0]

		ensureUnlockedDatabase(client, unlockBehavior)
		result, err := client.CredentialsForURL(url, 0, 100)
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

	case "get":
		var fieldName string
		var nameParts []string
		for i := 0; i < len(args); i++ {
			arg := args[i]
			if (arg == "-f" || arg == "--field") && i+1 < len(args) {
				fieldName = args[i+1]
				i++
			} else if strings.HasPrefix(arg, "--field=") {
				fieldName = strings.TrimPrefix(arg, "--field=")
			} else if strings.HasPrefix(arg, "-f=") {
				fieldName = strings.TrimPrefix(arg, "-f=")
			} else {
				nameParts = append(nameParts, arg)
			}
		}

		if len(nameParts) == 0 {
			fatal("missing required argument: name")
		}
		name := strings.Join(nameParts, " ")

		ensureUnlockedDatabase(client, unlockBehavior)
		result, err := client.Search(name, 0, 100)
		if err != nil {
			fatal("searching for entry: %v", err)
		}

		var matches []strongbox.AutoFillCredential
		for _, cred := range result.Results {
			if strings.EqualFold(cred.Title, name) {
				matches = append(matches, cred)
			}
		}

		if len(matches) == 0 {
			// If no exact title match, use search results as-is if there's only one
			if len(result.Results) == 1 {
				matches = result.Results
			} else if len(result.Results) > 1 {
				fatal("multiple entries found for '%s', please be more specific", name)
			} else {
				fatal("no entry found for '%s'", name)
			}
		}

		if len(matches) > 1 {
			fatal("multiple entries found with title '%s', please use a more unique name or path", name)
		}

		entry := matches[0]
		if fieldName != "" {
			printField(entry, fieldName)
		} else {
			probeTerminal()
			printResult(entry, true)
		}

	case "lock":
		idOrNickname := requireArg(args, 0, "database-id/nickname")
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

	case "unlock":
		idOrNickname := requireArg(args, 0, "database-id/nickname")
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

	case "groups":
		idOrNickname := requireArg(args, 0, "database-id/nickname")
		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)
		result, err := client.GetGroups(dbID)
		if err != nil {
			fatal("getting groups: %v", err)
		}
		printResult(result, false)

	case "generate-password":
		result, err := client.GeneratePassword()
		if err != nil {
			fatal("generating password: %v", err)
		}
		printResult(result, false)

	case "generate-password-v2":
		result, err := client.GeneratePasswordV2()
		if err != nil {
			fatal("generating password: %v", err)
		}
		printResult(result, false)

	case "password-strength":
		pw := requireArg(args, 0, "password")
		result, err := client.GetPasswordStrength(pw)
		if err != nil {
			fatal("checking password strength: %v", err)
		}
		printResult(result, false)

	case "copy-field":
		idOrNickname := requireArg(args, 0, "database-id/nickname")
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
		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)
		result, err := client.CopyField(dbID, nodeID, field, fieldStr == "totp")
		if err != nil {
			fatal("copying field: %v", err)
		}
		printResult(result, false)

	case "copy-string":
		value := requireArg(args, 0, "value")
		result, err := client.CopyString(value)
		if err != nil {
			fatal("copying string: %v", err)
		}
		printResult(result, false)

	case "create-entry":
		idOrNickname := requireArg(args, 0, "database-id/nickname")
		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)
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
		printResult(result, false)

	case "defaults":
		idOrNickname := requireArg(args, 0, "database-id/nickname")
		status := ensureUnlockedDatabase(client, unlockBehavior)
		dbID := findDatabase(status, idOrNickname)
		result, err := client.GetNewEntryDefaults(dbID)
		if err != nil {
			fatal("getting defaults: %v", err)
		}
		printResult(result, false)

	case "icon":
		idOrNickname := requireArg(args, 0, "database-id/nickname")
		nodeID := requireArg(args, 1, "node-id")
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

	default:
		usage()
	}
}

func printField(entry strongbox.AutoFillCredential, fieldName string) {
	var val string
	switch fieldName {
	case "username":
		val = entry.Username
	case "password":
		val = entry.Password
	case "url":
		val = entry.URL
	case "totp":
		val = entry.TOTP
	case "notes":
		val = entry.Notes
	case "uuid":
		val = entry.UUID
	case "database":
		val = entry.DatabaseName
	case "modified":
		val = entry.Modified
	default:
		// Check custom fields
		found := false
		for _, f := range entry.CustomFields {
			if f.Key == fieldName {
				val = f.Value
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "error: field '%s' not found\n", fieldName)
			os.Exit(1)
		}
	}
	fmt.Print(val)
}
