package main

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"math"
	"net/url"
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

// Helper functions

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func requireArg(args []string, index int, name string) string {
	if index >= len(args) {
		fatal("missing required argument: %s", name)
	}
	return args[index]
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

func isTerminal() bool {
	fi, _ := os.Stdout.Stat()
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func isInputTerminal() bool {
	fi, _ := os.Stdin.Stat()
	return (fi.Mode() & os.ModeCharDevice) != 0
}

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
			case <-timer.C:
				return string(resp)
			}
		}
	}

	// Probe IIP (iTerm2)
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

	// Probe Sixel
	fmt.Print("\x1b[c")
	os.Stdout.Sync()
	response = readWithTimeout(1000*time.Millisecond, "c")
	if (strings.Contains(response, "\x1b[?") || strings.Contains(response, "[?")) &&
		(strings.Contains(response, ";4;") || strings.Contains(response, ";4c") || strings.Contains(response, "?4;") || strings.Contains(response, "?4c")) {
		terminalImageSupport = ImageSupportSixel
	}
}

func shortenURL(urlStr string) string {
	if urlStr == "" {
		return ""
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		// Fallback to simple truncation if not a valid URL
		if len(urlStr) > 63 {
			return urlStr[:30] + "..." + urlStr[len(urlStr)-30:]
		}
		return urlStr
	}

	host := u.Host
	if host != "" {
		parts := strings.Split(host, ".")
		if len(parts) > 3 {
			newParts := make([]string, len(parts))
			copy(newParts, parts)
			for i := 1; i < len(parts)-2; i++ {
				if len(parts[i]) > 0 {
					newParts[i] = string(parts[i][0]) + "*"
				}
			}
			host = strings.Join(newParts, ".")
		}
	}

	path := u.Path
	if path != "" {
		trimmedPath := strings.Trim(path, "/")
		if trimmedPath != "" {
			parts := strings.Split(trimmedPath, "/")
			if len(parts) > 3 {
				newParts := make([]string, len(parts))
				for i, p := range parts {
					if len(p) > 0 {
						newParts[i] = string(p[0])
					} else {
						newParts[i] = p
					}
				}
				path = "/" + strings.Join(newParts, "/")
				if strings.HasSuffix(u.Path, "/") {
					path += "/"
				}
			}
		}
	}

	query := u.RawQuery
	if query != "" {
		parts := strings.Split(query, "&")
		if len(parts) > 3 {
			newParts := make([]string, len(parts))
			for i, p := range parts {
				if len(p) > 0 {
					newParts[i] = string(p[0])
				} else {
					newParts[i] = p
				}
			}
			query = strings.Join(newParts, "&")
		}
	}

	fragment := u.Fragment
	if fragment != "" {
		sep := ""
		if strings.Contains(fragment, "/") {
			sep = "/"
		} else if strings.Contains(fragment, "-") {
			sep = "-"
		}

		if sep != "" {
			parts := strings.Split(fragment, sep)
			if len(parts) > 3 {
				newParts := make([]string, len(parts))
				for i, p := range parts {
					if len(p) > 0 {
						newParts[i] = string(p[0])
					} else {
						newParts[i] = p
					}
				}
				fragment = strings.Join(newParts, sep)
			}
		}
	}

	// Reconstruct URL
	res := ""
	if u.Scheme != "" {
		res += u.Scheme + "://"
	}
	res += host
	res += path
	if query != "" {
		res += "?" + query
	}
	if fragment != "" {
		res += "#" + fragment
	}

	if len(res) > 63 {
		return res[:30] + "..." + res[len(res)-30:]
	}
	return res
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

	fmt.Fprintf(w, "\x1bPq")
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
	}

	if outputFormat == OutputFormatWide {
		if printWide(v, privacy) {
			return
		}
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
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", c.Title, c.Username, shortenURL(c.URL), c.DatabaseName, c.Modified)
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
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", c.Title, c.Username, shortenURL(c.URL), c.DatabaseName, c.Modified)
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

func printWide(v any, privacy bool) bool {
	v = transformForOutput(v, privacy)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	switch res := v.(type) {
	case *strongbox.SearchResponse:
		if len(res.Results) == 0 {
			fmt.Println("No results found.")
			return true
		}
		fmt.Fprintln(w, "TITLE\tUSERNAME\tURL\tDATABASE\tMODIFIED\tTOTP\tENTROPY(U/P/CF)")
		for _, c := range res.Results {
			totp := "No"
			if c.TOTP != "" {
				totp = "Yes"
			}
			cfEntropy := 0.0
			for _, f := range c.CustomFields {
				cfEntropy += calculateEntropy(f.Value)
			}
			entropy := fmt.Sprintf("%.1f/%.1f/%.1f", calculateEntropy(c.Username), calculateEntropy(c.Password), cfEntropy)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.Title, c.Username, shortenURL(c.URL), c.DatabaseName, c.Modified, totp, entropy)
		}
		w.Flush()
		return true

	case *strongbox.CredentialsForURLResponse:
		if len(res.Results) == 0 {
			fmt.Println("No results found.")
			return true
		}
		fmt.Fprintln(w, "TITLE\tUSERNAME\tURL\tDATABASE\tMODIFIED\tTOTP\tENTROPY(U/P/CF)")
		for _, c := range res.Results {
			totp := "No"
			if c.TOTP != "" {
				totp = "Yes"
			}
			cfEntropy := 0.0
			for _, f := range c.CustomFields {
				cfEntropy += calculateEntropy(f.Value)
			}
			entropy := fmt.Sprintf("%.1f/%.1f/%.1f", calculateEntropy(c.Username), calculateEntropy(c.Password), cfEntropy)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.Title, c.Username, shortenURL(c.URL), c.DatabaseName, c.Modified, totp, entropy)
		}
		w.Flush()
		return true

	case *strongbox.AutoFillCredential:
		return printPrettyCredential(*res, privacy, w)
	case strongbox.AutoFillCredential:
		return printPrettyCredential(res, privacy, w)
	}

	return printPretty(v, privacy)
}

func printPrettyCredential(res strongbox.AutoFillCredential, privacy bool, w *tabwriter.Writer) bool {
	if res.Icon != "" {
		fmt.Fprintf(w, "Icon:\t%s\n", res.Icon)
	}
	fmt.Fprintf(w, "Title:\t%s\n", res.Title)
	fmt.Fprintf(w, "Username:\t%s\n", res.Username)
	fmt.Fprintf(w, "Password:\t%s\n", res.Password)
	fmt.Fprintf(w, "URL:\t%s\n", shortenURL(res.URL))
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
		processed := processCredential(*res, privacy)
		return &processed
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
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(v)
		return
	}

	output := string(jsonBytes)
	output = strings.ReplaceAll(output, `\u001b`, "\x1b")
	output = strings.ReplaceAll(output, `\u0007`, "\x07")

	fmt.Println(output)
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

func ensureUnlockedDatabase(client *strongbox.Client, unlockBehavior string) *strongbox.GetStatusResponse {
	status, err := client.GetStatus()
	if err != nil {
		errStart := exec.Command("open", "-a", "Strongbox").Run()
		if errStart != nil {
			fatal("getting status: %v (failed to start Strongbox: %v)", err, errStart)
		}

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

	if unlockBehavior == "false" {
		fmt.Fprintf(os.Stderr, "error: all databases are locked. Please unlock at least one database in Strongbox.\n")
		os.Exit(1)
	}

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
		}

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
	for _, db := range status.Databases {
		if strings.EqualFold(db.UUID, idOrNickname) {
			return db.UUID
		}
	}

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

	return idOrNickname
}
