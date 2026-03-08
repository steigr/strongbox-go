package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/steigr/strongbox-go/pkg/strongbox"
)

func main() {
	typeStr := flag.String("type", "", "Message type (numeric or name, e.g., 'status', 'search')")
	payload := flag.String("payload", "", "JSON payload (if empty, reads from stdin)")
	proxyPath := flag.String("proxy-path", "", "Path to afproxy binary")
	raw := flag.Bool("raw", false, "Output raw encrypted response")
	flag.Parse()

	if *typeStr == "" {
		fmt.Fprintln(os.Stderr, "Error: --type is required")
		flag.Usage()
		os.Exit(1)
	}

	msgType, err := parseMessageType(*typeStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var input []byte
	if *payload != "" {
		input = []byte(*payload)
	} else {
		input, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
	}

	// Basic validation of payload (should be JSON)
	if len(input) > 0 {
		var js any
		if err := json.Unmarshal(input, &js); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: payload is not valid JSON: %v\n", err)
		}
	} else if msgType != strongbox.MessageTypeStatus {
		// Most messages need a payload, but status can be sent without one (just PK)
		input = []byte("{}")
	}

	var opts []strongbox.Option
	if *proxyPath != "" {
		opts = append(opts, strongbox.WithProxyPath(*proxyPath))
	}

	client, err := strongbox.NewClient(opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	if *raw {
		// Send raw and output encrypted response
		var inner any
		if len(input) > 0 {
			json.Unmarshal(input, &inner)
		}

		// We still need the server public key for most messages
		// If it's not status, ensureServerPublicKey will call GetStatus

		req, err := client.BuildEncryptedRequest(inner, msgType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error building encrypted request: %v\n", err)
			os.Exit(1)
		}

		resp, err := client.SendRaw(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error sending raw request: %v\n", err)
			os.Exit(1)
		}

		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
	} else {
		// Normal operation: encrypt, send, decrypt, output JSON
		var inner any
		if len(input) > 0 {
			json.Unmarshal(input, &inner)
		}

		var result any
		err := client.SendEncrypted(inner, msgType, &result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	}
}

func parseMessageType(s string) (strongbox.AutoFillMessageType, error) {
	// Try numeric
	if val, err := strconv.Atoi(s); err == nil {
		return strongbox.AutoFillMessageType(val), nil
	}

	// Try name
	if msgType, ok := strongbox.ParseMessageType(s); ok {
		return msgType, nil
	}
	return 0, fmt.Errorf("unknown message type: %s", s)
}
