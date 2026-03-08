# afproxy-cli

`afproxy-cli` is a low-level tool for direct, encrypted interaction with Strongbox's `afproxy` native messaging host. It handles the NaCl encryption/decryption envelope, allowing you to send raw JSON payloads and receive decrypted responses.

## Usage

```bash
afproxy-cli --type <message-type> [--payload '<json-payload>'] [--raw]
```

- `--type`: Message type as a name (e.g., `status`, `search`) or numeric ID.
- `--payload`: JSON message body. If omitted, it reads from standard input.
- `--raw`: Outputs the encrypted outer envelope (JSON) instead of the decrypted response.

## Examples

Assume `jq` and `yq` are installed and available in your `PATH`.

### Get Strongbox Status

Using `jq`:
```bash
afproxy-cli --type status </dev/null | jq .
```

Using `yq`:
```bash
afproxy-cli --type status </dev/null | yq .
```

### Search for Credentials

Search for "github" and extract only the titles:
```bash
afproxy-cli --type search --payload '{"query": "github", "skip": 0, "take": 10}' | jq -r '.results[].title'
```

### Get Credentials for a URL

```bash
afproxy-cli --type get-url --payload '{"url": "https://github.com"}' | jq '.results[0]'
```

### Complex Script: List Unlocked Databases

This script uses `afproxy-cli` to get the status and then filters for unlocked databases using `jq`:

```bash
#!/bin/bash
afproxy-cli --type status | jq -r '.databases[] | select(.locked == false) | .nickName'
```

### Complex Script: Find and Copy Password

Find an entry by title and copy its password to the clipboard (macOS `pbcopy`):

```bash
#!/bin/bash
QUERY="github"
ENTRY_UUID=$(afproxy-cli --type search --payload "{\"query\": \"$QUERY\"}" | jq -r ".results[] | select(.title == \"$QUERY\") | .uuid")
DB_ID=$(afproxy-cli --type search --payload "{\"query\": \"$QUERY\"}" | jq -r ".results[] | select(.title == \"$QUERY\") | .databaseId")

if [ -n "$ENTRY_UUID" ]; then
  # Use strongbox-go's copy-field mechanism via afproxy-cli
  # Message type 3 is CopyField. Field 1 is Password.
  afproxy-cli --type copy-field --payload "{\"databaseId\": \"$DB_ID\", \"nodeId\": \"$ENTRY_UUID\", \"field\": 1}" | jq .
else
  echo "Entry not found"
fi
```

## Message Types

The following named types are supported:
- `status`
- `search`
- `get-url`
- `copy-field`
- `lock`
- `unlock`
- `create-entry`
- `get-groups`
- `get-defaults`
- `generate-password`
- `get-icon`
- `generate-password-v2`
- `password-strength`
- `get-defaults-v2`
- `copy-string`
