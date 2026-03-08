// Credentials demonstrates how to look up credentials that match a given URL
// using [strongbox.Client.CredentialsForURL].
//
// The program accepts an optional URL argument (defaults to "https://github.com")
// and prints the title and username of each matching credential found across all
// unlocked Strongbox databases.
//
// # Usage
//
//	go run ./examples/credentials [url]
//
// # Examples
//
//	go run ./examples/credentials
//	go run ./examples/credentials https://example.com
package main
