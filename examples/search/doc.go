// Search demonstrates how to search for credentials across all unlocked
// Strongbox databases using [strongbox.Client.Search].
//
// The program accepts an optional query argument (defaults to "github") and
// prints the title and username of every matching credential. The query is
// matched against credential titles, usernames, URLs, and other fields.
//
// # Usage
//
//	go run ./examples/search [query]
//
// # Examples
//
//	go run ./examples/search
//	go run ./examples/search example.com
package main
