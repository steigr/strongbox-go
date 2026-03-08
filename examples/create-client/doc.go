// Create-client demonstrates how to create a [strongbox.Client] with default
// and custom options.
//
// By default [strongbox.NewClient] expects the afproxy binary at the standard
// macOS path /Applications/Strongbox.app/Contents/MacOS/afproxy. Use
// [strongbox.WithProxyPath] to override the location when Strongbox is installed
// elsewhere.
//
// # Usage
//
//	go run ./examples/create-client
package main
