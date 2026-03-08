// Status demonstrates how to retrieve the current status of the Strongbox
// server using [strongbox.Client.GetStatus].
//
// The program prints the server version and lists all known databases along
// with their lock state (Locked / Unlocked). This is also the call that
// performs the initial NaCl box handshake with the server.
//
// # Usage
//
//	go run ./examples/status
package main
