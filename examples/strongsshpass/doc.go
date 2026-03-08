// Strongsshpass is a lightweight sshpass replacement that retrieves SSH
// passwords from Strongbox instead of requiring them on the command line or
// in an environment variable.
//
// The program extracts the <user>@<host> pair from the supplied SSH arguments,
// searches Strongbox for matching credentials using [strongbox.Client.Search],
// selects the most recently modified match, and feeds the password to ssh via
// the SSH_ASKPASS mechanism.
//
// Credential matching filters results by username (case-insensitive) and
// checks whether the credential URL or title contains the target host. When
// multiple credentials match, the one with the most recent Modified timestamp
// is chosen.
//
// # Usage
//
//	go run ./examples/strongsshpass [ssh-args...] <user>@<host>
//
// # Examples
//
//	go run ./examples/strongsshpass user@host
//	go run ./examples/strongsshpass -p 2222 user@host
package main
