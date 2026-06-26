package main

import (
	"os/exec"
	"time"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Strongbox status and databases",
	Long:  `Display the current status of Strongbox including all databases and their lock states.`,
	Run: func(cmd *cobra.Command, args []string) {
		probeTerminal()
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
		printResult(status, false)
	},
}
