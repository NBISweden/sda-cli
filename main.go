package main

import (
	"fmt"
	"os"

	"github.com/NBISweden/sda-cli/cmd"
	_ "github.com/NBISweden/sda-cli/create_key"
	_ "github.com/NBISweden/sda-cli/decrypt"
	_ "github.com/NBISweden/sda-cli/download"
	_ "github.com/NBISweden/sda-cli/encrypt"
	_ "github.com/NBISweden/sda-cli/htsget"
	_ "github.com/NBISweden/sda-cli/list"
	_ "github.com/NBISweden/sda-cli/login"
	_ "github.com/NBISweden/sda-cli/upload"
	_ "github.com/NBISweden/sda-cli/version"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
