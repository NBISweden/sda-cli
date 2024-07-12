package gui

import (
	"fmt"

	"github.com/ncruces/zenity"
)

func ZenityGui() error {
	// Create a list of the available actions
	actions, err := zenity.List("Select an action", []string{"download", "upload"})
	if err != nil {
		fmt.Println("Error in list: ", err)
		return err
	}

	fmt.Println("Action: ", actions)

	return nil
}
