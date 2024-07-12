package gui

import (
	"fmt"
	"reflect"

	"github.com/ncruces/zenity"
)

func ZenityGui(allActions []reflect.Value) error {
	availableActions := convertActions(allActions)
	// Create a list of the available actions
	actions, err := zenity.List("Select an action", availableActions)
	if err != nil {
		fmt.Println("Error in list: ", err)
		return err
	}

	fmt.Println("Action: ", actions)

	return nil
}

// convertActions transforms the reflect value in a slice
func convertActions(actions []reflect.Value) []string {
	var stringActions []string
	for _, action := range actions {
		stringActions = append(stringActions, action.Interface().(string))
	}
	return stringActions
}
