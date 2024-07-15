package gui

import (
	"fmt"
	"os"
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

// keyPath is a function for returning the crypt4gh public key path
// by using the select file feature
func keyPath() (string, error) {
	defaultPath := os.Getenv("PWD")
	pubKeyPath, err := zenity.SelectFile(zenity.Filename(defaultPath))
	if err != nil {
		fmt.Println("Error in select public key")
		return "", err
	}

	return pubKeyPath, nil
}
