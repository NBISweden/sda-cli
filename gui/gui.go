package gui

import (
	"fmt"
	"os"
	"reflect"

	"github.com/ncruces/zenity"
)

// Default path when a file selection window opens
var defaultPath = os.Getenv("PWD")

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
	pubKeyPath, err := zenity.SelectFile(zenity.Filename(defaultPath))
	if err != nil {
		fmt.Println("Error in select public key")
		return "", err
	}

	return pubKeyPath, nil
}

// addFiles function is returning multiple filepaths by using the
// multiple files selection feature.
func addFiles() ([]string, error) {
	filesPath, err := zenity.SelectFileMultiple(zenity.Filename(defaultPath))
	if err != nil {
		fmt.Println("Error in adding files")
		return []string{}, err
	}

	return filesPath, nil
}
