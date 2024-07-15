package gui

import (
	"fmt"
	"os"
	"reflect"

	"github.com/NBISweden/sda-cli/encrypt"
	"github.com/ncruces/zenity"
)

var (
	defaultPath = os.Getenv("PWD")
	args        []string
)

func ZenityGui(allActions []reflect.Value) error {
	availableActions := convertActions(allActions)
	// Create a list of the available actions
	selectedAction, err := zenity.List("Select an action", availableActions)
	if err != nil {
		fmt.Println("Error in list: ", err)
		return err
	}

	fmt.Println("Action: ", selectedAction)

	switch selectedAction {
	case "encrypt":
		err = encryptCase()
		if err != nil {
			return err
		}
	}

	return nil
}

// convertActions transforms the reflect value in a slice
func convertActions(actions []reflect.Value) []string {
	var stringActions []string
	for _, action := range actions {
		if action.String() == "gui" {
			continue
		}
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

// infoWindow is a function for creating an information window with a title and a text
func infoWindow(windowTitle, windowText string) error {
	err := zenity.Info(windowText, zenity.Title(windowTitle), zenity.NoIcon)
	if err != nil {
		fmt.Println("Error in displaying information message")
		return err
	}
	return nil
}

// encryptCase is a function for collecting all the info needed to call the encrypt module
// and encrypt files.
// - Get the key path
// - Get the file paths
// - Create a slice with the args
// - Encrypt the files
// TODO add the feature of using multiple keys
func encryptCase() error {
	args = append(args, "encrypt")

	err := infoWindow(
		"Load crypt4gh public key",
		"In the next step choose the crypt4gh public key which will be used for encrypting the files.",
	)
	if err != nil {
		return err
	}

	publicKeyPath, err := keyPath()
	if err != nil {
		return err
	}
	args = append(args, "-key", publicKeyPath)

	err = infoWindow(
		"Ready to add files for encryption",
		"The public key has been loaded. In the next step choose files to encrypt",
	)
	if err != nil {
		return err
	}

	files, err := addFiles()
	if err != nil {
		return err
	}
	args = append(args, files...)

	err = encrypt.Encrypt(args)
	if err != nil {
		return err
	}

	return nil
}
