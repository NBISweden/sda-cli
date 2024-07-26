package gui

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/NBISweden/sda-cli/encrypt"
	"github.com/NBISweden/sda-cli/upload"
	"github.com/ncruces/zenity"
)

var (
	defaultPath = os.Getenv("PWD")
	args        []string
)

func ZenityGui(allActions []reflect.Value) error {
	availableActions := convertActions(allActions)
	// Create a list of the available actions
	selectedAction, err := createList(availableActions, "Choose an action")
	if err != nil {
		return err
	}

	fmt.Println("Action: ", selectedAction)

	switch selectedAction {
	case "encrypt":
		err = encryptCase()
		if err != nil {
			return err
		}
	case "upload":
		err = uploadCase()
		if err != nil {
			return err
		}
	default:
		err = infoWindow("Action not implemented", "The selected action is not implemented yet")
		if err != nil {
			return err
		}
		fmt.Println("Action not implemented")
	}

	return nil
}

// convertActions transforms the reflect value in a slice
func convertActions(actions []reflect.Value) []string {
	var stringActions []string
	notInclude := "gui version"
	for _, action := range actions {
		if strings.Contains(notInclude, action.String()) {
			continue
		}
		stringActions = append(stringActions, action.Interface().(string))
	}
	return stringActions
}

// createList is a function for creating a list with a title and a slice of items
// and returns the selected item
func createList(listItems []string, listTitle string) (string, error) {
	selectedItem, err := zenity.List(
		listTitle,
		listItems,
		zenity.Width(400),
		zenity.Height(300),
	)
	if err != nil {
		fmt.Println("Error in list: ", err)
		return "", err
	}

	return selectedItem, nil
}

// singleSelection is a function for returning filepaths or folder paths
// by using the select file feature
func singleSelection(windowTitle string, folder bool) (string, error) {
	var filePath string
	var err error

	switch folder {
	case true:
		filePath, err = zenity.SelectFile(
			zenity.Filename(defaultPath),
			zenity.Directory(),
			zenity.Title(windowTitle),
		)
		if err != nil {
			fmt.Println("Error in folder selection")
			return "", err
		}
	default:
		filePath, err = zenity.SelectFile(
			zenity.Filename(defaultPath),
			zenity.Title(windowTitle),
		)
		if err != nil {
			fmt.Println("Error in file selection")
			return "", err
		}
	}

	return filePath, nil
}

// addFiles function is returning multiple filepaths by using the
// multiple files selection feature.
func addFiles() ([]string, error) {
	filesPath, err := zenity.SelectFileMultiple(
		zenity.Filename(defaultPath),
		zenity.Title("Choose your files"),
	)
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

	publicKeyPath, err := singleSelection("Choose the public key file", false)
	if err != nil {
		return err
	}
	args = append(args, "-key", publicKeyPath)

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

// uploadCase is a function for collecting all the info needed to call the upload module
// and upload files.
func uploadCase() error {
	args = append(args, "upload")

	configPath, err := singleSelection("Choose the config file", false)
	if err != nil {
		return err
	}
	args = append(args, "-config", configPath)

	files, err := addFiles()
	if err != nil {
		return err
	}
	args = append(args, files...)

	err = upload.Upload(args)
	if err != nil {
		return err
	}

	return nil
}
