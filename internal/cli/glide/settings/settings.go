/*
Copyright 2023 The Paraglider Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path"
)

const (
	projectFolder = "/.paraglider/"
	settingsFile  = "settings.json"
)

var (
	Global CLISettings = CLISettings{ServerAddr: "http://localhost:8080", ActiveNamespace: "default"}
)

type CLISettings struct {
	ServerAddr      string
	ActiveNamespace string
}

func createProjectfolder() string {
	usr, _ := user.Current()
	fol := path.Join(usr.HomeDir, projectFolder)
	// create folder
	err := os.MkdirAll(fol, 0755)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	return fol
}

func settingPath() string {
	usr, _ := user.Current()
	return path.Join(usr.HomeDir, projectFolder, settingsFile)
}

func setSettings() {
	createProjectfolder()
	SaveSettings(Global)
}

func SaveSettings(cliSettings CLISettings) {
	// persist settings and update Global
	jsonC, err := json.MarshalIndent(&cliSettings, "", "\t")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to marshal settings into json: %v\n", err)
		return
	}
	err = os.WriteFile(settingPath(), jsonC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Uanble to write json settings: %v", err)
	}
	Global = CLISettings{
		ServerAddr:      cliSettings.ServerAddr,
		ActiveNamespace: cliSettings.ActiveNamespace,
	}
}

func ReadSettings() {
	data, err := os.ReadFile(settingPath())
	if err != nil {
		fmt.Fprintf(os.Stdout, "Unable to read settings file: %v\n", err)
		// only persist settings. No need to update Global
		setSettings()
	} else {
		err = json.Unmarshal(data, &Global)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to unmarshal json into settings: %v\n", err)
		}
	}
}
