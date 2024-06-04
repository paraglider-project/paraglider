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
	"log"
	"os"
	"os/user"
	"path"
)

const (
	projectFolder = "/.paraglider/"
	settinsFile   = "settings.json"
)

var (
	Global CLISettings = CLISettings{ServerAddr: "http://localhost:8080", ActiveNamespace: "default"}
)

type CLISettings struct {
	ServerAddr      string
	ActiveNamespace string
}

func CreateProjectfolder() string {
	usr, _ := user.Current()
	fol := path.Join(usr.HomeDir, projectFolder)
	//Create folder
	err := os.MkdirAll(fol, 0755)
	if err != nil {
		log.Println(err)
	}
	return fol
}

func configPath() string {
	//set cfg file in home directory
	usr, _ := user.Current()
	return path.Join(usr.HomeDir, projectFolder, settinsFile)
}

func setSettings() {
	CreateProjectfolder()
	SaveSettings(Global)
}

func SaveSettings(cliSettings CLISettings) {
	// persist settings and update Global
	jsonC, err := json.MarshalIndent(&cliSettings, "", "\t")
	if err != nil {
		log.Printf("Unable to parse json: %v\n", err)
		return
	}
	os.WriteFile(configPath(), jsonC, 0644)
	Global = CLISettings{
		ServerAddr:      cliSettings.ServerAddr,
		ActiveNamespace: cliSettings.ActiveNamespace,
	}
}

func ReadSettings() {
	data, err := os.ReadFile(configPath())
	if err != nil {
		log.Printf("Unable to read json file: %v\n", err)
		// only set the state. No need to refresh Global
		setSettings()
	} else {
		json.Unmarshal(data, &Global)
	}
}
