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

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	DefaultConfigLocation = "/.paraglider/settings.json"
	DefaultServerAddr     = "http://localhost:8080"
	DefaultNamespace      = "default"
)

var (
	ActiveConfig *CliConfig
)

type CliConfig struct {
	Settings CliSettings
	Path     string
}

type CliSettings struct {
	ServerAddr      string `json:"serverAddr"`
	ActiveNamespace string `json:"activeNamespace"`
}

func ReadOrCreateConfig() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(homeDir, DefaultConfigLocation)
	newConfig := &CliConfig{Path: path}

	_, err = os.Stat(newConfig.Path)
	if os.IsNotExist(err) {
		parentDir := filepath.Dir(newConfig.Path)
		_, err := os.Stat(parentDir)
		if os.IsNotExist(err) {
			err := os.MkdirAll(parentDir, 0755)
			if err != nil {
				return err
			}
		}
		newConfig.Settings = CliSettings{ServerAddr: DefaultServerAddr, ActiveNamespace: DefaultNamespace}
	} else {
		data, err := os.ReadFile(newConfig.Path)
		if err != nil {
			return err
		}

		err = json.Unmarshal(data, &newConfig.Settings)
		if err != nil {
			return err
		}
	}

	ActiveConfig = newConfig
	return nil
}

func SaveActiveConfig() error {
	data, err := json.Marshal(&ActiveConfig.Settings)
	if err != nil {
		return err
	}

	err = os.WriteFile(ActiveConfig.Path, data, 0644)
	if err != nil {
		return err
	}

	return nil
}
