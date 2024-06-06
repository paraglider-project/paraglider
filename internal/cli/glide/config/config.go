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
	"os"
	"path/filepath"

	yaml "gopkg.in/yaml.v3"
)

const (
	DefaultConfigLocation = "~/.paraglider/clicfg"
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
	ServerAddr      string `yaml:"serverAddr"`
	ActiveNamespace string `yaml:"activeNamespace"`
}

func ReadOrCreateConfig() error {
	newConfig := &CliConfig{Path: DefaultConfigLocation}

	_, err := os.Stat(newConfig.Path)
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
		f, err := os.Open(newConfig.Path)
		if err != nil {
			return err
		}
		defer f.Close()

		decoder := yaml.NewDecoder(f)
		err = decoder.Decode(&newConfig.Settings)
		if err != nil {
			return err
		}
	}

	ActiveConfig = newConfig
	return nil
}

func SaveActiveConfig() error {
	yamlData, err := yaml.Marshal(&ActiveConfig.Settings)
	if err != nil {
		return err
	}

	err = os.WriteFile(ActiveConfig.Path, yamlData, 0644)
	if err != nil {
		return err
	}

	return nil
}
