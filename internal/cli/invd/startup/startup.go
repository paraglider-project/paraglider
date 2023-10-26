/*
Copyright 2023 The Invisinets Authors.

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

package startup

import (
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	az "github.com/NetSys/invisinets/pkg/azure_plugin"
	frontend "github.com/NetSys/invisinets/pkg/frontend"
	gcp "github.com/NetSys/invisinets/pkg/gcp"
	tagservice "github.com/NetSys/invisinets/pkg/tag_service"
)

func NewCommand() *cobra.Command {
	executor := &executor{}
	return &cobra.Command{
		Use:     "startup",
		Aliases: []string{"startup"},
		Short:   "Starts all the microservices with given config file",
		Args:    cobra.ExactArgs(1),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
}

type executor struct {
	tagPort        int
	azPort         int
	gcpPort        int
	controllerAddr string
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	// Read the config
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()

	var cfg frontend.Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		return err
	}

	e.controllerAddr = cfg.Server.Host + ":" + cfg.Server.Port

	e.tagPort, err = strconv.Atoi(cfg.TagService.Port)
	if err != nil {
		return err
	}

	for _, cloud := range cfg.Clouds {
		if cloud.Name == "gcp" {
			e.gcpPort, err = strconv.Atoi(cloud.Port)
			if err != nil {
				return err
			}
		} else if cloud.Name == "azure" {
			e.azPort, err = strconv.Atoi(cloud.Port)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	go func() {
		tagservice.Setup(6379, e.tagPort, true)
	}()

	go func() {
		gcp.Setup(e.gcpPort, e.controllerAddr)
	}()

	go func() {
		az.Setup(e.azPort, e.controllerAddr)
	}()

	frontend.Setup(args[0])
	return nil
}
