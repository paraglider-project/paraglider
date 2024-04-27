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

	az "github.com/NetSys/invisinets/pkg/azure"
	gcp "github.com/NetSys/invisinets/pkg/gcp"
	ibm "github.com/NetSys/invisinets/pkg/ibm_plugin/server"

	kvservice "github.com/NetSys/invisinets/pkg/kvstore"
	orchestrator "github.com/NetSys/invisinets/pkg/orchestrator"
	"github.com/NetSys/invisinets/pkg/orchestrator/config"
	tagservice "github.com/NetSys/invisinets/pkg/tag_service"
)

func NewCommand() *cobra.Command {
	executor := &executor{}
	cmd := &cobra.Command{
		Use:     "startup <path to config>",
		Aliases: []string{"startup"},
		Short:   "Starts all the microservices with given config file",
		Args:    cobra.ExactArgs(1),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	cmd.Flags().Bool("clearkeys", false, "Clears all the keys in the redis database")
	return cmd
}

type executor struct {
	tagPort          int
	kvPort           int
	azPort           int
	gcpPort          int
	ibmPort          int
	orchestratorAddr string
	clearKeys        bool
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	// Read the config
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()

	var cfg config.Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		return err
	}

	e.orchestratorAddr = cfg.Server.Host + ":" + cfg.Server.RpcPort

	e.tagPort, err = strconv.Atoi(cfg.TagService.Port)
	if err != nil {
		return err
	}

	if cfg.KVStore.Port != "" {
		e.kvPort, err = strconv.Atoi(cfg.KVStore.Port)
		if err != nil {
			return err
		}
	}

	for _, cloud := range cfg.CloudPlugins {
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
		} else if cloud.Name == "ibm" {
			e.ibmPort, err = strconv.Atoi(cloud.Port)
			if err != nil {
				return err
			}
		}
	}

	e.clearKeys, err = cmd.Flags().GetBool("clearkeys")
	if err != nil {
		return err
	}

	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	go func() {
		tagservice.Setup(6379, e.tagPort, e.clearKeys)
	}()

	go func() {
		kvservice.Setup(6379, e.kvPort, e.clearKeys)
	}()

	go func() {
		gcp.Setup(e.gcpPort, e.orchestratorAddr)
	}()

	go func() {
		az.Setup(e.azPort, e.orchestratorAddr)
	}()

	go func() {
		ibm.Setup(e.ibmPort, e.orchestratorAddr)
	}()

	orchestrator.SetupWithFile(args[0], false)

	return nil
}
