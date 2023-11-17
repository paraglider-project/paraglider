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

package create

import (
	"io"
	"os"

	common "github.com/NetSys/invisinets/internal/cli/common"
	"github.com/NetSys/invisinets/internal/cli/inv/settings"
	"github.com/NetSys/invisinets/pkg/client"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/spf13/cobra"
)

func NewCommand() (*cobra.Command, *executor) {
	executor := &executor{writer: os.Stdout}
	cmd := &cobra.Command{
		Use:     "create <cloud> <resource_id> <resource_description_file>",
		Short:   "Create a resource",
		Args:    cobra.ExactArgs(3),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	return cmd, executor
}

type executor struct {
	common.CommandExecutor
	writer      io.Writer
	description []byte
}

func (e *executor) SetOutput(w io.Writer) {
	e.writer = w
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	descriptionFile, err := os.Open(args[2])
	if err != nil {
		return err
	}
	defer descriptionFile.Close()
	e.description, err = io.ReadAll(descriptionFile)
	if err != nil {
		return err
	}
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	resource := &invisinetspb.ResourceDescriptionString{Id: args[1], Description: string(e.description)}

	c := client.Client{ControllerAddress: settings.ServerAddr}
	err := c.CreateResource(args[0], resource)

	return err
}
