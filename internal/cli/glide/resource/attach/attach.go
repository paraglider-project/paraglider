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

package attach

import (
	"fmt"
	"io"
	"os"

	common "github.com/paraglider-project/paraglider/internal/cli/common"
	"github.com/paraglider-project/paraglider/internal/cli/glide/config"
	"github.com/paraglider-project/paraglider/pkg/client"
	"github.com/paraglider-project/paraglider/pkg/orchestrator"
	"github.com/spf13/cobra"
)

func NewCommand() (*cobra.Command, *executor) {
	executor := &executor{writer: os.Stdout, cliSettings: config.ActiveConfig.Settings}
	cmd := &cobra.Command{
		Use:     "attach <cloud> <resource_id>",
		Short:   "Attach a resource to active namespace",
		Args:    cobra.ExactArgs(2),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	return cmd, executor
}

type executor struct {
	common.CommandExecutor
	writer      io.Writer
	cliSettings config.CliSettings
}

func (e *executor) SetOutput(w io.Writer) {
	e.writer = w
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	fmt.Fprintf(e.writer, "Attaching resource to %s namespace\n", e.cliSettings.ActiveNamespace)
	paragliderClient := client.Client{ControllerAddress: e.cliSettings.ServerAddr}

	resource := &orchestrator.ResourceID{Id: args[1]}
	resourceInfo, err := paragliderClient.AttachResource(e.cliSettings.ActiveNamespace, args[0], resource)
	if err != nil {
		fmt.Fprintf(e.writer, "Failed to attach resource: %v\n", err)
		return err
	}

	fmt.Fprintf(e.writer, "Resource Attached.\ntag: %s\nuri: %s\nip: %s\n", resourceInfo["name"], resourceInfo["uri"], resourceInfo["ip"])

	return nil
}
