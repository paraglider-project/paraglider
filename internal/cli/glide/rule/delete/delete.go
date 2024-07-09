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

package delete

import (
	"io"
	"os"

	common "github.com/paraglider-project/paraglider/internal/cli/common"
	"github.com/paraglider-project/paraglider/internal/cli/glide/config"
	"github.com/paraglider-project/paraglider/pkg/client"
	"github.com/spf13/cobra"
)

func NewCommand() (*cobra.Command, *executor) {
	executor := &executor{writer: os.Stdout, cliSettings: config.ActiveConfig.Settings}
	cmd := &cobra.Command{
		Use:     "delete <cloud> <resource name> --rules <rule names>",
		Short:   "Delete a rule from a resource permit list",
		Args:    cobra.ExactArgs(2),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	cmd.Flags().StringSlice("rules", []string{}, "The names of the rules to delete")
	return cmd, executor
}

type executor struct {
	common.CommandExecutor
	writer      io.Writer
	cliSettings config.CliSettings
	ruleNames   []string
}

func (e *executor) SetOutput(w io.Writer) {
	e.writer = w
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	var err error
	e.ruleNames, err = cmd.Flags().GetStringSlice("rules")
	if err != nil {
		return err
	}
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	// Send the rules to the server
	c := client.Client{ControllerAddress: e.cliSettings.ServerAddr}
	err := c.DeletePermitListRules(e.cliSettings.ActiveNamespace, args[0], args[1], e.ruleNames)
	return err
}
