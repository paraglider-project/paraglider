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

package delete

import (
	"io"
	"os"

	common "github.com/paraglider-project/paraglider/internal/cli/common"
	"github.com/paraglider-project/paraglider/internal/cli/glide/settings"
	"github.com/paraglider-project/paraglider/pkg/client"
	"github.com/spf13/cobra"
)

func NewCommand() (*cobra.Command, *executor) {
	executor := &executor{writer: os.Stdout, cliSettings: settings.Global}
	cmd := &cobra.Command{
		Use:     "delete <tag name> [-member <member>]",
		Short:   "Delete a tag",
		Args:    cobra.ExactArgs(1),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	cmd.Flags().String("member", "", "The member to delete")
	return cmd, executor
}

type executor struct {
	common.CommandExecutor
	cliSettings settings.CLISettings
	writer      io.Writer
	member      string
}

func (e *executor) SetOutput(w io.Writer) {
	e.writer = w
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	var err error
	e.member, err = cmd.Flags().GetString("member")
	if err != nil {
		return err
	}
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	// Delete the tag from the server
	c := client.Client{ControllerAddress: e.cliSettings.ServerAddr}
	if e.member == "" {
		err := c.DeleteTag(args[0])
		return err
	} else {
		err := c.DeleteTagMembers(args[0], e.member)
		return err
	}
}
