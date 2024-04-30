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

package get

import (
	"fmt"
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
		Use:     "get <tag name> [--resolve]",
		Short:   "Get a tag",
		Args:    cobra.ExactArgs(1),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	cmd.Flags().Bool("resolve", false, "Resolve the tag to a list of IP addresses")
	return cmd, executor
}

type executor struct {
	common.CommandExecutor
	writer      io.Writer
	cliSettings settings.CLISettings
	resolveFlag bool
}

func (e *executor) SetOutput(w io.Writer) {
	e.writer = w
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	var err error
	e.resolveFlag, err = cmd.Flags().GetBool("resolve")
	if err != nil {
		return err
	}
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	// Get the tag from the server
	c := client.Client{ControllerAddress: e.cliSettings.ServerAddr}

	if e.resolveFlag {
		tagMappings, err := c.ResolveTag(args[0])
		if err != nil {
			return err
		}

		// Print the tag
		fmt.Fprintf(e.writer, "Tag %s:\n %v\n", args[0], tagMappings)
	} else {
		tagMapping, err := c.GetTag(args[0])
		if err != nil {
			return err
		}

		// Print the tag
		fmt.Fprintln(e.writer, tagMapping)
	}

	return nil
}
