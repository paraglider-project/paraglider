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

package set

import (
	"io"
	"os"

	common "github.com/NetSys/invisinets/internal/cli/common"
	"github.com/NetSys/invisinets/internal/cli/inv/settings"
	"github.com/NetSys/invisinets/pkg/client"
	"github.com/spf13/cobra"
)

func NewCommand() (*cobra.Command, *executor) {
	executor := &executor{writer: os.Stdout}
	cmd := &cobra.Command{
		Use:     "set",
		Short:   "Set current namespace",
		Args:    cobra.ExactArgs(1),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	return cmd, executor
}

type executor struct {
	common.CommandExecutor
	writer io.Writer
}

func (e *executor) SetOutput(w io.Writer) {
	e.writer = w
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	c := client.Client{ControllerAddress: settings.ServerAddr}
	err := c.SetNamespace(args[0])

	return err
}
