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

package set

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
		Use:     "set",
		Short:   "Set active namespace",
		Args:    cobra.ExactArgs(1),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	return cmd, executor
}

type executor struct {
	common.CommandExecutor
	writer      io.Writer
	cliSettings settings.CLISettings
}

func (e *executor) SetOutput(w io.Writer) {
	e.writer = w
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	// Get all namespaces from the orchestrator and confirm that the given string is one of them
	c := client.Client{ControllerAddress: e.cliSettings.ServerAddr}
	namespaces, err := c.ListNamespaces()

	if err != nil {
		return err
	}

	for namespace := range namespaces {
		if namespace == args[0] {
			return nil
		}
	}
	return fmt.Errorf("namespace %s does not exist", args[0])
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	c := client.Client{ControllerAddress: e.cliSettings.ServerAddr}
	err := c.SetNamespace(args[0])

	if err != nil {
		return err
	}

	fmt.Fprintf(e.writer, "Namespace: %v", args[0])

	return nil
}
