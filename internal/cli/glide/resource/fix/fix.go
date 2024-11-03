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

package fix

import (
	"fmt"
	"io"
	"os"

	common "github.com/paraglider-project/paraglider/internal/cli/common"
	"github.com/paraglider-project/paraglider/internal/cli/glide/config"
	"github.com/paraglider-project/paraglider/pkg/client"
	"github.com/spf13/cobra"
)

type executor struct {
	common.CommandExecutor
	writer      io.Writer
	cliSettings config.CliSettings
}

func NewCommand() (*cobra.Command, *executor) {
	executor := &executor{writer: os.Stdout, cliSettings: config.ActiveConfig.Settings}
	cmd := &cobra.Command{
		Use:     "fix <cloud> <resource_name>",
		Short:   "Fix any identified problems with a resource as identifid by the check command",
		Args:    cobra.ExactArgs(2),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	return cmd, executor
}

func (e *executor) SetOutput(w io.Writer) {
	e.writer = w
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	resource := args[1]
	fmt.Fprintf(e.writer, "Fixing issues with %s in %s namespace...\n\n", resource, e.cliSettings.ActiveNamespace)
	client := client.Client{ControllerAddress: e.cliSettings.ServerAddr}

	resp, err := client.FixResource(e.cliSettings.ActiveNamespace, args[0], resource)
	if err != nil {
		fmt.Fprintf(e.writer, "\033[91mFAIL: %v\033[0m\n", err)
		return nil
	}

	// Print the fix results
	for _, msg := range resp {
		fmt.Fprintf(e.writer, "\033[92m\u2713 FIXED: %v\033[0m\n", msg)
	}

	// todo: print the error that weren't fixed
	fmt.Fprintf(e.writer, "Fix Complete\n")

	return nil
}
