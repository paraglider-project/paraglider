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

	"github.com/spf13/cobra"

	common "github.com/paraglider-project/paraglider/internal/cli/common"
	"github.com/paraglider-project/paraglider/internal/cli/glide/config"
)

func NewCommand() (*cobra.Command, *executor) {
	executor := &executor{writer: os.Stdout, cliSettings: config.ActiveConfig.Settings}
	cmd := &cobra.Command{
		Use:     "get",
		Short:   "Get current server config",
		Args:    cobra.ExactArgs(0),
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
	fmt.Fprintln(e.writer, "Server address: ", e.cliSettings.ServerAddr)
	return nil
}
