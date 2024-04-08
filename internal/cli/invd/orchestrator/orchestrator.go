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

package orchestrator

import (
	"github.com/spf13/cobra"

	"github.com/NetSys/invisinets/pkg/orchestrator"
)

func NewCommand() *cobra.Command {
	executor := &executor{}
	return &cobra.Command{
		Use:     "orch <path to config>",
		Aliases: []string{"orch"},
		Short:   "Starts the orch server with given config file",
		Args:    cobra.ExactArgs(1),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
}

type executor struct {
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	orchestrator.SetupWithFile(args[0])
	return nil
}
