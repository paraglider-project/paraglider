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

package gcp

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	gcp "github.com/NetSys/invisinets/pkg/gcp"
)

func NewCommand() *cobra.Command {
	executor := &executor{}
	return &cobra.Command{
		Use:     "gcp",
		Aliases: []string{"gcp"},
		Short:   "Starts the GCP plugin server with given config file",
		Args:    cobra.ExactArgs(2),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
}

type executor struct {
	port int
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	var err error
	e.port, err = strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid port")
	}
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	gcp.Setup(e.port, args[1])
	return nil
}
