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

package tagserv

import (
	"strconv"

	"github.com/spf13/cobra"

	tagservice "github.com/NetSys/invisinets/pkg/tag_service"
)

func NewCommand() *cobra.Command {
	executor := &executor{}
	return &cobra.Command{
		Use:     "tagserv <database port> <server port> <clear keys>",
		Aliases: []string{"tagserv"},
		Short:   "Starts the tag server on given ports",
		Args:    cobra.ExactArgs(3),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
}

type executor struct {
	dbPort     int
	serverPort int
	clearKeys  bool
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	var err error
	e.dbPort, err = strconv.Atoi(args[0])
	if err != nil {
		return err
	}
	e.serverPort, err = strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	e.clearKeys, err = strconv.ParseBool(args[2])
	if err != nil {
		return err
	}

	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	tagservice.Setup(e.dbPort, e.serverPort, e.clearKeys)
	return nil
}
