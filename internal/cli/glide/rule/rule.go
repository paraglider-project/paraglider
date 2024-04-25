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

package rule

import (
	"github.com/NetSys/invisinets/internal/cli/glide/rule/add"
	"github.com/NetSys/invisinets/internal/cli/glide/rule/delete"
	"github.com/NetSys/invisinets/internal/cli/glide/rule/get"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule",
		Short: "Perform operations on rules",
	}

	addCmd, _ := add.NewCommand()
	cmd.AddCommand(addCmd)
	deleteCmd, _ := delete.NewCommand()
	cmd.AddCommand(deleteCmd)
	getCmd, _ := get.NewCommand()
	cmd.AddCommand(getCmd)

	return cmd
}
