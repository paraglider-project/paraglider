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

package tag

import (
	"github.com/NetSys/invisinets/internal/cli/inv/tag/delete"
	"github.com/NetSys/invisinets/internal/cli/inv/tag/get"
	"github.com/NetSys/invisinets/internal/cli/inv/tag/set"
	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tag",
		Short: "Perform operations on tags",
	}

	cmd.AddCommand(delete.NewCommand())
	cmd.AddCommand(get.NewCommand())
	cmd.AddCommand(set.NewCommand())

	return cmd
}
