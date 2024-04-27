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

package tag

import (
	"github.com/paraglider-project/paraglider/internal/cli/glide/tag/delete"
	"github.com/paraglider-project/paraglider/internal/cli/glide/tag/get"
	"github.com/paraglider-project/paraglider/internal/cli/glide/tag/set"
	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tag",
		Short: "Perform operations on tags",
	}

	deleteCmd, _ := delete.NewCommand()
	cmd.AddCommand(deleteCmd)
	getCmd, _ := get.NewCommand()
	cmd.AddCommand(getCmd)
	setCmd, _ := set.NewCommand()
	cmd.AddCommand(setCmd)

	return cmd
}
