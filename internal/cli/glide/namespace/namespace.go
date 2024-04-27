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

package namespace

import (
	"github.com/paraglider-project/paraglider/internal/cli/glide/namespace/get"
	"github.com/paraglider-project/paraglider/internal/cli/glide/namespace/list"
	"github.com/paraglider-project/paraglider/internal/cli/glide/namespace/set"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "namespace",
		Short: "Perform operations on the namespace",
	}

	getCmd, _ := get.NewCommand()
	cmd.AddCommand(getCmd)
	setCmd, _ := set.NewCommand()
	cmd.AddCommand(setCmd)
	listCmd, _ := list.NewCommand()
	cmd.AddCommand(listCmd)

	return cmd
}
