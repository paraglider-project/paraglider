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

package cmd

import (
	"fmt"
	"os"

	common "github.com/paraglider-project/paraglider/internal/cli/common"
	"github.com/paraglider-project/paraglider/internal/cli/glided/az"
	"github.com/paraglider-project/paraglider/internal/cli/glided/gcp"
	"github.com/paraglider-project/paraglider/internal/cli/glided/ibm"
	"github.com/paraglider-project/paraglider/internal/cli/glided/kvserv"
	"github.com/paraglider-project/paraglider/internal/cli/glided/orchestrator"
	"github.com/paraglider-project/paraglider/internal/cli/glided/startup"
	"github.com/paraglider-project/paraglider/internal/cli/glided/tagserv"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "glided",
	Short: "Paraglider Server CLI",
	Long:  `Paraglider Server CLI`,
}

func init() {
	rootCmd.AddCommand(az.NewCommand())
	rootCmd.AddCommand(gcp.NewCommand())
	rootCmd.AddCommand(ibm.NewCommand())
	rootCmd.AddCommand(orchestrator.NewCommand())
	rootCmd.AddCommand(tagserv.NewCommand())
	rootCmd.AddCommand(kvserv.NewCommand())
	rootCmd.AddCommand(startup.NewCommand())
	rootCmd.AddCommand(common.NewVersionCommand())
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "There was an error while executing your command: \n\n%s\n", err)
		os.Exit(1)
	}
}
