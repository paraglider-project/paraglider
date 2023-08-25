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

package cli

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"
    "strconv"

	"github.com/NetSys/invisinets/pkg/frontend"
    azure "github.com/NetSys/invisinets/pkg/azure_plugin"
    gcp "github.com/NetSys/invisinets/pkg/gcp"
)

var frontendCmd = &cobra.Command{
    Use:   "frontend",
    Aliases: []string{"frontend"},
    Short:  "Starts the frontend server with given config file",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        frontend.Setup(args[0])
    },
}

var azPluginCmd = &cobra.Command{
    Use:   "azpl",
    Aliases: []string{"az"},
    Short:  "Starts the Azure plugin",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        port, err := strconv.Atoi(args[0])
        if err != nil {
            fmt.Fprintf(os.Stderr, "Bad port #")
        }
        azure.Setup(port)
    },
}

var gcpPluginCmd = &cobra.Command{
    Use:   "gcppl",
    Aliases: []string{"gcp"},
    Short:  "Starts the GCP plugin",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        port, err := strconv.Atoi(args[0])
        if err != nil {
            fmt.Fprintf(os.Stderr, "Bad port #")
        }
        gcp.Setup(port)
    },
}

var rootCmd = &cobra.Command{
    Use:  "invisinets",
    Short: "Invisinets CLI",
    Long: `Invisinets CLI
   
Run Invisinets controller components`,
    Run: func(cmd *cobra.Command, args []string) {

    },
}

func init() {
    rootCmd.AddCommand(frontendCmd)
    rootCmd.AddCommand(azPluginCmd)
    rootCmd.AddCommand(gcpPluginCmd)
}

func Execute() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
        os.Exit(1)
    }
}