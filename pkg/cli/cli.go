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
    "strconv"
	"github.com/spf13/cobra"

	"github.com/NetSys/invisinets/pkg/frontend"
    az "github.com/NetSys/invisinets/pkg/azure_plugin"
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

var azCmd = &cobra.Command{
    Use:   "az",
    Aliases: []string{"az"},
    Short:  "Starts the Azure plugin server on given port",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        port, err := strconv.Atoi(args[0])
        if err != nil {
            fmt.Println("Invalid port.")
            return
        }
        az.Setup(port)
    },
}

var gcpCmd = &cobra.Command{
    Use:   "gcp",
    Aliases: []string{"gcp"},
    Short:  "Starts the GCP plugin server with given config file",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        port, err := strconv.Atoi(args[0])
        if err != nil {
            fmt.Println("Invalid port.")
            return
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
    rootCmd.AddCommand(azCmd)
    rootCmd.AddCommand(gcpCmd)
}

func Execute() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
        os.Exit(1)
    }
}