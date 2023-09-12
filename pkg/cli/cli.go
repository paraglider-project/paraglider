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
    tagservice "github.com/NetSys/invisinets/pkg/tag_service"
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

var tagServiceCmd = &cobra.Command{
    Use:   "tagserv",
    Aliases: []string{"tagserv"},
    Short:  "Starts the tag server on given ports",
    Args:  cobra.ExactArgs(2),
    Run: func(cmd *cobra.Command, args []string) {
        dbPort, err := strconv.Atoi(args[0])
        if err != nil{
            return
        }
        serverPort, err := strconv.Atoi(args[1])
        if err != nil{
            return
        }
        tagservice.Setup(dbPort, serverPort)
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
    rootCmd.AddCommand(tagServiceCmd)
}

func Execute() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
        os.Exit(1)
    }
}