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

package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	az "github.com/NetSys/invisinets/pkg/azure_plugin"
	"github.com/NetSys/invisinets/pkg/frontend"
	gcp "github.com/NetSys/invisinets/pkg/gcp"
	tagservice "github.com/NetSys/invisinets/pkg/tag_service"
)

func NewFrontendCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "frontend",
		Aliases: []string{"frontend"},
		Short:   "Starts the frontend server with given config file",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			frontend.Setup(args[0])
		},
	}
}

func NewTagServCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "tagserv",
		Aliases: []string{"tagserv"},
		Short:   "Starts the tag server on given ports",
		Args:    cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			dbPort, err := strconv.Atoi(args[0])
			if err != nil {
				return
			}
			serverPort, err := strconv.Atoi(args[1])
			if err != nil {
				return
			}
			clearKeys, err := strconv.ParseBool(args[2])
			if err != nil {
				return
			}
			tagservice.Setup(dbPort, serverPort, clearKeys)
		},
	}
}

func NewAZCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "az",
		Aliases: []string{"az"},
		Short:   "Starts the Azure plugin server on given port",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			port, err := strconv.Atoi(args[0])
			if err != nil {
				fmt.Println("Invalid port.")
				return
			}
			az.Setup(port, args[1])
		},
	}
}

func NewGCPCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "gcp",
		Aliases: []string{"gcp"},
		Short:   "Starts the GCP plugin server with given config file",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			port, err := strconv.Atoi(args[0])
			if err != nil {
				fmt.Println("Invalid port.")
				return
			}
			gcp.Setup(port, args[1])
		},
	}
}
