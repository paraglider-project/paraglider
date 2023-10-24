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
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	common "github.com/NetSys/invisinets/internal/cli/common"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "invd",
	Short: "Invisinets Server CLI",
	Long:  `Invisinets Server CLI`,
}

func init() {
	rootCmd.AddCommand(NewFrontendCommand())
	rootCmd.AddCommand(NewTagServCommand())
	rootCmd.AddCommand(NewAZCommand())
	rootCmd.AddCommand(NewGCPCommand())
	rootCmd.AddCommand(common.NewVersionCommand())
}

func Execute() {
	// Cancel gracefully on SIGINT and SIGTERM.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	err := rootCmd.ExecuteContext(ctx)
	if err != nil && err == ctx.Err() {
		fmt.Fprintln(os.Stderr, "Cancelled.")
		os.Exit(1)
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your command: \n\n%s\n", err)
		os.Exit(1)
	}
}
