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
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	common "github.com/NetSys/invisinets/internal/cli/common"
	"github.com/NetSys/invisinets/internal/cli/glide/namespace"
	"github.com/NetSys/invisinets/internal/cli/glide/resource"
	"github.com/NetSys/invisinets/internal/cli/glide/rule"
	"github.com/NetSys/invisinets/internal/cli/glide/server"
	"github.com/NetSys/invisinets/internal/cli/glide/tag"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "glide",
	Short: "Paraglider CLI",
	Long:  `Paraglider CLI`,
}

func init() {
	rootCmd.AddCommand(resource.NewCommand())
	rootCmd.AddCommand(rule.NewCommand())
	rootCmd.AddCommand(tag.NewCommand())
	rootCmd.AddCommand(common.NewVersionCommand())
	rootCmd.AddCommand(server.NewCommand())
	rootCmd.AddCommand(namespace.NewCommand())
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
