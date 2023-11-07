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

package utils

import (
	"fmt"
	"io"
	"net/http"

	"github.com/NetSys/invisinets/internal/cli/inv/settings"
	"github.com/spf13/cobra"
)

func ProcessResponse(resp *http.Response, w io.Writer) error {
	if settings.PrintOutput {
		fmt.Fprintln(w, "Status Code: ", resp.StatusCode)
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, "Response Body: ", string(bodyBytes))
	} else { // If not printing results to terminal, return error based on status code (helpful for testing)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Request failed with status code %d", resp.StatusCode)
		}
	}

	return nil
}

type CommandExecutor interface {
	Validate(cmd *cobra.Command, args []string) error
	Execute(cmd *cobra.Command, args []string) error
	SetOutput(w io.Writer)
}
