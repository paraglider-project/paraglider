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

package get

import (
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	executor := &executor{}
	cmd := &cobra.Command{
		Use:     "get",
		Short:   "Get a rule",
		Args:    cobra.ExactArgs(2),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	return cmd
}

type executor struct {
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	// Get the rules from the server
	url := fmt.Sprintf("http://0.0.0.0:8080/cloud/%s/permit-list/%s", args[0], args[1])
	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	fmt.Println("Status Code: ", resp.StatusCode)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println("Response Body: ", string(bodyBytes))

	return nil
}