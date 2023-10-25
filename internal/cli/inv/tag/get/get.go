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
		Short:   "Get a tag",
		Args:    cobra.ExactArgs(1),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	cmd.Flags().Bool("resolve", false, "Resolve the tag to a list of IP addresses")
	return cmd
}

type executor struct {
	resolveFlag bool
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	var err error
	e.resolveFlag, err = cmd.Flags().GetBool("resolve")
	if err != nil {
		return err
	}
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	// Get the tag from the server
	var url string
	if !e.resolveFlag {
		url = fmt.Sprintf("http://0.0.0.0:8080/tags/%s", args[0])
	} else {
		url = fmt.Sprintf("http://0.0.0.0:8080/tags/%s/resolve", args[0])
	}

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
