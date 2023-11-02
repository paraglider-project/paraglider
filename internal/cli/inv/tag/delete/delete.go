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

package delete

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	executor := &executor{}
	cmd := &cobra.Command{
		Use:     "delete <tag name> [-members <member list>]",
		Short:   "Delete a tag",
		Args:    cobra.ExactArgs(1),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	cmd.Flags().StringSlice("members", []string{}, "The member(s) to delete")
	return cmd
}

type executor struct {
	members []string
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	var err error
	e.members, err = cmd.Flags().GetStringSlice("members")
	if err != nil {
		return err
	}
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	// Delete the tag from the server
	var url string
	var req *http.Request
	if len(e.members) == 0 {
		url = fmt.Sprintf("http://0.0.0.0:8080/tags/%s", args[0])
		var err error
		req, err = http.NewRequest(http.MethodDelete, url, nil)
		if err != nil {
			return err
		}
	} else {
		url = fmt.Sprintf("http://0.0.0.0:8080/tags/%s/members/", args[0])
		body, err := json.Marshal(e.members)
		if err != nil {
			return err
		}
		req, err = http.NewRequest(http.MethodDelete, url, bytes.NewBuffer(body))
		if err != nil {
			return err
		}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
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
