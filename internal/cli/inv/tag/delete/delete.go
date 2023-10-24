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
	"net/http"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	executor := &executor{}
	cmd := &cobra.Command{
		Use:     "delete",
		Short:   "Delete a tag",
		Args:    cobra.ExactArgs(1),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	cmd.Flags().String("member", "", "The member to delete")
	return cmd
}

type executor struct {
	member string
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	var err error
	e.member, err = cmd.Flags().GetString("member")
	if err != nil {
		return err
	}
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	// Delete the tag from the server
	var url string
	if e.member == "" {
		url = fmt.Sprintf("http://0.0.0.0:8080/tags/%s", args[0])
	} else {
		url = fmt.Sprintf("http://0.0.0.0:8080/tags/%s/members/%s", args[0], e.member)
	}

	members := []string{e.member}
	body, err := json.Marshal(members)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	fmt.Println(resp)
	return nil
}
