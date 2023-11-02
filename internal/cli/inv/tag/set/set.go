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

package set

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/NetSys/invisinets/internal/cli/inv/settings"
	"github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	executor := &executor{}
	cmd := &cobra.Command{
		Use:     "set <tag name> [--children <child tag list> | --uri <uri> | --ip <ip>]",
		Short:   "Set a tag",
		Args:    cobra.ExactArgs(1),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	cmd.Flags().StringSlice("children", []string{}, "List of child tags")
	cmd.Flags().String("uri", "", "URI of the tag")
	cmd.Flags().String("ip", "", "IP of the tag")
	return cmd
}

type executor struct {
	children []string
	uri      string
	ip       string
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	var err error
	e.children, err = cmd.Flags().GetStringSlice("children")
	if err != nil {
		return err
	}

	e.uri, err = cmd.Flags().GetString("uri")
	if err != nil {
		return err
	}

	e.ip, err = cmd.Flags().GetString("ip")
	if err != nil {
		return err
	}

	if len(e.children) == 0 && e.uri == "" && e.ip == "" {
		return fmt.Errorf("must specify at least one of --children, --uri, or --ip")
	}
	if len(e.children) > 0 && (e.uri != "" || e.ip != "") {
		return fmt.Errorf("cannot specify --children with --uri or --ip")
	}

	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	tagMapping := &tagservicepb.TagMapping{TagName: args[0], ChildTags: e.children}
	body, err := json.Marshal(tagMapping)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("http://%s/tags/%s", settings.ServerAddr, args[0])

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	fmt.Println("Status Code: ", resp.StatusCode)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println("Response Body: ", string(bodyBytes))

	fmt.Println(resp)
	return nil
}
