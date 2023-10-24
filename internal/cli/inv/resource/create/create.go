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

package create

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	executor := &executor{}
	return &cobra.Command{
		Use:     "create",
		Short:   "Create a resource",
		Args:    cobra.ExactArgs(3),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
}

type executor struct {
	description []byte
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	descriptionFile, err := os.Open(args[2])
	if err != nil {
		return err
	}
	defer descriptionFile.Close()
	e.description, err = io.ReadAll(descriptionFile)
	if err != nil {
		return err
	}
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	body := []byte(fmt.Sprintf(`{
		"id": %s,
		"description": %s
	}`, args[1], string(e.description)))
	url := fmt.Sprintf("http://0.0.0.0:8080/cloud/%s/resources/", args[0])

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	fmt.Println(resp)
	return nil
}
