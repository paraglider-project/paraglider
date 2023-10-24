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

package add

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	executor := &executor{}
	cmd := &cobra.Command{
		Use:     "add",
		Short:   "Add a rule",
		Args:    cobra.ExactArgs(2),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	cmd.Flags().Bool("bidirectional", false, "Whether the rule should be bidirectional")
	cmd.Flags().String("rulefile", "", "The file containing the rules to add")
	cmd.Flags().String("ping", "", "IP/tag to allow ping to")
	cmd.Flags().String("ssh", "", "IP/tag to allow SSH to")
	return cmd
}

type executor struct {
	ruleFile      string
	pingTag       string
	sshTag        string
	bidirectional bool
}

func (e *executor) Validate(cmd *cobra.Command, args []string) error {
	var err error
	e.ruleFile, err = cmd.Flags().GetString("rulefile")
	if err != nil {
		return err
	}
	e.pingTag, err = cmd.Flags().GetString("ping")
	if err != nil {
		return err
	}
	e.sshTag, err = cmd.Flags().GetString("ssh")
	if err != nil {
		return err
	}
	e.bidirectional, err = cmd.Flags().GetBool("bidirectional")
	if err != nil {
		return err
	}
	return nil
}

func (e *executor) Execute(cmd *cobra.Command, args []string) error {
	rules := []*invisinetspb.PermitListRule{}
	if e.ruleFile != "" {
		// Read the rules from the file
		ruleFile, err := os.Open(e.ruleFile)
		if err != nil {
			return err
		}
		defer ruleFile.Close()
		fileRules, err := io.ReadAll(ruleFile)
		if err != nil {
			return err
		}
		// Parse the rules
		json.Unmarshal(fileRules, &rules)
	}
	if e.pingTag != "" {
		// Add the rules to allow ping
		rules = append(rules, &invisinetspb.PermitListRule{Id: "allow-ping-inbound", Tags: []string{e.pingTag}, Protocol: 1, Direction: 0, DstPort: -1, SrcPort: -1})
		rules = append(rules, &invisinetspb.PermitListRule{Id: "allow-ping-outbound", Tags: []string{e.pingTag}, Protocol: 1, Direction: 1, DstPort: -1, SrcPort: -1})
	}
	if e.sshTag != "" {
		// Add the rule to allow SSH
		rules = append(rules, &invisinetspb.PermitListRule{Id: "allow-ssh-inbound", Tags: []string{e.sshTag}, Protocol: 6, Direction: 0, DstPort: 22, SrcPort: -1})
		rules = append(rules, &invisinetspb.PermitListRule{Id: "allow-ssh-outbound", Tags: []string{e.sshTag}, Protocol: 6, Direction: 1, DstPort: -1, SrcPort: 22})
	}

	// Send the rules to the server
	permitList := &invisinetspb.PermitList{AssociatedResource: args[1], Rules: rules}
	url := fmt.Sprintf("http://0.0.0.0:8080/cloud/%s/permit-list/rules", args[0])

	body, err := json.Marshal(permitList)
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
