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
	"encoding/json"
	"io"
	"os"

	common "github.com/NetSys/invisinets/internal/cli/common"
	"github.com/NetSys/invisinets/internal/cli/inv/settings"
	"github.com/NetSys/invisinets/pkg/client"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/spf13/cobra"
)

func NewCommand() (*cobra.Command, *executor) {
	executor := &executor{writer: os.Stdout, cliSettings: settings.Global}
	cmd := &cobra.Command{
		Use:     "delete <cloud> <resource name> [--rulefile <path to rule json file> | --ping <tag> | --ssh <tag>]",
		Short:   "Delete a rule from a resource permit list",
		Args:    cobra.ExactArgs(2),
		PreRunE: executor.Validate,
		RunE:    executor.Execute,
	}
	cmd.Flags().String("rulefile", "", "The file containing the rules to add")
	cmd.Flags().String("ping", "", "IP/tag to allow ping to")
	cmd.Flags().String("ssh", "", "IP/tag to allow SSH to")
	return cmd, executor
}

type executor struct {
	common.CommandExecutor
	writer      io.Writer
	cliSettings settings.CLISettings
	ruleFile    string
	pingTag     string
	sshTag      string
}

func (e *executor) SetOutput(w io.Writer) {
	e.writer = w
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
		err = json.Unmarshal(fileRules, &rules)
		if err != nil {
			return err
		}
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
	c := client.Client{ControllerAddress: e.cliSettings.ServerAddr}
	err := c.DeletePermitListRules(e.cliSettings.ActiveNamespace, args[0], args[1], rules)
	return err
}
