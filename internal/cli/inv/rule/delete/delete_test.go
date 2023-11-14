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
	"testing"

	"github.com/NetSys/invisinets/internal/cli/inv/settings"
	fake "github.com/NetSys/invisinets/pkg/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleDeleteValidate(t *testing.T) {
	cmd, executor := NewCommand()

	args := []string{fake.CloudName, "uri"}
	ruleFile := "not-a-file.json"
	tag := "tag"
	err := cmd.Flags().Set("rulefile", ruleFile)
	require.Nil(t, err)
	err = cmd.Flags().Set("ping", tag)
	require.Nil(t, err)
	err = cmd.Flags().Set("ssh", tag)
	require.Nil(t, err)
	err = executor.Validate(cmd, args)

	assert.Nil(t, err)
	assert.Equal(t, executor.ruleFile, ruleFile)
	assert.Equal(t, executor.pingTag, tag)
	assert.Equal(t, executor.sshTag, tag)
}

func TestRuleDeleteExecute(t *testing.T) {
	server := &fake.FakeFrontendServer{}
	settings.ServerAddr = server.SetupFakeFrontendServer()

	cmd, executor := NewCommand()
	executor.pingTag = "pingTag"
	executor.sshTag = "sshTag"

	args := []string{fake.CloudName, "uri"}
	err := executor.Execute(cmd, args)

	assert.Nil(t, err)
}
