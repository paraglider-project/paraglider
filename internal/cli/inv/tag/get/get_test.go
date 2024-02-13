//go:build unit

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
	"bytes"
	"testing"

	"github.com/NetSys/invisinets/internal/cli/inv/settings"
	fake "github.com/NetSys/invisinets/pkg/fake/controller/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTagGetValidate(t *testing.T) {
	cmd, executor := NewCommand()

	args := []string{"tag"}

	err := cmd.Flags().Set("resolve", "true")

	require.Nil(t, err)

	err = executor.Validate(cmd, args)

	assert.Nil(t, err)
	assert.True(t, executor.resolveFlag)
}

func TestTagGetExecute(t *testing.T) {
	server := &fake.FakeOrchestratorRESTServer{}
	serverAddr := server.SetupFakeOrchestratorRESTServer()

	cmd, executor := NewCommand()
	executor.cliSettings = settings.CLISettings{ServerAddr: serverAddr}
	var output bytes.Buffer
	executor.writer = &output
	executor.resolveFlag = false

	// Get the tag
	tagName := "tag1"
	args := []string{tagName}
	err := executor.Execute(cmd, args)

	assert.Nil(t, err)
	assert.Contains(t, output.String(), tagName)
	assert.Contains(t, output.String(), fake.GetFakeTagMapping(tagName).TagName)
	assert.Contains(t, output.String(), fake.GetFakeTagMapping(tagName).ChildTags[0])

	// Resolve the tag
	executor.resolveFlag = true
	err = executor.Execute(cmd, args)

	assert.Nil(t, err)
	assert.Contains(t, output.String(), tagName)
	assert.Contains(t, output.String(), fake.GetFakeTagMappingLeafTags(tagName)[0].TagName)
}
