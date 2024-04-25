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

package set

import (
	"strings"
	"testing"

	"github.com/NetSys/invisinets/internal/cli/glide/settings"
	fake "github.com/NetSys/invisinets/pkg/fake/orchestrator/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTagSetValidate(t *testing.T) {
	args := []string{"tag"}

	// Just children specified
	cmd, executor := NewCommand()
	children := []string{"child1", "child2"}
	err := cmd.Flags().Set("children", strings.Join(children, ","))
	require.Nil(t, err)

	err = executor.Validate(cmd, args)

	assert.Nil(t, err)
	assert.Equal(t, children, executor.children)

	// Just the URI/IP specified
	cmd, executor = NewCommand()
	err = cmd.Flags().Set("uri", "uri")
	require.Nil(t, err)
	err = cmd.Flags().Set("ip", "ip")
	require.Nil(t, err)

	err = executor.Validate(cmd, args)

	assert.Nil(t, err)
	assert.Equal(t, "uri", executor.uri)
	assert.Equal(t, "ip", executor.ip)

	// Both children and URI/IP specified
	cmd, executor = NewCommand()
	children = []string{"child1", "child2"}
	err = cmd.Flags().Set("children", strings.Join(children, ","))
	require.Nil(t, err)
	err = cmd.Flags().Set("uri", "uri")
	require.Nil(t, err)
	err = cmd.Flags().Set("ip", "ip")
	require.Nil(t, err)

	err = executor.Validate(cmd, args)

	assert.NotNil(t, err)
}

func TestTagSetExecute(t *testing.T) {
	server := &fake.FakeOrchestratorRESTServer{}
	serverAddr := server.SetupFakeOrchestratorRESTServer()

	cmd, executor := NewCommand()
	executor.cliSettings = settings.CLISettings{ServerAddr: serverAddr}

	// Just children set
	executor.children = []string{"child1", "child2"}
	args := []string{"tag"}

	err := executor.Execute(cmd, args)
	assert.Nil(t, err)

	// Just URI/IP set
	executor.children = []string{}
	executor.uri = "uri"
	executor.ip = "ip"

	err = executor.Execute(cmd, args)
	assert.Nil(t, err)
}
