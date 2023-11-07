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
	"testing"

	"github.com/NetSys/invisinets/internal/cli/inv/settings"
	utils "github.com/NetSys/invisinets/internal/cli/inv/utils/testutils"
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
	settings.PrintOutput = false
	server := &utils.FakeFrontendServer{}
	server.SetupFakeServer()

	cmd, executor := NewCommand()
	executor.resolveFlag = false

	// Get the tag
	args := []string{"tag"}
	err := executor.Execute(cmd, args)

	assert.Nil(t, err)
	assert.Equal(t, "GET", server.GetLastRequestMethod())

	// Resolve the tag
	executor.resolveFlag = true
	err = executor.Execute(cmd, args)

	assert.Nil(t, err)

	assert.Equal(t, "GET", server.GetLastRequestMethod()) // TODO now: we should diambiguate between these
}
