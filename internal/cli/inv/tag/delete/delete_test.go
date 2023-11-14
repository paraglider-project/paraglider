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
	"strings"
	"testing"

	"github.com/NetSys/invisinets/internal/cli/inv/settings"
	fake "github.com/NetSys/invisinets/pkg/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTagDeleteValidate(t *testing.T) {
	cmd, executor := NewCommand()

	args := []string{"tag"}
	members := []string{"child1", "child2"}

	err := cmd.Flags().Set("members", strings.Join(members, ","))
	require.Nil(t, err)

	err = executor.Validate(cmd, args)

	assert.Nil(t, err)
	assert.Equal(t, members, executor.members)
}

func TestTagDeleteExecute(t *testing.T) {
	server := &fake.FakeFrontendServer{}
	settings.ServerAddr = server.SetupFakeFrontendServer()

	cmd, executor := NewCommand()

	// Delete entire tag
	args := []string{"tag"}
	err := executor.Execute(cmd, args)

	assert.Nil(t, err)

	// Delete members of tag
	executor.members = []string{"child1", "child2"}
	err = executor.Execute(cmd, args)

	assert.Nil(t, err)
}
