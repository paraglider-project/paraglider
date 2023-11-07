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
	"encoding/json"
	"strings"
	"testing"

	"github.com/NetSys/invisinets/internal/cli/inv/settings"
	utils "github.com/NetSys/invisinets/internal/cli/inv/utils/testutils"
	"github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
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
	settings.PrintOutput = false
	server := &utils.FakeFrontendServer{}
	server.SetupFakeServer()

	cmd, executor := NewCommand()

	// Just children set
	executor.children = []string{"child1", "child2"}
	args := []string{"tag"}

	err := executor.Execute(cmd, args)
	assert.Nil(t, err)

	request := server.GetLastRequestBody()
	expected := &tagservicepb.TagMapping{TagName: args[0], ChildTags: executor.children}
	content := &tagservicepb.TagMapping{}
	err = json.Unmarshal(request, content)

	require.Nil(t, err)

	assert.Equal(t, "POST", server.GetLastRequestMethod())
	assert.Equal(t, expected, content)

	// Just URI/IP set
	executor.children = []string{}
	executor.uri = "uri"
	executor.ip = "ip"

	err = executor.Execute(cmd, args)
	assert.Nil(t, err)

	request = server.GetLastRequestBody()
	expected = &tagservicepb.TagMapping{TagName: args[0], Uri: &executor.uri, Ip: &executor.ip}
	content = &tagservicepb.TagMapping{}
	err = json.Unmarshal(request, content)

	require.Nil(t, err)

	assert.Equal(t, "POST", server.GetLastRequestMethod())
	assert.Equal(t, expected, content)
}
