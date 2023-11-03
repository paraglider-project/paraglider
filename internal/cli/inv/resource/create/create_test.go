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
	"encoding/json"
	"testing"

	"github.com/NetSys/invisinets/internal/cli/inv/settings"
	utils "github.com/NetSys/invisinets/internal/cli/inv/utils/testutils"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourceCreateValidate(t *testing.T) {
	cmd, executor := NewCommand()

	args := []string{utils.CloudName, "uri", "not-a-file.json"}
	err := executor.Validate(cmd, args)

	assert.NotNil(t, err)

	// TODO @smcclure20: add more test cases
}

func TestResourceCreateExecute(t *testing.T) {
	settings.PrintOutput = false
	server := &utils.FakeFrontendServer{}
	server.SetupFakeServer()

	cmd, executor := NewCommand()
	executor.description = []byte(`descriptionstring`)

	args := []string{utils.CloudName, "uri", ""}
	err := executor.Execute(cmd, args)

	assert.Nil(t, err)

	request := server.GetLastRequestBody()
	content := &invisinetspb.ResourceDescriptionString{}
	err = json.Unmarshal(request, content)

	require.Nil(t, err)

	assert.Equal(t, "POST", server.GetLastRequestMethod())
	assert.Equal(t, "descriptionstring", content.Description)
	assert.Equal(t, "uri", content.Id)
}
