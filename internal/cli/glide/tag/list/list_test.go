//go:build unit

/*
Copyright 2023 The Paraglider Authors.

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

package list

import (
	"bytes"
	"testing"

	"github.com/paraglider-project/paraglider/internal/cli/glide/settings"
	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rest"
	"github.com/stretchr/testify/assert"
)

func TestTagListExecute(t *testing.T) {
	server := &fake.FakeOrchestratorRESTServer{}
	serverAddr := server.SetupFakeOrchestratorRESTServer()

	cmd, executor := NewCommand()
	executor.cliSettings = settings.CLISettings{ServerAddr: serverAddr}
	var output bytes.Buffer
	executor.writer = &output

	// list the tags
	err := executor.Execute(cmd, nil)

	assert.Nil(t, err)
	assert.Contains(t, output.String(), fake.ListFakeTagMapping()[0].TagName)
	assert.Contains(t, output.String(), fake.ListFakeTagMapping()[1].TagName)
	assert.Contains(t, output.String(), fake.ListFakeTagMapping()[2].TagName)
}
