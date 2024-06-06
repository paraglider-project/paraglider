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

package set

import (
	"testing"

	"github.com/paraglider-project/paraglider/internal/cli/glide/config"
	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rest"
	"github.com/stretchr/testify/assert"
)

func TestNamespaceSetValidate(t *testing.T) {
	server := &fake.FakeOrchestratorRESTServer{}
	serverAddr := server.SetupFakeOrchestratorRESTServer()

	err := config.ReadOrCreateConfig()
	assert.Nil(t, err)

	cmd, executor := NewCommand()
	executor.cliSettings = &config.CliSettings{ServerAddr: serverAddr, ActiveNamespace: fake.Namespace}

	// Valid option
	for namespace := range fake.GetFakeNamespaces() {
		err = executor.Validate(cmd, []string{namespace})
		assert.Nil(t, err)
	}

	// Invalid option
	err = executor.Validate(cmd, []string{"invalid-namespace"})
	assert.NotNil(t, err)
}

func TestNamespaceSetExecute(t *testing.T) {
	err := config.ReadOrCreateConfig()
	assert.Nil(t, err)

	cmd, executor := NewCommand()
	executor.cliSettings = &config.CliSettings{ActiveNamespace: "default"}

	err = executor.Execute(cmd, []string{"new-namespace"})

	assert.Nil(t, err)
	assert.Equal(t, "new-namespace", executor.cliSettings.ActiveNamespace)
}
