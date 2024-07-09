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

package delete

import (
	"strings"
	"testing"

	"github.com/paraglider-project/paraglider/internal/cli/glide/config"
	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleDeleteValidate(t *testing.T) {
	err := config.ReadOrCreateConfig()
	assert.Nil(t, err)

	cmd, executor := NewCommand()

	args := []string{fake.CloudName, "uri"}
	rules := "name1,names2"
	err = cmd.Flags().Set("rules", rules)
	require.Nil(t, err)
	err = executor.Validate(cmd, args)

	assert.Nil(t, err)
	assert.Equal(t, executor.ruleNames, strings.Split(rules, ","))
}

func TestRuleDeleteExecute(t *testing.T) {
	server := &fake.FakeOrchestratorRESTServer{}
	serverAddr := server.SetupFakeOrchestratorRESTServer()

	err := config.ReadOrCreateConfig()
	assert.Nil(t, err)

	cmd, executor := NewCommand()
	executor.cliSettings = config.CliSettings{ServerAddr: serverAddr, ActiveNamespace: fake.Namespace}
	executor.ruleNames = []string{"name1", "name2"}

	args := []string{fake.CloudName, "uri"}
	err = executor.Execute(cmd, args)

	assert.Nil(t, err)
}
