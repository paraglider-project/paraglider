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
	fake "github.com/NetSys/invisinets/pkg/fake"
	"github.com/stretchr/testify/assert"
)

func TestRuleGetExecute(t *testing.T) {
	server := &fake.FakeFrontendServer{}
	settings.ServerAddr = server.SetupFakeFrontendServer()

	cmd, executor := NewCommand()
	var output bytes.Buffer
	executor.writer = &output

	args := []string{fake.CloudName, "uri"}
	err := executor.Execute(cmd, args)

	assert.Nil(t, err)
	assert.Contains(t, output.String(), fake.GetFakePermitList("uri").AssociatedResource)
}
