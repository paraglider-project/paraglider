//go:build integration

/*
Copyright 2024 The Paraglider Authors.

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

package aws

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	"github.com/paraglider-project/paraglider/pkg/utils"
	"github.com/stretchr/testify/require"

	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rpc"
)

func TestIntegration(t *testing.T) {
	accountId := GetAwsAccountId()
	namespace := "default"

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.AZURE)
	if err != nil {
		t.Fatal(err)
	}
	awsServer := &AWSPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	instanceName := "paraglider-test-vm"
	instanceRegion := "us-east-2a"
	runInstancesInput := getTestInstance(instanceRegion)
	descriptionJson, err := json.Marshal(runInstancesInput)
	require.NoError(t, err)
	req := &paragliderpb.CreateResourceRequest{
		Deployment: &paragliderpb.ParagliderDeployment{
			Id:        accountId,
			Namespace: namespace,
		},
		Name:        instanceName,
		Description: descriptionJson,
	}
	resp, err := awsServer.CreateResource(context.TODO(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, instanceName, resp.Name)
}
