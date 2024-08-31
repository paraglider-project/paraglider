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
	"testing"

	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rpc"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	"github.com/paraglider-project/paraglider/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestIntegration(t *testing.T) {
	accountId := GetAwsAccountId()
	namespace := SetupAwsTesting("test-integration")
	region := "us-east-2"
	defer TeardownAwsTesting(namespace, region)

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.AZURE)
	if err != nil {
		t.Fatal(err)
	}
	awsServer := &AwsPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	instanceName := "paraglider-test-vm"
	instanceAvailabilityZone := "us-east-2a"
	testInstanceJson, err := getTestInstanceInputJson(instanceAvailabilityZone)
	if err != nil {
		t.Fatal(err)
	}
	req := &paragliderpb.CreateResourceRequest{
		Deployment: &paragliderpb.ParagliderDeployment{
			Id:        accountId,
			Namespace: namespace,
		},
		Name:        instanceName,
		Description: testInstanceJson,
	}
	resp, err := awsServer.CreateResource(context.TODO(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, instanceName, resp.Name)
}
