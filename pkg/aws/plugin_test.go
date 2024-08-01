//go:build unit

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
	"testing"

	orchestrator "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rpc"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	"github.com/paraglider-project/paraglider/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestCreateResource(t *testing.T) {
	testCases := []struct {
		name            string
		fakeServerState fakeServerState
	}{
		{
			name:            "FromScratch",
			fakeServerState: fakeServerState{},
		},
		{
			name: "ExistingNetwork",
			fakeServerState: fakeServerState{
				vpc:    fakeVpc,
				subnet: fakeSubnet,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Setup test
			ctx, fakeAwsClients, err := setupTest(testCase.fakeServerState)
			if err != nil {
				t.Fatalf("unable to setup test: %v", err)
			}

			// Setup fake orchestrator and plugin
			_, fakeOrchestratorServerAddr, err := orchestrator.SetupFakeOrchestratorRPCServer(utils.AWS)
			if err != nil {
				t.Fatalf("unable to setup fake orchestrator: %v", err)
			}
			awsPluginServer := &AwsPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}

			// Create instance
			testInstanceJson, err := getTestInstanceInputJson(fakeAvailabilityZone)
			if err != nil {
				t.Fatalf("unable to get test instance JSON: %v", err)
			}
			createResourceReq := &paragliderpb.CreateResourceRequest{
				Deployment:  &paragliderpb.ParagliderDeployment{Namespace: fakeNamespace, Id: fakeAccountId},
				Name:        fakeInstanceName,
				Description: testInstanceJson,
			}
			createResourceResp, err := awsPluginServer._CreateResource(ctx, createResourceReq, fakeAwsClients)
			require.NoError(t, err)
			require.Equal(t, fakeInstanceName, createResourceResp.Name)
			require.Equal(t, getInstanceArn(createResourceReq.Deployment.Id, fakeRegion, fakeInstanceId), createResourceResp.Uri)
			require.Equal(t, fakeInstancePrivateIpAddress, createResourceResp.Ip)
		})
	}
}
