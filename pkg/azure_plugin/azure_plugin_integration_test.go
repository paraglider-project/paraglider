//go:build integration

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

package azure_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	fake "github.com/NetSys/invisinets/pkg/fake/orchestrator/rpc"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/orchestrator"
	"github.com/NetSys/invisinets/pkg/orchestrator/config"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createVM(ctx context.Context, server *azurePluginServer, subscriptionId string, resourceGroupName string, namespace string, location string, name string) (*invisinetspb.CreateResourceResponse, error) {
	parameters := GetTestVmParameters(location)
	parametersBytes, err := json.Marshal(parameters)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal VM parameters")
	}
	resourceDescription := &invisinetspb.ResourceDescription{
		Id:          fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s", subscriptionId, resourceGroupName, name),
		Description: parametersBytes,
		Namespace:   namespace,
	}
	return server.CreateResource(ctx, resourceDescription)
}

// This test will test the following:
// 1. Create a resource
// 2. Add a permit list
// 3. Get the permit list
// 4- Delete permit list rule
// 5. Get the permit list and valdiates again
func TestBasicPermitListOps(t *testing.T) {
	subscriptionId := GetAzureSubscriptionId()
	resourceGroupName := SetupAzureTesting(subscriptionId, "integration")
	defer TeardownAzureTesting(subscriptionId, resourceGroupName)
	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.AZURE)
	if err != nil {
		t.Fatal(err)
	}

	s := InitializeServer(fakeOrchestratorServerAddr)
	ctx := context.Background()

	vmNamePrefix := "sample-vm"
	vmLocation := "westus"
	parameters := GetTestVmParameters(vmLocation)
	descriptionJson, err := json.Marshal(parameters)
	require.NoError(t, err)
	vmID := "/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + vmNamePrefix + "-" + uuid.NewString()
	createResourceResp, err := s.CreateResource(ctx, &invisinetspb.ResourceDescription{
		Id:          vmID,
		Description: descriptionJson,
		Namespace:   "default",
	})
	require.NoError(t, err)
	require.NotNil(t, createResourceResp)
	assert.Equal(t, createResourceResp.Uri, vmID)

	rules := []*invisinetspb.PermitListRule{
		{
			Name:      "test-rule1",
			Targets:   []string{"47.235.107.235"},
			Direction: invisinetspb.Direction_OUTBOUND,
			SrcPort:   80,
			DstPort:   80,
			Protocol:  6,
		},
	}
	addPermitListResp, err := s.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: rules, Namespace: "default", Resource: vmID})
	require.NoError(t, err)
	require.NotNil(t, addPermitListResp)

	// Assert the NSG created is equivalent to the pl rules by using the get permit list api
	getPermitListResp, err := s.GetPermitList(ctx, &invisinetspb.GetPermitListRequest{Resource: vmID, Namespace: "default"})
	require.NoError(t, err)
	require.NotNil(t, getPermitListResp)

	assert.ElementsMatch(t, getPermitListResp.Rules, rules)

	// Delete permit list rule
	deletePermitListResp, err := s.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: []string{rules[0].Name}, Namespace: "default", Resource: vmID})
	require.NoError(t, err)
	require.NotNil(t, deletePermitListResp)

	// Assert the rule is deleted by using the get permit list api
	getPermitListResp, err = s.GetPermitList(ctx, &invisinetspb.GetPermitListRequest{Resource: vmID, Namespace: "default"})
	require.NoError(t, err)
	require.NotNil(t, getPermitListResp)

	assert.ElementsMatch(t, getPermitListResp.Rules, []*invisinetspb.PermitListRule{})
}

func TestCrossNamespaces(t *testing.T) {
	// Setup resource groups
	subscriptionId := GetAzureSubscriptionId()
	resourceGroup1Name := SetupAzureTesting(subscriptionId, "integration3")
	defer TeardownAzureTesting(subscriptionId, resourceGroup1Name)
	resourceGroup2Name := SetupAzureTesting(subscriptionId, "integration4")
	defer TeardownAzureTesting(subscriptionId, resourceGroup2Name)

	// Set Azure plugin port
	azureServerPort := 7991

	// Setup orchestrator server
	resourceGroup1Namespace := "rg1"
	resourceGroup2Namespace := "rg2"
	orchestratorServerConfig := config.Config{
		Server: config.Server{
			Host:    "localhost",
			Port:    "8080",
			RpcPort: "8081",
		},
		CloudPlugins: []config.CloudPlugin{
			{
				Name: utils.AZURE,
				Host: "localhost",
				Port: strconv.Itoa(azureServerPort),
			},
		},
		Namespaces: map[string][]config.CloudDeployment{
			resourceGroup1Namespace: {
				{
					Name:       utils.AZURE,
					Deployment: fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", subscriptionId, resourceGroup1Name),
				},
			},
			resourceGroup2Namespace: {
				{
					Name:       utils.AZURE,
					Deployment: fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", subscriptionId, resourceGroup2Name),
				},
			},
		},
	}
	orchestratorServerAddr := orchestratorServerConfig.Server.Host + ":" + orchestratorServerConfig.Server.RpcPort
	orchestrator.Setup(orchestratorServerConfig, true)

	// Setup Azure plugin server
	azureServer := Setup(azureServerPort, orchestratorServerAddr)
	ctx := context.Background()

	// Create vm1 in rg1
	vm1Name := "vm-invisinets-test1"
	vm1Location := "westus"
	createVM1Resp, err := createVM(ctx, azureServer, subscriptionId, resourceGroup1Name, resourceGroup1Namespace, vm1Location, vm1Name)
	require.NoError(t, err)
	require.NotNil(t, createVM1Resp)
	assert.Equal(t, createVM1Resp.Name, vm1Name)

	// Create vm2 in rg2
	vm2Name := "vm-invisinets-test2"
	vm2Location := "westus"
	createVM2Resp, err := createVM(ctx, azureServer, subscriptionId, resourceGroup2Name, resourceGroup2Namespace, vm2Location, vm2Name)
	require.NoError(t, err)
	require.NotNil(t, createVM2Resp)
	assert.Equal(t, createVM2Resp.Name, vm2Name)

	// Add permit list rules to vm1 and vm2 to ping each other
	vm1ResourceId := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s", subscriptionId, resourceGroup1Name, vm1Name)
	vm2ResourceId := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s", subscriptionId, resourceGroup2Name, vm2Name)
	vmResourceIds := []string{vm1ResourceId, vm2ResourceId}
	vm1Ip, err := GetVmIpAddress(vm1ResourceId)
	require.NoError(t, err)
	vm2Ip, err := GetVmIpAddress(vm2ResourceId)
	require.NoError(t, err)
	vm1Rules := []*invisinetspb.PermitListRule{
		{
			Name:      "vm2-ping-ingress",
			Direction: invisinetspb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm2Ip},
		},
		{
			Name:      "vm2-ping-egress",
			Direction: invisinetspb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm2Ip},
		},
	}
	vm2Rules := []*invisinetspb.PermitListRule{
		{
			Name:      "vm1-ping-ingress",
			Direction: invisinetspb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm1Ip},
		},
		{
			Name:      "vm1-ping-egress",
			Direction: invisinetspb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm1Ip},
		},
	}
	vmRules := [][]*invisinetspb.PermitListRule{vm1Rules, vm2Rules}
	namespaces := []string{resourceGroup1Namespace, resourceGroup2Namespace}
	for i, vmResourceId := range vmResourceIds {
		addPermitListRulesReq := &invisinetspb.AddPermitListRulesRequest{Rules: vmRules[i], Namespace: namespaces[i], Resource: vmResourceId}
		addPermitListRulesResp, err := azureServer.AddPermitListRules(ctx, addPermitListRulesReq)
		require.NoError(t, err)
		require.NotNil(t, addPermitListRulesResp)
	}

	// Run connectivity checks on both directions between vm1 and vm2
	azureConnectivityCheckVM1toVM2, err := RunPingConnectivityCheck(vm1ResourceId, vm2Ip)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheckVM1toVM2)
	azureConnectivityCheckVM2toVM1, err := RunPingConnectivityCheck(vm2ResourceId, vm1Ip)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheckVM2toVM1)
}
