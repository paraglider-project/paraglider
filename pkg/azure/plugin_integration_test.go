//go:build integration

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

package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/google/uuid"
	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rpc"
	"github.com/paraglider-project/paraglider/pkg/orchestrator"
	"github.com/paraglider-project/paraglider/pkg/orchestrator/config"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createVM(ctx context.Context, server *azurePluginServer, subscriptionId string, resourceGroupName string, namespace string, location string, name string) (*paragliderpb.CreateResourceResponse, error) {
	parameters := GetTestVmParameters(location)
	parametersBytes, err := json.Marshal(parameters)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal VM parameters")
	}
	resourceDescription := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", subscriptionId, resourceGroupName), Namespace: namespace},
		Name:        name,
		Description: parametersBytes,
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
	vmName := vmNamePrefix + "-" + uuid.NewString()
	vmID := "/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + vmName
	createResourceResp, err := s.CreateResource(ctx, &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", subscriptionId, resourceGroupName), Namespace: "default"},
		Name:        vmName,
		Description: descriptionJson,
	})
	require.NoError(t, err)
	require.NotNil(t, createResourceResp)
	assert.Equal(t, createResourceResp.Uri, vmID)

	rules := []*paragliderpb.PermitListRule{
		{
			Name:      "test-rule1",
			Targets:   []string{"47.235.107.235"},
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   80,
			DstPort:   80,
			Protocol:  6,
		},
	}
	addPermitListResp, err := s.AddPermitListRules(ctx, &paragliderpb.AddPermitListRulesRequest{Rules: rules, Namespace: "default", Resource: vmID})
	require.NoError(t, err)
	require.NotNil(t, addPermitListResp)

	// Assert the NSG created is equivalent to the pl rules by using the get permit list api
	getPermitListResp, err := s.GetPermitList(ctx, &paragliderpb.GetPermitListRequest{Resource: vmID, Namespace: "default"})
	require.NoError(t, err)
	require.NotNil(t, getPermitListResp)

	assert.ElementsMatch(t, getPermitListResp.Rules, rules)

	// Delete permit list rule
	deletePermitListResp, err := s.DeletePermitListRules(ctx, &paragliderpb.DeletePermitListRulesRequest{RuleNames: []string{rules[0].Name}, Namespace: "default", Resource: vmID})
	require.NoError(t, err)
	require.NotNil(t, deletePermitListResp)

	// Assert the rule is deleted by using the get permit list api
	getPermitListResp, err = s.GetPermitList(ctx, &paragliderpb.GetPermitListRequest{Resource: vmID, Namespace: "default"})
	require.NoError(t, err)
	require.NotNil(t, getPermitListResp)

	assert.ElementsMatch(t, getPermitListResp.Rules, []*paragliderpb.PermitListRule{})
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
	vm1Name := "vm-paraglider-test1"
	vm1Location := "westus"
	createVM1Resp, err := createVM(ctx, azureServer, subscriptionId, resourceGroup1Name, resourceGroup1Namespace, vm1Location, vm1Name)
	require.NoError(t, err)
	require.NotNil(t, createVM1Resp)
	assert.Equal(t, createVM1Resp.Name, vm1Name)

	// Create vm2 in rg2
	vm2Name := "vm-paraglider-test2"
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
	vm1Rules := []*paragliderpb.PermitListRule{
		{
			Name:      "vm2-ping-ingress",
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm2Ip},
		},
		{
			Name:      "vm2-ping-egress",
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm2Ip},
		},
	}
	vm2Rules := []*paragliderpb.PermitListRule{
		{
			Name:      "vm1-ping-ingress",
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm1Ip},
		},
		{
			Name:      "vm1-ping-egress",
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{vm1Ip},
		},
	}
	vmRules := [][]*paragliderpb.PermitListRule{vm1Rules, vm2Rules}
	namespaces := []string{resourceGroup1Namespace, resourceGroup2Namespace}
	for i, vmResourceId := range vmResourceIds {
		addPermitListRulesReq := &paragliderpb.AddPermitListRulesRequest{Rules: vmRules[i], Namespace: namespaces[i], Resource: vmResourceId}
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

func TestMultipleRegionsIntraNamespace(t *testing.T) {
	// Setup
	subscriptionId := GetAzureSubscriptionId()
	resourceGroupName := SetupAzureTesting(subscriptionId, "integration5")
	defer TeardownAzureTesting(subscriptionId, resourceGroupName)
	defaultNamespace := "default"

	// Set Azure plugin port
	azureServerPort := 7991

	// Setup orchestrator server
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
			defaultNamespace: {
				{
					Name:       utils.AZURE,
					Deployment: fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", subscriptionId, resourceGroupName),
				},
			},
		},
	}
	orchestratorServerAddr := orchestratorServerConfig.Server.Host + ":" + orchestratorServerConfig.Server.RpcPort
	orchestrator.Setup(orchestratorServerConfig, true)

	// Setup Azure plugin server
	azureServer := Setup(azureServerPort, orchestratorServerAddr)
	ctx := context.Background()

	// Create 2 VMs in different regions
	vm1Name := "vm-paraglider-test-west"
	vm1Location := "westus"
	createVM1Resp, err := createVM(ctx, azureServer, subscriptionId, resourceGroupName, defaultNamespace, vm1Location, vm1Name)
	require.NoError(t, err)
	require.NotNil(t, createVM1Resp)
	assert.Equal(t, createVM1Resp.Name, vm1Name)

	vm2Name := "vm-paraglider-test-east"
	vm2Location := "eastus"
	createVM2Resp, err := createVM(ctx, azureServer, subscriptionId, resourceGroupName, defaultNamespace, vm2Location, vm2Name)
	require.NoError(t, err)
	require.NotNil(t, createVM2Resp)
	assert.Equal(t, createVM2Resp.Name, vm2Name)

	vm1ResourceId := "/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + vm1Name
	vm2ResourceId := "/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + vm2Name
	vm1Ip, err := GetVmIpAddress(vm1ResourceId)
	require.NoError(t, err)
	vm2Ip, err := GetVmIpAddress(vm2ResourceId)
	require.NoError(t, err)

	// Create and add permit list rules to vm1 and vm2 to ping each other
	vm1Rules := []*paragliderpb.PermitListRule{
		{
			Name:      "vm2-ping-ingress",
			Targets:   []string{vm2Ip},
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
		},
		{
			Name:      "vm2-ping-egress",
			Targets:   []string{vm2Ip},
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
		},
	}

	vm2Rules := []*paragliderpb.PermitListRule{
		{
			Name:      "vm1-ping-ingress",
			Targets:   []string{vm1Ip},
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
		},
		{
			Name:      "vm1-ping-egress",
			Targets:   []string{vm1Ip},
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
		},
	}
	vmRules := [][]*paragliderpb.PermitListRule{vm1Rules, vm2Rules}
	for i, vmResourceId := range []string{vm1ResourceId, vm2ResourceId} {
		addPermitListRulesReq := &paragliderpb.AddPermitListRulesRequest{Rules: vmRules[i], Namespace: defaultNamespace, Resource: vmResourceId}
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
