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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	namespace := "default"
	subscriptionId := GetAzureSubscriptionId()
	resourceGroupName := SetupAzureTesting(subscriptionId, "integration1")
	defer TeardownAzureTesting(subscriptionId, resourceGroupName, namespace)
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
		Deployment:  &paragliderpb.ParagliderDeployment{Id: fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", subscriptionId, resourceGroupName), Namespace: namespace},
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
	addPermitListResp, err := s.AddPermitListRules(ctx, &paragliderpb.AddPermitListRulesRequest{Rules: rules, Namespace: namespace, Resource: vmID})
	require.NoError(t, err)
	require.NotNil(t, addPermitListResp)

	// Assert the NSG created is equivalent to the pl rules by using the get permit list api
	getPermitListResp, err := s.GetPermitList(ctx, &paragliderpb.GetPermitListRequest{Resource: vmID, Namespace: namespace})
	require.NoError(t, err)
	require.NotNil(t, getPermitListResp)

	assert.ElementsMatch(t, getPermitListResp.Rules, rules)

	// Delete permit list rule
	deletePermitListResp, err := s.DeletePermitListRules(ctx, &paragliderpb.DeletePermitListRulesRequest{RuleNames: []string{rules[0].Name}, Namespace: namespace, Resource: vmID})
	require.NoError(t, err)
	require.NotNil(t, deletePermitListResp)

	// Assert the rule is deleted by using the get permit list api
	getPermitListResp, err = s.GetPermitList(ctx, &paragliderpb.GetPermitListRequest{Resource: vmID, Namespace: namespace})
	require.NoError(t, err)
	require.NotNil(t, getPermitListResp)

	assert.ElementsMatch(t, getPermitListResp.Rules, []*paragliderpb.PermitListRule{})
}

func TestCrossNamespaces(t *testing.T) {
	// Set namespaces
	resourceGroup1Namespace := "rg1"
	resourceGroup2Namespace := "rg2"

	// Setup resource groups
	subscriptionId := GetAzureSubscriptionId()
	resourceGroup1Name := SetupAzureTesting(subscriptionId, "integration3")
	defer TeardownAzureTesting(subscriptionId, resourceGroup1Name, resourceGroup1Namespace)
	resourceGroup2Name := SetupAzureTesting(subscriptionId, "integration4")
	defer TeardownAzureTesting(subscriptionId, resourceGroup2Name, resourceGroup2Namespace)

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
	azureConnectivityCheckVM1toVM2, err := RunPingConnectivityCheck(vm1ResourceId, vm2Ip, resourceGroup1Namespace)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheckVM1toVM2)
	azureConnectivityCheckVM2toVM1, err := RunPingConnectivityCheck(vm2ResourceId, vm1Ip, resourceGroup2Namespace)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheckVM2toVM1)
}

func TestMultipleRegionsIntraNamespace(t *testing.T) {
	// Setup
	subscriptionId := GetAzureSubscriptionId()
	resourceGroupName := SetupAzureTesting(subscriptionId, "integration5")
	defaultNamespace := "default"
	defer TeardownAzureTesting(subscriptionId, resourceGroupName, defaultNamespace)

	// Set Azure plugin port
	azureServerPort := 7992

	// Setup orchestrator server
	orchestratorServerConfig := config.Config{
		Server: config.Server{
			Host:    "localhost",
			Port:    "8080",
			RpcPort: "9091",
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
	azureConnectivityCheckVM1toVM2, err := RunPingConnectivityCheck(vm1ResourceId, vm2Ip, defaultNamespace)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheckVM1toVM2)
	azureConnectivityCheckVM2toVM1, err := RunPingConnectivityCheck(vm2ResourceId, vm1Ip, defaultNamespace)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheckVM2toVM1)
}

func TestAttachResourceIntegration(t *testing.T) {
	namespace := "default"
	subscriptionId := GetAzureSubscriptionId()
	resourceGroupName := SetupAzureTesting(subscriptionId, "integration6")
	defer TeardownAzureTesting(subscriptionId, resourceGroupName, namespace)
	ctx := context.Background()

	// Set Azure plugin port
	azureServerPort := 7994

	// Setup orchestrator server
	orchestratorServerConfig := config.Config{
		Server: config.Server{
			Host:    "localhost",
			Port:    "9092",
			RpcPort: "9093",
		},
		CloudPlugins: []config.CloudPlugin{
			{
				Name: utils.AZURE,
				Host: "localhost",
				Port: strconv.Itoa(azureServerPort),
			},
		},
		Namespaces: map[string][]config.CloudDeployment{
			namespace: {
				{
					Name:       utils.AZURE,
					Deployment: getDeploymentUri(subscriptionId, resourceGroupName),
				},
			},
		},
	}
	orchestratorServerAddr := orchestratorServerConfig.Server.Host + ":" + orchestratorServerConfig.Server.RpcPort
	orchestrator.Setup(orchestratorServerConfig, true)

	// Setup Azure plugin server
	azureServer := Setup(azureServerPort, orchestratorServerAddr)

	vmLocation := "westus"
	externalVmParameters := GetTestVmParameters(vmLocation)
	externalVmName := "external-vm"
	externalVnetName := "external-vnet"
	externalVmID := getVmUri(subscriptionId, resourceGroupName, externalVmName)
	resourceIdInfo := ResourceIDInfo{
		SubscriptionID:    subscriptionId,
		ResourceGroupName: resourceGroupName,
		ResourceName:      externalVmName,
	}

	// Find unused address spaces for external address
	conn, err := grpc.NewClient(azureServer.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		utils.Log.Printf("Azure Integration test: Could not dial the orchestrator")
		return
	}
	defer conn.Close()
	client := paragliderpb.NewControllerClient(conn)
	reqAddressSpaces := make([]int32, 1)
	response, err := client.FindUnusedAddressSpaces(context.Background(), &paragliderpb.FindUnusedAddressSpacesRequest{Sizes: reqAddressSpaces})
	if err != nil {
		utils.Log.Printf("Failed to find unused address spaces: %v", err)
		return
	}
	assert.Greater(t, len(response.AddressSpaces), 0)
	externalAddressSpace := response.AddressSpaces[0]
	azureHandler, err := azureServer.setupAzureHandler(resourceIdInfo, namespace)
	require.NoError(t, err)

	// Create Non-Paraglider Vnet
	externalVnetParams := getVirtualNetworkParameters(vmLocation, externalAddressSpace)
	externalVnet, err := azureHandler.CreateOrUpdateVirtualNetwork(ctx, externalVnetName, externalVnetParams)
	require.NotNil(t, externalVnet)
	require.NoError(t, err)

	// Create Non-Paraglider VM
	resourceSubnet := externalVnet.Properties.Subnets[0]
	resourceHandler := &azureResourceHandlerVM{}
	externalVmIp, err := resourceHandler.createWithNetwork(ctx, &externalVmParameters, resourceSubnet, externalVmName, azureHandler, []string{})
	require.NoError(t, err)
	require.NotNil(t, externalVmIp)

	externalVnet, err = azureHandler.GetVnet(ctx, externalVnetName)
	require.NoError(t, err)
	require.Nil(t, externalVnet.Tags)
	require.Empty(t, externalVnet.Properties.VirtualNetworkPeerings)

	// Attach resource to Paraglider
	attachResourceReq := &paragliderpb.AttachResourceRequest{
		Namespace: namespace,
		Resource:  externalVmID,
	}
	attachResourceResp, err := azureServer.AttachResource(ctx, attachResourceReq)
	require.NoError(t, err)
	require.NotNil(t, attachResourceResp)
	assert.Equal(t, externalVmID, attachResourceResp.Uri)

	externalVnet, err = azureHandler.GetVnet(ctx, externalVnetName)
	require.NoError(t, err)

	// Vnet tags and peerings should be created after attachment
	require.NotNil(t, externalVnet.Tags)
	assert.Equal(t, namespace, *externalVnet.Tags[namespaceTagKey])
	require.NotEmpty(t, externalVnet.Properties.VirtualNetworkPeerings)

	// Create Paraglider VM
	vmNamePrefix := "sample-vm"
	pgVmName := vmNamePrefix + "-" + uuid.NewString()
	pgVmID := getVmUri(subscriptionId, resourceGroupName, pgVmName)
	pgVmParameters := GetTestVmParameters(vmLocation)
	descriptionJson, err := json.Marshal(&pgVmParameters)
	require.NoError(t, err)
	createResourceResp, err := azureServer.CreateResource(ctx, &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: getDeploymentUri(subscriptionId, resourceGroupName), Namespace: namespace},
		Name:        pgVmName,
		Description: descriptionJson,
	})
	require.NoError(t, err)
	require.NotNil(t, createResourceResp)
	assert.Equal(t, createResourceResp.Uri, pgVmID)

	// Add permit list rules to Paraglider VM
	pgVmIp, err := GetVmIpAddress(pgVmID)
	require.NoError(t, err)
	pgVmRules := []*paragliderpb.PermitListRule{
		{
			Name:      "external-vm-ping-egress",
			Targets:   []string{externalVmIp},
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
		},
		{
			Name:      "external-vm-ping-ingress",
			Targets:   []string{externalVmIp},
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
		},
	}

	externalVmRules := []*paragliderpb.PermitListRule{
		{
			Name:      "paraglider-vm-ping-egress",
			Targets:   []string{pgVmIp},
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
		},
		{
			Name:      "paraglider-vm-ping-ingress",
			Targets:   []string{pgVmIp},
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
		},
	}

	// Add permit list rules to Paraglider VM
	vmRules := [][]*paragliderpb.PermitListRule{pgVmRules, externalVmRules}
	vmResourceIds := []string{pgVmID, externalVmID}
	for i, vmResourceId := range vmResourceIds {
		addPermitListRulesReq := &paragliderpb.AddPermitListRulesRequest{Rules: vmRules[i], Namespace: namespace, Resource: vmResourceId}
		addPermitListRulesResp, err := azureServer.AddPermitListRules(ctx, addPermitListRulesReq)
		require.NoError(t, err)
		require.NotNil(t, addPermitListRulesResp)
	}

	// Run connectivity checks on both directions between vm1 and vm2
	azureConnectivityCheck1, err := RunPingConnectivityCheck(pgVmID, externalVmIp, namespace)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheck1)
	azureConnectivityCheck2, err := RunPingConnectivityCheck(externalVmID, pgVmIp, namespace)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheck2)
}
