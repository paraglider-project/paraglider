//go:build multicloud

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

package multicloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"cloud.google.com/go/networkmanagement/apiv1/networkmanagementpb"
	azure "github.com/paraglider-project/paraglider/pkg/azure"
	gcp "github.com/paraglider-project/paraglider/pkg/gcp"
	orchestrator "github.com/paraglider-project/paraglider/pkg/orchestrator"
	config "github.com/paraglider-project/paraglider/pkg/orchestrator/config"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO @seankimkdy: should this be turned into a system test where we actually call the cloud plugins through the orchestrator GRPC?
func TestMulticloud(t *testing.T) {
	// Azure config
	azurePluginPort := 7991
	azureSubscriptionId := azure.GetAzureSubscriptionId()
	azureResourceGroupName := azure.SetupAzureTesting(azureSubscriptionId, "multicloud")
	azureDeploymentId := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", azureSubscriptionId, azureResourceGroupName)
	defer azure.TeardownAzureTesting(azureSubscriptionId, azureResourceGroupName)

	// GCP config
	gcpPluginPort := 7992
	gcpProjectId := gcp.SetupGcpTesting("multicloud")
	defer gcp.TeardownGcpTesting(gcpProjectId)

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
				Port: strconv.Itoa(azurePluginPort),
			},
			{
				Name: utils.GCP,
				Host: "localhost",
				Port: strconv.Itoa(gcpPluginPort),
			},
		},
		Namespaces: map[string][]config.CloudDeployment{
			"default": {
				{
					Name:       utils.AZURE,
					Deployment: fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", azureSubscriptionId, azureResourceGroupName),
				},
			},
			"other": {
				{
					Name:       utils.GCP,
					Deployment: fmt.Sprintf("projects/%s", gcpProjectId),
				},
			},
		},
	}
	orchestratorServerAddr := orchestratorServerConfig.Server.Host + ":" + orchestratorServerConfig.Server.RpcPort
	orchestrator.Setup(orchestratorServerConfig, true)
	fmt.Println("Setup orchestrator server")

	// Setup Azure
	azureServer := azure.Setup(azurePluginPort, orchestratorServerAddr)
	fmt.Println("Setup Azure server")

	// Setup GCP
	gcpServer := gcp.Setup(gcpPluginPort, orchestratorServerAddr)
	fmt.Println("Setup GCP server")

	ctx := context.Background()

	// Create Azure VM 1
	azureVm1Location := "westus"
	azureVm1Parameters := azure.GetTestVmParameters(azureVm1Location)
	azureVm1Description, err := json.Marshal(azureVm1Parameters)
	azureVm1Name := "paraglider-vm-test-1"
	azureVm1ResourceId := "/subscriptions/" + azureSubscriptionId + "/resourceGroups/" + azureResourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + azureVm1Name
	azureCreateResourceResp1, err := azureServer.CreateResource(
		ctx,
		&paragliderpb.CreateResourceRequest{
			Deployment:  &paragliderpb.ParagliderDeployment{Id: azureDeploymentId, Namespace: "default"},
			Name:        azureVm1Name,
			Description: azureVm1Description,
		},
	)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotNil(t, azureCreateResourceResp1)
	assert.Equal(t, azureCreateResourceResp1.Uri, azureVm1ResourceId)
	fmt.Println("Created Azure VM")

	// Create GCP VM
	gcpVmZone := "us-west1-a"
	gcpVmName := utils.GetGitHubRunPrefix() + "vm-paraglider-test"
	gcpVmParameters := gcp.GetTestVmParameters(gcpProjectId, gcpVmZone, gcpVmName)
	gcpVmDescription, err := json.Marshal(gcpVmParameters)
	gcpCreateResourceResp, err := gcpServer.CreateResource(
		ctx,
		&paragliderpb.CreateResourceRequest{
			Deployment:  &paragliderpb.ParagliderDeployment{Id: "projects/" + gcpProjectId, Namespace: "other"},
			Name:        gcpVmName,
			Description: gcpVmDescription,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, gcpCreateResourceResp)
	assert.Equal(t, gcpCreateResourceResp.Name, gcpVmName)
	fmt.Println("Created GCP VM")

	// Create GCP permit list for Azure VM 1
	azureVm1IpAddress, err := azure.GetVmIpAddress(azureVm1ResourceId)
	require.NoError(t, err)
	gcpVmPermitList1Req := &paragliderpb.AddPermitListRulesRequest{
		Resource: fmt.Sprintf("projects/%s/zones/%s/instances/%s", gcpProjectId, gcpVmZone, gcpVmName),
		Rules: []*paragliderpb.PermitListRule{
			{
				Name:      "azure1-inbound-rule",
				Direction: paragliderpb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{azureVm1IpAddress},
			},
			{
				Name:      "azure1-outbound-rule",
				Direction: paragliderpb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{azureVm1IpAddress},
			},
			{ // SSH rule for debugging
				Name:      "ssh-inbound-rule",
				Direction: paragliderpb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   22,
				Protocol:  6,
				Targets:   []string{"0.0.0.0/0"},
			},
		},
		Namespace: "other",
	}
	gcpAddPermitListRulesResp, err := gcpServer.AddPermitListRules(ctx, gcpVmPermitList1Req)
	require.NoError(t, err)
	require.NotNil(t, gcpAddPermitListRulesResp)
	fmt.Println("Added GCP permit list rules")

	// Create Azure VM1 permit list
	gcpVmIpAddress, err := gcp.GetInstanceIpAddress(gcpProjectId, gcpVmZone, gcpVmName)
	require.NoError(t, err)
	azureVm1PermitListReq := &paragliderpb.AddPermitListRulesRequest{
		Resource: azureVm1ResourceId,
		Rules: []*paragliderpb.PermitListRule{
			{
				Name:      "gcp-inbound-rule",
				Direction: paragliderpb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{gcpVmIpAddress},
			},
			{
				Name:      "gcp-outbound-rule",
				Direction: paragliderpb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{gcpVmIpAddress},
			},
			{ // SSH rule for debugging
				Name:      "ssh-inbound-rule",
				Direction: paragliderpb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   22,
				Protocol:  6,
				Targets:   []string{"0.0.0.0/0"},
			},
		},
		Namespace: "default",
	}
	azureAddPermitListRules1Resp, err := azureServer.AddPermitListRules(ctx, azureVm1PermitListReq)
	require.NoError(t, err)
	require.NotNil(t, azureAddPermitListRules1Resp)
	fmt.Println("Added Azure permit list rules")

	// Run GCP connectivity tests (ping from GCP VM to Azure VM)
	gcpConnectivityTest1GcpVmEndpoint := &networkmanagementpb.Endpoint{
		IpAddress: gcpVmIpAddress,
		Network:   gcp.GetVpcUrl(gcpProjectId, "other"),
		ProjectId: gcpProjectId,
	}
	gcpConnectivityTest1AzureVmEndpoint := &networkmanagementpb.Endpoint{
		IpAddress:   azureVm1IpAddress,
		NetworkType: networkmanagementpb.Endpoint_NON_GCP_NETWORK,
	}
	gcp.RunPingConnectivityTest(t, gcpProjectId, "gcp-azure-1", gcpConnectivityTest1GcpVmEndpoint, gcpConnectivityTest1AzureVmEndpoint)

	// Run Azure connectivity check (ping from Azure VM to GCP VM)
	azureConnectivityCheck1, err := azure.RunPingConnectivityCheck(azureVm1ResourceId, gcpVmIpAddress)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheck1)

	// Create Azure VM 2
	azureVm2Location := "eastus"
	azureVm2Parameters := azure.GetTestVmParameters(azureVm2Location)
	azureVm2Description, err := json.Marshal(azureVm2Parameters)
	azureVm2Name := "paraglider-vm-test-2"
	azureVm2ResourceId := "/subscriptions/" + azureSubscriptionId + "/resourceGroups/" + azureResourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + azureVm2Name
	azureCreateResourceResp2, err := azureServer.CreateResource(
		ctx,
		&paragliderpb.CreateResourceRequest{
			Deployment:  &paragliderpb.ParagliderDeployment{Id: azureDeploymentId, Namespace: "default"},
			Name:        azureVm2Name,
			Description: azureVm2Description,
		},
	)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotNil(t, azureCreateResourceResp2)
	assert.Equal(t, azureCreateResourceResp2.Uri, azureVm2ResourceId)
	fmt.Println("Created Azure VM")

	// Create GCP permit list for Azure VM 2
	azureVm2IpAddress, err := azure.GetVmIpAddress(azureVm2ResourceId)
	require.NoError(t, err)
	gcpVmPermitList2Req := &paragliderpb.AddPermitListRulesRequest{
		Resource: fmt.Sprintf("projects/%s/zones/%s/instances/%s", gcpProjectId, gcpVmZone, gcpVmName),
		Rules: []*paragliderpb.PermitListRule{
			{
				Name:      "azure2-inbound-rule",
				Direction: paragliderpb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{azureVm2IpAddress},
			},
			{
				Name:      "azure2-outbound-rule",
				Direction: paragliderpb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{azureVm2IpAddress},
			},
			{ // SSH rule for debugging
				Name:      "ssh-inbound-rule",
				Direction: paragliderpb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   22,
				Protocol:  6,
				Targets:   []string{"0.0.0.0/0"},
			},
		},
		Namespace: "other",
	}
	gcpAddPermitListRules2Resp, err := gcpServer.AddPermitListRules(ctx, gcpVmPermitList2Req)
	require.NoError(t, err)
	require.NotNil(t, gcpAddPermitListRules2Resp)
	fmt.Println("Added GCP permit list rules")

	// Create Azure VM 2 permit list
	azureVm2PermitListReq := &paragliderpb.AddPermitListRulesRequest{
		Resource: azureVm2ResourceId,
		Rules: []*paragliderpb.PermitListRule{
			{
				Name:      "gcp-inbound-rule",
				Direction: paragliderpb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{gcpVmIpAddress},
			},
			{
				Name:      "gcp-outbound-rule",
				Direction: paragliderpb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{gcpVmIpAddress},
			},
			{ // SSH rule for debugging
				Name:      "ssh-inbound-rule",
				Direction: paragliderpb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   22,
				Protocol:  6,
				Targets:   []string{"0.0.0.0/0"},
			},
		},
		Namespace: "default",
	}
	azureAddPermitListRules2Resp, err := azureServer.AddPermitListRules(ctx, azureVm2PermitListReq)
	require.NoError(t, err)
	require.NotNil(t, azureAddPermitListRules2Resp)
	fmt.Println("Added Azure permit list rules")

	// Run GCP connectivity tests (ping from GCP VM to Azure VM)
	gcpConnectivityTest2GcpVmEndpoint := &networkmanagementpb.Endpoint{
		IpAddress: gcpVmIpAddress,
		Network:   gcp.GetVpcUrl(gcpProjectId, "other"),
		ProjectId: gcpProjectId,
	}
	gcpConnectivityTest2AzureVmEndpoint := &networkmanagementpb.Endpoint{
		IpAddress:   azureVm2IpAddress,
		NetworkType: networkmanagementpb.Endpoint_NON_GCP_NETWORK,
	}
	gcp.RunPingConnectivityTest(t, gcpProjectId, "gcp-azure-2", gcpConnectivityTest2GcpVmEndpoint, gcpConnectivityTest2AzureVmEndpoint)

	// Run Azure connectivity check (ping from Azure VM to GCP VM)
	azureConnectivityCheck2, err := azure.RunPingConnectivityCheck(azureVm2ResourceId, gcpVmIpAddress)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheck2)
}
