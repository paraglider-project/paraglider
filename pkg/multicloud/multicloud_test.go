//go:build multicloud

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

package multicloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"cloud.google.com/go/networkmanagement/apiv1/networkmanagementpb"
	azure_plugin "github.com/NetSys/invisinets/pkg/azure_plugin"
	gcp "github.com/NetSys/invisinets/pkg/gcp"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	orchestrator "github.com/NetSys/invisinets/pkg/orchestrator"
	config "github.com/NetSys/invisinets/pkg/orchestrator/config"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO @seankimkdy: should this be turned into a system test where we actually call the cloud plugins through the controller GRPC?
func TestMulticloud(t *testing.T) {
	// Azure config
	azurePluginPort := 7991
	azureSubscriptionId := azure_plugin.GetAzureSubscriptionId()
	azureResourceGroupName := azure_plugin.SetupAzureTesting(azureSubscriptionId, "multicloud")
	defer azure_plugin.TeardownAzureTesting(azureSubscriptionId, azureResourceGroupName)

	// GCP config
	gcpPluginPort := 7992
	gcpProjectId := gcp.SetupGcpTesting("multicloud")
	defer gcp.TeardownGcpTesting(gcpProjectId)

	// Setup controller server
	controllerServerConfig := config.Config{
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
	controllerServerAddr := orchestrator.SetupControllerServer(controllerServerConfig)
	fmt.Println("Setup controller server")

	// Setup Azure
	azureServer := azure_plugin.Setup(azurePluginPort, controllerServerAddr)
	fmt.Println("Setup Azure server")

	// Setup GCP
	gcpServer := gcp.Setup(gcpPluginPort, controllerServerAddr)
	fmt.Println("Setup GCP server")

	ctx := context.Background()

	// Create Azure VM 1
	azureVm1Location := "westus"
	azureVm1Parameters := azure_plugin.GetTestVmParameters(azureVm1Location)
	azureVm1Description, err := json.Marshal(azureVm1Parameters)
	azureVm1ResourceId := "/subscriptions/" + azureSubscriptionId + "/resourceGroups/" + azureResourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + "invisinets-vm-test-1"
	azureCreateResourceResp1, err := azureServer.CreateResource(
		ctx,
		&invisinetspb.ResourceDescription{Id: azureVm1ResourceId, Description: azureVm1Description, Namespace: "default"},
	)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotNil(t, azureCreateResourceResp1)
	assert.Equal(t, azureCreateResourceResp1.Uri, azureVm1ResourceId)
	fmt.Println("Created Azure VM")

	// Create GCP VM
	gcpVmZone := "us-west1-a"
	gcpVmName := utils.GetGitHubRunPrefix() + "vm-invisinets-test"
	gcpVmParameters := gcp.GetTestVmParameters(gcpProjectId, gcpVmZone, gcpVmName)
	gcpVmDescription, err := json.Marshal(gcpVmParameters)
	gcpCreateResourceResp, err := gcpServer.CreateResource(
		ctx,
		&invisinetspb.ResourceDescription{Description: gcpVmDescription, Namespace: "other"},
	)
	require.NoError(t, err)
	require.NotNil(t, gcpCreateResourceResp)
	assert.Equal(t, gcpCreateResourceResp.Name, gcpVmName)
	fmt.Println("Created GCP VM")

	// Create GCP permit list for Azure VM 1
	azureVm1IpAddress, err := azure_plugin.GetVmIpAddress(azureVm1ResourceId)
	require.NoError(t, err)
	gcpVmPermitList1Req := &invisinetspb.AddPermitListRulesRequest{
		Resource: fmt.Sprintf("projects/%s/zones/%s/instances/%s", gcpProjectId, gcpVmZone, gcpVmName),
		Rules: []*invisinetspb.PermitListRule{
			{
				Name:      "azure1-inbound-rule",
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{azureVm1IpAddress},
			},
			{
				Name:      "azure1-outbound-rule",
				Direction: invisinetspb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{azureVm1IpAddress},
			},
			{ // SSH rule for debugging
				Name:      "ssh-inbound-rule",
				Direction: invisinetspb.Direction_INBOUND,
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
	azureVm1PermitListReq := &invisinetspb.AddPermitListRulesRequest{
		Resource: azureVm1ResourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Name:      "gcp-inbound-rule",
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{gcpVmIpAddress},
			},
			{
				Name:      "gcp-outbound-rule",
				Direction: invisinetspb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{gcpVmIpAddress},
			},
			{ // SSH rule for debugging
				Name:      "ssh-inbound-rule",
				Direction: invisinetspb.Direction_INBOUND,
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
		Network:   gcp.GetVpcUri(gcpProjectId, "other"),
		ProjectId: gcpProjectId,
	}
	gcpConnectivityTest1AzureVmEndpoint := &networkmanagementpb.Endpoint{
		IpAddress:   azureVm1IpAddress,
		NetworkType: networkmanagementpb.Endpoint_NON_GCP_NETWORK,
	}
	gcp.RunPingConnectivityTest(t, gcpProjectId, "gcp-azure-1", gcpConnectivityTest1GcpVmEndpoint, gcpConnectivityTest1AzureVmEndpoint)

	// Run Azure connectivity check (ping from Azure VM to GCP VM)
	azureConnectivityCheck1, err := azure_plugin.RunPingConnectivityCheck(azureVm1ResourceId, gcpVmIpAddress)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheck1)

	// Create Azure VM 2
	azureVm2Location := "eastus"
	azureVm2Parameters := azure_plugin.GetTestVmParameters(azureVm2Location)
	azureVm2Description, err := json.Marshal(azureVm2Parameters)
	azureVm2ResourceId := "/subscriptions/" + azureSubscriptionId + "/resourceGroups/" + azureResourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + "invisinets-vm-test-2"
	azureCreateResourceResp2, err := azureServer.CreateResource(
		ctx,
		&invisinetspb.ResourceDescription{Id: azureVm2ResourceId, Description: azureVm2Description, Namespace: "default"},
	)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotNil(t, azureCreateResourceResp2)
	assert.Equal(t, azureCreateResourceResp2.Uri, azureVm2ResourceId)
	fmt.Println("Created Azure VM")

	// Create GCP permit list for Azure VM 2
	azureVm2IpAddress, err := azure_plugin.GetVmIpAddress(azureVm2ResourceId)
	require.NoError(t, err)
	gcpVmPermitList2Req := &invisinetspb.AddPermitListRulesRequest{
		Resource: fmt.Sprintf("projects/%s/zones/%s/instances/%s", gcpProjectId, gcpVmZone, gcpVmName),
		Rules: []*invisinetspb.PermitListRule{
			{
				Name:      "azure2-inbound-rule",
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{azureVm2IpAddress},
			},
			{
				Name:      "azure2-outbound-rule",
				Direction: invisinetspb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{azureVm2IpAddress},
			},
			{ // SSH rule for debugging
				Name:      "ssh-inbound-rule",
				Direction: invisinetspb.Direction_INBOUND,
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
	azureVm2PermitListReq := &invisinetspb.AddPermitListRulesRequest{
		Resource: azureVm2ResourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Name:      "gcp-inbound-rule",
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{gcpVmIpAddress},
			},
			{
				Name:      "gcp-outbound-rule",
				Direction: invisinetspb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{gcpVmIpAddress},
			},
			{ // SSH rule for debugging
				Name:      "ssh-inbound-rule",
				Direction: invisinetspb.Direction_INBOUND,
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
		Network:   gcp.GetVpcUri(gcpProjectId, "other"),
		ProjectId: gcpProjectId,
	}
	gcpConnectivityTest2AzureVmEndpoint := &networkmanagementpb.Endpoint{
		IpAddress:   azureVm2IpAddress,
		NetworkType: networkmanagementpb.Endpoint_NON_GCP_NETWORK,
	}
	gcp.RunPingConnectivityTest(t, gcpProjectId, "gcp-azure-2", gcpConnectivityTest2GcpVmEndpoint, gcpConnectivityTest2AzureVmEndpoint)

	// Run Azure connectivity check (ping from Azure VM to GCP VM)
	azureConnectivityCheck2, err := azure_plugin.RunPingConnectivityCheck(azureVm2ResourceId, gcpVmIpAddress)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheck2)
}
