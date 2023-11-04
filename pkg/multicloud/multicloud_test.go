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
	frontend "github.com/NetSys/invisinets/pkg/frontend"
	gcp "github.com/NetSys/invisinets/pkg/gcp"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
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
	controllerServerConfig := frontend.Config{
		Clouds: []frontend.Cloud{
			{
				Name:          utils.AZURE,
				Host:          "localhost",
				Port:          strconv.Itoa(azurePluginPort),
				InvDeployment: fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", azureSubscriptionId, azureResourceGroupName),
			},
			{
				Name:          utils.GCP,
				Host:          "localhost",
				Port:          strconv.Itoa(gcpPluginPort),
				InvDeployment: fmt.Sprintf("projects/%s", gcpProjectId),
			},
		},
	}
	controllerServerAddr := frontend.SetupControllerServer(controllerServerConfig)
	fmt.Println("Setup controller server")

	// Setup Azure
	azureServer := azure_plugin.Setup(azurePluginPort, controllerServerAddr)
	fmt.Println("Setup Azure server")

	// Setup GCP
	gcpServer := gcp.Setup(gcpPluginPort, controllerServerAddr)
	fmt.Println("Setup GCP server")

	ctx := context.Background()

	// Create Azure VM
	azureVmLocation := "westus"
	azureVmParameters := azure_plugin.GetTestVmParameters(azureVmLocation)
	azureVmDescription, err := json.Marshal(azureVmParameters)
	azureVmResourceId := "/subscriptions/" + azureSubscriptionId + "/resourceGroups/" + azureResourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + "invisinets-vm-test"
	azureCreateResourceResp, err := azureServer.CreateResource(
		ctx,
		&invisinetspb.ResourceDescription{Id: azureVmResourceId, Description: azureVmDescription, Namespace: "default"},
	)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotNil(t, azureCreateResourceResp)
	assert.Equal(t, azureCreateResourceResp.Uri, azureVmResourceId)
	fmt.Println("Created Azure VM")
	// Create GCP VM
	gcpVmZone := "us-west1-a"
	gcpVmName := utils.GetGitHubRunPrefix() + "vm-invisinets-test"
	gcpVmParameters := gcp.GetTestVmParameters(gcpProjectId, gcpVmZone, gcpVmName)
	gcpVmDescription, err := json.Marshal(gcpVmParameters)
	gcpCreateResourceResp, err := gcpServer.CreateResource(
		ctx,
		&invisinetspb.ResourceDescription{Description: gcpVmDescription, Namespace: "default"},
	)
	require.NoError(t, err)
	require.NotNil(t, gcpCreateResourceResp)
	assert.Equal(t, gcpCreateResourceResp.Name, gcpVmName)
	fmt.Println("Created GCP VM")

	// Create GCP permit list
	azureVmIpAddress, err := azure_plugin.GetVmIpAddress(azureVmResourceId)
	require.NoError(t, err)
	gcpVmPermitList := &invisinetspb.PermitList{
		AssociatedResource: fmt.Sprintf("projects/%s/zones/%s/instances/%s", gcpProjectId, gcpVmZone, gcpVmName),
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{azureVmIpAddress},
			},
			{
				Direction: invisinetspb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{azureVmIpAddress},
			},
			{ // SSH rule for debugging
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   22,
				Protocol:  6,
				Targets:   []string{"0.0.0.0/0"},
			},
		},
		Namespace: "default",
	}
	gcpAddPermitListRulesResp, err := gcpServer.AddPermitListRules(ctx, gcpVmPermitList)
	require.NoError(t, err)
	require.NotNil(t, gcpAddPermitListRulesResp)
	assert.True(t, gcpAddPermitListRulesResp.Success)
	fmt.Println("Added GCP permit list rules")

	// Create Azure permit list
	gcpVmIpAddress, err := gcp.GetInstanceIpAddress(gcpProjectId, gcpVmZone, gcpVmName)
	require.NoError(t, err)
	azureVmPermitList := &invisinetspb.PermitList{
		AssociatedResource: azureVmResourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{gcpVmIpAddress},
			},
			{
				Direction: invisinetspb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{gcpVmIpAddress},
			},
			{ // SSH rule for debugging
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   22,
				Protocol:  6,
				Targets:   []string{"0.0.0.0/0"},
			},
		},
		Namespace: "default",
	}
	azureAddPermitListRulesResp, err := azureServer.AddPermitListRules(ctx, azureVmPermitList)
	require.NoError(t, err)
	require.NotNil(t, azureAddPermitListRulesResp)
	assert.True(t, azureAddPermitListRulesResp.Success)
	fmt.Println("Added Azure permit list rules")

	// Run GCP connectivity tests (ping from GCP VM to Azure VM)
	gcpConnectivityTestGcpVmEndpoint := &networkmanagementpb.Endpoint{
		IpAddress: gcpVmIpAddress,
		Network:   "projects/" + gcpProjectId + "/" + gcp.GetVpcUri("default"),
		ProjectId: gcpProjectId,
	}
	gcpConnectivityTestAzureVmEndpoint := &networkmanagementpb.Endpoint{
		IpAddress:   azureVmIpAddress,
		NetworkType: networkmanagementpb.Endpoint_NON_GCP_NETWORK,
	}
	gcp.RunPingConnectivityTest(t, gcpProjectId, "gcp-azure", gcpConnectivityTestGcpVmEndpoint, gcpConnectivityTestAzureVmEndpoint)

	// Run Azure connectivity check (ping from Azure VM to GCP VM)
	azureConnectivityCheck, err := azure_plugin.RunPingConnectivityCheck(azureVmResourceId, gcpVmIpAddress)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheck)
}
