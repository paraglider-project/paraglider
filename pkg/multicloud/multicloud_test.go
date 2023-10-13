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
	"strings"
	"testing"

	"cloud.google.com/go/compute/apiv1/computepb"
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
	azurePluginPort := 1000
	gcpPluginPort := 1001

	// Setup Azure
	azureSubscriptionId := azure_plugin.GetAzureSubscriptionId()
	azureResourceGroupName := utils.GetGitHubRunPrefix() + "invisinets-multicloud-test"
	azure_plugin.SetupAzureTesting(azureSubscriptionId, azureResourceGroupName)
	defer azure_plugin.TeardownAzureTesting(azureSubscriptionId, azureResourceGroupName)
	go azure_plugin.Setup(azurePluginPort, controllerServerAddr)
	fmt.Println("Setup Azure server")

	// Setup GCP
	gcpProject := gcp.GetGcpProject()
	gcpTeardownInfo := &gcp.GcpTestTeardownInfo{
		Project:            gcpProject,
		InsertInstanceReqs: make([]*computepb.InsertInstanceRequest, 0),
	}
	defer gcp.TeardownGcpTesting(gcpTeardownInfo)
	go gcp.Setup(gcpPluginPort, controllerServerAddr)
	fmt.Println("Setup GCP server")

	// Setup controller server
	controllerServerConfig := frontend.Config{
		Clouds: []frontend.Cloud{
			{
				Name:          utils.AZURE,
				Host:          "localhost",
				Port:          azurePluginPort
				InvDeployment: fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", azureSubscriptionId, azureResourceGroupName),
			},
			{
				Name:          utils.GCP,
				Host:          "localhost",
				Port:          gcpPluginPort,
				InvDeployment: fmt.Sprintf("projects/%s", gcpProject),
			},
		},
	}
	controllerServerAddr := frontend.SetupControllerServer(controllerServerConfig)
	fmt.Println("Setup controller server")

	ctx := context.Background()

	// Create Azure VM
	azureVmLocation := "westus"
	azureVmParameters := azure_plugin.GetTestVmParameters(azureVmLocation)
	azureVmDescription, err := json.Marshal(azureVmParameters)
	azureVmId := "/subscriptions/" + azureSubscriptionId + "/resourceGroups/" + azureResourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + "invisinets-vm-test"
	azureCreateResourceResp, err := azureServer.CreateResource(
		ctx,
		&invisinetspb.ResourceDescription{Id: azureVmId, Description: azureVmDescription},
	)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotNil(t, azureCreateResourceResp)
	assert.True(t, azureCreateResourceResp.Success)
	assert.Equal(t, azureCreateResourceResp.UpdatedResource.Id, azureVmId)
	fmt.Println("Created Azure VM")
	// Create GCP VM
	gcpVmZone := "us-west1-a"
	gcpVmName := utils.GetGitHubRunPrefix() + "vm-invisinets-test"
	gcpVmParameters := gcp.GetTestVmParameters(gcpProject, gcpVmZone, gcpVmName)
	gcpTeardownInfo.InsertInstanceReqs = append(gcpTeardownInfo.InsertInstanceReqs, gcpVmParameters)
	gcpVmDescription, err := json.Marshal(gcpVmParameters)
	gcpCreateResourceResp, err := gcpServer.CreateResource(
		ctx,
		&invisinetspb.ResourceDescription{Description: gcpVmDescription},
	)
	require.NoError(t, err)
	require.NotNil(t, gcpCreateResourceResp)
	assert.True(t, gcpCreateResourceResp.Success)
	fmt.Println("Created GCP VM")

	// Create GCP permit list
	azureVmIpAddress, err := azure_plugin.GetVmIpAddress(azureVmId)
	require.NoError(t, err)
	gcpVmPermitList := &invisinetspb.PermitList{
		AssociatedResource: fmt.Sprintf("projects/%s/zones/%s/instances/%s", gcpProject, gcpVmZone, gcpVmName),
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
	gcpVmIpAddress, err := gcp.GetInstanceIpAddress(gcpProject, gcpVmZone, gcpVmName)
	require.NoError(t, err)
	azureVmPermitList := &invisinetspb.PermitList{
		AssociatedResource: azureVmId,
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
	gcpVmEndpoint := &networkmanagementpb.Endpoint{
		IpAddress: gcpVmIpAddress,
		Network:   "projects/" + gcpProject + "/" + gcp.GetVpcUri(),
		ProjectId: gcpProject,
	}
	azureVmEndpoint := &networkmanagementpb.Endpoint{
		IpAddress:   azureVmIpAddress,
		NetworkType: networkmanagementpb.Endpoint_NON_GCP_NETWORK,
	}
	gcp.RunPingConnectivityTest(t, gcpTeardownInfo, gcpProject, "gcp-azure", gcpVmEndpoint, azureVmEndpoint)

	// TODO @seankimkdy: add Azure network watcher test
}
