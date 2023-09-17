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
	"net"
	"os"
	"strings"
	"testing"

	"cloud.google.com/go/compute/apiv1/computepb"
	azure_plugin "github.com/NetSys/invisinets/pkg/azure_plugin"
	frontend "github.com/NetSys/invisinets/pkg/frontend"
	gcp "github.com/NetSys/invisinets/pkg/gcp"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// TODO @seankimkdy: will substitue with cloud specific ones after #66 is merged
func initializeCloudServer(srv invisinetspb.CloudPluginServer) string {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen: %v", err)
	}
	gsrv := grpc.NewServer()
	invisinetspb.RegisterCloudPluginServer(gsrv, srv)
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err)
		}
	}()

	return l.Addr().String()
}

// TODO @seankimkdy: should this be turned into a system test where we actually
func TestMulticloud(t *testing.T) {
	// Setup Azure
	azureSubscriptionId := azure_plugin.GetAzureSubscriptionId()
	azureResourceGroupName := utils.GetGitHubRunPrefix() + "invisinets-multicloud-test"
	azure_plugin.SetupAzureTesting(azureSubscriptionId, azureResourceGroupName)
	defer azure_plugin.TeardownAzureTesting(azureSubscriptionId, azureResourceGroupName)
	azureServer := azure_plugin.InitializeServer()
	azureServerAddr := initializeCloudServer(azureServer)
	fmt.Println("Setup Azure server")

	// Setup GCP
	gcpProject := gcp.GetGcpProject()
	gcpTeardownInfo := &gcp.GcpTestTeardownInfo{
		Project:            gcpProject,
		InsertInstanceReqs: make([]*computepb.InsertInstanceRequest, 0),
	}
	defer gcp.TeardownGcpTesting(gcpTeardownInfo)
	gcpServer := &gcp.GCPPluginServer{}
	gcpServerAddr := initializeCloudServer(gcpServer)
	fmt.Println("Setup GCP server")

	// Setup controller server
	controllerServerConfig := frontend.Config{
		Clouds: []frontend.Cloud{
			{
				Name:          utils.AZURE,
				Host:          strings.Split(azureServerAddr, ":")[0],
				Port:          strings.Split(azureServerAddr, ":")[1],
				InvDeployment: fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", azureSubscriptionId, azureResourceGroupName),
			},
			{
				Name:          utils.GCP,
				Host:          strings.Split(gcpServerAddr, ":")[0],
				Port:          strings.Split(gcpServerAddr, ":")[1],
				InvDeployment: fmt.Sprintf("projects/%s", gcpProject),
			},
		},
	}
	controllerServerAddr := frontend.SetupControllerServer(controllerServerConfig)
	azure_plugin.FrontendServerAddr = controllerServerAddr
	gcp.FrontendServerAddr = controllerServerAddr
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
	gcpVmParameters := gcp.GetTestVmParameters(gcpProject, gcpVmName, gcpVmZone)
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

	// Create Azure VPN gateway
	azureCreateVpnGatewayResp, err := azureServer.CreateVpnGateway(ctx, azureSubscriptionId, azureResourceGroupName, utils.GCP)
	require.NoError(t, err)
	fmt.Println("Created Azure VPN gateway")
	// Create GCP VPN gateway
	gcpCreateVpnGatewayResp, err := gcpServer.CreateVpnGateway(ctx, utils.AZURE)
	require.NoError(t, err)
	fmt.Println("Created GCP VPN gateway")

	// Create Azure VPN BGP
	azureBgpIps, err := azureServer.CreateVpnBgp(ctx, azureSubscriptionId, azureResourceGroupName, utils.GCP)
	require.NoError(t, err)
	// Create GCP VPN BGP
	gcpBgpIps, err := gcpServer.CreateVpnBgp(ctx, utils.AZURE)
	require.NoError(t, err)

	sharedKey := "u92lKc2lSJtaO82dj1v557S7iIuZ7NlN" // TODO @seankimkdy: dynamically generate
	// Create Azure VPN connections
	_, err = azureServer.CreateVpnConnections(
		ctx,
		azureSubscriptionId,
		azureResourceGroupName,
		utils.GCP,
		gcpCreateVpnGatewayResp.Asn,
		"10.1.0.0/16", // Would be passed from other cloud plugin -> frontend
		gcpCreateVpnGatewayResp.InterfaceIps,
		gcpBgpIps,
		sharedKey,
	)
	require.NoError(t, err)
	fmt.Println("Created Azure VPN connections")
	// Create GCP VPN connecitons
	_, err = gcpServer.CreateVpnConnections(
		ctx,
		utils.AZURE,
		azureCreateVpnGatewayResp.Asn,
		"10.0.0.0/16", // Would be passed from other cloud plugin -> frontend
		azureCreateVpnGatewayResp.InterfaceIps,
		azureBgpIps,
		sharedKey,
	)
	require.NoError(t, err)
	fmt.Println("Created GCP VPN connections")
}
