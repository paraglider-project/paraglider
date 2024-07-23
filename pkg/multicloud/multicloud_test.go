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
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/google/uuid"
	azure "github.com/paraglider-project/paraglider/pkg/azure"
	gcp "github.com/paraglider-project/paraglider/pkg/gcp"
	ibm "github.com/paraglider-project/paraglider/pkg/ibm"
	"github.com/paraglider-project/paraglider/pkg/kvstore"
	orchestrator "github.com/paraglider-project/paraglider/pkg/orchestrator"
	config "github.com/paraglider-project/paraglider/pkg/orchestrator/config"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	tagging "github.com/paraglider-project/paraglider/pkg/tag_service"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NOTE: set isAzureNetworkWatcherDeployed to false if AzureNetworkWatcher isn't deployed on the test's region.
// required to test connectivity initiated from Azure's VM to a remote VM launched during testing.
const isAzureNetworkWatcherDeployed = true

// TODO @seankimkdy: should this be turned into a system test where we actually call the cloud plugins through the orchestrator GRPC?
func TestMulticloud(t *testing.T) {
	// Azure config
	azurePluginPort := 7991
	azureSubscriptionId := azure.GetAzureSubscriptionId()
	azureResourceGroupName := azure.SetupAzureTesting(azureSubscriptionId, "multicloud")
	azureDeploymentId := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", azureSubscriptionId, azureResourceGroupName)
	defer azure.TeardownAzureTesting(azureSubscriptionId, azureResourceGroupName, "default")

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
	gcpIcmpTestResult1, err := gcp.RunIcmpConnectivityTest("gcp-azure-1", "other", gcpProjectId, gcpVmName, gcpVmZone, azureVm1IpAddress, 5)
	require.NoError(t, err)
	require.True(t, gcpIcmpTestResult1)

	// Run Azure connectivity check (ping from Azure VM to GCP VM)
	azureConnectivityCheck1, err := azure.RunPingConnectivityCheck(azureVm1ResourceId, gcpVmIpAddress, "default")
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
	gcpIcmpTestResult2, err := gcp.RunIcmpConnectivityTest("gcp-azure-2", "other", gcpProjectId, gcpVmName, gcpVmZone, azureVm2IpAddress, 5)
	require.NoError(t, err)
	require.True(t, gcpIcmpTestResult2)

	// Run Azure connectivity check (ping from Azure VM to GCP VM)
	azureConnectivityCheck2, err := azure.RunPingConnectivityCheck(azureVm2ResourceId, gcpVmIpAddress, "default")
	require.Nil(t, err)
	require.True(t, azureConnectivityCheck2)
}

// usage: go test --tags=multicloud -run TestMulticloudIBMAzure -timeout 0
// -timeout 0 removes limit of 10 minutes runtime, which is necessary due to long deployment time of Azure's VPN.
// Note: if user doesn't have resource group privileges, set env PARAGLIDER_AZURE_RESOURCE_GROUP with an existing resource group
func TestMulticloudIBMAzure(t *testing.T) {
	// TODO remove condition after an IBM account is integrated to a git workflow.
	// skip test if it runs on a git-action.
	if os.Getenv("GH_RUN_NUMBER") != "" {
		t.Skip("test temporarily disabled from git-actions until an IBM account is integrated to a git workflow")
	}
	dbPort := 6379
	kvstorePort := 7993
	taggingPort := 7994
	// ibm config
	IBMServerPort := 7992
	resourceGroupID := ibm.GetIBMResourceGroupID()
	ibmResourceIDPrefix := "/resourcegroup/" + resourceGroupID + "/zone/us-east-1" + "/instance/"
	image, zone, instanceName := "r014-0acbdcb5-a68f-4a52-98ea-4da4fe89bacb", "us-east-1", "pg-vm-east-1" // IBM VM vars
	ibmNamespace := "pg-multicloud-ibm"
	ibmDeploymentId := "/resourcegroup/" + resourceGroupID
	vmProfile := "bx2-2x8"
	// azure config
	azureServerPort := 7991
	azureSubscriptionId := azure.GetAzureSubscriptionId()
	azureResourceGroupName := azure.SetupAzureTesting(azureSubscriptionId, "ibmazure")
	azureNamespace := "multicloud"
	defer azure.TeardownAzureTesting(azureSubscriptionId, azureResourceGroupName, azureNamespace)

	region, err := ibm.ZoneToRegion(zone)
	require.NoError(t, err)
	// removes all of paraglider's deployments on IBM when test ends (if INVISINETS_TEST_PERSIST=1)
	defer func() {
		err := ibm.TerminateParagliderDeployments(region)
		require.NoError(t, err)
	}()

	azureDeploymentId := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", azureSubscriptionId, azureResourceGroupName)
	azureVmName := "pg-vm-test-" + uuid.NewString()[:4]
	// temporary print due to possible issue with Azure's log visibility
	fmt.Printf("\nAzure's testing namespace: %v.\nAzure's testing VM: %v\n", azureNamespace, azureVmName)

	orchestratorServerConfig := config.Config{
		Server: config.Server{
			Host:    "localhost",
			Port:    "8080",
			RpcPort: "8081",
		},
		TagService: config.TagService{
			Port: strconv.Itoa(taggingPort),
			Host: "localhost",
		},
		KVStore: config.TagService{
			Port: strconv.Itoa(kvstorePort),
			Host: "localhost",
		},
		CloudPlugins: []config.CloudPlugin{
			{
				Name: utils.IBM,
				Host: "localhost",
				Port: strconv.Itoa(IBMServerPort),
			},

			{
				Name: utils.AZURE,
				Host: "localhost",
				Port: strconv.Itoa(azureServerPort),
			},
		},
		Namespaces: map[string][]config.CloudDeployment{
			ibmNamespace: {
				{
					Name:       utils.IBM,
					Deployment: ibmDeploymentId,
				},
			},
			azureNamespace: {
				{
					Name:       utils.AZURE,
					Deployment: azureDeploymentId,
				},
			},
		},
	}

	// start controller server
	fmt.Println("Setting up controller server")
	orchestratorServerAddr := orchestratorServerConfig.Server.Host + ":" + orchestratorServerConfig.Server.RpcPort
	orchestrator.Setup(orchestratorServerConfig, true)

	// start ibm plugin server
	fmt.Println("Setting up IBM server")
	ibmServer := ibm.Setup(IBMServerPort, orchestratorServerAddr)

	// start azure plugin server
	fmt.Println("Setting up Azure server")
	azureServer := azure.Setup(azureServerPort, orchestratorServerAddr)

	// start kv store server
	fmt.Println("Setting up kv store server")
	tagging.Setup(dbPort, taggingPort, true)

	// start tagging server
	fmt.Println("Setting up kv tagging server")
	kvstore.Setup(dbPort, kvstorePort, true)

	ctx := context.Background()

	// Create Azure VM
	fmt.Println("\nCreating Azure VM...")
	azureVm1Location := "westus"
	azureVm1Parameters := azure.GetTestVmParameters(azureVm1Location)
	azureVm1Description, err := json.Marshal(azureVm1Parameters)
	require.NoError(t, err)
	azureVmResourceId := "/subscriptions/" + azureSubscriptionId + "/resourceGroups/" + azureResourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + azureVmName
	azureCreateResourceResp1, err := azureServer.CreateResource(
		ctx,
		&paragliderpb.CreateResourceRequest{
			Deployment:  &paragliderpb.ParagliderDeployment{Id: azureDeploymentId, Namespace: azureNamespace},
			Name:        azureVmName,
			Description: azureVm1Description,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, azureCreateResourceResp1)
	assert.Equal(t, azureCreateResourceResp1.Uri, azureVmResourceId)

	// Create IBM VM
	fmt.Println("Creating IBM VM...")
	ibmVMPrototype := &vpcv1.InstancePrototypeInstanceByImage{
		Image:   &vpcv1.ImageIdentityByID{ID: &image},
		Zone:    &vpcv1.ZoneIdentityByName{Name: &zone},
		Name:    core.StringPtr(instanceName),
		Profile: &vpcv1.InstanceProfileIdentityByName{Name: core.StringPtr(vmProfile)},
	}

	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(ibmVMPrototype)})
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{Name: instanceName, Deployment: &paragliderpb.ParagliderDeployment{Id: ibmDeploymentId, Namespace: ibmNamespace}, Description: description}
	createResourceResponse, err := ibmServer.CreateResource(ctx, resource)
	require.NoError(t, err)
	require.NotNil(t, createResourceResponse)
	URIParts := strings.Split(createResourceResponse.Uri, "/")
	IBMResourceID := ibmResourceIDPrefix + URIParts[len(URIParts)-1]

	// Add permit list for IBM VM
	fmt.Println("Adding IBM permit list rules...")
	azureVmIpAddress, err := azure.GetVmIpAddress(azureVmResourceId)
	require.NoError(t, err)

	ibmPermitList := []*paragliderpb.PermitListRule{
		// inbound ICMP protocol rule to accept & respond to pings
		{
			Name:      "inboundICMPAzure",
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{azureVmIpAddress},
		},
		// outbound ICMP protocol rule to initiate pings
		{
			Name:      "outboundICMPAzure",
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{azureVmIpAddress},
		},
		// allow inbound ssh connection
		{
			Name:      "inboundSSH",
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   22,
			DstPort:   22,
			Protocol:  6,
			Targets:   []string{"0.0.0.0/0"},
		},
	}

	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: ibmNamespace,
		Resource:  IBMResourceID,
		Rules:     ibmPermitList,
	}

	respAddRules, err := ibmServer.AddPermitListRules(ctx, addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, respAddRules)

	// Create Azure VM permit list
	ibmVmIpAddress := createResourceResponse.Ip
	fmt.Println("Adding Azure permit list rules...")
	azureVm1PermitListReq := &paragliderpb.AddPermitListRulesRequest{
		Resource: azureVmResourceId,
		Rules: []*paragliderpb.PermitListRule{
			// allow all inbound traffic from ibmVmIpAddress
			{
				Name:      "ibm-inbound-rule",
				Direction: paragliderpb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{ibmVmIpAddress},
			},
			// allow all outbound traffic to ibmVmIpAddress
			{
				Name:      "ibm-outbound-rule",
				Direction: paragliderpb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{ibmVmIpAddress},
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
		Namespace: azureNamespace,
	}
	azureAddPermitListRules1Resp, err := azureServer.AddPermitListRules(ctx, azureVm1PermitListReq)
	require.NoError(t, err)
	require.NotNil(t, azureAddPermitListRules1Resp)

	// Run Azure connectivity check (ping from Azure VM to IBM VM)
	// requires Azure Network Watcher to be deployed in the test's region.
	if isAzureNetworkWatcherDeployed {
		fmt.Println("running Azure connectivity test...")
		azureConnectivityCheck1, err := azure.RunPingConnectivityCheck(azureVmResourceId, ibmVmIpAddress, azureNamespace)
		require.Nil(t, err)
		require.True(t, azureConnectivityCheck1)
	}

	fmt.Println("Running cleanup functions...")
}
