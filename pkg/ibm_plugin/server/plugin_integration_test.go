//go:build ibm

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

package ibm

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/google/uuid"
	"github.com/paraglider-project/paraglider/pkg/azure"
	ibmCommon "github.com/paraglider-project/paraglider/pkg/ibm_plugin"
	sdk "github.com/paraglider-project/paraglider/pkg/ibm_plugin/sdk"
	"github.com/paraglider-project/paraglider/pkg/kvstore"
	"github.com/paraglider-project/paraglider/pkg/orchestrator"
	"github.com/paraglider-project/paraglider/pkg/orchestrator/config"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	tagging "github.com/paraglider-project/paraglider/pkg/tag_service"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testDeployment, resourceGroupID string

// NOTE: if user doesn't have resource group privileges set DoesHaveResourceGroupPrivileges to false
const DoesHaveResourceGroupPrivileges = false

// NOTE: if user doesn't have resource group privileges set azureResourceGroupName to match an existing resource group
var azureResourceGroupName string = "challenge-1377"

func TestMain(m *testing.M) {
	flag.Parse()
	resourceGroupID = ibmCommon.GetIBMResourceGroupID()
	testResourceIDUSEast1 = "/resourcegroup/" + resourceGroupID + "/zone/" + testZoneUSEast1 + "/instance/"
	testResourceIDUSEast2 = "/resourcegroup/" + resourceGroupID + "/zone/" + testZoneUSEast2 + "/instance/"
	testResourceIDUSEast3 = "/resourcegroup/" + resourceGroupID + "/zone/" + testZoneUSEast3 + "/instance/"
	testResourceIDEUDE1 = "/resourcegroup/" + resourceGroupID + "/zone/" + testZoneEUDE1 + "/instance/"
	testResourceIDUSSouth1 = "/resourcegroup/" + resourceGroupID + "/zone/" + testZoneUSSouth1 + "/instance/"
	testDeployment = "/resourcegroup/" + resourceGroupID
	exitCode := m.Run()
	os.Exit(exitCode)
}

// TODO(cohen-j-omer) will add verification for number of rules
// usage: go test --tags=ibm -run TestAddPermitRulesIntegration -timeout 0
// -timeout 0 removes limit of 10 min. runtime, which is necessary due to long deployment time of Azure's VPN.
func TestAddPermitRulesIntegration(t *testing.T) {
	dbPort := 6379
	IBMServerPort := 7992
	kvstorePort := 7993
	taggingPort := 7994
	IBMResourceIDPrefix := testResourceIDUSEast1
	image, zone, instanceName := testImageUSEast, testZoneUSEast1, testInstanceNameUSEast1

	// removes all of paraglide's deployments on IBM
	region, err := ibmCommon.ZoneToRegion(zone)
	require.NoError(t, err)

	defer func() {
		err := sdk.TerminateParagilderDeployments(resourceGroupID, region)
		require.NoError(t, err)
	}()

	orchestratorServerConfig := config.Config{
		Server: config.Server{
			Host:    "localhost",
			Port:    "8080",
			RpcPort: "8081",
		},
		TagService: config.TagService{
			Host: "localhost",
			Port: strconv.Itoa(taggingPort),
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
		},
		Namespaces: map[string][]config.CloudDeployment{
			testNamespace: {
				{
					Name:       utils.IBM,
					Deployment: testDeployment,
				},
			},
		},
	}

	// start controller server
	fmt.Println("Setting up controller server and kvstore server")
	orchestratorServerAddr := orchestratorServerConfig.Server.Host + ":" + orchestratorServerConfig.Server.RpcPort
	orchestrator.Setup(orchestratorServerConfig, true)

	// start ibm plugin server
	fmt.Println("Setting up IBM server")
	ibmServer := Setup(IBMServerPort, orchestratorServerAddr)

	fmt.Println("Setting up kv store server")
	tagging.Setup(dbPort, taggingPort, true)

	fmt.Println("Setting up kv tagging server")
	kvstore.Setup(dbPort, kvstorePort, true)

	// Create IBM VM
	fmt.Println("\nCreating IBM VM...")
	imageIdentity := vpcv1.ImageIdentityByID{ID: &image}
	zoneIdentity := vpcv1.ZoneIdentityByName{Name: &zone}
	myTestProfile := string(testProfile)

	testPrototype := &vpcv1.InstancePrototypeInstanceByImage{
		Image:   &imageIdentity,
		Zone:    &zoneIdentity,
		Name:    core.StringPtr(instanceName),
		Profile: &vpcv1.InstanceProfileIdentityByName{Name: &myTestProfile},
	}

	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(testPrototype)})
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{Name: instanceName, Deployment: &paragliderpb.ParagliderDeployment{Id: testDeployment, Namespace: testNamespace}, Description: description}
	res, err := ibmServer.CreateResource(context.Background(), resource)
	require.NoError(t, err)
	require.NotNil(t, res)
	// append instance's ID
	URIParts := strings.Split(res.Uri, "/")
	resID := IBMResourceIDPrefix + URIParts[len(URIParts)-1]

	// Add permit list for IBM VM
	fmt.Println("Adding IBM permit list rules...")

	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: testNamespace,
		Resource:  resID,
		Rules:     pingTestPermitList,
	}

	resp, err := ibmServer.AddPermitListRules(context.Background(), addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)

	utils.Log.Printf("Test response: %+v", resp)
}

// TODO(cohen-j-omer) will add IBM connectivity check method
// usage: go test --tags=ibm -run TestMulticloudIBMAzure -timeout 0
// -timeout 0 removes limit of 10 minutes runtime, which is necessary due to long deployment time of Azure's VPN.
func TestMulticloudIBMAzure(t *testing.T) {
	dbPort := 6379
	kvstorePort := 7993
	taggingPort := 7994
	// ibm config
	IBMServerPort := 7992
	IBMResourceIDPrefix := testResourceIDUSEast1
	image, zone, instanceName := testImageUSEast, testZoneUSEast1, testInstanceNameUSEast1
	// azure config
	azureServerPort := 7991
	azureSubscriptionId := azure.GetAzureSubscriptionId()

	// removes all of paraglide's deployments on IBM
	region, err := ibmCommon.ZoneToRegion(zone)
	require.NoError(t, err)
	defer func() {
		err := sdk.TerminateParagilderDeployments(resourceGroupID, region)
		require.NoError(t, err)
	}()

	// requires resource group creation/deletion privileges
	if DoesHaveResourceGroupPrivileges {
		azureResourceGroupName := azure.SetupAzureTesting(azureSubscriptionId, "ibmazure")
		defer azure.TeardownAzureTesting(azureSubscriptionId, azureResourceGroupName)
	}

	azureNamespace := "test" + uuid.NewString()[:4]
	azureDeploymentId := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", azureSubscriptionId, azureResourceGroupName)
	azureVmName := "pg-vm-test-" + uuid.NewString()[:4]
	// temporary print due to possible issue with Azure's log visibility
	fmt.Printf("\nAzure's testing namespace: %v.\nAzure's testing azureVmName: %v\n", azureNamespace, azureVmName)

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
			testNamespace: {
				{
					Name:       utils.IBM,
					Deployment: testDeployment,
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
	ibmServer := Setup(IBMServerPort, orchestratorServerAddr)

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
	imageIdentity := vpcv1.ImageIdentityByID{ID: &image}
	zoneIdentity := vpcv1.ZoneIdentityByName{Name: &zone}
	myTestProfile := string(testProfile)

	testPrototype := &vpcv1.InstancePrototypeInstanceByImage{
		Image:   &imageIdentity,
		Zone:    &zoneIdentity,
		Name:    core.StringPtr(instanceName),
		Profile: &vpcv1.InstanceProfileIdentityByName{Name: &myTestProfile},
	}

	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(testPrototype)})
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{Name: instanceName, Deployment: &paragliderpb.ParagliderDeployment{Id: testDeployment, Namespace: testNamespace}, Description: description}
	createResourceResponse, err := ibmServer.CreateResource(ctx, resource)
	require.NoError(t, err)
	require.NotNil(t, createResourceResponse)
	URIParts := strings.Split(createResourceResponse.Uri, "/")
	IBMResourceID := IBMResourceIDPrefix + URIParts[len(URIParts)-1]

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
		Namespace: testNamespace,
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

	// TODO Remove condition check once PR#290 is merged (https://github.com/paraglider-project/paraglider/pull/290)
	// Run Azure connectivity check (ping from Azure VM to IBM VM)
	// requires resource group creation due to Azure Network Watcher being deployed on a separate resource group
	if DoesHaveResourceGroupPrivileges {
		fmt.Println("running Azure connectivity test...")
		azureConnectivityCheck1, err := azure.RunPingConnectivityCheck(azureVmResourceId, ibmVmIpAddress)
		require.Nil(t, err)
		require.True(t, azureConnectivityCheck1)
	}
}
