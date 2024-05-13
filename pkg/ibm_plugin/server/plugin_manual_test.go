//go:build ibm

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

package ibm

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"

	"github.com/NetSys/invisinets/pkg/azure_plugin"
	fake "github.com/NetSys/invisinets/pkg/fake/controller/rpc"
	ibmCommon "github.com/NetSys/invisinets/pkg/ibm_plugin"
	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/orchestrator"
	"github.com/NetSys/invisinets/pkg/orchestrator/config"
	utils "github.com/NetSys/invisinets/pkg/utils"
)

var testResGroupName = flag.String("sg", "pywren", "Name of the user's security group")
var testResourceIDUSEast1 string
var testResourceIDUSEast2 string
var testResourceIDUSEast3 string
var testResourceIDEUDE1 string
var testResourceIDUSSouth1 string

func TestMain(m *testing.M) {
	flag.Parse()
	testResourceIDUSEast1 = "/ResourceGroupName/" + *testResGroupName + "/Zone/" + testZoneUSEast1 + "/ResourceID/" + testInstanceNameUSEast1
	testResourceIDUSEast2 = "/ResourceGroupName/" + *testResGroupName + "/Zone/" + testZoneUSEast2 + "/ResourceID/" + testInstanceNameUSEast2
	testResourceIDUSEast3 = "/ResourceGroupName/" + *testResGroupName + "/Zone/" + testZoneUSEast3 + "/ResourceID/" + testInstanceNameUSEast3
	testResourceIDEUDE1 = "/ResourceGroupName/" + *testResGroupName + "/Zone/" + testZoneEUDE1 + "/ResourceID/" + testInstanceNameEUDE1
	testResourceIDUSSouth1 = "/ResourceGroupName/" + *testResGroupName + "/Zone/" + testZoneUSSouth1 + "/ResourceID/" + testInstanceNameUSSouth1
	exitCode := m.Run()
	os.Exit(exitCode)
}

const (
	testUSEastRegion         = "us-east"
	testUSSouthRegion        = "us-south"
	testEURegion             = "eu-de"
	testZoneUSEast1          = testUSEastRegion + "-1"
	testZoneUSEast2          = testUSEastRegion + "-2"
	testZoneUSEast3          = testUSEastRegion + "-3"
	testZoneUSSouth1         = testUSSouthRegion + "-1"
	testZoneEUDE1            = testEURegion + "-1"
	testInstanceNameUSEast1  = "invisinets-vm-east-1"
	testInstanceNameUSEast2  = "invisinets-vm-east-2"
	testInstanceNameUSEast3  = "invisinets-vm-east-3"
	testInstanceNameUSSouth1 = "invisinets-vm-south-1"
	testInstanceNameEUDE1    = "invisinets-vm-de-1"

	testImageUSEast  = "r014-0acbdcb5-a68f-4a52-98ea-4da4fe89bacb" // us-east Ubuntu 22.04
	testImageEUDE    = "r010-f68ef7b3-1c5e-4ef7-8040-7ae0f5bf04fd" // eu-de Ubuntu 22.04
	testImageUSSouth = "r006-01deb923-46f6-44c3-8fdc-99d8493d2464" // us-south Ubuntu 22.04
	testProfile      = "bx2-2x8"
	testNamespace    = "inv-namespace"
)

// permit list example
var testPermitList []*invisinetspb.PermitListRule = []*invisinetspb.PermitListRule{
	//TCP protocol rules
	{
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   443,
		DstPort:   443,
		Protocol:  6,
		Targets:   []string{"10.0.0.0/18"},
	},
	{
		Direction: invisinetspb.Direction_OUTBOUND,
		SrcPort:   8080,
		DstPort:   8080,
		Protocol:  6,
		Targets:   []string{"10.0.128.12", "10.0.128.13"},
	},
	//All protocol rules
	{
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  -1,
		Targets:   []string{"10.0.64.0/22", "10.0.64.0/24"},
	},
	{
		Direction: invisinetspb.Direction_OUTBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  -1,
		Targets:   []string{"10.0.64.1"},
	},
}

// permit list to test connectivity via pings. Made to test Transit and VPN gateways configurations
var pingTestPermitList []*invisinetspb.PermitListRule = []*invisinetspb.PermitListRule{ //nolint:all keeping unused variable for future testing
	//ICMP protocol rule to accept pings
	{
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  1,
		Targets:   []string{"0.0.0.0/0"},
	},
	// ssh to accept ssh connection
	{
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   22,
		DstPort:   22,
		Protocol:  6,
		Targets:   []string{"0.0.0.0/0"},
	},
	//All protocol to allow all egress traffic
	{
		Direction: invisinetspb.Direction_OUTBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  -1,
		Targets:   []string{"0.0.0.0/0"},
	},
}

// go test --tags=ibm -run TestCreateNewResource -sg=<security group name>
func TestCreateNewResource(t *testing.T) {
	// Notes for tester:
	// to change region set the values below according to constants above, e.g.:
	// - test arguments for EU-DE-1:
	// image, zone, instanceName, resourceID := testImageEUDE, testZoneEUDE1, testInstanceNameEUDE1, testResourceIDEUDE1
	// - test arguments for us-east-2:
	// image, zone, instanceName, resourceID := testImageUSEast, testZoneUSEast2, testInstanceNameUSEast2, testResourceIDUSEast2
	// - test arguments for us-south-1:
	// image, zone, instanceName, resourceID := testImageUSSouth, testZoneUSSouth1, testInstanceNameUSSouth1, testResourceIDUSSouth1
	image, zone, instanceName, resourceID := testImageUSEast, testZoneUSEast1, testInstanceNameUSEast1, testResourceIDUSEast1

	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	imageIdentity := vpcv1.ImageIdentityByID{ID: &image}
	zoneIdentity := vpcv1.ZoneIdentityByName{Name: &zone}
	myTestProfile := string(testProfile)

	testPrototype := &vpcv1.InstancePrototypeInstanceByImage{
		Image:   &imageIdentity,
		Zone:    &zoneIdentity,
		Name:    core.StringPtr(instanceName),
		Profile: &vpcv1.InstanceProfileIdentityByName{Name: &myTestProfile},
	}

	s := &ibmPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient:            make(map[string]*sdk.CloudClient)}

	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(testPrototype)})
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Id: resourceID, Description: description, Namespace: testNamespace}
	resp, err := s.CreateResource(context.Background(), resource)
	if err != nil {
		println(err)
	}
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// usage: go test --tags=ibm -run TestGetPermitList -sg=<security group name>
func TestGetPermitRules(t *testing.T) {
	resourceID := testResourceIDUSEast1 // replace as needed with other IDs, e.g. testResourceIDEUDE1

	s := &ibmPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}

	resp, err := s.GetPermitList(context.Background(), &invisinetspb.GetPermitListRequest{Resource: resourceID,
		Namespace: testNamespace})
	require.NoError(t, err)
	require.NotNil(t, resp)

	b, err := json.MarshalIndent(resp, "", "  ")
	require.NoError(t, err)
	// Note: direction:0(inbound) will not be printed.
	utils.Log.Printf("Permit rules of instance %v are:\n%v", testInstanceNameUSEast1, string(b))
}

// usage: go test --tags=ibm -run TestAddPermitListRules -sg=<security group name>
func TestAddPermitRules(t *testing.T) {
	resourceID := testResourceIDUSEast1 // replace as needed with other IDs, e.g. testResourceIDEUDE1

	addRulesRequest := &invisinetspb.AddPermitListRulesRequest{
		Namespace: testNamespace,
		Resource:  resourceID,
		Rules:     testPermitList,
	}

	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}

	s := &ibmPluginServer{cloudClient: make(map[string]*sdk.CloudClient),
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	resp, err := s.AddPermitListRules(context.Background(), addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)

	utils.Log.Printf("Response: %+v", resp)
}

// usage: go test --tags=ibm -run TestDeletePermitListRule -sg=<security group name>
func TestDeletePermitRules(t *testing.T) {
	resourceID := testResourceIDUSEast1 // replace as needed with other IDs, e.g. testResourceIDUSSouth1

	rInfo, err := getResourceIDInfo(resourceID)
	require.NoError(t, err)

	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	require.NoError(t, err)

	cloudClient, err := sdk.NewIBMCloudClient(rInfo.ResourceGroupName, region)
	require.NoError(t, err)

	// Get the VM ID from the resource ID (typically refers to VM Name)
	vmData, err := cloudClient.GetInstanceData(rInfo.ResourceID)
	require.NoError(t, err)

	vmID := *vmData.ID

	invisinetsSgsData, err := cloudClient.GetInvisinetsTaggedResources(sdk.SG, []string{vmID}, sdk.ResourceQuery{Region: region})
	require.NoError(t, err)

	require.NotEqualValues(t, len(invisinetsSgsData), 0, "no security groups were found for VM "+rInfo.ResourceID)

	// assuming up to a single invisinets subnet can exist per zone
	vmInvisinetsSgID := invisinetsSgsData[0].ID

	ibmRulesToDelete, err := sdk.InvisinetsToIBMRules(vmInvisinetsSgID, testPermitList)
	require.NoError(t, err)

	rulesIDs, err := cloudClient.GetRulesIDs(ibmRulesToDelete, vmInvisinetsSgID)
	require.NoError(t, err)

	deleteRulesRequest := &invisinetspb.DeletePermitListRulesRequest{
		Namespace: testNamespace,
		Resource:  resourceID,
		RuleNames: rulesIDs,
	}

	s := &ibmPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}

	resp, err := s.DeletePermitListRules(context.Background(), deleteRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)

	utils.Log.Printf("Response: %v", resp)
}

// usage: go test --tags=ibm -run TestGetUsedAddressSpaces -sg=<security group name>
// this function logs subnets' address spaces from all invisinets' VPCs.
func TestGetExistingAddressSpaces(t *testing.T) {
	// GetUsedAddressSpaces() is independent of any region, since it returns
	// address spaces in global scope, so any test resource ID will do.
	deployments := &invisinetspb.GetUsedAddressSpacesRequest{
		Deployments: []*invisinetspb.InvisinetsDeployment{{Id: testResourceIDUSEast1}},
	}

	s := &ibmPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}

	usedAddressSpace, err := s.GetUsedAddressSpaces(context.Background(), deployments)
	require.NoError(t, err)
	require.NotEmpty(t, usedAddressSpace)

	utils.Log.Printf("Response: %v", usedAddressSpace)
}

// usage: go test --tags=ibm -run TestCreateVpnGateway -sg=<security group name>
func TestCreateVpnGateway(t *testing.T) {
	resourceID := testResourceIDUSEast1 // replace as needed with other IDs, e.g. testResourceIDUSSouth1

	s := &ibmPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}
	createVPNRequest := &invisinetspb.CreateVpnGatewayRequest{
		Deployment: &invisinetspb.InvisinetsDeployment{Id: resourceID, Namespace: testNamespace}}
	resp, err := s.CreateVpnGateway(context.Background(), createVPNRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)

	utils.Log.Printf("Response: %v", resp)
}

// usage: go test --tags=ibm -run TestCreateVpnConnections -sg=<security group name>
func TestCreateVpnConnections(t *testing.T) {

	peerVPNGatewayIP := "4.227.185.167"   // remote VPN gateway IP connection will direct traffic to
	deploymentID := testResourceIDUSEast1 // replace as needed with other IDs, e.g. testResourceIDUSSouth1

	s := &ibmPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}
	createVPNRequest := &invisinetspb.CreateVpnConnectionsRequest{
		Deployment:         &invisinetspb.InvisinetsDeployment{Id: deploymentID, Namespace: testNamespace},
		GatewayIpAddresses: []string{peerVPNGatewayIP},
		SharedKey:          "password",
		RemoteAddresses:    []string{"10.0.0.0/24"},
		Cloud:              utils.AZURE,
		IsBGPDisabled:      true,
	}
	resp, err := s.CreateVpnConnections(context.Background(), createVPNRequest)
	require.NoError(t, err)

	utils.Log.Printf("Response: %v", resp)
}

// usage: go test --tags=ibm -run TestGetUsedBgpPeeringIpAddresses -sg=<security group name>
func TestGetUsedBgpPeeringIpAddresses(t *testing.T) {
	// only detail affecting GetUsedBgpPeeringIpAddresses from deploymentID is the resource group
	// as it retrieves ip addresses from all VPNs from the request's namespace.
	deploymentID1 := testResourceIDEUDE1 // replace as needed with other IDs, e.g. testResourceIDUSSouth1

	s := &ibmPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}

	request := &invisinetspb.GetUsedBgpPeeringIpAddressesRequest{
		Deployments: []*invisinetspb.InvisinetsDeployment{
			{Id: deploymentID1, Namespace: testNamespace}},
	}

	resp, err := s.GetUsedBgpPeeringIpAddresses(context.Background(), request)
	require.NoError(t, err)

	utils.Log.Printf("Response: %v", resp)
}

// usage: go test --tags=ibm -run TestAddPermitListRules -sg=<security group name> -timeout 0
// -timeout 0 removes limit of 10 min. runtime, which is necessary due to long deployment time of Azure's VPN.
func TestAddPermitRulesIntegration(t *testing.T) {
	azureServerPort := 7991
	IBMServerPort := 7992
	IBMDeploymentID := testResourceIDUSEast1

	orchestratorServerConfig := config.Config{
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
					Deployment: IBMDeploymentID,
				},
			},
		},
	}

	// start controller server
	orchestratorServerAddr := orchestrator.SetupControllerServer(orchestratorServerConfig)

	// start ibm plugin server
	ibmServer := Setup(IBMServerPort, orchestratorServerAddr)

	// start azure plugin server
	_ = azure_plugin.Setup(azureServerPort, orchestratorServerAddr)

	addRulesRequest := &invisinetspb.AddPermitListRulesRequest{
		Namespace: testNamespace,
		Resource:  IBMDeploymentID,
		// using a rule with a public ip, since private ips are required to reference existing VMs.
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  -1,
				Targets:   []string{"47.235.107.235"},
			},
		},
	}

	resp, err := ibmServer.AddPermitListRules(context.Background(), addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)

	utils.Log.Printf("Response: %+v", resp)
}

// usage: go test --tags=ibm -run TestMulticloudIBMAzure -sg=<security group name> -timeout 0
// -timeout 0 removes limit of 10 minutes runtime, which is necessary due to long deployment time of Azure's VPN.
// Note: Azure's Network Watcher must be deployed in the region before execution
func TestMulticloudIBMAzure(t *testing.T) {
	// ibm config
	IBMServerPort := 7992
	IBMDeploymentID := testResourceIDUSEast1
	image, zone, instanceName, resourceID := testImageUSEast, testZoneUSEast1, testInstanceNameUSEast1, testResourceIDUSEast1
	// azure config
	azureServerPort := 7991
	azureSubscriptionId := azure_plugin.GetAzureSubscriptionId()
	azureResourceGroupName := azure_plugin.SetupAzureTesting(azureSubscriptionId, "ibmazure")
	defer azure_plugin.TeardownAzureTesting(azureSubscriptionId, azureResourceGroupName)

	azureNamespace := "multicloud" + uuid.NewString()[:6]
	AzureDeploymentID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", azureSubscriptionId, azureResourceGroupName)

	orchestratorServerConfig := config.Config{
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
					Deployment: IBMDeploymentID,
				},
			},
			azureNamespace: {
				{
					Name:       utils.AZURE,
					Deployment: AzureDeploymentID,
				},
			},
		},
	}

	// start controller server
	orchestratorServerAddr := orchestrator.SetupControllerServer(orchestratorServerConfig)
	fmt.Println("Setup controller server")

	// start ibm plugin server
	fmt.Println("Setting up IBM server")
	ibmServer := Setup(IBMServerPort, orchestratorServerAddr)

	// start azure plugin server
	fmt.Println("Setting up Azure server")
	azureServer := azure_plugin.Setup(azureServerPort, orchestratorServerAddr)

	ctx := context.Background()

	// Create Azure VM
	fmt.Println("Creating Azure VM...")
	azureVm1Location := "westus"
	azureVm1Parameters := azure_plugin.GetTestVmParameters(azureVm1Location)
	azureVm1Description, err := json.Marshal(azureVm1Parameters)
	require.NoError(t, err)
	azureVm1ResourceId := "/subscriptions/" + azureSubscriptionId + "/resourceGroups/" + azureResourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + "invisinets-vm-multicloud708"
	azureCreateResourceResp1, err := azureServer.CreateResource(
		ctx,
		&invisinetspb.ResourceDescription{Id: azureVm1ResourceId, Description: azureVm1Description, Namespace: azureNamespace},
	)
	require.NoError(t, err)
	require.NotNil(t, azureCreateResourceResp1)
	assert.Equal(t, azureCreateResourceResp1.Uri, azureVm1ResourceId)

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

	resource := &invisinetspb.ResourceDescription{Id: resourceID, Description: description, Namespace: testNamespace}
	createResourceResponse, err := ibmServer.CreateResource(ctx, resource)
	if err != nil {
		println(err)
	}
	require.NoError(t, err)
	require.NotNil(t, createResourceResponse)

	// Add permit list for IBM VM
	fmt.Println("Adding IBM permit list rules...")
	azureVmIpAddress, err := azure_plugin.GetVmIpAddress(azureVm1ResourceId)
	require.NoError(t, err)

	ibmPermitList := []*invisinetspb.PermitListRule{
		//inbound ICMP protocol rule to accept & respond to pings
		{
			Direction: invisinetspb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{azureVmIpAddress},
		},
		//outbound ICMP protocol rule to initiate pings
		{
			Direction: invisinetspb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{azureVmIpAddress},
		},
		// allow inbound ssh connection
		{
			Direction: invisinetspb.Direction_INBOUND,
			SrcPort:   22,
			DstPort:   22,
			Protocol:  6,
			Targets:   []string{"0.0.0.0/0"},
		},
	}

	addRulesRequest := &invisinetspb.AddPermitListRulesRequest{
		Namespace: testNamespace,
		Resource:  IBMDeploymentID,
		Rules:     ibmPermitList,
	}

	respAddRules, err := ibmServer.AddPermitListRules(ctx, addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, respAddRules)

	// Create Azure VM permit list
	ibmVmIpAddress := createResourceResponse.Ip

	fmt.Println("Adding Azure permit list rules...")
	azureVm1PermitListReq := &invisinetspb.AddPermitListRulesRequest{
		Resource: azureVm1ResourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Name:      "ibm-inbound-rule",
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{ibmVmIpAddress},
			},
			{
				Name:      "ibm-outbound-rule",
				Direction: invisinetspb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{ibmVmIpAddress},
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
		Namespace: azureNamespace,
	}
	azureAddPermitListRules1Resp, err := azureServer.AddPermitListRules(ctx, azureVm1PermitListReq)
	require.NoError(t, err)
	require.NotNil(t, azureAddPermitListRules1Resp)

	// Run Azure connectivity check (ping from Azure VM to IBM VM)
	// Note: Azure's Network Watcher must be deployed in the region before execution
	fmt.Println("running Azure connectivity test...")
	azureConnectivityCheck1, err := azure_plugin.RunPingConnectivityCheck(azureVm1ResourceId, ibmVmIpAddress)
	require.Nil(t, err)
	require.True(t, azureConnectivityCheck1)
}
