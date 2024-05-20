// //go:build ibm

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	azure "github.com/paraglider-project/paraglider/pkg/azure"
	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rpc"
	ibmCommon "github.com/paraglider-project/paraglider/pkg/ibm_plugin"
	sdk "github.com/paraglider-project/paraglider/pkg/ibm_plugin/sdk"
	"github.com/paraglider-project/paraglider/pkg/kvstore"
	"github.com/paraglider-project/paraglider/pkg/orchestrator"
	"github.com/paraglider-project/paraglider/pkg/orchestrator/config"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	tagging "github.com/paraglider-project/paraglider/pkg/tag_service"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

var testResGroupName = flag.String("sg", "8145289ddf7047ea93fd2835de391f43", "ID of the user's security group")
var testResourceIDUSEast1 string
var testResourceIDUSEast2 string
var testResourceIDUSEast3 string
var testResourceIDEUDE1 string
var testResourceIDUSSouth1 string
var testDeployment string

func TestMain(m *testing.M) {
	flag.Parse()
	testResourceIDUSEast1 = "/resourcegroup/" + *testResGroupName + "/zone/" + testZoneUSEast1 + "/instance/"
	testResourceIDUSEast2 = "/resourcegroup/" + *testResGroupName + "/zone/" + testZoneUSEast2 + "/instance/"
	testResourceIDUSEast3 = "/resourcegroup/" + *testResGroupName + "/zone/" + testZoneUSEast3 + "/instance/"
	testResourceIDEUDE1 = "/resourcegroup/" + *testResGroupName + "/zone/" + testZoneEUDE1 + "/instance/"
	testResourceIDUSSouth1 = "/resourcegroup/" + *testResGroupName + "/zone/" + testZoneUSSouth1 + "/instance/"
	testDeployment = "/resourcegroup/" + *testResGroupName
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
	testInstanceNameUSEast1  = "pg-vm-east-1"
	testInstanceNameUSEast2  = "pg-vm-east-2"
	testInstanceNameUSEast3  = "pg-vm-east-3"
	testInstanceNameUSSouth1 = "pg-vm-south-1"
	testInstanceNameEUDE1    = "pg-vm-de-1"

	testImageUSEast  = "r014-0acbdcb5-a68f-4a52-98ea-4da4fe89bacb" // us-east Ubuntu 22.04
	testImageEUDE    = "r010-f68ef7b3-1c5e-4ef7-8040-7ae0f5bf04fd" // eu-de Ubuntu 22.04
	testImageUSSouth = "r006-01deb923-46f6-44c3-8fdc-99d8493d2464" // us-south Ubuntu 22.04
	testProfile      = "bx2-2x8"
	testNamespace    = "paraglider-namespace"
)

// permit list example
var testPermitList []*paragliderpb.PermitListRule = []*paragliderpb.PermitListRule{
	//TCP protocol rules
	{
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   443,
		DstPort:   443,
		Protocol:  6,
		Targets:   []string{"10.0.0.0/18"},
	},
	{
		Direction: paragliderpb.Direction_OUTBOUND,
		SrcPort:   8080,
		DstPort:   8080,
		Protocol:  6,
		Targets:   []string{"10.0.128.12", "10.0.128.13"},
	},
	//All protocol rules
	{
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  -1,
		Targets:   []string{"10.0.64.0/22", "10.0.64.0/24"},
	},
	{
		Direction: paragliderpb.Direction_OUTBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  -1,
		Targets:   []string{"10.0.64.1"},
	},
}

// permit list to test connectivity via pings. Made to test Transit and VPN gateways configurations
var pingTestPermitList []*paragliderpb.PermitListRule = []*paragliderpb.PermitListRule{ //nolint:all keeping unused variable for future testing
	//ICMP protocol rule to accept pings
	{
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  1,
		Targets:   []string{"0.0.0.0/0"},
	},
	// ssh to accept ssh connection
	{
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   22,
		DstPort:   22,
		Protocol:  6,
		Targets:   []string{"0.0.0.0/0"},
	},
	//All protocol to allow all egress traffic
	{
		Direction: paragliderpb.Direction_OUTBOUND,
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
	// image, zone, instanceName, resourceID := testImageUSEast, testZoneUSEast1, testInstanceNameUSEast1, testResourceIDUSEast1
	image, zone, instanceName := testImageUSEast, testZoneUSEast1, testInstanceNameUSEast1

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

	s := &IBMPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient:            make(map[string]*sdk.CloudClient)}

	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(testPrototype)})
	require.NoError(t, err)

	resource := &paragliderpb.ResourceDescription{Deployment: &paragliderpb.ParagliderDeployment{Id: testDeployment, Namespace: testNamespace}, Description: description}
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

	s := &IBMPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}

	resp, err := s.GetPermitList(context.Background(), &paragliderpb.GetPermitListRequest{Resource: resourceID,
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

	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: testNamespace,
		Resource:  resourceID,
		Rules:     testPermitList,
	}

	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}

	s := &IBMPluginServer{cloudClient: make(map[string]*sdk.CloudClient),
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

	cloudClient, err := sdk.NewIBMCloudClient(rInfo.ResourceGroup, region)
	require.NoError(t, err)

	// Get the VM ID from the resource ID (typically refers to VM Name)
	vmData, err := cloudClient.GetInstanceData(rInfo.ResourceID)
	require.NoError(t, err)

	vmID := *vmData.ID

	paragliderSgsData, err := cloudClient.GetParagliderTaggedResources(sdk.SG, []string{vmID}, sdk.ResourceQuery{Region: region})
	require.NoError(t, err)

	require.NotEqualValues(t, len(paragliderSgsData), 0, "no security groups were found for VM "+rInfo.ResourceID)

	// assuming up to a single paraglider subnet can exist per zone
	vmParagliderSgID := paragliderSgsData[0].ID

	ibmRulesToDelete, err := sdk.ParagliderToIBMRules(vmParagliderSgID, testPermitList)
	require.NoError(t, err)

	rulesIDs, err := cloudClient.GetRulesIDs(ibmRulesToDelete, vmParagliderSgID)
	require.NoError(t, err)

	deleteRulesRequest := &paragliderpb.DeletePermitListRulesRequest{
		Namespace: testNamespace,
		Resource:  resourceID,
		RuleNames: rulesIDs,
	}

	s := &IBMPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}

	resp, err := s.DeletePermitListRules(context.Background(), deleteRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)

	utils.Log.Printf("Response: %v", resp)
}

// usage: go test --tags=ibm -run TestGetUsedAddressSpaces -sg=<security group name>
// this function logs subnets' address spaces from all paraglider VPCs.
func TestGetExistingAddressSpaces(t *testing.T) {
	// GetUsedAddressSpaces() is independent of any region, since it returns
	// address spaces in global scope, so any test resource ID will do.
	deployments := &paragliderpb.GetUsedAddressSpacesRequest{
		Deployments: []*paragliderpb.ParagliderDeployment{{Id: testResourceIDUSEast1}},
	}

	s := &IBMPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}

	usedAddressSpace, err := s.GetUsedAddressSpaces(context.Background(), deployments)
	require.NoError(t, err)
	require.NotEmpty(t, usedAddressSpace)

	utils.Log.Printf("Response: %v", usedAddressSpace)
}

// usage: go test --tags=ibm -run TestCreateVpnGateway -sg=<security group name>
func TestCreateVpnGateway(t *testing.T) {
	resourceID := testResourceIDUSEast1 // replace as needed with other IDs, e.g. testResourceIDUSSouth1

	s := &IBMPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}
	createVPNRequest := &paragliderpb.CreateVpnGatewayRequest{
		Deployment: &paragliderpb.ParagliderDeployment{Id: resourceID, Namespace: testNamespace}}
	resp, err := s.CreateVpnGateway(context.Background(), createVPNRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)

	utils.Log.Printf("Response: %v", resp)
}

// usage: go test --tags=ibm -run TestCreateVpnConnections -sg=<security group name>
func TestCreateVpnConnections(t *testing.T) {

	peerVPNGatewayIP := "4.227.185.167"   // remote VPN gateway IP connection will direct traffic to
	deploymentID := testResourceIDUSEast1 // replace as needed with other IDs, e.g. testResourceIDUSSouth1

	s := &IBMPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}
	createVPNRequest := &paragliderpb.CreateVpnConnectionsRequest{
		Deployment:         &paragliderpb.ParagliderDeployment{Id: deploymentID, Namespace: testNamespace},
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

	s := &IBMPluginServer{cloudClient: make(map[string]*sdk.CloudClient)}

	request := &paragliderpb.GetUsedBgpPeeringIpAddressesRequest{
		Deployments: []*paragliderpb.ParagliderDeployment{
			{Id: deploymentID1, Namespace: testNamespace}},
	}

	resp, err := s.GetUsedBgpPeeringIpAddresses(context.Background(), request)
	require.NoError(t, err)

	utils.Log.Printf("Response: %v", resp)
}

// usage: go test --tags=ibm -run TestAddPermitListRules -sg=<security group id> -timeout 0
// -timeout 0 removes limit of 10 min. runtime, which is necessary due to long deployment time of Azure's VPN.
// Note: Run kvstore and tagging service before execution
func TestAddPermitRulesIntegration(t *testing.T) {
	IBMServerPort := 7992
	kvstorePort := 7993
	taggingPort := 7994
	IBMDeploymentID := testDeployment
	IBMResourceIDPrefix := testResourceIDUSEast1
	image, zone, instanceName := testImageUSEast, testZoneUSEast1, testInstanceNameUSEast1

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
		KVStore: struct {
			Port string `yaml:"port"`
			Host string `yaml:"host"`
		}{
			Host: "localhost",
			Port: strconv.Itoa(kvstorePort),
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
					Deployment: IBMDeploymentID,
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

	resource := &paragliderpb.ResourceDescription{Name: instanceName, Deployment: &paragliderpb.ParagliderDeployment{Id: testDeployment, Namespace: testNamespace}, Description: description}
	res, err := ibmServer.CreateResource(context.Background(), resource)
	require.NoError(t, err)
	require.NotNil(t, res)
	URIParts := strings.Split(res.Uri, "/")
	resID := IBMResourceIDPrefix + URIParts[len(URIParts)-1]

	// Add permit list for IBM VM
	fmt.Println("Adding IBM permit list rules...")

	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: testNamespace,
		Resource:  resID,
		// using a rule with a public ip, since private ips are required to reference existing VMs.
		Rules: []*paragliderpb.PermitListRule{
			{
				Name:      "testPermitListRule",
				Direction: paragliderpb.Direction_OUTBOUND,
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

// go test --tags=ibm -run TestRunKVStore -timeout 0
func TestRunKVStore(t *testing.T) {
	dbPort := 6379
	kvstorePort := 7993

	kvstore.Setup(dbPort, kvstorePort, true)
}

func TestRunTaggingService(t *testing.T) {
	dbPort := 6379
	taggingPort := 7994

	tagging.Setup(dbPort, taggingPort, true)
}

// usage: go test --tags=ibm -run TestMulticloudIBMAzure -sg=<security group id> -timeout 0
// -timeout 0 removes limit of 10 minutes runtime, which is necessary due to long deployment time of Azure's VPN.
// Note: Run kvstore and tagging service before execution
func TestMulticloudIBMAzure(t *testing.T) {
	kvstorePort := 7993
	// ibm config
	IBMServerPort := 7992
	IBMDeploymentID := testDeployment
	IBMResourceIDPrefix := testResourceIDUSEast1
	image, zone, instanceName := testImageUSEast, testZoneUSEast1, testInstanceNameUSEast1
	// azure config
	azureServerPort := 7991
	azureSubscriptionId := azure.GetAzureSubscriptionId()
	azureResourceGroupName := "challenge-1377"
	
	// NOTE: Uncomment the following lines if a user have resource group privileges
	// azureResourceGroupName := azure.SetupAzureTesting(azureSubscriptionId, "ibmazure")
	// defer azure.TeardownAzureTesting(azureSubscriptionId, azureResourceGroupName)

	azureNamespace := "multicloud" + uuid.NewString()[:6]
	azureDeploymentId := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/...", azureSubscriptionId, azureResourceGroupName)
	azureVm1Name := "pg-vm-multicloud-" + uuid.NewString()[:6]

	orchestratorServerConfig := config.Config{
		Server: config.Server{
			Host:    "localhost",
			Port:    "8080",
			RpcPort: "8081",
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
					Deployment: IBMDeploymentID,
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

	ctx := context.Background()

	// Create Azure VM
	fmt.Println("Creating Azure VM...")
	azureVm1Location := "westus"
	azureVm1Parameters := azure.GetTestVmParameters(azureVm1Location)
	azureVm1Description, err := json.Marshal(azureVm1Parameters)
	require.NoError(t, err)
	azureVm1ResourceId := "/subscriptions/" + azureSubscriptionId + "/resourceGroups/" + azureResourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + azureVm1Name
	azureCreateResourceResp1, err := azureServer.CreateResource(
		ctx,
		&paragliderpb.ResourceDescription{
			Deployment:  &paragliderpb.ParagliderDeployment{Id: azureDeploymentId, Namespace: azureNamespace},
			Name:        azureVm1Name,
			Description: azureVm1Description,
		},
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

	resource := &paragliderpb.ResourceDescription{Name: instanceName, Deployment: &paragliderpb.ParagliderDeployment{Id: testDeployment, Namespace: testNamespace}, Description: description}
	createResourceResponse, err := ibmServer.CreateResource(ctx, resource)
	require.NoError(t, err)
	require.NotNil(t, createResourceResponse)
	URIParts := strings.Split(createResourceResponse.Uri, "/")
	IBMResourceID := IBMResourceIDPrefix + URIParts[len(URIParts)-1]

	// Add permit list for IBM VM
	fmt.Println("Adding IBM permit list rules...")
	azureVmIpAddress, err := azure.GetVmIpAddress(azureVm1ResourceId)
	require.NoError(t, err)

	ibmPermitList := []*paragliderpb.PermitListRule{
		//inbound ICMP protocol rule to accept & respond to pings
		{
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{azureVmIpAddress},
		},
		//outbound ICMP protocol rule to initiate pings
		{
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  1,
			Targets:   []string{azureVmIpAddress},
		},
		// allow inbound ssh connection
		{
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
		Resource: azureVm1ResourceId,
		Rules: []*paragliderpb.PermitListRule{
			{
				Name:      "ibm-inbound-rule",
				Direction: paragliderpb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   -1,
				Protocol:  1,
				Targets:   []string{ibmVmIpAddress},
			},
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
	// Uncomment following lines if Azure's Network Watcher has been deployed in the region before execution.
	// fmt.Println("running Azure connectivity test...")
	// azureConnectivityCheck1, err := azure.RunPingConnectivityCheck(azureVm1ResourceId, ibmVmIpAddress)
	// require.Nil(t, err)
	// require.True(t, azureConnectivityCheck1)
}
