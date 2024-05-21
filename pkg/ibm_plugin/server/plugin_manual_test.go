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
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/stretchr/testify/require"

	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rpc"
	ibmCommon "github.com/paraglider-project/paraglider/pkg/ibm_plugin"
	sdk "github.com/paraglider-project/paraglider/pkg/ibm_plugin/sdk"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

var testResourceIDUSEast1 string
var testResourceIDUSEast2 string
var testResourceIDUSEast3 string
var testResourceIDEUDE1 string
var testResourceIDUSSouth1 string

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

// permit list to test connectivity via pings. Made to test Transit and VPN gateways configurations
var pingTestPermitList []*paragliderpb.PermitListRule = []*paragliderpb.PermitListRule{
	//ICMP protocol rule to accept pings
	{
		Name:      "inboundICMP",
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  1,
		Targets:   []string{"0.0.0.0/0"},
	},
	// ssh to accept ssh connection
	{
		Name:      "inboundSSH",
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   22,
		DstPort:   22,
		Protocol:  6,
		Targets:   []string{"0.0.0.0/0"},
	},
	//All protocol to allow all egress traffic
	{
		Name:      "outboundALL",
		Direction: paragliderpb.Direction_OUTBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  -1,
		Targets:   []string{"0.0.0.0/0"},
	},
}

// go test --tags=ibm -run TestCreateNewResource
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

// usage: go test --tags=ibm -run TestGetPermitList
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

// usage: go test --tags=ibm -run TestAddPermitListRules
func TestAddPermitRules(t *testing.T) {
	resourceID := testResourceIDUSEast1 // replace as needed with other IDs, e.g. testResourceIDEUDE1

	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: testNamespace,
		Resource:  resourceID,
		Rules:     pingTestPermitList,
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

// usage: go test --tags=ibm -run TestDeletePermitListRule
func TestDeletePermitRules(t *testing.T) {
	resourceID := testResourceIDUSEast1 // replace as needed with other IDs, e.g. testResourceIDUSSouth1

	rInfo, err := getResourceMeta(resourceID)
	require.NoError(t, err)

	region, err := ibmCommon.ZoneToRegion(rInfo.Zone)
	require.NoError(t, err)

	cloudClient, err := sdk.NewIBMCloudClient(rInfo.ResourceGroup, region)
	require.NoError(t, err)

	vmData, err := cloudClient.GetInstanceDataFromID(rInfo.ResourceID)
	require.NoError(t, err)

	vmID := *vmData.ID

	paragliderSgsData, err := cloudClient.GetParagliderTaggedResources(sdk.SG, []string{vmID}, sdk.ResourceQuery{Region: region})
	require.NoError(t, err)

	require.NotEqualValues(t, len(paragliderSgsData), 0, "no security groups were found for VM "+rInfo.ResourceID)

	// assuming up to a single paraglider subnet can exist per zone
	vmParagliderSgID := paragliderSgsData[0].ID

	ibmRulesToDelete, err := sdk.ParagliderToIBMRules(vmParagliderSgID, pingTestPermitList)
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

// usage: go test --tags=ibm -run TestGetUsedAddressSpaces
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

// usage: go test --tags=ibm -run TestCreateVpnGateway
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

// usage: go test --tags=ibm -run TestCreateVpnConnections
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

// usage: go test --tags=ibm -run TestGetUsedBgpPeeringIpAddresses
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
