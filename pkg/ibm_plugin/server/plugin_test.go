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
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/stretchr/testify/require"

	"github.com/NetSys/invisinets/pkg/fake"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
)

const (
	testResGroupName  = "invisinets"
	testUSRegion      = "us-east"
	testUSZone1       = testUSRegion + "-1"
	testUSZone2       = testUSRegion + "-2"
	testEURegion      = "eu-de"
	testEUZone1       = testEURegion + "-1"
	testInstanceName1 = "invisinets-vm-1"
	testInstanceName2 = "invisinets-vm-2"

	testResourceID1 = "/ResourceGroupID/" + testResGroupName + "/Zone/" + testUSZone1 + "/ResourceID/" + testInstanceName1
	testResourceID2 = "/ResourceGroupID/" + testResGroupName + "/Zone/" + testUSZone2 + "/ResourceID/" + testInstanceName2

	testResourceID1 = "/ResourceGroupID/" + testResGroupName + "/Region/" + testUSZone1

	testImageID = "r014-0acbdcb5-a68f-4a52-98ea-4da4fe89bacb" // Ubuntu 22.04
	testProfile = "bx2-2x8"
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

// go test --tags=ibm -run TestCreateResource
func TestCreateResourceNewVPC(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeControllerServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	imageIdentity := vpcv1.ImageIdentityByID{ID: core.StringPtr(testImageID)}
	zoneIdentity := vpcv1.ZoneIdentityByName{Name: core.StringPtr(testUSZone2)}
	myTestProfile := string(testProfile)

	testPrototype := &vpcv1.InstancePrototypeInstanceByImage{
		Image:   &imageIdentity,
		Zone:    &zoneIdentity,
		Name:    core.StringPtr(testInstanceName1),
		Profile: &vpcv1.InstanceProfileIdentityByName{Name: &myTestProfile},
	}

	s := &ibmPluginServer{
		frontendServerAddr: fakeControllerServerAddr}
	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(testPrototype)})
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Id: testResourceID1, Description: description}
	resp, err := s.CreateResource(context.Background(), resource)
	if err != nil {
		println(err)
	}
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// go test --tags=ibm -run TestCreateResourceExistingVPC
func TestCreateResourceExistingVPC(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeControllerServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	imageIdentity := vpcv1.ImageIdentityByID{ID: core.StringPtr(testImageID)}
	zoneIdentity := vpcv1.ZoneIdentityByName{Name: core.StringPtr(testUSZone2)}
	myTestProfile := string(testProfile)

	testPrototype := &vpcv1.InstancePrototypeInstanceByImage{
		Image:   &imageIdentity,
		Zone:    &zoneIdentity,
		Name:    core.StringPtr(testInstanceName2),
		Profile: &vpcv1.InstanceProfileIdentityByName{Name: &myTestProfile},
	}

	s := &ibmPluginServer{
		frontendServerAddr: fakeControllerServerAddr}
	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(testPrototype)})
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Id: testResourceID2, Description: description}
	resp, err := s.CreateResource(context.Background(), resource)
	if err != nil {
		println(err)
	}
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// usage: go test --tags=ibm -run TestGetPermitList
func TestGetPermitList(t *testing.T) {
	resourceID := &invisinetspb.ResourceID{Id: testResourceID1}

	s := &ibmPluginServer{}

	resp, err := s.GetPermitList(context.Background(), resourceID)
	require.NoError(t, err)
	require.NotNil(t, resp)

	b, err := json.MarshalIndent(resp, "", "  ")
	require.NoError(t, err)
	// Note: direction:0(inbound) will not be printed.
	utils.Log.Printf("Permit rules of instance %v are:\n%v", testInstanceName1, string(b))
}

// usage: go test --tags=ibm -run TestAddPermitListRules
func TestAddPermitListRules(t *testing.T) {
	permitList := &invisinetspb.PermitList{
		AssociatedResource: testResourceID1,
		Rules:              testPermitList,
	}

	s := &ibmPluginServer{}

	resp, err := s.AddPermitListRules(context.Background(), permitList)
	require.NoError(t, err)
	require.NotNil(t, resp)

	utils.Log.Printf("Response: %v", resp)
}

// usage: go test --tags=ibm -run TestDeletePermitListRule
func TestDeletePermitListRules(t *testing.T) {
	permitList := &invisinetspb.PermitList{
		AssociatedResource: testResourceID1,
		Rules:              testPermitList,
	}

	s := &ibmPluginServer{}

	resp, err := s.DeletePermitListRules(context.Background(), permitList)
	require.NoError(t, err)
	require.NotNil(t, resp)

	utils.Log.Printf("Response: %v", resp)
}

// usage: go test --tags=ibm -run TestGetUsedAddressSpaces
func TestGetUsedAddressSpaces(t *testing.T) {
	deployment := &invisinetspb.InvisinetsDeployment{Id: testResourceID1}

	s := &ibmPluginServer{}

	usedAddressSpace, err := s.GetUsedAddressSpaces(context.Background(), deployment)
	require.NoError(t, err)
	require.NotEmpty(t, usedAddressSpace)
}
