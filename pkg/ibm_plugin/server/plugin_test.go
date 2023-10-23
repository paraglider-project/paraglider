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
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/stretchr/testify/require"

	"github.com/NetSys/invisinets/pkg/fake"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
)

// test cli flags
var vmID string   // (optional flag) existing invisinets VM ID.
var region string // (optional flag) existing invisinets VM ID.
var zone string   // (optional flag) zone to launch a VM in.
var delVPC bool   // (optional flag) if set to true cleans resources after test.

const (
	testResGroupName = "invisinets"
	testRegion       = "us-east"
	testZone         = testRegion + "-1"
	testInstanceName = "invisinets-vm"

	testResourceID = "/ResourceGroupID/" + testResGroupName + "/Region/" + testRegion + "/ResourceID/" + testInstanceName

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

func init() {
	flag.StringVar(&vmID, "vmID", "", "Existing invisinets VM ID")
	flag.StringVar(&region, "region", "", "IBM region")
	flag.StringVar(&zone, "zone", "", "IBM zone")
	flag.BoolVar(&delVPC, "delVPC", false, "if specified, terminates vpc after tests end")
}

// to terminate the created vpc specify -delVPC.
// to launch VM in a specific zone specify -zone=<zoneName>, e.g.:
// go test --tags=ibm -run TestCreateResource -delVPC
// NOTE: use sdk's TestTerminateVPC to delete the VPC post run.
func TestCreateResource(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeControllerServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	imageIdentity := vpcv1.ImageIdentityByID{ID: core.StringPtr(testImageID)}
	zoneIdentity := vpcv1.ZoneIdentityByName{Name: core.StringPtr(testZone)}
	myTestProfile := string(testProfile)

	testPrototype := &vpcv1.InstancePrototypeInstanceByImage{
		Image:   &imageIdentity,
		Zone:    &zoneIdentity,
		Name:    core.StringPtr(testInstanceName),
		Profile: &vpcv1.InstanceProfileIdentityByName{Name: &myTestProfile},
	}

	s := &ibmPluginServer{
		frontendServerAddr: fakeControllerServerAddr}
	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(testPrototype)})
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Id: testResourceID, Description: description}
	resp, err := s.CreateResource(context.Background(), resource)
	if err != nil {
		println(err)
	}
	require.NoError(t, err)
	require.NotNil(t, resp)

	if delVPC {
		vpcID, err := s.cloudClient.VMToVPCID(resp.UpdatedResource.Id)
		require.NoError(t, err)
		err = s.cloudClient.TerminateVPC(vpcID)
		require.NoError(t, err)
	}
}

// usage: go test --tags=ibm -run TestGetPermitList
func TestGetPermitList(t *testing.T) {
	resourceID := &invisinetspb.ResourceID{Id: testResourceID}

	s := &ibmPluginServer{}

	resp, err := s.GetPermitList(context.Background(), resourceID)
	require.NoError(t, err)
	require.NotNil(t, resp)

	b, err := json.MarshalIndent(resp, "", "  ")
	require.NoError(t, err)
	// Note: direction:0(inbound) will not be printed.
	utils.Log.Printf("Permit rules of instance %v are:\n%v", testInstanceName, string(b))
}

// usage: go test --tags=ibm -run TestAddPermitListRules
func TestAddPermitListRules(t *testing.T) {
	permitList := &invisinetspb.PermitList{
		AssociatedResource: testResourceID,
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
		AssociatedResource: testResourceID,
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
	deployment := &invisinetspb.InvisinetsDeployment{Id: testResourceID}

	s := &ibmPluginServer{}

	usedAddressSpace, err := s.GetUsedAddressSpaces(context.Background(), deployment)
	require.NoError(t, err)
	require.NotEmpty(t, usedAddressSpace)
}
