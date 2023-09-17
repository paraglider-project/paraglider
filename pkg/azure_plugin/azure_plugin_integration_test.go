//go:build integration

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

package azure_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	fake "github.com/NetSys/invisinets/pkg/fake"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	vmNamePrefix = "sample-vm"
	vmLocation   = "westus"
)

var (
	subscriptionId    string
	resourceGroupName string
)

// Deletes Resource group which in turn deletes all the resources created
// If deletion fails: refer to https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/delete-resource-group

// Main integration test function
// any test that needs to be run as part of integration test should be added here
// as a subtest, this is to ensure that the setup and teardown is done only once before or after all the tests
func TestAzurePluginIntegration(t *testing.T) {
	subscriptionId = GetAzureSubscriptionId()
	resourceGroupName = invisinetsPrefix + "-integration-test" // Must be defined within a test and not as a global var as invisinetsPrefix is subject to change in init()
	// SetupAzureTesting(subscriptionId, resourceGroupName)
	// defer TeardownAzureTesting(subscriptionId, resourceGroupName)

	// t.Run("TestAddAndGetPermitList", testAddAndGetPermitList)

	s := InitializeServer()
	ctx := context.Background()
	resp, err := s.GetUsedAddressSpaces(ctx, &invisinetspb.InvisinetsDeployment{
		Id: fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionId, "expressroute-rg"),
	})
	require.NoError(t, err)
	fmt.Printf("%v:\n", resp.AddressSpaces)
	// fmt.Printf("length: %d\n", len(resp))
}

// This test will test the following:
// 1. Create a resource
// 2. Add a permit list
// 3. Get the permit list
// 4- Delete permit list rule
// 5. Get the permit list and valdiates again
func testAddAndGetPermitList(t *testing.T) {
	fakeControllerServerAddr, err := fake.SetupFakeControllerServer()
	if err != nil {
		t.Fatal(err)
	}
	FrontendServerAddr = fakeControllerServerAddr

	s := InitializeServer()
	ctx := context.Background()

	parameters := GetTestVmParameters(vmLocation)
	descriptionJson, err := json.Marshal(parameters)
	require.NoError(t, err)
	vmID := "/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroupName + "/providers/Microsoft.Compute/virtualMachines/" + vmNamePrefix + "-" + uuid.NewString()
	createResourceResp, err := s.CreateResource(ctx, &invisinetspb.ResourceDescription{
		Id:          vmID,
		Description: descriptionJson,
	})
	require.NoError(t, err)
	require.NotNil(t, createResourceResp)
	assert.True(t, createResourceResp.Success)
	assert.Equal(t, createResourceResp.UpdatedResource.Id, vmID)

	permitList := &invisinetspb.PermitList{
		AssociatedResource: vmID,
		Rules: []*invisinetspb.PermitListRule{
			{
				Tag:       []string{"10.1.0.5"},
				Direction: invisinetspb.Direction_OUTBOUND,
				SrcPort:   80,
				DstPort:   80,
				Protocol:  6,
			},
		},
	}
	addPermitListResp, err := s.AddPermitListRules(ctx, permitList)
	require.NoError(t, err)
	require.NotNil(t, addPermitListResp)
	assert.True(t, addPermitListResp.Success)
	assert.Equal(t, addPermitListResp.UpdatedResource.Id, vmID)

	// Assert the NSG created is equivalent to the pl rules by using the get permit list api
	getPermitListResp, err := s.GetPermitList(ctx, &invisinetspb.ResourceID{Id: vmID})
	require.NoError(t, err)
	require.NotNil(t, getPermitListResp)

	// add the id to the initial permit list  for an easier comparison
	// because it is only set in the get not the add
	permitList.Rules[0].Id = getPermitListResp.Rules[0].Id
	assert.ElementsMatch(t, getPermitListResp.Rules, permitList.Rules)

	// Delete permit list rule
	deletePermitListResp, err := s.DeletePermitListRules(ctx, permitList)
	require.NoError(t, err)
	require.NotNil(t, deletePermitListResp)
	assert.True(t, deletePermitListResp.Success)

	// Assert the rule is deleted by using the get permit list api
	getPermitListResp, err = s.GetPermitList(ctx, &invisinetspb.ResourceID{Id: vmID})
	require.NoError(t, err)
	require.NotNil(t, getPermitListResp)

	assert.ElementsMatch(t, getPermitListResp.Rules, []*invisinetspb.PermitListRule{})
}

// func testVpnGateway(t *testing.T) {
// 	vmID := getVmId()
// 	permitList := &invisinetspb.PermitList{AssociatedResource: vmID,
// 		Rules: []*invisinetspb.PermitListRule{&invisinetspb.PermitListRule{Tag: []string{"10.1.0.5"}, Direction: invisinetspb.Direction_OUTBOUND, SrcPort: 80, DstPort: 80, Protocol: 6}}}
// 	s, ctx := setupValidResourceAndPermitList(t, permitList, vmID)

// 	_, err := s.CreateVpnGateway(ctx, subscriptionId, resourceGroupName)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }
