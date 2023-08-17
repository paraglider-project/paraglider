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
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	vmNamePrefix   = "sample-vm"
	location       = "westus"
)

var (
	subscriptionId = os.Getenv("INVISINETS_AZURE_SUBSCRIPTION_ID")
	resourceGroup  = "invisinets-test-" + uuid.New().String()
	resourceGroupsClient  *armresources.ResourceGroupsClient
)

func setupIntegration() {
	if subscriptionId == "" {
		panic("Environment variable 'INVISINETS_AZURE_SUBSCRIPTION_ID' must be set")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		panic(fmt.Sprintf("Error while getting azure credentials during setup: %v", err))
	}
	clientFactory, err := armresources.NewClientFactory(subscriptionId, cred, nil)
	if err != nil {
		panic(fmt.Sprintf("Error while creating client factory during setup: %v", err))
	}
	resourceGroupsClient = clientFactory.NewResourceGroupsClient()
	_, err = resourceGroupsClient.CreateOrUpdate(context.Background(), resourceGroup, armresources.ResourceGroup{
		Location: to.Ptr(location),
	}, nil)
	if err != nil {
		panic(fmt.Sprintf("Error while creating resource group: %v", err))
	}
}

// Deletes Resource group which in turn deletes all the resources created
// If deletion fails: refer to https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/delete-resource-group
func tearDown() {
	ctx := context.Background()
	poller, err := resourceGroupsClient.BeginDelete(ctx, resourceGroup, nil)
	if err != nil {
		panic(fmt.Sprintf("Error while deleting resource group: %v", err))
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		panic(fmt.Sprintf("Error while waiting for resource group deletion: %v", err))
	}
}

func TestAzurePluginIntegration(t *testing.T) {
	setupIntegration()
	defer tearDown()

	t.Run("TestAddAndGetPermitList", testAddAndGetPermitList)
}

// This test will test the following:
// 1. Create a resource
// 2. Add a permit list
// 3. Get the permit list
// 4- Delete permit list rule
// 5. Get the permit list and valdiates again
func testAddAndGetPermitList(t *testing.T) {
	vmID := getVmId()
	permitList := &invisinetspb.PermitList{AssociatedResource: vmID,
		Rules: []*invisinetspb.PermitListRule{&invisinetspb.PermitListRule{Tag: []string{"10.1.0.5"}, Direction: invisinetspb.Direction_OUTBOUND, SrcPort: 80, DstPort: 80, Protocol: 6}}}
	s, ctx := setupValidResourceAndPermitList(t, permitList, vmID)

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

func setupValidResourceAndPermitList(t *testing.T, permitList *invisinetspb.PermitList, vmID string) (*azurePluginServer, context.Context) {
	s := &azurePluginServer{
		azureHandler: &azureSDKHandler{},
	}
	ctx := context.Background()

	parameters := getTestVirtualMachine()
	descriptionJson, err := json.Marshal(parameters)
	require.NoError(t, err)
	createResourceResp, err := s.CreateResource(ctx, &invisinetspb.ResourceDescription{
		Id:           vmID,
		Description:  descriptionJson,
		AddressSpace: "10.0.0.0/16",
	})
	require.NoError(t, err)
	require.NotNil(t, createResourceResp)
	assert.True(t, createResourceResp.Success)
	assert.Equal(t, createResourceResp.UpdatedResource.Id, vmID)

	addPermitListResp, err := s.AddPermitListRules(ctx, permitList)
	require.NoError(t, err)
	require.NotNil(t, addPermitListResp)
	assert.True(t, addPermitListResp.Success)
	assert.Equal(t, addPermitListResp.UpdatedResource.Id, vmID)

	return s, ctx
}

func getTestVirtualMachine() armcompute.VirtualMachine {
	return armcompute.VirtualMachine{
		Location: to.Ptr(location),
		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: &armcompute.ImageReference{
					Offer:     to.Ptr("debian-10"),
					Publisher: to.Ptr("Debian"),
					SKU:       to.Ptr("10"),
					Version:   to.Ptr("latest"),
				},
			},
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes("Standard_B1s")),
			},
			OSProfile: &armcompute.OSProfile{ //
				ComputerName:  to.Ptr("sample-compute"),
				AdminUsername: to.Ptr("sample-user"),
				AdminPassword: to.Ptr("Password01!@#"),
			},
		},
	}
}

func getVmId() string {
	return "/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroup + "/providers/Microsoft.Compute/virtualMachines/" + vmNamePrefix + "-" + uuid.NewString()
}
