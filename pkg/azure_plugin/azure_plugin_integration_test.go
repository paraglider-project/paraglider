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
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	vmName     = "sample-vm"
	diskName   = "sample-disk"
	location   = "westus"
	apiVersion = "2019-07-01"
)

var (
	subscriptionId = os.Getenv("INVISINETS_AZURE_SUBSCRIPTION_ID")
	resourceGroup  = os.Getenv("INVISINETS_AZURE_RESOURCE_GROUP_NAME")
)

func teardown(resourceIDs *[]string) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		panic(fmt.Sprintf("Error while getting azure credentials in teardown, you need to manually de-allocate resources: %v", err))
	}

	resourcesClient, err := armresources.NewClient(subscriptionId, cred, nil)
	ctx := context.Background()
	if err != nil {
		panic(fmt.Sprintf("Error while creating client, you need to manually de-allocate resources: %v", err))
	}

	for _, resourceID := range *resourceIDs {
		poller, err := resourcesClient.BeginDeleteByID(ctx, resourceID, apiVersion, nil)
		if err != nil {
			panic(fmt.Sprintf("Error while deleting resource %s, you need to manually de-allocate resources: %v", resourceID, err))
		}

		_, err = poller.PollUntilDone(ctx, nil)
		if err != nil {
			panic(fmt.Sprintf("Error while deleting resource %s, you need to manually de-allocate resources: %v", resourceID, err))
		}
	}

}

// This test will test the following:
// 1. Create a resource
// 2. Add a permit list
// 3. Get the permit list
func TestAddAndGetPermitList(t *testing.T) {
	resourceIDs := make([]string, 0)
	s := &azurePluginServer{
		azureHandler: &azureSDKHandler{},
	}
	ctx := context.Background()
	defer teardown(&resourceIDs)

	parameters := armcompute.VirtualMachine{
		Location: to.Ptr(location),
		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: &armcompute.ImageReference{
					Offer:     to.Ptr("WindowsServer"),
					Publisher: to.Ptr("MicrosoftWindowsServer"),
					SKU:       to.Ptr("2019-Datacenter"),
					Version:   to.Ptr("latest"),
				},
				OSDisk: &armcompute.OSDisk{
					Name:         to.Ptr(diskName),
					CreateOption: to.Ptr(armcompute.DiskCreateOptionTypesFromImage),
					Caching:      to.Ptr(armcompute.CachingTypesReadWrite),
					ManagedDisk: &armcompute.ManagedDiskParameters{
						StorageAccountType: to.Ptr(armcompute.StorageAccountTypesStandardLRS),
					},
				},
			},
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes("Standard_F2s")),
			},
			OSProfile: &armcompute.OSProfile{ //
				ComputerName:  to.Ptr("sample-compute"),
				AdminUsername: to.Ptr("sample-user"),
				AdminPassword: to.Ptr("Password01!@#"),
			},
		},
	}
	descriptionJson, err := json.Marshal(parameters)
	if err != nil {
		t.Fatal(err)
	}

	vmID := "/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroup + "/providers/Microsoft.Compute/virtualMachines/" + vmName
	createResourceResp, err := s.CreateResource(ctx, &invisinetspb.ResourceDescription{
		Id:           vmID,
		Description:  descriptionJson,
		AddressSpace: "10.0.0.0/16",
	})

	require.NoError(t, err)
	require.NotNil(t, createResourceResp)
	assert.True(t, createResourceResp.Success)
	assert.Equal(t, createResourceResp.UpdatedResource.Id, vmID)

	resourceIDs = append(resourceIDs, createResourceResp.UpdatedResource.Id)

	vmNic, err := s.azureHandler.GetResourceNIC(ctx, createResourceResp.UpdatedResource.Id)
	require.NoError(t, err)
	require.NotNil(t, vmNic)

	resourceIDs = append(resourceIDs, *vmNic.ID)

	diskId := "/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroup + "/providers/Microsoft.Compute/disks/" + diskName
	resourceIDs = append(resourceIDs, diskId)
	vnetName := InvisinetsPrefix + "-" + location + "-vnet"
	vnetID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s", subscriptionId, resourceGroup, vnetName)
	resourceIDs = append(resourceIDs, vnetID)

	// Add permit list
	permitList := &invisinetspb.PermitList{AssociatedResource: vmID,
		Rules: []*invisinetspb.PermitListRule{&invisinetspb.PermitListRule{Tag: []string{"10.1.0.5"}, Direction: invisinetspb.Direction_OUTBOUND, SrcPort: 80, DstPort: 80, Protocol: 6}}}

	addPermitListResp, err := s.AddPermitListRules(ctx, permitList)
	require.NoError(t, err)
	require.NotNil(t, addPermitListResp)
	assert.True(t, addPermitListResp.Success)
	assert.Equal(t, addPermitListResp.UpdatedResource.Id, vmID)

	// Assert the NSG created is equivalent to the pl rules by using the get permit list api
	getPermitListResp, err := s.GetPermitList(ctx, &invisinetspb.ResourceID{Id: vmID})
	require.NoError(t, err)
	require.NotNil(t, getPermitListResp)

	// get the nsg id from the nsg rule id
	nsgRuleIdParts := strings.Split(getPermitListResp.Rules[0].Id, "/")
	nsgID := strings.Join(nsgRuleIdParts[:len(nsgRuleIdParts)-2], "/")
	resourceIDs = append(resourceIDs, nsgID)

	// add the id to the initial permit list  for an easier comparison
	// because it is only set in the get not the add
	permitList.Rules[0].Id = getPermitListResp.Rules[0].Id
	assert.ElementsMatch(t, getPermitListResp.Rules, permitList.Rules)
}
