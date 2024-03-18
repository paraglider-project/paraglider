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
	"errors"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/NetSys/invisinets/pkg/invisinetspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	vmResourceID  string = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
	aksResourceID string = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks"
	badResourceID string = "badResourceID"
	namespace     string = "namespace"
)

func getFakeNIC() armnetwork.Interface {
	name := "nic-name"
	id := "nic-id"
	ipConfigName := "ip-config"
	address := "address"
	subnet := getFakeSubnet()
	return armnetwork.Interface{
		Name: &name,
		ID:   &id,
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Name: &ipConfigName,
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						PrivateIPAddress: &address,
						Subnet:           &subnet,
					},
				},
			},
		},
	}
}

func getFakeNSG() armnetwork.SecurityGroup {
	id := "nsg-id"
	return armnetwork.SecurityGroup{
		ID: &id,
	}
}

func getFakeSubnet() armnetwork.Subnet {
	id := "subnet-id"
	address := "address"
	return armnetwork.Subnet{
		ID: &id,
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: &address,
			NetworkSecurityGroup: &armnetwork.SecurityGroup{
				ID: getFakeNSG().ID,
			},
		},
	}
}

func getFakeVM() armcompute.VirtualMachine {
	name := "vm-name"
	location := "location"
	return armcompute.VirtualMachine{
		Name:     &name,
		Location: &location,
	}
}

func getFakeCluster() armcontainerservice.ManagedCluster {
	name := "cluster-name"
	location := "location"
	return armcontainerservice.ManagedCluster{
		Name:     &name,
		Location: &location,
	}
}

func getFakeVMGenericResource() armresources.GenericResource {
	vm := getFakeVM()
	return armresources.GenericResource{
		ID:       vm.ID,
		Location: vm.Location,
		Properties: map[string]interface{}{
			"networkProfile": map[string]interface{}{
				"networkInterfaces": []map[string]interface{}{
					{"id": getFakeNIC().ID},
				},
			},
		},
	}
}

func getFakeAKSGenericResource() armresources.GenericResource {
	location := "location"
	id := aksResourceID
	return armresources.GenericResource{
		ID:       &id,
		Location: &location,
		Properties: map[string]interface{}{
			"agentPoolProfiles": []map[string]interface{}{
				{
					"vnetSubnetID": getFakeSubnet().ID,
				},
			},
		},
	}
}

func getFakeVMResourceDescription() (*invisinetspb.ResourceDescription, error) {
	vm := getFakeVM()
	desc, err := json.Marshal(vm)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return &invisinetspb.ResourceDescription{Description: desc}, nil
}

func getFakeClusterResourceDescription() (*invisinetspb.ResourceDescription, error) {
	cluster := getFakeCluster()
	desc, err := json.Marshal(cluster)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return &invisinetspb.ResourceDescription{Description: desc}, nil
}

func getFakeResourceInfo() ResourceIDInfo {
	name := "name"
	rgName := "rg-name"
	return ResourceIDInfo{
		ResourceName:      name,
		ResourceGroupName: rgName,
		SubscriptionID:    "00000000-0000-0000-0000-000000000000",
	}
}

func setupMockFunctions(mockAzureHandler *MockAzureSDKHandler) {
	// TODO: Make these variables actually exist
	fakeNIC := getFakeNIC()
	fakeNSG := getFakeNSG()
	fakeSubnet := getFakeSubnet()
	fakeVm := getFakeVM()
	fakeCluster := getFakeCluster()
	ctx := context.Background()
	mockAzureHandler.On("GetResource", ctx, vmResourceID).Return(getFakeVMGenericResource(), nil)
	mockAzureHandler.On("GetResource", ctx, aksResourceID).Return(getFakeAKSGenericResource(), nil)
	mockAzureHandler.On("GetResource", ctx, badResourceID).Return(nil, errors.New("Resource with ID is not found"))
	mockAzureHandler.On("GetNetworkInterface", ctx, fakeNIC.ID).Return(&fakeNIC, nil)
	mockAzureHandler.On("GetSecurityGroup", ctx, fakeNSG.ID).Return(&fakeNSG, nil) // TODO: have this depend on the security group ID?
	mockAzureHandler.On("GetSubnetByID", ctx, fakeSubnet.ID).Return(&fakeSubnet, nil)
	mockAzureHandler.On("CreateNetworkInterface", ctx, fakeSubnet.ID, fakeVm.Location, fakeNIC.Name).Return(&fakeNIC, nil)
	mockAzureHandler.On("CreateVirtualMachine", ctx, fakeVm, fakeVm.Name).Return(&fakeVm, nil)
	mockAzureHandler.On("GetNetworkInterface", ctx, fakeNIC.ID).Return(&fakeNIC, nil)
	mockAzureHandler.On("CreateAKSCluster", ctx, fakeCluster, fakeCluster.Name).Return(&fakeCluster, nil)
}

func TestGetAndCheckResourceState(t *testing.T) {
	mockAzureHandler := SetupMockAzureSDKHandler()
	setupMockFunctions(mockAzureHandler)

	// Bad resource ID
	_, err := GetAndCheckResourceState(context.Background(), mockAzureHandler, "badResourceID", namespace)
	require.Error(t, err)

	// Test for VM correct namespace
	vmInfo, err := GetAndCheckResourceState(context.Background(), mockAzureHandler, vmResourceID, namespace)

	require.NoError(t, err)
	assert.Equal(t, vmInfo.SubnetID, getFakeSubnet().ID)
	assert.Equal(t, vmInfo.Address, getFakeNIC().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
	assert.Equal(t, vmInfo.Location, getFakeVM().Location)
	assert.Equal(t, vmInfo.NSG.ID, getFakeNIC().ID)

	// Test for VM incorrect namespace
	_, err = GetAndCheckResourceState(context.Background(), mockAzureHandler, vmResourceID, "badNamespace")

	require.Error(t, err)

	// Test for AKS
	aksInfo, err := GetNetworkInfoFromResource(context.Background(), mockAzureHandler, aksResourceID)

	require.NoError(t, err)
	assert.Equal(t, aksInfo.SubnetID, getFakeSubnet().ID)
	assert.Equal(t, aksInfo.Address, getFakeSubnet().Properties.AddressPrefix)
	assert.Equal(t, aksInfo.Location, getFakeCluster().Location)
	assert.Equal(t, aksInfo.NSG.ID, getFakeSubnet().Properties.NetworkSecurityGroup.ID)
}

func TestGetNetworkInfoFromResource(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	setupMockFunctions(mockAzureHandler)

	// Bad resource ID
	_, err := GetNetworkInfoFromResource(context.Background(), mockAzureHandler, "badResourceID")
	require.Error(t, err)

	// Test for VM
	vmInfo, err := GetNetworkInfoFromResource(context.Background(), mockAzureHandler, vmResourceID)

	require.NoError(t, err)
	assert.Equal(t, vmInfo.SubnetID, getFakeSubnet().ID)
	assert.Equal(t, vmInfo.Address, getFakeNIC().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
	assert.Equal(t, vmInfo.Location, getFakeVM().Location)
	assert.Equal(t, vmInfo.NSG.ID, getFakeNIC().ID)

	// Test for AKS
	aksInfo, err := GetNetworkInfoFromResource(context.Background(), mockAzureHandler, aksResourceID)

	require.NoError(t, err)
	assert.Equal(t, aksInfo.SubnetID, getFakeSubnet().ID)
	assert.Equal(t, aksInfo.Address, getFakeSubnet().Properties.AddressPrefix)
	assert.Equal(t, aksInfo.Location, getFakeCluster().Location)
	assert.Equal(t, aksInfo.NSG.ID, getFakeSubnet().Properties.NetworkSecurityGroup.ID)
}

func TestReadAndProvisionResource(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	setupMockFunctions(mockAzureHandler)

	// Test for VM
	resourceDescription, err := getFakeVMResourceDescription()
	require.NoError(t, err)

	subnet := getFakeSubnet()
	resourceInfo := getFakeResourceInfo()
	ip, err := ReadAndProvisionResource(context.Background(), resourceDescription, &subnet, &resourceInfo, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, ip, getFakeNIC().Properties.IPConfigurations[0].Properties.PrivateIPAddress) // TODO: Fill these in with the correct value

	// Test for AKS
	resourceDescriptionCluster, err := getFakeClusterResourceDescription()
	require.NoError(t, err)
	ip, err = ReadAndProvisionResource(context.Background(), resourceDescriptionCluster, &subnet, &resourceInfo, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, ip, getFakeSubnet().Properties.AddressPrefix) // TODO: Fill these in with the correct value
}

func TestAzureVMGetNetworkInfo(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	setupMockFunctions(mockAzureHandler)

	vmHandler := &AzureVM{}
	resource := getFakeVMGenericResource()

	netInfo, err := vmHandler.GetNetworkInfo(&resource, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, netInfo.SubnetID, getFakeSubnet().ID)
	assert.Equal(t, netInfo.Address, getFakeNIC().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
	assert.Equal(t, netInfo.Location, getFakeVM().Location)
	assert.Equal(t, netInfo.NSG.ID, getFakeNIC().ID)
}

func TestAzureVMFromResourceDecription(t *testing.T) {
	vmHandler := &AzureVM{}

	resourceDescription, err := getFakeVMResourceDescription()
	require.NoError(t, err)
	vm, err := vmHandler.FromResourceDecription(resourceDescription.Description)

	require.NoError(t, err)
	assert.Equal(t, vm.Name, getFakeVM().ID) // TODO: Fill these in with the correct value

}

func TestAzureVMCreateWithNetwork(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	setupMockFunctions(mockAzureHandler)

	vmHandler := &AzureVM{}

	vm := getFakeVM()
	subnet := getFakeSubnet()
	resourceInfo := &ResourceIDInfo{ResourceName: *vm.Name}
	ip, err := vmHandler.CreateWithNetwork(context.Background(), &vm, &subnet, resourceInfo, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, ip, getFakeNIC().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
}

func TestAzureAKSGetNetworkInfo(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	setupMockFunctions(mockAzureHandler)

	aksHandler := &AzureAKS{}
	resource := getFakeAKSGenericResource()

	netInfo, err := aksHandler.GetNetworkInfo(&resource, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, netInfo.SubnetID, getFakeSubnet().ID)
	assert.Equal(t, netInfo.Address, getFakeSubnet().Properties.AddressPrefix)
	assert.Equal(t, netInfo.Location, getFakeCluster().Location)
	assert.Equal(t, netInfo.NSG.ID, getFakeSubnet().Properties.NetworkSecurityGroup.ID)
}

func TestAzureAKSFromResourceDecription(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	setupMockFunctions(mockAzureHandler)

	aksHandler := &AzureAKS{}

	resourceDescription, err := getFakeClusterResourceDescription()
	require.NoError(t, err)
	cluster, err := aksHandler.FromResourceDecription(resourceDescription.Description)

	require.NoError(t, err)
	assert.Equal(t, cluster.Name, getFakeCluster().Name) // TODO: Fill these in with the correct value

}

func TestAzureAKSCreateWithNetwork(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	setupMockFunctions(mockAzureHandler)

	aksHandler := &AzureAKS{}

	cluster := getFakeCluster()
	subnet := getFakeSubnet()
	resourceInfo := &ResourceIDInfo{ResourceName: *getFakeCluster().Name}
	ip, err := aksHandler.CreateWithNetwork(context.Background(), &cluster, &subnet, resourceInfo, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, ip, getFakeSubnet().Properties.AddressPrefix)
}
