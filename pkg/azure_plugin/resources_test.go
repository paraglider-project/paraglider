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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/NetSys/invisinets/pkg/invisinetspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	vmURI         string = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
	aksURI        string = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks"
	badResourceID string = "badResourceID"
	namespace     string = "namespace"
)

func getFakeInterface() armnetwork.Interface {
	name := "nic-name"
	id := "nic-id/" + name
	ipConfigName := "ip-config"
	address := "address"
	subnet := getFakeSubnet()
	nsg := getFakeNSG()
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
			NetworkSecurityGroup: &nsg,
		},
	}
}

func getFakeNSG() armnetwork.SecurityGroup {
	id := "nsg-id"
	return armnetwork.SecurityGroup{
		ID:   &id,
		Name: to.Ptr("nsg-name"),
	}
}

func getFakeSubnet() armnetwork.Subnet {
	id := fmt.Sprintf("a/b/c/d/e/f/g/h/%s/subnet-id", getInvisinetsNamespacePrefix(namespace))
	address := "address"
	return armnetwork.Subnet{
		ID: &id,
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: &address,
			NetworkSecurityGroup: &armnetwork.SecurityGroup{
				ID:   getFakeNSG().ID,
				Name: getFakeNSG().Name,
			},
		},
	}
}

func getFakeVirtualMachine(networkInfo bool) armcompute.VirtualMachine {
	name := "vm-name"
	location := "location"
	vm := armcompute.VirtualMachine{
		Name:       &name,
		Location:   &location,
		ID:         to.Ptr(vmURI),
		Properties: &armcompute.VirtualMachineProperties{},
	}
	if networkInfo {
		vm.Properties.NetworkProfile = &armcompute.NetworkProfile{
			NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
				{ID: getFakeInterface().ID},
			},
		}
	}
	return vm
}

func getFakeCluster(networkInfo bool) armcontainerservice.ManagedCluster {
	name := "cluster-name"
	location := "location"
	cluster := armcontainerservice.ManagedCluster{
		Name:       &name,
		Location:   &location,
		ID:         to.Ptr(aksURI),
		Properties: &armcontainerservice.ManagedClusterProperties{},
	}
	if networkInfo {
		cluster.Properties.AgentPoolProfiles = []*armcontainerservice.ManagedClusterAgentPoolProfile{
			{
				VnetSubnetID: getFakeSubnet().ID,
			},
		}
	}
	return cluster
}

func getFakeVMGenericResource() armresources.GenericResource {
	vm := getFakeVirtualMachine(false)
	return armresources.GenericResource{
		ID:       vm.ID,
		Location: vm.Location,
		Type:     to.Ptr("Microsoft.Compute/VirtualMachines"),
		Properties: armcompute.VirtualMachineProperties{
			NetworkProfile: &armcompute.NetworkProfile{
				NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
					{ID: getFakeInterface().ID},
				},
			},
		},
	}
}

func getFakeAKSGenericResource() armresources.GenericResource {
	cluster := getFakeCluster(false)
	return armresources.GenericResource{
		ID:       cluster.ID,
		Location: cluster.Location,
		Type:     to.Ptr("Microsoft.ContainerService/managedClusters"),
		Properties: armcontainerservice.ManagedClusterProperties{
			AgentPoolProfiles: []*armcontainerservice.ManagedClusterAgentPoolProfile{
				{
					VnetSubnetID: getFakeSubnet().ID,
				},
			},
		},
	}
}

func getFakeVMResourceDescription(vm *armcompute.VirtualMachine) (*invisinetspb.ResourceDescription, error) {
	desc, err := json.Marshal(vm)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return &invisinetspb.ResourceDescription{Description: desc, Id: *vm.ID}, nil
}

func getFakeClusterResourceDescription(cluster *armcontainerservice.ManagedCluster) (*invisinetspb.ResourceDescription, error) {
	desc, err := json.Marshal(cluster)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return &invisinetspb.ResourceDescription{Description: desc, Id: *cluster.ID}, nil
}

func getFakeResourceInfo(name string) ResourceIDInfo {
	rgName := "rg-name"
	return ResourceIDInfo{
		ResourceName:      name,
		ResourceGroupName: rgName,
		SubscriptionID:    "00000000-0000-0000-0000-000000000000",
	}
}

func setupMockFunctions(mockAzureHandler *MockAzureSDKHandler) (*armcompute.VirtualMachine, *armcontainerservice.ManagedCluster) {
	fakeNIC := getFakeInterface()
	fakeNSG := getFakeNSG()
	fakeSubnet := getFakeSubnet()
	fakeVm := getFakeVirtualMachine(true)
	fakeCluster := getFakeCluster(true)
	ctx := context.Background()
	fakeAKSGeneric := getFakeAKSGenericResource()
	fakeVMGeneric := getFakeVMGenericResource()
	mockAzureHandler.On("GetResource", ctx, vmURI).Return(&fakeVMGeneric, nil)
	mockAzureHandler.On("GetResource", ctx, aksURI).Return(&fakeAKSGeneric, nil)
	mockAzureHandler.On("GetResource", ctx, badResourceID).Return(nil, errors.New("Resource with ID is not found"))
	mockAzureHandler.On("GetNetworkInterface", ctx, *fakeNIC.Name).Return(&fakeNIC, nil)
	mockAzureHandler.On("GetSecurityGroup", ctx, *fakeNSG.Name).Return(&fakeNSG, nil) // TODO: have this depend on the security group ID?
	mockAzureHandler.On("GetSubnetByID", ctx, *fakeSubnet.ID).Return(&fakeSubnet, nil)
	mockAzureHandler.On("CreateNetworkInterface", ctx, *fakeSubnet.ID, *fakeVm.Location, mock.Anything).Return(&fakeNIC, nil)
	mockAzureHandler.On("CreateVirtualMachine", ctx, mock.Anything, *fakeVm.Name).Return(&fakeVm, nil)
	mockAzureHandler.On("GetNetworkInterface", ctx, *fakeNIC.Name).Return(&fakeNIC, nil)
	mockAzureHandler.On("CreateAKSCluster", ctx, mock.Anything, *fakeCluster.Name).Return(&fakeCluster, nil)
	return &fakeVm, &fakeCluster
}

func TestGetAndCheckResourceState(t *testing.T) {
	mockAzureHandler := SetupMockAzureSDKHandler()
	vm, cluster := setupMockFunctions(mockAzureHandler)

	// Bad resource ID
	_, err := GetAndCheckResourceState(context.Background(), mockAzureHandler, "badResourceID", namespace)
	require.Error(t, err)

	// Test for VM correct namespace
	vmInfo, err := GetAndCheckResourceState(context.Background(), mockAzureHandler, vmURI, namespace)

	require.NoError(t, err)
	assert.Equal(t, vmInfo.SubnetID, *getFakeSubnet().ID)
	assert.Equal(t, vmInfo.Address, *getFakeInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
	assert.Equal(t, vmInfo.Location, *vm.Location)
	assert.Equal(t, *vmInfo.NSG.ID, *getFakeNSG().ID)

	// Test for VM incorrect namespace
	_, err = GetAndCheckResourceState(context.Background(), mockAzureHandler, vmURI, "badNamespace")

	require.Error(t, err)

	// Test for AKS
	aksInfo, err := GetNetworkInfoFromResource(context.Background(), mockAzureHandler, aksURI)

	require.NoError(t, err)
	assert.Equal(t, aksInfo.SubnetID, *getFakeSubnet().ID)
	assert.Equal(t, aksInfo.Address, *getFakeSubnet().Properties.AddressPrefix)
	assert.Equal(t, aksInfo.Location, *cluster.Location)
	assert.Equal(t, *aksInfo.NSG.ID, *getFakeNSG().ID)
}

func TestGetNetworkInfoFromResource(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	vm, cluster := setupMockFunctions(mockAzureHandler)

	// Bad resource ID
	_, err := GetNetworkInfoFromResource(context.Background(), mockAzureHandler, "badResourceID")
	require.Error(t, err)

	// Test for VM
	vmInfo, err := GetNetworkInfoFromResource(context.Background(), mockAzureHandler, vmURI)

	require.NoError(t, err)
	assert.Equal(t, vmInfo.SubnetID, *getFakeSubnet().ID)
	assert.Equal(t, vmInfo.Address, *getFakeInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
	assert.Equal(t, vmInfo.Location, *vm.Location)
	assert.Equal(t, *vmInfo.NSG.ID, *getFakeNSG().ID)

	// Test for AKS
	aksInfo, err := GetNetworkInfoFromResource(context.Background(), mockAzureHandler, aksURI)

	require.NoError(t, err)
	assert.Equal(t, aksInfo.SubnetID, *getFakeSubnet().ID)
	assert.Equal(t, aksInfo.Address, *getFakeSubnet().Properties.AddressPrefix)
	assert.Equal(t, aksInfo.Location, *cluster.Location)
	assert.Equal(t, *aksInfo.NSG.ID, *getFakeNSG().ID)
}

func TestReadAndProvisionResource(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	setupMockFunctions(mockAzureHandler)
	vm := getFakeVirtualMachine(false)
	cluster := getFakeCluster(false)

	// Test for VM
	resourceDescription, err := getFakeVMResourceDescription(&vm)
	require.NoError(t, err)

	subnet := getFakeSubnet()
	resourceInfo := getFakeResourceInfo(*vm.Name)
	ip, err := ReadAndProvisionResource(context.Background(), resourceDescription, &subnet, &resourceInfo, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, ip, *getFakeInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)

	// Test for AKS
	resourceInfo = getFakeResourceInfo(*cluster.Name)
	resourceDescriptionCluster, err := getFakeClusterResourceDescription(&cluster)
	require.NoError(t, err)
	ip, err = ReadAndProvisionResource(context.Background(), resourceDescriptionCluster, &subnet, &resourceInfo, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, ip, *getFakeSubnet().Properties.AddressPrefix)
}

func TestGetResourceInfoFromResourceDesc(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	setupMockFunctions(mockAzureHandler)
	vm := getFakeVirtualMachine(false)
	cluster := getFakeCluster(false)

	// Test for VM
	resourceDescription, err := getFakeVMResourceDescription(&vm)
	require.NoError(t, err)

	resourceInfo, err := GetResourceInfoFromResourceDesc(context.Background(), resourceDescription)

	require.NoError(t, err)
	assert.Equal(t, resourceInfo.ResourceName, *vm.Name)
	assert.Equal(t, resourceInfo.ResourceID, *vm.ID)
	assert.Equal(t, resourceInfo.Location, *vm.Location)

	// Test for AKS
	resourceDescriptionCluster, err := getFakeClusterResourceDescription(&cluster)
	require.NoError(t, err)
	resourceInfo, err = GetResourceInfoFromResourceDesc(context.Background(), resourceDescriptionCluster)

	require.NoError(t, err)
	assert.Equal(t, resourceInfo.ResourceName, *cluster.Name)
	assert.Equal(t, resourceInfo.ResourceID, *cluster.ID)
	assert.Equal(t, resourceInfo.Location, *cluster.Location)
}

func TestAzureVMGetNetworkInfo(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	vm, _ := setupMockFunctions(mockAzureHandler)

	vmHandler := &AzureVM{}
	resource := getFakeVMGenericResource()

	netInfo, err := vmHandler.GetNetworkInfo(&resource, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, netInfo.SubnetID, *getFakeSubnet().ID)
	assert.Equal(t, netInfo.Address, *getFakeInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
	assert.Equal(t, netInfo.Location, *vm.Location)
	assert.Equal(t, *netInfo.NSG.ID, *getFakeNSG().ID)
}

func TestAzureVMFromResourceDecription(t *testing.T) {
	vmHandler := &AzureVM{}
	fakeVm := getFakeVirtualMachine(false)

	resourceDescription, err := getFakeVMResourceDescription(&fakeVm)
	require.NoError(t, err)
	vm, err := vmHandler.FromResourceDecription(resourceDescription.Description)

	require.NoError(t, err)
	assert.Equal(t, vm.Name, fakeVm.Name)

}

func TestAzureVMCreateWithNetwork(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	vm, _ := setupMockFunctions(mockAzureHandler)

	vmHandler := &AzureVM{}

	subnet := getFakeSubnet()
	resourceInfo := &ResourceIDInfo{ResourceName: *vm.Name}
	ip, err := vmHandler.CreateWithNetwork(context.Background(), vm, &subnet, resourceInfo, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, ip, *getFakeInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
}

func TestAzureAKSGetNetworkInfo(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	_, cluster := setupMockFunctions(mockAzureHandler)

	aksHandler := &AzureAKS{}
	resource := getFakeAKSGenericResource()

	netInfo, err := aksHandler.GetNetworkInfo(&resource, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, netInfo.SubnetID, *getFakeSubnet().ID)
	assert.Equal(t, netInfo.Address, *getFakeSubnet().Properties.AddressPrefix)
	assert.Equal(t, netInfo.Location, *cluster.Location)
	assert.Equal(t, *netInfo.NSG.ID, *getFakeNSG().ID)
}

func TestAzureAKSFromResourceDecription(t *testing.T) {
	fakeCluster := getFakeCluster(false)
	aksHandler := &AzureAKS{}

	resourceDescription, err := getFakeClusterResourceDescription(&fakeCluster)
	require.NoError(t, err)
	cluster, err := aksHandler.FromResourceDecription(resourceDescription.Description)

	require.NoError(t, err)
	assert.Equal(t, cluster.Name, cluster.Name)

}

func TestAzureAKSCreateWithNetwork(t *testing.T) {
	mockAzureHandler := &MockAzureSDKHandler{}
	_, cluster := setupMockFunctions(mockAzureHandler)

	aksHandler := &AzureAKS{}

	subnet := getFakeSubnet()
	resourceInfo := &ResourceIDInfo{ResourceName: *cluster.Name}
	ip, err := aksHandler.CreateWithNetwork(context.Background(), cluster, &subnet, resourceInfo, mockAzureHandler)

	require.NoError(t, err)
	assert.Equal(t, ip, *getFakeSubnet().Properties.AddressPrefix)
}
