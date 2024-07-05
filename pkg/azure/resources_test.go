//go:build unit

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

package azure

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupFakeServerWithState(t *testing.T) (*httptest.Server, *fakeServerState) {
	serverState := &fakeServerState{
		subId:   subID,
		rgName:  rgName,
		nsg:     getFakeNSG(),
		vnet:    getFakeParagliderVirtualNetwork(),
		nic:     getFakeParagliderInterface(),
		subnet:  getFakeParagliderSubnet(),
		vm:      to.Ptr(getFakeVirtualMachine(true)),
		cluster: to.Ptr(getFakeCluster(true)),
	}

	fakeServer, _ := SetupFakeAzureServer(t, serverState)
	return fakeServer, serverState
}

func TestGetAndCheckResourceState(t *testing.T) {
	fakeServer, serverState := setupFakeServerWithState(t)
	defer Teardown(fakeServer)

	handler := &AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	_ = handler.InitializeClients(nil)

	t.Run("GetAndCheckResourceState: Success - Valid Paraglider VM & namespace", func(t *testing.T) {
		vmInfo, err := GetAndCheckResourceState(context.Background(), handler, vmURI, namespace)
		require.NoError(t, err)
		assert.Equal(t, vmInfo.SubnetID, *getFakeParagliderSubnet().ID)
		assert.Equal(t, vmInfo.Address, *getFakeParagliderInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
		assert.Equal(t, vmInfo.Location, *serverState.vm.Location)
		assert.Equal(t, *vmInfo.NSG.ID, *getFakeNSG().ID)
	})

	t.Run("GetAndCheckResourceState: Success - Valid Paraglider AKS & Vnet", func(t *testing.T) {
		aksInfo, err := GetAndCheckResourceState(context.Background(), handler, aksURI, namespace)
		require.NoError(t, err)
		assert.Equal(t, aksInfo.SubnetID, *getFakeParagliderSubnet().ID)
		assert.Equal(t, aksInfo.Address, *getFakeParagliderSubnet().Properties.AddressPrefix)
		assert.Equal(t, aksInfo.Location, *serverState.cluster.Location)
		assert.Equal(t, *aksInfo.NSG.ID, *getFakeNSG().ID)
	})

	t.Run("GetAndCheckResourceState: Failure - Bad Resource ID", func(t *testing.T) {
		_, err := GetAndCheckResourceState(context.Background(), handler, "badResourceID", namespace)
		require.Error(t, err)
	})

	t.Run("GetAndCheckResourceState: Failure - Incorrect VM Namespace", func(t *testing.T) {
		_, err := GetAndCheckResourceState(context.Background(), handler, vmURI, "badNamespace")
		require.Error(t, err)
	})

	t.Run("GetAndCheckResourceState: Success - Attached non-paraglider vnet(with tag)", func(t *testing.T) {
		serverState := &fakeServerState{
			subId:   subID,
			rgName:  rgName,
			nsg:     getFakeNSG(),
			vnet:    getFakeAttachedVirtualNetwork(),
			nic:     getFakeInterface(),
			subnet:  getFakeSubnet(),
			vm:      to.Ptr(getFakeVirtualMachine(true)),
			cluster: to.Ptr(getFakeCluster(true)),
		}
		fakeServer, _ := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		err := handler.InitializeClients(nil)
		require.NoError(t, err)

		vmInfo, err := GetAndCheckResourceState(context.Background(), handler, vmURI, namespace)
		require.NoError(t, err)
		assert.Equal(t, vmInfo.SubnetID, *getFakeSubnet().ID)
		assert.Equal(t, vmInfo.Address, *getFakeInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
		assert.Equal(t, vmInfo.Location, *serverState.vm.Location)
		assert.Equal(t, *vmInfo.NSG.ID, *getFakeNSG().ID)
	})
}

func TestGetNetworkInfoFromResource(t *testing.T) {
	fakeServer, serverState := setupFakeServerWithState(t)
	defer Teardown(fakeServer)

	handler := &AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Bad resource ID
	_, err = GetNetworkInfoFromResource(context.Background(), handler, "badResourceID")
	require.Error(t, err)

	// Test for VM
	vmInfo, err := GetNetworkInfoFromResource(context.Background(), handler, vmURI)

	require.NoError(t, err)
	assert.Equal(t, vmInfo.SubnetID, *getFakeParagliderSubnet().ID)
	assert.Equal(t, vmInfo.Address, *getFakeParagliderInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
	assert.Equal(t, vmInfo.Location, *serverState.vm.Location)
	assert.Equal(t, *vmInfo.NSG.ID, *getFakeNSG().ID)

	// Test for AKS
	aksInfo, err := GetNetworkInfoFromResource(context.Background(), handler, aksURI)

	require.NoError(t, err)
	assert.Equal(t, aksInfo.SubnetID, *getFakeParagliderSubnet().ID)
	assert.Equal(t, aksInfo.Address, *getFakeParagliderSubnet().Properties.AddressPrefix)
	assert.Equal(t, aksInfo.SubnetID, *getFakeParagliderSubnet().ID)
	assert.Equal(t, aksInfo.Address, *getFakeParagliderSubnet().Properties.AddressPrefix)
	assert.Equal(t, aksInfo.Location, *serverState.cluster.Location)
	assert.Equal(t, *aksInfo.NSG.ID, *getFakeNSG().ID)
}

func TestValidateResourceExists(t *testing.T) {
	fakeServer, _ := setupFakeServerWithState(t)
	defer Teardown(fakeServer)

	handler := &AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Test for VM
	existingResource, err := ValidateResourceExists(context.Background(), handler, vmURI)
	require.NoError(t, err)
	require.NotNil(t, existingResource)
	assert.Equal(t, vmURI, *existingResource.ID)

	// Test for AKS
	existingCluster, err := ValidateResourceExists(context.Background(), handler, aksURI)
	require.NoError(t, err)
	require.NotNil(t, existingCluster)
	assert.Equal(t, aksURI, *existingCluster.ID)
}

func TestReadAndProvisionResource(t *testing.T) {
	fakeServer, _ := setupFakeServerWithState(t)
	defer Teardown(fakeServer)

	handler := &AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	vm := getFakeVirtualMachine(false)
	cluster := getFakeCluster(false)

	// Test for VM
	resourceDescription, err := getFakeVMResourceDescription(&vm)
	require.NoError(t, err)

	subnet := getFakeParagliderSubnet()
	resourceInfo := getFakeResourceInfo(*vm.Name)
	ip, err := ReadAndProvisionResource(context.Background(), resourceDescription, subnet, &resourceInfo, handler, []string{})

	require.NoError(t, err)
	assert.Equal(t, ip, *getFakeParagliderInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)

	// Test for AKS
	resourceInfo = getFakeResourceInfo(*cluster.Name)
	resourceDescriptionCluster, err := getFakeClusterResourceDescription(&cluster)
	require.NoError(t, err)
	ip, err = ReadAndProvisionResource(context.Background(), resourceDescriptionCluster, subnet, &resourceInfo, handler, []string{"1.1.1.1/1", "2.2.2.2/2"})

	require.NoError(t, err)
	assert.Equal(t, ip, *getFakeParagliderSubnet().Properties.AddressPrefix)
}

func TestGetResourceInfoFromResourceDesc(t *testing.T) {
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

func TestAzureResourceHandlerVMGetResourceInfoFromDescription(t *testing.T) {
	vm := getFakeVirtualMachine(false)

	vmHandler := &azureResourceHandlerVM{}
	resourceDescription, err := getFakeVMResourceDescription(&vm)
	require.NoError(t, err)
	resourceInfo, err := vmHandler.getResourceInfoFromDescription(context.Background(), resourceDescription)

	require.NoError(t, err)
	assert.Equal(t, resourceInfo.ResourceName, *vm.Name)
}

func TestAzureResourceHandlerVMReadAndProvisionResource(t *testing.T) {
	serverState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vm:     to.Ptr(getFakeVirtualMachine(true)),
		nic:    getFakeParagliderInterface(),
	}
	fakeServer, _ := SetupFakeAzureServer(t, serverState)
	defer Teardown(fakeServer)

	handler := &AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	vm := getFakeVirtualMachine(false)

	vmHandler := &azureResourceHandlerVM{}
	resourceDescription, err := getFakeVMResourceDescription(&vm)
	require.NoError(t, err)

	resourceInfo := getFakeResourceInfo(*vm.Name)
	subnet := getFakeParagliderSubnet()
	ip, err := vmHandler.readAndProvisionResource(context.Background(), resourceDescription, subnet, &resourceInfo, handler, []string{})

	require.NoError(t, err)
	assert.Equal(t, ip, *getFakeParagliderInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
}

func TestAzureVMGetNetworkInfo(t *testing.T) {
	fakeServer, serverState := setupFakeServerWithState(t)
	defer Teardown(fakeServer)

	handler := &AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	vmHandler := &azureResourceHandlerVM{}
	resource := getFakeVMGenericResource()

	netInfo, err := vmHandler.getNetworkInfo(context.Background(), &resource, handler)

	require.NoError(t, err)
	assert.Equal(t, netInfo.SubnetID, *getFakeParagliderSubnet().ID)
	assert.Equal(t, netInfo.Address, *getFakeParagliderInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
	assert.Equal(t, netInfo.Location, *serverState.vm.Location)
	assert.Equal(t, *netInfo.NSG.ID, *getFakeNSG().ID)
}

func TestAzureVMFromResourceDecription(t *testing.T) {
	vmHandler := &azureResourceHandlerVM{}
	fakeVm := getFakeVirtualMachine(false)

	resourceDescription, err := getFakeVMResourceDescription(&fakeVm)
	require.NoError(t, err)
	_, err = vmHandler.fromResourceDecription(resourceDescription.Description)

	require.NoError(t, err)
}

func TestAzureVMCreateWithNetwork(t *testing.T) {
	serverState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vm:     to.Ptr(getFakeVirtualMachine(true)),
		nic:    getFakeParagliderInterface(),
	}
	fakeServer, _ := SetupFakeAzureServer(t, serverState)
	defer Teardown(fakeServer)

	handler := &AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	vmHandler := &azureResourceHandlerVM{}

	subnet := getFakeParagliderSubnet()
	vm := getFakeVirtualMachine(false)
	ip, err := vmHandler.createWithNetwork(context.Background(), &vm, subnet, *vm.Name, handler, []string{})

	require.NoError(t, err)
	assert.Equal(t, ip, *getFakeParagliderInterface().Properties.IPConfigurations[0].Properties.PrivateIPAddress)
}

func TestAzureAKSGetNetworkInfo(t *testing.T) {
	serverState := &fakeServerState{
		subId:   subID,
		rgName:  rgName,
		cluster: to.Ptr(getFakeCluster(true)),
		nsg:     getFakeNSG(),
		subnet:  getFakeParagliderSubnet(),
	}
	fakeServer, _ := SetupFakeAzureServer(t, serverState)
	defer Teardown(fakeServer)

	handler := &AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	aksHandler := &azureResourceHandlerAKS{}
	resource := getFakeAKSGenericResource()

	netInfo, err := aksHandler.getNetworkInfo(context.Background(), &resource, handler)

	require.NoError(t, err)
	assert.Equal(t, netInfo.SubnetID, *getFakeParagliderSubnet().ID)
	assert.Equal(t, netInfo.Address, *getFakeParagliderSubnet().Properties.AddressPrefix)
	assert.Equal(t, netInfo.Location, *serverState.cluster.Location)
	assert.Equal(t, *netInfo.NSG.ID, *getFakeNSG().ID)
}

func TestAzureAKSFromResourceDecription(t *testing.T) {
	fakeCluster := getFakeCluster(false)
	aksHandler := &azureResourceHandlerAKS{}

	resourceDescription, err := getFakeClusterResourceDescription(&fakeCluster)
	require.NoError(t, err)
	_, err = aksHandler.fromResourceDecription(resourceDescription.Description)

	require.NoError(t, err)
}

func TestAzureAKSCreateWithNetwork(t *testing.T) {
	serverState := &fakeServerState{
		subId:   subID,
		rgName:  rgName,
		cluster: to.Ptr(getFakeCluster(true)),
		subnet:  getFakeParagliderSubnet(),
		nsg:     getFakeNSG(),
	}
	fakeServer, _ := SetupFakeAzureServer(t, serverState)
	defer Teardown(fakeServer)

	handler := &AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	aksHandler := &azureResourceHandlerAKS{}

	subnet := getFakeParagliderSubnet()
	cluster := getFakeCluster(false)
	ip, err := aksHandler.createWithNetwork(context.Background(), &cluster, subnet, *cluster.Name, handler, []string{"1.1.1.1/1", "2.2.2.2/2"})

	require.NoError(t, err)
	assert.Equal(t, ip, *getFakeParagliderSubnet().Properties.AddressPrefix)
}

func TestAzureResourceHandlerAKSGetResourceInfoFromDescription(t *testing.T) {
	cluster := getFakeCluster(false)

	aksHandler := &azureResourceHandlerAKS{}
	resourceDescription, err := getFakeClusterResourceDescription(&cluster)
	require.NoError(t, err)
	resourceInfo, err := aksHandler.getResourceInfoFromDescription(context.Background(), resourceDescription)

	require.NoError(t, err)
	assert.Equal(t, resourceInfo.ResourceName, *cluster.Name)
}

func TestAzureResourceHandlerAKSReadAndProvisionResource(t *testing.T) {
	serverState := &fakeServerState{
		subId:   subID,
		rgName:  rgName,
		cluster: to.Ptr(getFakeCluster(true)),
		nsg:     getFakeNSG(),
		subnet:  getFakeParagliderSubnet(),
	}
	fakeServer, _ := SetupFakeAzureServer(t, serverState)
	defer Teardown(fakeServer)

	handler := &AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	cluster := getFakeCluster(false)

	aksHandler := &azureResourceHandlerAKS{}
	resourceDescription, err := getFakeClusterResourceDescription(&cluster)
	require.NoError(t, err)

	resourceInfo := getFakeResourceInfo(*cluster.Name)
	subnet := getFakeParagliderSubnet()
	ip, err := aksHandler.readAndProvisionResource(context.Background(), resourceDescription, subnet, &resourceInfo, handler, []string{"1.1.1.1/1", "2.2.2.2/2"})

	require.NoError(t, err)
	assert.Equal(t, ip, *getFakeParagliderSubnet().Properties.AddressPrefix)
}
