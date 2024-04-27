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

package azure

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// Gets subscription ID defined in environment variable
func GetAzureSubscriptionId() string {
	subscriptionId := os.Getenv("INVISINETS_AZURE_SUBSCRIPTION_ID")
	if subscriptionId == "" {
		panic("Environment variable 'INVISINETS_AZURE_SUBSCRIPTION_ID' must be set")
	}
	return subscriptionId
}

// Creates a resource groups client
func createResourceGroupsClient(subscriptionId string) *armresources.ResourceGroupsClient {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		panic(fmt.Sprintf("Error while getting azure credentials during setup: %v", err))
	}
	clientFactory, err := armresources.NewClientFactory(subscriptionId, cred, nil)
	if err != nil {
		panic(fmt.Sprintf("Error while creating client factory during setup: %v", err))
	}

	return clientFactory.NewResourceGroupsClient()
}

func SetupAzureTesting(subscriptionId string, testName string) string {
	resourceGroupName := "inv-" + testName
	if os.Getenv("GH_RUN_NUMBER") != "" {
		resourceGroupName += "-" + os.Getenv("GH_RUN_NUMBER")
	}
	resourceGroupsClient := createResourceGroupsClient(subscriptionId)
	_, err := resourceGroupsClient.CreateOrUpdate(context.Background(), resourceGroupName, armresources.ResourceGroup{
		Location: to.Ptr("westus"),
	}, nil)
	if err != nil {
		panic(fmt.Sprintf("Error while creating resource group: %v", err))
	}
	return resourceGroupName
}

func TeardownAzureTesting(subscriptionId string, resourceGroupName string) {
	if os.Getenv("INVISINETS_TEST_PERSIST") != "1" {
		ctx := context.Background()
		resourceGroupsClient := createResourceGroupsClient(subscriptionId)
		poller, err := resourceGroupsClient.BeginDelete(ctx, resourceGroupName, nil)
		if err != nil {
			// If deletion fails: refer to https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/delete-resource-group
			panic(fmt.Sprintf("Error while deleting resource group: %v", err))
		}
		_, err = poller.PollUntilDone(ctx, nil)
		if err != nil {
			panic(fmt.Sprintf("Error while waiting for resource group deletion: %v", err))
		}
	}
}

func GetTestVmParameters(location string) armcompute.VirtualMachine {
	return armcompute.VirtualMachine{
		Location: to.Ptr(location),
		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: &armcompute.ImageReference{
					// When changing, make sure it's compatible with the Network Watcher Agent extension which is needed for connectivity checks
					// https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/network-watcher-linux?toc=%2Fazure%2Fnetwork-watcher#operating-system
					Offer:     to.Ptr("0001-com-ubuntu-minimal-jammy"),
					Publisher: to.Ptr("canonical"),
					SKU:       to.Ptr("minimal-22_04-lts-gen2"),
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

func InitializeServer(orchestratorAddr string) *azurePluginServer {
	return &azurePluginServer{
		orchestratorServerAddr: orchestratorAddr,
	}
}

// TODO @seankimkdy: figure out how to merge this with Azure SDK handler
func GetVmIpAddress(vmId string) (string, error) {
	resourceIdInfo, err := getResourceIDInfo(vmId)
	if err != nil {
		return "", fmt.Errorf("unable to parse VM ID: %w", err)
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("unable to get azure credentials: %w", err)
	}
	computeClientFactory, err := armcompute.NewClientFactory(resourceIdInfo.SubscriptionID, cred, nil)
	if err != nil {
		return "", fmt.Errorf("unable to create compute client factory: %w", err)
	}
	networkClientFactory, err := armnetwork.NewClientFactory(resourceIdInfo.SubscriptionID, cred, nil)
	if err != nil {
		return "", fmt.Errorf("unable to create network client factory: %w", err)
	}
	virtualMachinesClient := computeClientFactory.NewVirtualMachinesClient()
	interfacesClient := networkClientFactory.NewInterfacesClient()
	ctx := context.Background()

	virtualMachine, err := virtualMachinesClient.Get(ctx, resourceIdInfo.ResourceGroupName, resourceIdInfo.ResourceName, nil)
	if err != nil {
		return "", fmt.Errorf("unable to get virtual machine: %w", err)
	}

	networkInterfaceIdSplit := strings.Split(*virtualMachine.Properties.NetworkProfile.NetworkInterfaces[0].ID, "/")
	networkInterfaceName := networkInterfaceIdSplit[len(networkInterfaceIdSplit)-1]
	networkInterface, err := interfacesClient.Get(ctx, resourceIdInfo.ResourceGroupName, networkInterfaceName, &armnetwork.InterfacesClientGetOptions{Expand: nil})
	if err != nil {
		return "", fmt.Errorf("unable to get network interface: %w", err)
	}

	return *networkInterface.Properties.IPConfigurations[0].Properties.PrivateIPAddress, nil
}

func RunPingConnectivityCheck(sourceVmResourceID string, destinationIPAddress string) (bool, error) {
	resourceIDInfo, err := getResourceIDInfo(sourceVmResourceID)
	if err != nil {
		return false, fmt.Errorf("unable to parse resource ID: %w", err)
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return false, fmt.Errorf("unable to get azure credentials: %w", err)
	}
	ctx := context.Background()

	// Fetch source virtual machine for location
	virtualMachinesClient, err := armcompute.NewVirtualMachinesClient(resourceIDInfo.SubscriptionID, cred, nil)
	if err != nil {
		return false, fmt.Errorf("unable to create virtual machines client: %w", err)
	}
	vm, err := virtualMachinesClient.Get(ctx, resourceIDInfo.ResourceGroupName, resourceIDInfo.ResourceName, &armcompute.VirtualMachinesClientGetOptions{Expand: nil})
	if err != nil {
		return false, fmt.Errorf("unable to get virtual machine: %w", err)
	}

	// Install Network Watcher Agent VM extension
	virtualMachineExtensionsClient, err := armcompute.NewVirtualMachineExtensionsClient(resourceIDInfo.SubscriptionID, cred, nil)
	if err != nil {
		return false, fmt.Errorf("unable to create virtual machine extensions client: %w", err)
	}
	extensionParameters := armcompute.VirtualMachineExtension{
		Location: vm.Location,
		Properties: &armcompute.VirtualMachineExtensionProperties{
			Publisher:          to.Ptr("Microsoft.Azure.NetworkWatcher"),
			Type:               to.Ptr("NetworkWatcherAgentLinux"),
			TypeHandlerVersion: to.Ptr("1.4"),
		},
	}
	vmExtensionPollerResponse, err := virtualMachineExtensionsClient.BeginCreateOrUpdate(ctx, resourceIDInfo.ResourceGroupName, resourceIDInfo.ResourceName, "network-watcher-agent-linux", extensionParameters, nil)
	if err != nil {
		return false, fmt.Errorf("unable to create or update virtual machine extension: %w", err)
	}
	_, err = vmExtensionPollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("unable to poll create or update virtual machine extension: %w", err)
	}

	// Run connectivity check
	watchersClient, err := armnetwork.NewWatchersClient(resourceIDInfo.SubscriptionID, cred, nil)
	if err != nil {
		return false, fmt.Errorf("unable to create watchers client: %w", err)
	}
	connectivityParameters := armnetwork.ConnectivityParameters{
		Destination:        &armnetwork.ConnectivityDestination{Address: to.Ptr(destinationIPAddress)},
		Source:             &armnetwork.ConnectivitySource{ResourceID: to.Ptr(sourceVmResourceID)},
		PreferredIPVersion: to.Ptr(armnetwork.IPVersionIPv4),
		Protocol:           to.Ptr(armnetwork.ProtocolIcmp),
	}
	// Retries up to 5 times
	for i := 0; i < 5; i++ {
		checkConnectivityPollerResponse, err := watchersClient.BeginCheckConnectivity(ctx, "NetworkWatcherRG", fmt.Sprintf("NetworkWatcher_%s", *vm.Location), connectivityParameters, nil)
		if err != nil {
			return false, err
		}
		resp, err := checkConnectivityPollerResponse.PollUntilDone(ctx, nil)
		if err != nil {
			return false, err
		}
		// TODO @seankimkdy: Unclear why ConnectionStatus returns "Reachable" which is not a valid armnetwork.ConnectionStatus constant (https://github.com/Azure/azure-sdk-for-go/issues/21777)
		if *resp.ConnectivityInformation.ConnectionStatus == armnetwork.ConnectionStatus("Reachable") {
			return true, nil
		}
	}

	return false, nil
}
