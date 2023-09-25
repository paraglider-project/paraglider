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

func SetupAzureTesting(subscriptionId string, resourceGroupName string) {
	resourceGroupsClient := createResourceGroupsClient(subscriptionId)
	_, err := resourceGroupsClient.CreateOrUpdate(context.Background(), resourceGroupName, armresources.ResourceGroup{
		Location: to.Ptr("westus"),
	}, nil)
	if err != nil {
		panic(fmt.Sprintf("Error while creating resource group: %v", err))
	}
}

func TeardownAzureTesting(subscriptionId string, resourceGroupName string) {
	ctx := context.Background()
	resourceGroupsClient := createResourceGroupsClient(subscriptionId)
	poller, err := resourceGroupsClient.BeginDelete(ctx, resourceGroupName, nil)
	if err != nil {
		panic(fmt.Sprintf("Error while deleting resource group: %v", err))
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		panic(fmt.Sprintf("Error while waiting for resource group deletion: %v", err))
	}
}

func GetTestVmParameters(location string) armcompute.VirtualMachine {
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

func InitializeServer() *azurePluginServer {
	return &azurePluginServer{
		azureHandler: &azureSDKHandler{},
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
