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
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"google.golang.org/protobuf/proto"
)

const (
	virtualMachineTypeName        = "Microsoft.Compute/virtualMachines"
	managedClusterTypeName        = "Microsoft.ContainerService/managedClusters"
	localNetworkGatewayTypeName   = "Microsoft.Network/localNetworkGateways"
	diskTypeName                  = "Microsoft.Compute/disks"
	connectionTypeName            = "Microsoft.Network/connections"
	networkInterfaceTypeName      = "Microsoft.Network/networkInterfaces"
	networkSecurityGroupTypeName  = "Microsoft.Network/networkSecurityGroups"
	publicIPAddressTypeName       = "Microsoft.Network/publicIPAddresses"
	virtualNetworkGatewayTypeName = "Microsoft.Network/virtualNetworkGateways"
	virtualNetworkTypeName        = "Microsoft.Network/virtualNetworks"
	networkWatcherTypeName        = "Microsoft.Network/networkWatchers"
)

// Gets subscription ID defined in environment variable
func GetAzureSubscriptionId() string {
	subscriptionId := os.Getenv("PARAGLIDER_AZURE_SUBSCRIPTION_ID")
	if subscriptionId == "" {
		panic("Environment variable 'PARAGLIDER_AZURE_SUBSCRIPTION_ID' must be set")
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
	// Use set resource group
	var resourceGroupName string
	if resourceGroupName = os.Getenv("PARAGLIDER_AZURE_RESOURCE_GROUP"); resourceGroupName != "" {
		return resourceGroupName
	}

	// Create new resource group
	resourceGroupName = "paraglider-" + testName
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

func TeardownAzureTesting(subscriptionId string, resourceGroupName string, namespace string) {
	if os.Getenv("PARAGLIDER_TEST_PERSIST") != "1" {
		if os.Getenv("PARAGLIDER_AZURE_RESOURCE_GROUP") == "" {
			// Delete resource group
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
		} else {
			// Delete resources without deleting the resource group
			// Order deletion is based off of https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/delete-resource-group#how-order-of-deletion-is-determined
			ctx := context.Background()
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				panic(fmt.Sprintf("Error while getting azure credentials: %v", err))
			}
			resourcesClient, err := armresources.NewClient(subscriptionId, cred, nil)
			if err != nil {
				panic(fmt.Sprintf("Error while creating resources client: %v", err))
			}
			providersClient, err := armresources.NewProvidersClient(subscriptionId, cred, nil)
			if err != nil {
				panic(fmt.Sprintf("Error while creating providers client: %v", err))
			}
			pager := resourcesClient.NewListPager(&armresources.ClientListOptions{
				Filter: proto.String(fmt.Sprintf("tagName eq '%s' and tagValue eq '%s'", namespaceTagKey, namespace)),
			})
			resourceTypeToResources := make(map[string][]*armresources.GenericResourceExpanded)
			resourceTypeToAPIVersion := make(map[string]string)
			for pager.More() {
				result, err := pager.NextPage(ctx)
				if err != nil {
					panic(fmt.Sprintf("failed to get next page of resources: %v", err))
				}

				for _, resource := range result.Value {
					resourceIDInfo, err := getResourceIDInfo(*resource.ID)
					if err != nil {
						panic(fmt.Sprintf("Unable to parse resource ID info: %v", err))
					}

					// Need to check here since resourceGroup can't be used with tags in the above filter
					// Ignore case when checking because Azure sometimes capitalizes the resource group name for no apparent reason
					if strings.EqualFold(resourceIDInfo.ResourceGroupName, resourceGroupName) {
						// Group resources by type and get the correct API version for the type
						if _, ok := resourceTypeToResources[*resource.Type]; !ok {
							resourceTypeToResources[*resource.Type] = make([]*armresources.GenericResourceExpanded, 0)
							// Find correct API version
							_, ok := resourceTypeToAPIVersion[*resource.Type]
							if !ok {
								providerNamespace := strings.Split(*resource.Type, "/")[0]
								resp, err := providersClient.Get(ctx, providerNamespace, nil)
								if err != nil {
									panic(fmt.Errorf("Unable to get provider resource type: %w", err))
								}
								// Store all API versions under this provider namespace to reduce potential duplicate requests
								for _, resourceType := range resp.Provider.ResourceTypes {
									// Breakdown of the term "resource type" overloading
									// - *resource.Type = "Microsoft.Compute/virtualMachines"
									// - providerNamespace = "Microsoft.Compute"
									// - *resourceType.ResourceType is one of "virtualMachines", "disks", etc.
									resourceTypeToAPIVersion[providerNamespace+"/"+*resourceType.ResourceType] = *resourceType.APIVersions[0] // Use most recent API version
								}
							}
						}
						resourceTypeToResources[*resource.Type] = append(resourceTypeToResources[*resource.Type], resource)
					}

				}
				// Delete resources in the following order
				deletionOrder := []string{
					virtualMachineTypeName,
					managedClusterTypeName,
					networkInterfaceTypeName,
					diskTypeName,
					connectionTypeName,
					virtualNetworkGatewayTypeName,
					localNetworkGatewayTypeName,
					publicIPAddressTypeName,
					virtualNetworkTypeName,
					networkSecurityGroupTypeName,
					networkWatcherTypeName,
				}
				for _, resourceType := range deletionOrder {
					if resources, ok := resourceTypeToResources[resourceType]; ok {
						err = deleteResources(ctx, resourcesClient, resources, resourceTypeToAPIVersion[resourceType])
						if err != nil {
							panic(fmt.Errorf("Failed to delete resource type %s: %w", resourceType, err))
						}
						delete(resourceTypeToResources, resourceType)
					}
				}

				if len(resourceTypeToResources) > 0 {
					fmt.Printf("Attempting to clean up unexpected resources")
					for resourceType, resources := range resourceTypeToResources {
						err = deleteResources(ctx, resourcesClient, resources, resourceTypeToAPIVersion[resourceType])
						if err != nil {
							panic(fmt.Errorf("Failed to delete resource type %s: %w", resourceType, err))
						}
					}
				}
			}
		}
	}
}

func deleteResources(ctx context.Context, resourcesClient *armresources.Client, resources []*armresources.GenericResourceExpanded, apiVersion string) error {
	for _, resource := range resources {
		pollerResp, err := resourcesClient.BeginDeleteByID(ctx, *resource.ID, apiVersion, nil)
		if err != nil {
			return fmt.Errorf("Error while deleting resource: %v", err)
		}
		_, err = pollerResp.PollUntilDone(ctx, nil)
		if err != nil {
			return fmt.Errorf("Error while deleting resource: %v", err)
		}
	}
	return nil
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
		azureCredentialGetter:  &AzureCredentialGetter{},
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

func findNetworkWatcher(ctx context.Context, watchersClient *armnetwork.WatchersClient, location string) (*ResourceIDInfo, error) {
	pager := watchersClient.NewListAllPager(nil)
	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get next page of resources: %v", err)
		}

		for _, networkWatcher := range result.Value {
			if *networkWatcher.Location == location {
				networkWatcherResourceIDInfo, err := getResourceIDInfo(*networkWatcher.ID)
				if err != nil {
					return nil, fmt.Errorf("unable to parse network watcher ID: %w", err)
				}
				return &networkWatcherResourceIDInfo, nil
			}
		}
	}
	return nil, nil
}

func RunPingConnectivityCheck(sourceVmResourceID string, destinationIPAddress string, sourceVmNamespace string) (bool, error) {
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

	// Configure network watcher
	// Hard coded resource group for CI pipeline (https://github.com/paraglider-project/paraglider/issues/217)
	networkWatcherResourceGroup := "NetworkWatcherRG"
	networkWatcherName := "NetworkWatcher_" + *vm.Location
	if os.Getenv("PARAGLIDER_AZURE_RESOURCE_GROUP") != "" {
		// Check if network watcher already exists within the subscription since Azure limits network watchers to one per subscription for each region
		networkWatcherResourceIDInfo, err := findNetworkWatcher(ctx, watchersClient, *vm.Location)
		if err != nil {
			return false, fmt.Errorf("error when finding network watcher: %w", err)
		}
		if networkWatcherResourceIDInfo != nil {
			// Use existing network watcher
			networkWatcherResourceGroup = networkWatcherResourceIDInfo.ResourceGroupName
			networkWatcherName = networkWatcherResourceIDInfo.ResourceName
		} else {
			// Create network watcher in provided resource group
			networkWatcherResourceGroup = os.Getenv("PARAGLIDER_AZURE_RESOURCE_GROUP")
			// Tag it to make sure it gets deleted
			_, err := watchersClient.CreateOrUpdate(ctx, networkWatcherResourceGroup, networkWatcherName, armnetwork.Watcher{Location: vm.Location, Tags: map[string]*string{namespaceTagKey: to.Ptr(sourceVmNamespace)}}, nil)
			if err != nil {
				return false, fmt.Errorf("unable to create network watcher: %w", err)
			}
		}
	}

	// Retries up to 5 times
	for i := 0; i < 5; i++ {
		checkConnectivityPollerResponse, err := watchersClient.BeginCheckConnectivity(ctx, networkWatcherResourceGroup, networkWatcherName, connectivityParameters, nil)
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

// Create VPN gateway vnet if not already created
// The vnet is created even if there's no multicloud connections at the moment for ease of connection in the future.
// Note that vnets are free, so this is not a problem.
func GetOrCreateVpnGatewayVNet(ctx context.Context, azureHandler *AzureSDKHandler, namespace string) (*armnetwork.VirtualNetwork, error) {
	vpnGwVnetName := getVpnGatewayVnetName(namespace)
	vnet, err := azureHandler.GetVirtualNetwork(ctx, vpnGwVnetName)
	if err != nil {
		if isErrorNotFound(err) {
			virtualNetworkParameters := armnetwork.VirtualNetwork{
				Location: to.Ptr(vpnLocation),
				Properties: &armnetwork.VirtualNetworkPropertiesFormat{
					AddressSpace: &armnetwork.AddressSpace{
						AddressPrefixes: []*string{to.Ptr(gatewaySubnetAddressPrefix)},
					},
					Subnets: []*armnetwork.Subnet{
						{
							Name: to.Ptr(gatewaySubnetName),
							Properties: &armnetwork.SubnetPropertiesFormat{
								AddressPrefix: to.Ptr(gatewaySubnetAddressPrefix),
							},
						},
					},
				},
			}
 
			azureHandler.createParagliderNamespaceTag(&virtualNetworkParameters.Tags)
			// todo: investigate this line for the tests
			vnet, err := azureHandler.CreateOrUpdateVirtualNetwork(ctx, getVpnGatewayVnetName(namespace), virtualNetworkParameters)
			if err != nil {
				return nil, fmt.Errorf("unable to create VPN gateway vnet: %w", err)
			}

			return vnet, nil
		} else {
			return nil, fmt.Errorf("unable to get VPN gateway vnet: %w", err)
		}
	}

	return vnet, nil
}

// Create peering VPN gateway vnet and VM vnet. If the VPN gateway already exists, then establish a VPN gateway transit relationship where the vnet can use the gatewayVnet's VPN gateway.
// - This peering is created even if there's no multicloud connections at the moment for ease of connection in the future.
// - Peerings are only charged based on amount of data transferred, so this will not incur extra charge until the VPN gateway is created.
// - VPN gateway transit relationship cannot be established before the VPN gateway creation.
// - If the VPN gateway hasn't been created, then the gateway transit relationship will be established on VPN gateway creation.
func CreateGatewayVnetPeering(ctx context.Context, azureHandler *AzureSDKHandler, vnetName string, vpnGwVnetName string, namespace string) error {
	_, err := azureHandler.GetVirtualNetworkPeering(ctx, vnetName, vpnGwVnetName)
	var peeringExists bool
	if err != nil {
		if isErrorNotFound(err) {
			peeringExists = false
		} else {
			return fmt.Errorf("unable to get vnet peering between VM vnet and VPN gateway vnet: %w", err)
		}
	} else {
		peeringExists = true
	}

	// Only add peering if it doesn't exist
	if !peeringExists {
		vpnGwName := getVpnGatewayName(namespace)
		_, err = azureHandler.GetVirtualNetworkGateway(ctx, vpnGwName)
		if err != nil {
			if isErrorNotFound(err) {
				// Create regular peering which will be augmented with gateway transit relationship later on VPN gateway creation
				err = azureHandler.CreateVnetPeering(ctx, vnetName, vpnGwVnetName)
				if err != nil {
					return fmt.Errorf("unable to create vnet peerings between VM vnet and VPN gateway vnet: %w", err)
				}
			} else {
				return fmt.Errorf("unable to get VPN gateway: %w", err)
			}
		} else {
			// Create peering with gateway transit relationship if VPN gateway already exists
			err = azureHandler.CreateOrUpdateVnetPeeringRemoteGateway(ctx, vnetName, vpnGwVnetName, nil, nil)
			if err != nil {
				return fmt.Errorf("unable to create vnet peerings (with gateway transit) between VM vnet and VPN gateway vnet: %w", err)
			}
		}
	}

	return nil
}

// Returns true if the specified Vnet's address space overlaps with any of the used address spaces. Otherwise, returns false.
func DoesVnetOverlapWithParaglider(ctx context.Context, handler *AzureSDKHandler, vnetName string, server *azurePluginServer) (bool, error) {
	vnetAddressSpace, err := handler.GetVnetAddressSpace(ctx, vnetName)
	if err != nil {
		return true, err
	}

	req := &paragliderpb.GetUsedAddressSpacesRequest{
		Deployments: []*paragliderpb.ParagliderDeployment{
			{Id: getDeploymentUri(handler.subscriptionID, handler.resourceGroupName), Namespace: handler.paragliderNamespace},
		},
	}
	response, err := server.GetUsedAddressSpaces(ctx, req)
	if err != nil {
		return true, err
	}

	// Check if the Vnet address space overlaps with any of the used address spaces
	for _, mapping := range response.AddressSpaceMappings {
		for _, addressSpace := range mapping.AddressSpaces {
			for _, vnetAddress := range vnetAddressSpace {
				doesOverlap, err := utils.DoCIDROverlap(vnetAddress, addressSpace)
				if err != nil {
					return true, err
				}

				if doesOverlap {
					return true, nil
				}
			}
		}
	}

	return false, nil
}
