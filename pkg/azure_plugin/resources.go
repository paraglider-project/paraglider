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

// TODO NOW: Naming / cleanup (also look at comments from the PR when doing this)

package azure_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

const (
	virtualMachineTypeName = "Microsoft.Compute/virtualMachines"
	managedClusterTypeName = "Microsoft.ContainerService/managedClusters"
)

type resourceNetworkInfo struct {
	SubnetID string
	Address  string
	Location string
	NSG      *armnetwork.SecurityGroup
}

type resourceInfo struct {
	ResourceName               string
	ResourceID                 string
	Location                   string
	RequiresSubnet             bool
	NumAdditionalAddressSpaces int
}

func getNameFromUri(uri string) string {
	split := strings.Split(uri, "/")
	return split[len(split)-1]
}

func getDnsServiceCidr(serviceCidr string) string {
	// Get the first three octets of the service CIDR
	split := strings.Split(serviceCidr, ".")
	return fmt.Sprintf("%s.%s.%s.10", split[0], split[1], split[2])
}

// Determine type of resource based on ID and return the relevant network handler
func getResourceNetworkHandler(resourceID string) (azureResourceNetworkHandler, error) {
	if strings.Contains(resourceID, virtualMachineTypeName) {
		return &azureVM{}, nil
	} else if strings.Contains(resourceID, managedClusterTypeName) {
		return &azureAKS{}, nil
	} else {
		return nil, fmt.Errorf("resource type %s is not supported", resourceID)
	}
}

// Determine type of resource based on ID and return the relevant full resource handler
func getResourceHandlerNew(resourceID string) (iAzureResourceHandler, error) {
	if strings.Contains(resourceID, virtualMachineTypeName) {
		return &azureResourceHandlerVM{}, nil
	} else if strings.Contains(resourceID, managedClusterTypeName) {
		return &azureResourceHandlerAKS{}, nil
	} else {
		return nil, fmt.Errorf("resource type %s is not supported", resourceID)
	}
}

// Type defition for supported Azure resources
type supportedAzureResource interface {
	armcompute.VirtualMachine | armcontainerservice.ManagedCluster
}

// Gets the resource and returns relevant networking state. Also checks that the resource is in the correct namespace.
func GetAndCheckResourceState(c context.Context, handler AzureSDKHandler, resourceID string, namespace string) (*resourceNetworkInfo, error) {
	// Check the namespace
	if namespace == "" {
		return nil, fmt.Errorf("namespace cannot be empty")
	}

	// Get the resource
	netInfo, err := GetNetworkInfoFromResource(c, handler, resourceID)
	if err != nil {
		return nil, err
	}

	// Check its namespace
	vnet := getVnetFromSubnetId(netInfo.SubnetID)
	if !strings.HasPrefix(vnet, getInvisinetsNamespacePrefix(namespace)) {
		return nil, fmt.Errorf("resource %s is not in the namespace %s (subnet ID: %s)", resourceID, namespace, netInfo.SubnetID)
	}

	// Return the relevant NSG
	return netInfo, nil
}

// Gets the resource and returns relevant networking state
func GetNetworkInfoFromResource(c context.Context, handler AzureSDKHandler, resourceID string) (*resourceNetworkInfo, error) {
	// get a generic resource
	resource, err := handler.GetResource(c, resourceID)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource %s: %+v", resourceID, err)
		return nil, err
	}

	// get the network info using network handler
	netHandler, err := getResourceNetworkHandler(resourceID)
	networkInfo, err := netHandler.getNetworkInfo(resource, handler)
	if err != nil {
		utils.Log.Printf("An error occured while getting network info for resource %s: %+v", resourceID, err)
		return nil, err
	}
	return networkInfo, nil
}

// Gets basic resource information from the description
// Returns the resource name, ID, location, and whether the resource will require its own subnet in a struct
func GetResourceInfoFromResourceDesc(ctx context.Context, resource *invisinetspb.ResourceDescription) (*resourceInfo, error) {
	handler, err := getResourceHandlerNew(resource.Id)
	if err != nil {
		return nil, err
	}
	return handler.getResourceInfoFromDescription(ctx, resource)
}

// Reads the resource description and provisions the resource with the given subnet
func ReadAndProvisionResource(ctx context.Context, resource *invisinetspb.ResourceDescription, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, sdkHandler AzureSDKHandler, additionalAddressSpaces []string) (string, error) {
	handler, err := getResourceHandlerNew(resource.Id)
	if err != nil {
		return "", err
	}
	return handler.readAndProvisionResource(ctx, resource, subnet, resourceInfo, sdkHandler, additionalAddressSpaces)
}

// Interface that must be implemented for a resource to be supported
type iAzureResourceHandler interface {
	initialize() // TODO NOW: do we need this?
	getResourceInfoFromDescription(ctx context.Context, resource *invisinetspb.ResourceDescription) (*resourceInfo, error)
	readAndProvisionResource(ctx context.Context, resource *invisinetspb.ResourceDescription, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, sdkHandler AzureSDKHandler, additionalAddressSpaces []string) (string, error)
}

// Struct that holds the handler and network handler for a resource while implementing the interface
type azureResourceHandler[T supportedAzureResource] struct {
	iAzureResourceHandler
	handler    azureResourceProvisioningHandler[T]
	netHandler azureResourceNetworkHandler
}

// Interface to implement for the resource provisioning handler
type azureResourceProvisioningHandler[T supportedAzureResource] interface {
	createWithNetwork(ctx context.Context, resource *T, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, sdkHandler AzureSDKHandler, additionalAddressSpaces []string) (string, error)
	fromResourceDecription(resourceDesc []byte) (*T, error)
}

// Interface to implement for the resource network handler
type azureResourceNetworkHandler interface {
	getNetworkInfo(resource *armresources.GenericResource, sdkHandler AzureSDKHandler) (*resourceNetworkInfo, error)
	getNetworkRequirements() (bool, int)
}

// VM implementation of the AzureResourceHandler interface
type azureResourceHandlerVM struct {
	azureResourceHandler[armcompute.VirtualMachine]
}

func (r *azureResourceHandlerVM) initialize() {
	handler := &azureVM{}
	r.handler = handler
	r.netHandler = handler
}

func (r *azureResourceHandlerVM) getResourceInfoFromDescription(ctx context.Context, resource *invisinetspb.ResourceDescription) (*resourceInfo, error) {
	r.initialize()
	vm, err := r.handler.fromResourceDecription(resource.Description)
	if err != nil {
		return nil, err
	}
	requiresSubnet, extraPrefixes := r.netHandler.getNetworkRequirements()
	return &resourceInfo{ResourceName: getNameFromUri(resource.Id), ResourceID: resource.Id, Location: *vm.Location, RequiresSubnet: requiresSubnet, NumAdditionalAddressSpaces: extraPrefixes}, nil
}

func (r *azureResourceHandlerVM) readAndProvisionResource(ctx context.Context, resource *invisinetspb.ResourceDescription, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, sdkHandler AzureSDKHandler, additionalAddressSpaces []string) (string, error) {
	r.initialize()
	vm, err := r.handler.fromResourceDecription(resource.Description)
	if err != nil {
		return "", err
	}
	ip, err := r.handler.createWithNetwork(ctx, vm, subnet, resourceInfo, sdkHandler, make([]string, 0))
	if err != nil {
		return "", err
	}
	return ip, nil
}

// VM implementation of the resource provisioning handler and network handler
type azureVM struct {
	azureResourceProvisioningHandler[armcompute.VirtualMachine]
	azureResourceNetworkHandler
}

func (r *azureVM) getNetworkRequirements() (bool, int) {
	return false, 0
}

// Gets the network information for a virtual machine
func (r *azureVM) getNetworkInfo(resource *armresources.GenericResource, sdkHandler AzureSDKHandler) (*resourceNetworkInfo, error) {
	properties, ok := resource.Properties.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to read resource.Properties")
	}

	netprofile := properties["networkProfile"].(map[string]interface{})
	nicID := netprofile["networkInterfaces"].([]interface{})[0].(map[string]interface{})["id"].(string)

	nicName, err := GetLastSegment(nicID)
	if err != nil {
		return nil, err
	}
	nic, err := sdkHandler.GetNetworkInterface(context.Background(), nicName)
	if err != nil {
		utils.Log.Printf("An error occured while getting the network interface:%+v", err)
		return nil, err
	}

	nsgName, err := GetLastSegment(*nic.Properties.NetworkSecurityGroup.ID)
	if err != nil {
		return nil, err
	}
	nsg, err := sdkHandler.GetSecurityGroup(context.Background(), nsgName)
	if err != nil {
		utils.Log.Printf("An error occured while getting the network security group:%+v", err)
		return nil, err
	}

	info := resourceNetworkInfo{
		SubnetID: *nic.Properties.IPConfigurations[0].Properties.Subnet.ID,
		Address:  *nic.Properties.IPConfigurations[0].Properties.PrivateIPAddress,
		Location: *resource.Location,
		NSG:      nsg,
	}
	return &info, nil
}

// Creates a virtual machine with the given subnet
// Returns the private IP address of the virtual machine
func (r *azureVM) createWithNetwork(ctx context.Context, vm *armcompute.VirtualMachine, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, sdkHandler AzureSDKHandler, additionalAddressSpaces []string) (string, error) {
	nic, err := sdkHandler.CreateNetworkInterface(ctx, *subnet.ID, *vm.Location, getInvisinetsResourceName("nic"))
	if err != nil {
		utils.Log.Printf("An error occured while creating network interface:%+v", err)
		return "", err
	}

	vm.Properties.NetworkProfile = &armcompute.NetworkProfile{
		NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
			{
				ID: nic.ID,
			},
		},
	}

	vm, err = sdkHandler.CreateVirtualMachine(ctx, *vm, resourceInfo.ResourceName)
	if err != nil {
		utils.Log.Printf("An error occured while creating the virtual machine:%+v", err)
		return "", err
	}

	nicName, err := GetLastSegment(*vm.Properties.NetworkProfile.NetworkInterfaces[0].ID)
	if err != nil {
		return "", err
	}

	nic, err = sdkHandler.GetNetworkInterface(ctx, nicName)
	if err != nil {
		utils.Log.Printf("An error occured while getting the network interface:%+v", err)
		return "", err
	}

	return *nic.Properties.IPConfigurations[0].Properties.PrivateIPAddress, nil
}

// Converts the resource description to a virtual machine object
func (r *azureVM) fromResourceDecription(resourceDesc []byte) (*armcompute.VirtualMachine, error) {
	vm := &armcompute.VirtualMachine{}
	err := json.Unmarshal(resourceDesc, vm)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource description:%+v", err)
	}

	// Some validations on the VM
	if vm.Location == nil || vm.Properties == nil {
		return nil, fmt.Errorf("resource description is missing location or properties")
	}

	// Reject VMs that already have network interfaces
	if vm.Properties.NetworkProfile != nil && vm.Properties.NetworkProfile.NetworkInterfaces != nil {
		return nil, fmt.Errorf("resource description cannot contain network interface")
	}

	return vm, nil
}

// AKS implementation of the NewAzureResourceHandler interface
type azureResourceHandlerAKS struct {
	azureResourceHandler[armcontainerservice.ManagedCluster]
}

func (r *azureResourceHandlerAKS) initialize() {
	handler := &azureAKS{}
	r.handler = handler
	r.netHandler = handler
}

func (r *azureResourceHandlerAKS) getResourceInfoFromDescription(ctx context.Context, resource *invisinetspb.ResourceDescription) (*resourceInfo, error) {
	r.initialize()
	aks, err := r.handler.fromResourceDecription(resource.Description)
	if err != nil {
		return nil, err
	}
	requiresSubnet, extraPrefixes := r.netHandler.getNetworkRequirements()
	return &resourceInfo{ResourceName: *aks.Name, ResourceID: resource.Id, Location: *aks.Location, RequiresSubnet: requiresSubnet, NumAdditionalAddressSpaces: extraPrefixes}, nil

}

func (r *azureResourceHandlerAKS) readAndProvisionResource(ctx context.Context, resource *invisinetspb.ResourceDescription, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, sdkHandler AzureSDKHandler, additionalAddressSpaces []string) (string, error) {
	r.initialize()
	aks, err := r.handler.fromResourceDecription(resource.Description)
	if err != nil {
		return "", err
	}
	ip, err := r.handler.createWithNetwork(ctx, aks, subnet, resourceInfo, sdkHandler, additionalAddressSpaces)
	if err != nil {
		return "", err
	}
	return ip, nil
}

// AKS implementation of the AzureResourceHandler interface
type azureAKS struct {
	azureResourceProvisioningHandler[armcontainerservice.ManagedCluster]
	azureResourceNetworkHandler
}

func (r *azureAKS) getNetworkRequirements() (bool, int) {
	return true, 1 // TODO @smcclure20: change with support for kubenet
}

// Gets the network information for an AKS cluster
func (r *azureAKS) getNetworkInfo(resource *armresources.GenericResource, sdkHandler AzureSDKHandler) (*resourceNetworkInfo, error) {
	properties, ok := resource.Properties.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to read resource.Properties")
	}
	profiles := properties["agentPoolProfiles"].([]interface{})
	firstProfile := profiles[0].(map[string]interface{})
	subnetID := firstProfile["vnetSubnetID"].(string)
	subnet, err := sdkHandler.GetSubnetByID(context.Background(), subnetID)
	if err != nil {
		utils.Log.Printf("An error occured while getting the subnet:%+v", err)
		return nil, err
	}
	nsgName, err := GetLastSegment(*subnet.Properties.NetworkSecurityGroup.ID)
	if err != nil {
		return nil, err
	}
	nsg, err := sdkHandler.GetSecurityGroup(context.Background(), nsgName)
	if err != nil {
		utils.Log.Printf("An error occured while getting the network security group:%+v", err)
		return nil, err
	}

	return &resourceNetworkInfo{
		SubnetID: *subnet.ID,
		Address:  *subnet.Properties.AddressPrefix,
		Location: *resource.Location,
		NSG:      nsg,
	}, nil
}

// Creates an AKS cluster with the given subnet
// Returns the address prefix of the subnet
func (r *azureAKS) createWithNetwork(ctx context.Context, resource *armcontainerservice.ManagedCluster, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, sdkHandler AzureSDKHandler, additionalAddressSpaces []string) (string, error) {
	// Set network parameters
	for _, profile := range resource.Properties.AgentPoolProfiles {
		profile.VnetSubnetID = subnet.ID
	}
	if resource.Properties.NetworkProfile == nil {
		resource.Properties.NetworkProfile = &armcontainerservice.NetworkProfile{}
	}
	// resource.Properties.NetworkProfile.PodCidr = &additionalAddressSpaces[0] // TODO @smcclure20: add this once we support kubenet instead of azure cni
	resource.Properties.NetworkProfile.ServiceCidr = &additionalAddressSpaces[0]
	resource.Properties.NetworkProfile.DNSServiceIP = to.Ptr(getDnsServiceCidr(additionalAddressSpaces[0]))

	// Create the AKS cluster
	_, err := sdkHandler.CreateAKSCluster(ctx, *resource, resourceInfo.ResourceName)
	if err != nil {
		utils.Log.Printf("An error occured while creating the AKS cluster:%+v", err)
		return "", err
	}

	// Associate the subnet with an NSG for the cluster
	allowedAddrs := map[string]string{"localsubnet": *subnet.Properties.AddressPrefix} // TODO @smcclure20: change with support for kubenet (include pod cidr)
	nsg, err := sdkHandler.CreateSecurityGroup(ctx, resourceInfo.ResourceName, *resource.Location, allowedAddrs)
	if err != nil {
		utils.Log.Printf("An error occured while creating the network security group:%+v", err)
		return "", err
	}

	err = sdkHandler.AssociateNSGWithSubnet(ctx, *subnet.ID, *nsg.ID)
	if err != nil {
		utils.Log.Printf("An error occured while associating the network security group with the subnet:%+v", err)
		return "", err
	}

	return *subnet.Properties.AddressPrefix, nil // TODO @smcclure20: change with support for kubenet
}

// Converts the resource description to an AKS cluster object
func (r *azureAKS) fromResourceDecription(resourceDesc []byte) (*armcontainerservice.ManagedCluster, error) {
	aks := &armcontainerservice.ManagedCluster{}
	err := json.Unmarshal(resourceDesc, aks)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource description:%+v", err)
	}

	// Some validations on the AKS
	if aks.Location == nil || aks.Properties == nil {
		return nil, fmt.Errorf("resource description is missing location or properties")
	}

	// Reject AKS that already have virtual networks
	for _, profile := range aks.Properties.AgentPoolProfiles {
		if profile.VnetSubnetID != nil {
			return nil, fmt.Errorf("resource description cannot contain virtual network")
		}
	}

	// Reject AKS that already has address spaces specified
	if aks.Properties.NetworkProfile != nil {
		if aks.Properties.NetworkProfile.PodCidr != nil || aks.Properties.NetworkProfile.ServiceCidr != nil {
			return nil, fmt.Errorf("resource description cannot contain address spaces")
		}

		if aks.Properties.NetworkProfile.NetworkPlugin != nil { // temporary check until we support kubenet
			if *aks.Properties.NetworkProfile.NetworkPlugin != "azure" {
				return nil, fmt.Errorf("resource description must have azure network plugin")
			}
		}
	}

	// Require private cluster TODO @smcclure20: generalize this later
	if aks.Properties.APIServerAccessProfile != nil {
		if !(*aks.Properties.APIServerAccessProfile.EnablePrivateCluster) {
			return nil, fmt.Errorf("resource description must have private cluster enabled")
		}
	}

	return aks, nil
}
