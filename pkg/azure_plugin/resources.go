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
	"strings"

	"github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

const (
	virtualMachineTypeName = "Microsoft.Compute/VirtualMachines"
	managedClusterTypeName = "Microsoft.ContainerService/ManagedClusters"
)

type ResourceNetworkInfo struct {
	SubnetID string
	Address  string
	Location string
	NSG      *armnetwork.SecurityGroup
}

type ResourceInfo struct {
	ResourceName   string
	ResourceID     string
	Location       string
	RequiresSubnet bool
}

// Gets the resource and returns relevant networking state. Also checks that the resource is in the correct namespace.
func GetAndCheckResourceState(c context.Context, handler AzureSDKHandler, resourceID string, namespace string) (*ResourceNetworkInfo, error) {
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
		return nil, fmt.Errorf("resource %s is not in the namespace %s", resourceID, namespace)
	}

	// Return the relevant NSG
	return netInfo, nil
}

// Gets the resource and returns relevant networking state
func GetNetworkInfoFromResource(c context.Context, handler AzureSDKHandler, resourceID string) (*ResourceNetworkInfo, error) {
	// get a generic resource
	resource, err := handler.GetResource(c, resourceID)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource %s: %+v", resourceID, err)
		return nil, err
	}

	// get the network info using typed handler
	var networkInfo *ResourceNetworkInfo
	if strings.Contains(*resource.Type, virtualMachineTypeName) {
		resourceHandler := &AzureVM{}
		networkInfo, err = resourceHandler.GetNetworkInfo(resource, handler)
		if err != nil {
			utils.Log.Printf("An error occured while getting network info for resource %s: %+v", resourceID, err)
			return nil, err
		}
	} else if strings.Contains(*resource.Type, managedClusterTypeName) {
		resourceHandler := &AzureAKS{}
		networkInfo, err = resourceHandler.GetNetworkInfo(resource, handler)
		if err != nil {
			utils.Log.Printf("An error occured while getting network info for resource %s: %+v", resourceID, err)
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("resource type %s is not supported", *resource.Type)
	}
	return networkInfo, nil
}

// Gets basic resource information from the description
// Returns the resource name, ID, location, and whether the resource will require its own subnet in a struct
func GetResourceInfoFromResourceDesc(ctx context.Context, resource *invisinetspb.ResourceDescription) (*ResourceInfo, error) {
	if strings.Contains(resource.Id, "virtualMachines") {
		handler := &AzureVM{}
		vm, err := handler.FromResourceDecription(resource.Description)
		if err != nil {
			return nil, err
		}
		return &ResourceInfo{ResourceName: *vm.Name, ResourceID: resource.Id, Location: *vm.Location, RequiresSubnet: false}, nil
	} else if strings.Contains(resource.Id, "managedClusters") {
		handler := &AzureAKS{}
		aks, err := handler.FromResourceDecription(resource.Description)
		if err != nil {
			return nil, err
		}
		return &ResourceInfo{ResourceName: *aks.Name, ResourceID: resource.Id, Location: *aks.Location, RequiresSubnet: true}, nil
	} else {
		return nil, fmt.Errorf("resource description contains unknown Azure resource")
	}
}

// Reads the resource description and provisions the resource with the given subnet
func ReadAndProvisionResource(ctx context.Context, resource *invisinetspb.ResourceDescription, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, sdkHandler AzureSDKHandler) (string, error) {
	var ip string
	if strings.Contains(resource.Id, "virtualMachines") {
		handler := &AzureVM{}
		vm, err := handler.FromResourceDecription(resource.Description)
		if err != nil {
			return "", err
		}
		ip, err = handler.CreateWithNetwork(ctx, vm, subnet, resourceInfo, sdkHandler)
		if err != nil {
			return "", err
		}
	} else if strings.Contains(resource.Id, "managedClusters") {
		handler := &AzureAKS{}
		aks, err := handler.FromResourceDecription(resource.Description)
		if err != nil {
			return "", err
		}
		ip, err = handler.CreateWithNetwork(ctx, aks, subnet, resourceInfo, sdkHandler)
		if err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("resource description contains unknown Azure resource")
	}

	return ip, nil
}

// Interface that must be implemented for a resource to be supported
type AzureResourceHandler[T any] interface {
	CreateWithNetwork(ctx context.Context, resource *T, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, handler AzureSDKHandler) (string, error)
	FromResourceDecription(resourceDesc []byte) (T, error)
	GetNetworkInfo(resource *armresources.GenericResource, handler AzureSDKHandler) (*ResourceNetworkInfo, error)
}

// VM implementation of the AzureResourceHandler interface
type AzureVM struct {
	AzureResourceHandler[armcompute.VirtualMachine]
}

// Gets the network information for a virtual machine
func (r *AzureVM) GetNetworkInfo(resource *armresources.GenericResource, handler AzureSDKHandler) (*ResourceNetworkInfo, error) {
	properties, ok := resource.Properties.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to read resource.Properties")
	}

	netprofile := properties["networkProfile"].(map[string]interface{})
	nicID := netprofile["networkInterfaces"].([]interface{})[0].(map[string]interface{})["id"].(string)

	nicName, err := handler.GetLastSegment(nicID)
	if err != nil {
		return nil, err
	}
	nic, err := handler.GetNetworkInterface(context.Background(), nicName)
	if err != nil {
		utils.Log.Printf("An error occured while getting the network interface:%+v", err)
		return nil, err
	}

	nsg, err := handler.GetSecurityGroup(context.Background(), *nic.Properties.NetworkSecurityGroup.Name)
	if err != nil {
		utils.Log.Printf("An error occured while getting the network security group:%+v", err)
		return nil, err
	}

	return &ResourceNetworkInfo{
		SubnetID: *nic.Properties.IPConfigurations[0].Properties.Subnet.ID,
		Address:  *nic.Properties.IPConfigurations[0].Properties.PrivateIPAddress,
		Location: *resource.Location,
		NSG:      nsg,
	}, nil
}

// Creates a virtual machine with the given subnet
// Returns the private IP address of the virtual machine
func (r *AzureVM) CreateWithNetwork(ctx context.Context, vm *armcompute.VirtualMachine, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, handler AzureSDKHandler) (string, error) {
	nic, err := handler.CreateNetworkInterface(ctx, *subnet.ID, *vm.Location, getInvisinetsResourceName("nic"))
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

	vm, err = handler.CreateVirtualMachine(ctx, *vm, resourceInfo.ResourceName)
	if err != nil {
		utils.Log.Printf("An error occured while creating the virtual machine:%+v", err)
		return "", err
	}

	nicName, err := handler.GetLastSegment(*vm.Properties.NetworkProfile.NetworkInterfaces[0].ID)
	if err != nil {
		return "", err
	}

	nic, err = handler.GetNetworkInterface(ctx, nicName)
	if err != nil {
		utils.Log.Printf("An error occured while getting the network interface:%+v", err)
		return "", err
	}

	return *nic.Properties.IPConfigurations[0].Properties.PrivateIPAddress, nil
}

// Converts the resource description to a virtual machine object
func (r *AzureVM) FromResourceDecription(resourceDesc []byte) (*armcompute.VirtualMachine, error) {
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

// AKS implementation of the AzureResourceHandler interface
type AzureAKS struct {
	AzureResourceHandler[armcontainerservice.ManagedCluster]
}

// Gets the network information for an AKS cluster
func (r *AzureAKS) GetNetworkInfo(resource *armresources.GenericResource, handler AzureSDKHandler) (*ResourceNetworkInfo, error) {
	properties, ok := resource.Properties.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to read resource.Properties")
	}
	profiles := properties["agentPoolProfiles"].([]interface{})
	firstProfile := profiles[0].(map[string]interface{})
	subnetID := firstProfile["vnetSubnetID"].(string)
	subnet, err := handler.GetSubnetByID(context.Background(), subnetID)
	if err != nil {
		utils.Log.Printf("An error occured while getting the subnet:%+v", err)
		return nil, err
	}
	nsgName, err := handler.GetLastSegment(*subnet.Properties.NetworkSecurityGroup.ID)
	if err != nil {
		return nil, err
	}
	nsg, err := handler.GetSecurityGroup(context.Background(), nsgName)
	if err != nil {
		utils.Log.Printf("An error occured while getting the network security group:%+v", err)
		return nil, err
	}

	return &ResourceNetworkInfo{
		SubnetID: *subnet.ID,
		Address:  *subnet.Properties.AddressPrefix,
		Location: *resource.Location,
		NSG:      nsg,
	}, nil
}

// Creates an AKS cluster with the given subnet
// Returns the address prefix of the subnet
func (r *AzureAKS) CreateWithNetwork(ctx context.Context, resource *armcontainerservice.ManagedCluster, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, handler AzureSDKHandler) (string, error) {
	for _, profile := range resource.Properties.AgentPoolProfiles {
		profile.VnetSubnetID = subnet.ID
	}
	_, err := handler.CreateAKSCluster(ctx, *resource, resourceInfo.ResourceName)
	if err != nil {
		utils.Log.Printf("An error occured while creating the AKS cluster:%+v", err)
		return "", err
	}

	// Associate the subnet with an NSG for the cluster
	allowedAddrs := map[string]string{"serviceCIDR": *resource.Properties.NetworkProfile.ServiceCidr, "localsubnet": *subnet.Properties.AddressPrefix}
	nsg, err := handler.CreateSecurityGroup(ctx, resourceInfo.ResourceName, *resource.Location, allowedAddrs)
	if err != nil {
		utils.Log.Printf("An error occured while creating the network security group:%+v", err)
		return "", err
	}

	err = handler.AssociateNSGWithSubnet(ctx, *subnet.ID, *nsg.ID)
	if err != nil {
		utils.Log.Printf("An error occured while associating the network security group with the subnet:%+v", err)
		return "", err
	}

	return *subnet.Properties.AddressPrefix, nil
}

// Converts the resource description to an AKS cluster object
func (r *AzureAKS) FromResourceDecription(resourceDesc []byte) (*armcontainerservice.ManagedCluster, error) {
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

	return aks, nil
}
