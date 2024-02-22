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
)

const (
	virtualMachineTypeName = "Microsoft.Compute/virtualMachines"
	managedClusterTypeName = "Microsoft.ContainerService/managedClusters"
)

// Is there any point to the abstract class? Just having the same interface to all resource types

func ReadAndProvisionResource(ctx context.Context, resource *invisinetspb.ResourceDescription, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, sdkHandler AzureSDKHandler) (string, error) {
	if strings.Contains(resource.Id, "virtualMachines") {
		handler := &AzureVM{}
		vm, err := handler.FromResourceDecription(resource.Description)
		if err != nil {
			return "", err
		}
		handler.CreateWithNetwork(ctx, vm, subnet, resourceInfo, sdkHandler)
	} else if strings.Contains(resource.Id, "managedClusters") {
		handler := &AzureAKS{}
		aks, err := handler.FromResourceDecription(resource.Description)
		if err != nil {
			return "", err
		}
		handler.CreateWithNetwork(ctx, aks, subnet, resourceInfo, sdkHandler)
	} else {
		return "", fmt.Errorf("resource description contains unknown Azure resource")
	}

	return "", nil
}

type AzureResourceHandler[T any] interface {
	CreateWithNetwork(ctx context.Context, resource *T, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, handler AzureSDKHandler) (string, error)
	FromResourceDecription(resourceDesc []byte) (T, error)
}

type AzureVM struct {
	AzureResourceHandler[armcompute.VirtualMachine]
}

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

	nic, err = handler.GetResourceNIC(ctx, *vm.ID)
	if err != nil {
		utils.Log.Printf("An error occured while getting the network interface:%+v", err)
		return "", err
	}

	return *nic.Properties.IPConfigurations[0].Properties.PrivateIPAddress, nil
}

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

type AzureAKS struct {
	AzureResourceHandler[armcontainerservice.ManagedCluster]
}

func (r *AzureAKS) CreateWithNetwork(ctx context.Context, resource *armcontainerservice.ManagedCluster, subnet *armnetwork.Subnet, resourceInfo *ResourceIDInfo, handler AzureSDKHandler) (string, error) {
	for _, profile := range resource.Properties.AgentPoolProfiles {
		profile.VnetSubnetID = subnet.ID
	}

	// TODO: Add something with the network profile? Need to understand the serviceCIDR

	aks, err := handler.CreateAKSCluster(ctx, *resource, resourceInfo.ResourceName)
	if err != nil {
		utils.Log.Printf("An error occured while creating the AKS cluster:%+v", err)
		return "", err
	}

	return *aks.Properties.Fqdn, nil
}

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

	// TODO: Something with the network profile? Need to understand the serviceCIDR

	return aks, nil
}
