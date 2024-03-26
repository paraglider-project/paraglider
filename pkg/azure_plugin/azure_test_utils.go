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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/mock"
)

/* ---- Mock SDK Handler ---- */

type MockAzureSDKHandler struct {
	mock.Mock
}

func SetupMockAzureSDKHandler() *MockAzureSDKHandler {
	var mockAzureHandler AzureSDKHandler = &MockAzureSDKHandler{}
	concreteMockAzureHandler := mockAzureHandler.(*MockAzureSDKHandler)
	return concreteMockAzureHandler
}

func (m *MockAzureSDKHandler) InitializeClients(cred azcore.TokenCredential) error {
	args := m.Called(cred)
	return args.Error(0)
}

func (m *MockAzureSDKHandler) GetAzureCredentials() (azcore.TokenCredential, error) {
	args := m.Called()
	cred := args.Get(0)
	if cred == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(azcore.TokenCredential), args.Error(1)
}

func (m *MockAzureSDKHandler) GetNetworkInterface(ctx context.Context, nicName string) (*armnetwork.Interface, error) {
	args := m.Called(ctx, nicName)
	nic := args.Get(0)
	if nic == nil {
		return nil, args.Error(1)
	}
	return nic.(*armnetwork.Interface), args.Error(1)
}

func (m *MockAzureSDKHandler) GetResource(ctx context.Context, resourceID string) (*armresources.GenericResource, error) {
	args := m.Called(ctx, resourceID)
	resource := args.Get(0)
	if resource == nil {
		return nil, args.Error(1)
	}
	return resource.(*armresources.GenericResource), args.Error(1)
}

func (m *MockAzureSDKHandler) CreateSecurityRule(ctx context.Context, rule *invisinetspb.PermitListRule, nsgName string, ruleName string, resourceIpAddress string, priority int32) (*armnetwork.SecurityRule, error) {
	args := m.Called(ctx, rule, nsgName, ruleName, resourceIpAddress, priority)
	srule := args.Get(0)
	// this check is done to handle panic: interface conversion: interface {} is nil, not *armnetwork.SecurityGroup
	// when you wnat to mock a nil return value
	if srule == nil {
		return nil, args.Error(1)
	}
	return srule.(*armnetwork.SecurityRule), args.Error(1)
}

func (m *MockAzureSDKHandler) DeleteSecurityRule(ctx context.Context, nsgName string, ruleName string) error {
	args := m.Called(ctx, nsgName, ruleName)
	return args.Error(0)
}

func (m *MockAzureSDKHandler) GetPermitListRuleFromNSGRule(rule *armnetwork.SecurityRule) (*invisinetspb.PermitListRule, error) {
	args := m.Called(rule)
	pl := args.Get(0)
	if pl == nil {
		return nil, args.Error(1)
	}
	return pl.(*invisinetspb.PermitListRule), args.Error(1)
}

func (m *MockAzureSDKHandler) GetSecurityGroup(ctx context.Context, nsgName string) (*armnetwork.SecurityGroup, error) {
	args := m.Called(ctx, nsgName)
	nsg := args.Get(0)
	if nsg == nil {
		return nil, args.Error(1)
	}
	return nsg.(*armnetwork.SecurityGroup), args.Error(1)
}

func (m *MockAzureSDKHandler) CreateInvisinetsVirtualNetwork(ctx context.Context, location string, name string, addressSpace string) (*armnetwork.VirtualNetwork, error) {
	args := m.Called(ctx, location, name, addressSpace)
	vnet := args.Get(0)
	if vnet == nil {
		return nil, args.Error(1)
	}
	return vnet.(*armnetwork.VirtualNetwork), args.Error(1)
}

func (m *MockAzureSDKHandler) AddSubnetToInvisinetsVnet(ctx context.Context, namespace string, vnetName string, subnetName string, orchestratorAddr string) (*armnetwork.Subnet, error) {
	args := m.Called(ctx, namespace, vnetName, subnetName, orchestratorAddr)
	subnet := args.Get(0)
	if subnet == nil {
		return nil, args.Error(1)
	}
	return subnet.(*armnetwork.Subnet), args.Error(1)
}

func (m *MockAzureSDKHandler) CreateSecurityGroup(ctx context.Context, name string, location string, allowedCIDRS map[string]string) (*armnetwork.SecurityGroup, error) {
	args := m.Called(ctx, location, name)
	nsg := args.Get(0)
	if nsg == nil {
		return nil, args.Error(1)
	}
	return nsg.(*armnetwork.SecurityGroup), args.Error(1)
}

func (m *MockAzureSDKHandler) AssociateNSGWithSubnet(ctx context.Context, subnetID string, nsgID string) error {
	args := m.Called(ctx, subnetID, nsgID)
	subnet := args.Get(0)
	if subnet == nil {
		return args.Error(1)
	}
	return args.Error(1)
}

func (m *MockAzureSDKHandler) CreateVirtualNetwork(ctx context.Context, name string, parameters armnetwork.VirtualNetwork) (*armnetwork.VirtualNetwork, error) {
	args := m.Called(ctx, name, parameters)
	vnet := args.Get(0)
	if vnet == nil {
		return nil, args.Error(1)
	}
	return vnet.(*armnetwork.VirtualNetwork), args.Error(1)
}

func (m *MockAzureSDKHandler) GetVirtualNetwork(ctx context.Context, name string) (*armnetwork.VirtualNetwork, error) {
	args := m.Called(ctx, name)
	vnet := args.Get(0)
	if vnet == nil {
		return nil, args.Error(1)
	}
	return vnet.(*armnetwork.VirtualNetwork), args.Error(1)
}

func (m *MockAzureSDKHandler) CreateNetworkInterface(ctx context.Context, subnetID string, location string, nicName string) (*armnetwork.Interface, error) {
	args := m.Called(ctx, subnetID, location, nicName)
	nic := args.Get(0)
	if nic == nil {
		return nil, args.Error(1)
	}
	return nic.(*armnetwork.Interface), args.Error(1)
}

func (m *MockAzureSDKHandler) CreateVirtualMachine(ctx context.Context, parameters armcompute.VirtualMachine, vmName string) (*armcompute.VirtualMachine, error) {
	args := m.Called(ctx, parameters, vmName)
	vm := args.Get(0)
	if vm == nil {
		return nil, args.Error(1)
	}
	return vm.(*armcompute.VirtualMachine), args.Error(1)
}

func (m *MockAzureSDKHandler) GetInvisinetsVnet(ctx context.Context, prefix string, location string, namespace string, orchestratorAddr string) (*armnetwork.VirtualNetwork, error) {
	args := m.Called(ctx, prefix, location, namespace, orchestratorAddr)
	vnet := args.Get(0)
	if vnet == nil {
		return nil, args.Error(1)
	}
	return vnet.(*armnetwork.VirtualNetwork), args.Error(1)
}

func (m *MockAzureSDKHandler) GetVNetsAddressSpaces(ctx context.Context, prefix string) (map[string]string, error) {
	args := m.Called(ctx, prefix)
	return args.Get(0).(map[string]string), args.Error(1)
}

func (m *MockAzureSDKHandler) GetLastSegment(resourceID string) (string, error) {
	args := m.Called(resourceID)
	return args.String(0), args.Error(1)
}

func (m *MockAzureSDKHandler) SetSubIdAndResourceGroup(subid string, resourceGroup string) {
	m.Called(subid, resourceGroup)
}

func (m *MockAzureSDKHandler) CreateVnetPeering(ctx context.Context, vnet1 string, vnet2 string) error {
	args := m.Called(ctx, vnet1, vnet2)
	return args.Error(0)
}

func (m *MockAzureSDKHandler) CreateOrUpdateVirtualNetworkPeering(ctx context.Context, virtualNetworkName string, virtualNetworkPeeringName string, parameters armnetwork.VirtualNetworkPeering) (*armnetwork.VirtualNetworkPeering, error) {
	args := m.Called(ctx, virtualNetworkName, virtualNetworkPeeringName, parameters)
	virtualNetworkPeering := args.Get(0)
	if virtualNetworkPeering == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkPeering.(*armnetwork.VirtualNetworkPeering), args.Error(1)
}

func (m *MockAzureSDKHandler) GetVirtualNetworkPeering(ctx context.Context, virtualNetworkName string, virtualNetworkPeeringName string) (*armnetwork.VirtualNetworkPeering, error) {
	args := m.Called(ctx, virtualNetworkName, virtualNetworkPeeringName)
	virtualNetworkPeering := args.Get(0)
	if virtualNetworkPeering == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkPeering.(*armnetwork.VirtualNetworkPeering), args.Error(1)
}

func (m *MockAzureSDKHandler) ListVirtualNetworkPeerings(ctx context.Context, virtualNetworkName string) ([]*armnetwork.VirtualNetworkPeering, error) {
	args := m.Called(ctx, virtualNetworkName)
	virtualNetworkPeerings := args.Get(0)
	if virtualNetworkPeerings == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkPeerings.([]*armnetwork.VirtualNetworkPeering), args.Error(1)
}

func (m *MockAzureSDKHandler) CreateOrUpdateVnetPeeringRemoteGateway(ctx context.Context, vnetName string, gatewayVnetName string, vnetToGatewayVnetPeering *armnetwork.VirtualNetworkPeering, gatewayVnetToVnetPeering *armnetwork.VirtualNetworkPeering) error {
	args := m.Called(ctx, vnetName, gatewayVnetName, vnetToGatewayVnetPeering, gatewayVnetToVnetPeering)
	return args.Error(0)
}

func (m *MockAzureSDKHandler) GetVNet(ctx context.Context, vnetName string) (*armnetwork.VirtualNetwork, error) {
	args := m.Called(ctx, vnetName)
	vnet := args.Get(0)
	if vnet == nil {
		return nil, args.Error(1)
	}
	return vnet.(*armnetwork.VirtualNetwork), args.Error(1)
}

func (m *MockAzureSDKHandler) CreateOrUpdateVirtualNetworkGateway(ctx context.Context, name string, parameters armnetwork.VirtualNetworkGateway) (*armnetwork.VirtualNetworkGateway, error) {
	args := m.Called(ctx, name, parameters)
	virtualNetworkGateway := args.Get(0)
	if virtualNetworkGateway == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkGateway.(*armnetwork.VirtualNetworkGateway), args.Error(1)
}

func (m *MockAzureSDKHandler) GetVirtualNetworkGateway(ctx context.Context, name string) (*armnetwork.VirtualNetworkGateway, error) {
	args := m.Called(ctx, name)
	virtualNetworkGateway := args.Get(0)
	if virtualNetworkGateway == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkGateway.(*armnetwork.VirtualNetworkGateway), args.Error(1)
}

func (m *MockAzureSDKHandler) CreatePublicIPAddress(ctx context.Context, name string, parameters armnetwork.PublicIPAddress) (*armnetwork.PublicIPAddress, error) {
	args := m.Called(ctx, name, parameters)
	publicIPAddress := args.Get(0)
	if publicIPAddress == nil {
		return nil, args.Error(1)
	}
	return publicIPAddress.(*armnetwork.PublicIPAddress), args.Error(1)
}

func (m *MockAzureSDKHandler) GetPublicIPAddress(ctx context.Context, name string) (*armnetwork.PublicIPAddress, error) {
	args := m.Called(ctx, name)
	publicIPAddress := args.Get(0)
	if publicIPAddress == nil {
		return nil, args.Error(1)
	}
	return publicIPAddress.(*armnetwork.PublicIPAddress), args.Error(1)
}

func (m *MockAzureSDKHandler) CreateSubnet(ctx context.Context, virtualNetworkName string, subnetName string, parameters armnetwork.Subnet) (*armnetwork.Subnet, error) {
	args := m.Called(ctx, virtualNetworkName, subnetName, parameters)
	subnet := args.Get(0)
	if subnet == nil {
		return nil, args.Error(1)
	}
	return subnet.(*armnetwork.Subnet), args.Error(1)
}

func (m *MockAzureSDKHandler) GetSubnet(ctx context.Context, virtualNetworkName string, subnetName string) (*armnetwork.Subnet, error) {
	args := m.Called(ctx, virtualNetworkName, subnetName)
	subnet := args.Get(0)
	if subnet == nil {
		return nil, args.Error(1)
	}
	return subnet.(*armnetwork.Subnet), args.Error(1)
}

func (m *MockAzureSDKHandler) GetSubnetByID(ctx context.Context, subnetID string) (*armnetwork.Subnet, error) {
	args := m.Called(ctx, subnetID)
	subnet := args.Get(0)
	if subnet == nil {
		return nil, args.Error(1)
	}
	return subnet.(*armnetwork.Subnet), args.Error(1)
}

func (m *MockAzureSDKHandler) CreateLocalNetworkGateway(ctx context.Context, name string, parameters armnetwork.LocalNetworkGateway) (*armnetwork.LocalNetworkGateway, error) {
	args := m.Called(ctx, name, parameters)
	localNetworkGateway := args.Get(0)
	if localNetworkGateway == nil {
		return nil, args.Error(1)
	}
	return localNetworkGateway.(*armnetwork.LocalNetworkGateway), args.Error(1)
}

func (m *MockAzureSDKHandler) GetLocalNetworkGateway(ctx context.Context, name string) (*armnetwork.LocalNetworkGateway, error) {
	args := m.Called(ctx, name)
	localNetworkGateway := args.Get(0)
	if localNetworkGateway == nil {
		return nil, args.Error(1)
	}
	return localNetworkGateway.(*armnetwork.LocalNetworkGateway), args.Error(1)
}

func (m *MockAzureSDKHandler) CreateVirtualNetworkGatewayConnection(ctx context.Context, name string, parameters armnetwork.VirtualNetworkGatewayConnection) (*armnetwork.VirtualNetworkGatewayConnection, error) {
	args := m.Called(ctx, name, parameters)
	virtualNetworkGatewayConnection := args.Get(0)
	if virtualNetworkGatewayConnection == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkGatewayConnection.(*armnetwork.VirtualNetworkGatewayConnection), args.Error(1)
}

func (m *MockAzureSDKHandler) GetVirtualNetworkGatewayConnection(ctx context.Context, name string) (*armnetwork.VirtualNetworkGatewayConnection, error) {
	args := m.Called(ctx, name)
	virtualNetworkGatewayConnection := args.Get(0)
	if virtualNetworkGatewayConnection == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkGatewayConnection.(*armnetwork.VirtualNetworkGatewayConnection), args.Error(1)
}

func (m *MockAzureSDKHandler) CreateAKSCluster(ctx context.Context, parameters armcontainerservice.ManagedCluster, clusterName string) (*armcontainerservice.ManagedCluster, error) {
	args := m.Called(ctx, parameters, clusterName)
	cluster := args.Get(0)
	if cluster == nil {
		return nil, args.Error(1)
	}
	return cluster.(*armcontainerservice.ManagedCluster), args.Error(1)
}
