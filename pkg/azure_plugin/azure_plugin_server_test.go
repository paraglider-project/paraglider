//go:build unit

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
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	fake "github.com/NetSys/invisinets/pkg/fake/controller/rpc"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/orchestrator"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var fakeAddressList = map[string]string{testLocation: validAddressSpace}

const defaultNamespace = "default"

type dummyTokenCredential struct{}

func (d *dummyTokenCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

/* ---- Mock SDK Handler ---- */

type mockAzureSDKHandler struct {
	mock.Mock
}

func (m *mockAzureSDKHandler) InitializeClients(cred azcore.TokenCredential) error {
	args := m.Called(cred)
	return args.Error(0)
}

func (m *mockAzureSDKHandler) GetAzureCredentials() (azcore.TokenCredential, error) {
	args := m.Called()
	cred := args.Get(0)
	if cred == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(azcore.TokenCredential), args.Error(1)
}

func (m *mockAzureSDKHandler) GetResourceNIC(ctx context.Context, resourceID string) (*armnetwork.Interface, error) {
	args := m.Called(ctx, resourceID)
	nic := args.Get(0)
	if nic == nil {
		return nil, args.Error(1)
	}
	return nic.(*armnetwork.Interface), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateSecurityRule(ctx context.Context, rule *invisinetspb.PermitListRule, nsgName string, ruleName string, resourceIpAddress string, priority int32) (*armnetwork.SecurityRule, error) {
	args := m.Called(ctx, rule, nsgName, ruleName, resourceIpAddress, priority)
	srule := args.Get(0)
	// this check is done to handle panic: interface conversion: interface {} is nil, not *armnetwork.SecurityGroup
	// when you wnat to mock a nil return value
	if srule == nil {
		return nil, args.Error(1)
	}
	return srule.(*armnetwork.SecurityRule), args.Error(1)
}

func (m *mockAzureSDKHandler) DeleteSecurityRule(ctx context.Context, nsgName string, ruleName string) error {
	args := m.Called(ctx, nsgName, ruleName)
	return args.Error(0)
}

func (m *mockAzureSDKHandler) GetPermitListRuleFromNSGRule(rule *armnetwork.SecurityRule) (*invisinetspb.PermitListRule, error) {
	args := m.Called(rule)
	pl := args.Get(0)
	if pl == nil {
		return nil, args.Error(1)
	}
	return pl.(*invisinetspb.PermitListRule), args.Error(1)
}

func (m *mockAzureSDKHandler) GetSecurityGroup(ctx context.Context, nsgName string) (*armnetwork.SecurityGroup, error) {
	args := m.Called(ctx, nsgName)
	nsg := args.Get(0)
	if nsg == nil {
		return nil, args.Error(1)
	}
	return nsg.(*armnetwork.SecurityGroup), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateInvisinetsVirtualNetwork(ctx context.Context, location string, name string, addressSpace string) (*armnetwork.VirtualNetwork, error) {
	args := m.Called(ctx, location, name, addressSpace)
	vnet := args.Get(0)
	if vnet == nil {
		return nil, args.Error(1)
	}
	return vnet.(*armnetwork.VirtualNetwork), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateVirtualNetwork(ctx context.Context, name string, parameters armnetwork.VirtualNetwork) (*armnetwork.VirtualNetwork, error) {
	args := m.Called(ctx, name, parameters)
	vnet := args.Get(0)
	if vnet == nil {
		return nil, args.Error(1)
	}
	return vnet.(*armnetwork.VirtualNetwork), args.Error(1)
}

func (m *mockAzureSDKHandler) GetVirtualNetwork(ctx context.Context, name string) (*armnetwork.VirtualNetwork, error) {
	args := m.Called(ctx, name)
	vnet := args.Get(0)
	if vnet == nil {
		return nil, args.Error(1)
	}
	return vnet.(*armnetwork.VirtualNetwork), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateNetworkInterface(ctx context.Context, subnetID string, location string, nicName string) (*armnetwork.Interface, error) {
	args := m.Called(ctx, subnetID, location, nicName)
	nic := args.Get(0)
	if nic == nil {
		return nil, args.Error(1)
	}
	return nic.(*armnetwork.Interface), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateVirtualMachine(ctx context.Context, parameters armcompute.VirtualMachine, vmName string) (*armcompute.VirtualMachine, error) {
	args := m.Called(ctx, parameters, vmName)
	vm := args.Get(0)
	if vm == nil {
		return nil, args.Error(1)
	}
	return vm.(*armcompute.VirtualMachine), args.Error(1)
}

func (m *mockAzureSDKHandler) GetInvisinetsVnet(ctx context.Context, prefix string, location string, namespace string, orchestratorAddr string) (*armnetwork.VirtualNetwork, error) {
	args := m.Called(ctx, prefix, location, namespace, orchestratorAddr)
	vnet := args.Get(0)
	if vnet == nil {
		return nil, args.Error(1)
	}
	return vnet.(*armnetwork.VirtualNetwork), args.Error(1)
}

func (m *mockAzureSDKHandler) GetVNetsAddressSpaces(ctx context.Context, prefix string) (map[string]string, error) {
	args := m.Called(ctx, prefix)
	return args.Get(0).(map[string]string), args.Error(1)
}

func (m *mockAzureSDKHandler) GetLastSegment(resourceID string) (string, error) {
	args := m.Called(resourceID)
	return args.String(0), args.Error(1)
}

func (m *mockAzureSDKHandler) SetSubIdAndResourceGroup(subid string, resourceGroup string) {
	m.Called(subid, resourceGroup)
}

func (m *mockAzureSDKHandler) CreateVnetPeeringOneWay(ctx context.Context, vnet1Name string, vnet2Name string, vnet2SubscriptionID string, vnet2ResourceGroupName string) error {
	args := m.Called(ctx, vnet1Name, vnet2Name, vnet2SubscriptionID, vnet2ResourceGroupName)
	return args.Error(0)
}

func (m *mockAzureSDKHandler) CreateVnetPeering(ctx context.Context, vnet1 string, vnet2 string) error {
	args := m.Called(ctx, vnet1, vnet2)
	return args.Error(0)
}

func (m *mockAzureSDKHandler) CreateOrUpdateVirtualNetworkPeering(ctx context.Context, virtualNetworkName string, virtualNetworkPeeringName string, parameters armnetwork.VirtualNetworkPeering) (*armnetwork.VirtualNetworkPeering, error) {
	args := m.Called(ctx, virtualNetworkName, virtualNetworkPeeringName, parameters)
	virtualNetworkPeering := args.Get(0)
	if virtualNetworkPeering == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkPeering.(*armnetwork.VirtualNetworkPeering), args.Error(1)
}

func (m *mockAzureSDKHandler) GetVirtualNetworkPeering(ctx context.Context, virtualNetworkName string, virtualNetworkPeeringName string) (*armnetwork.VirtualNetworkPeering, error) {
	args := m.Called(ctx, virtualNetworkName, virtualNetworkPeeringName)
	virtualNetworkPeering := args.Get(0)
	if virtualNetworkPeering == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkPeering.(*armnetwork.VirtualNetworkPeering), args.Error(1)
}

func (m *mockAzureSDKHandler) ListVirtualNetworkPeerings(ctx context.Context, virtualNetworkName string) ([]*armnetwork.VirtualNetworkPeering, error) {
	args := m.Called(ctx, virtualNetworkName)
	virtualNetworkPeerings := args.Get(0)
	if virtualNetworkPeerings == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkPeerings.([]*armnetwork.VirtualNetworkPeering), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateVnetPeeringGatewayVnet(ctx context.Context, vnetName string, gatewayVnetName string) error {
	args := m.Called(ctx, vnetName, gatewayVnetName)
	return args.Error(0)
}

func (m *mockAzureSDKHandler) CreateOrUpdateVnetPeeringRemoteGateway(ctx context.Context, vnetName string, gatewayVnetName string, vnetToGatewayVnetPeering *armnetwork.VirtualNetworkPeering, gatewayVnetToVnetPeering *armnetwork.VirtualNetworkPeering) error {
	args := m.Called(ctx, vnetName, gatewayVnetName, vnetToGatewayVnetPeering, gatewayVnetToVnetPeering)
	return args.Error(0)
}

func (m *mockAzureSDKHandler) GetVNet(ctx context.Context, vnetName string) (*armnetwork.VirtualNetwork, error) {
	args := m.Called(ctx, vnetName)
	vnet := args.Get(0)
	if vnet == nil {
		return nil, args.Error(1)
	}
	return vnet.(*armnetwork.VirtualNetwork), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateOrUpdateVirtualNetworkGateway(ctx context.Context, name string, parameters armnetwork.VirtualNetworkGateway) (*armnetwork.VirtualNetworkGateway, error) {
	args := m.Called(ctx, name, parameters)
	virtualNetworkGateway := args.Get(0)
	if virtualNetworkGateway == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkGateway.(*armnetwork.VirtualNetworkGateway), args.Error(1)
}

func (m *mockAzureSDKHandler) GetVirtualNetworkGateway(ctx context.Context, name string) (*armnetwork.VirtualNetworkGateway, error) {
	args := m.Called(ctx, name)
	virtualNetworkGateway := args.Get(0)
	if virtualNetworkGateway == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkGateway.(*armnetwork.VirtualNetworkGateway), args.Error(1)
}

func (m *mockAzureSDKHandler) CreatePublicIPAddress(ctx context.Context, name string, parameters armnetwork.PublicIPAddress) (*armnetwork.PublicIPAddress, error) {
	args := m.Called(ctx, name, parameters)
	publicIPAddress := args.Get(0)
	if publicIPAddress == nil {
		return nil, args.Error(1)
	}
	return publicIPAddress.(*armnetwork.PublicIPAddress), args.Error(1)
}

func (m *mockAzureSDKHandler) GetPublicIPAddress(ctx context.Context, name string) (*armnetwork.PublicIPAddress, error) {
	args := m.Called(ctx, name)
	publicIPAddress := args.Get(0)
	if publicIPAddress == nil {
		return nil, args.Error(1)
	}
	return publicIPAddress.(*armnetwork.PublicIPAddress), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateSubnet(ctx context.Context, virtualNetworkName string, subnetName string, parameters armnetwork.Subnet) (*armnetwork.Subnet, error) {
	args := m.Called(ctx, virtualNetworkName, subnetName, parameters)
	subnet := args.Get(0)
	if subnet == nil {
		return nil, args.Error(1)
	}
	return subnet.(*armnetwork.Subnet), args.Error(1)
}

func (m *mockAzureSDKHandler) GetSubnet(ctx context.Context, virtualNetworkName string, subnetName string) (*armnetwork.Subnet, error) {
	args := m.Called(ctx, virtualNetworkName, subnetName)
	subnet := args.Get(0)
	if subnet == nil {
		return nil, args.Error(1)
	}
	return subnet.(*armnetwork.Subnet), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateLocalNetworkGateway(ctx context.Context, name string, parameters armnetwork.LocalNetworkGateway) (*armnetwork.LocalNetworkGateway, error) {
	args := m.Called(ctx, name, parameters)
	localNetworkGateway := args.Get(0)
	if localNetworkGateway == nil {
		return nil, args.Error(1)
	}
	return localNetworkGateway.(*armnetwork.LocalNetworkGateway), args.Error(1)
}

func (m *mockAzureSDKHandler) GetLocalNetworkGateway(ctx context.Context, name string) (*armnetwork.LocalNetworkGateway, error) {
	args := m.Called(ctx, name)
	localNetworkGateway := args.Get(0)
	if localNetworkGateway == nil {
		return nil, args.Error(1)
	}
	return localNetworkGateway.(*armnetwork.LocalNetworkGateway), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateVirtualNetworkGatewayConnection(ctx context.Context, name string, parameters armnetwork.VirtualNetworkGatewayConnection) (*armnetwork.VirtualNetworkGatewayConnection, error) {
	args := m.Called(ctx, name, parameters)
	virtualNetworkGatewayConnection := args.Get(0)
	if virtualNetworkGatewayConnection == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkGatewayConnection.(*armnetwork.VirtualNetworkGatewayConnection), args.Error(1)
}

func (m *mockAzureSDKHandler) GetVirtualNetworkGatewayConnection(ctx context.Context, name string) (*armnetwork.VirtualNetworkGatewayConnection, error) {
	args := m.Called(ctx, name)
	virtualNetworkGatewayConnection := args.Get(0)
	if virtualNetworkGatewayConnection == nil {
		return nil, args.Error(1)
	}
	return virtualNetworkGatewayConnection.(*armnetwork.VirtualNetworkGatewayConnection), args.Error(1)
}

func setupAzurePluginServer() (*azurePluginServer, *mockAzureSDKHandler, context.Context) {
	// Create a new instance of the azurePluginServer
	server := &azurePluginServer{}

	// Create a mock implementation of the AzureSDKHandler interface
	var mockAzureHandler AzureSDKHandler = &mockAzureSDKHandler{}
	server.mockAzureHandler = mockAzureHandler
	server.orchestratorServerAddr = "fakecontrollerserveraddr"

	// Perform a type requireion to convert the AzureSDKHandler interface value to a *mockAzureSDKHandler concrete value, allowing access to methods and fields specific to the mockAzureSDKHandler type.
	concreteMockAzureHandler := mockAzureHandler.(*mockAzureSDKHandler)

	// Return &mockAzureHandler to test methods that take in *azureSDKHandler (e.g., getAndCheckResourceNamespace)
	return server, concreteMockAzureHandler, context.Background()
}

func getValidResourceDesc() (armcompute.VirtualMachine, []byte, error) {
	validVm := armcompute.VirtualMachine{
		Location:   to.Ptr(testLocation),
		Properties: &armcompute.VirtualMachineProperties{},
	}

	validDescripton, err := json.Marshal(validVm)
	return validVm, validDescripton, err
}

/* ---- Tests ---- */

func TestCreateResource(t *testing.T) {
	defaultSubnetName := "default"
	defaultSubnetID := "default-subnet-id"
	namespace := "defaultnamespace"
	vnetName := getVnetName(testLocation, namespace)
	t.Run("TestCreateResource: Success", func(t *testing.T) {
		// we need to recreate it for each test as it will be modified to include network interface
		vm, desc, err := getValidResourceDesc()
		if err != nil {
			t.Errorf("Error while creating valid resource description: %v", err)
		}

		server, mockAzureHandler, ctx := setupAzurePluginServer()

		// Set up mock behavior for the Azure SDK handler
		mockAzureHandler.On("SetSubIdAndResourceGroup", mock.Anything, mock.Anything).Return()
		mockAzureHandler.On("GetAzureCredentials").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return(nil)
		mockAzureHandler.On("GetInvisinetsVnet", ctx, vnetName, testLocation, namespace, server.orchestratorServerAddr).Return(&armnetwork.VirtualNetwork{
			Properties: &armnetwork.VirtualNetworkPropertiesFormat{
				Subnets: []*armnetwork.Subnet{
					{
						Name: to.Ptr(defaultSubnetName),
						ID:   to.Ptr(defaultSubnetID),
					},
				},
			},
		}, nil)
		mockAzureHandler.On("CreateNetworkInterface", ctx, defaultSubnetID, testLocation, mock.Anything).Return(&armnetwork.Interface{ID: to.Ptr(validNicId)}, nil)
		vmName := "vm_name"
		mockAzureHandler.On("CreateVirtualMachine", ctx, vm, mock.Anything).Return(&armcompute.VirtualMachine{ID: to.Ptr(vmResourceID), Name: &vmName}, nil)
		fakeNic := getFakeNIC()
		mockAzureHandler.On("GetResourceNIC", ctx, vmResourceID).Return(fakeNic, nil)
		vpnGwVnetName := getVpnGatewayVnetName(namespace)
		mockAzureHandler.On("GetVirtualNetwork", ctx, vpnGwVnetName).Return(&armnetwork.VirtualNetwork{}, nil)
		mockAzureHandler.On("GetVirtualNetworkGateway", ctx, getVpnGatewayName(namespace)).Return(&armnetwork.VirtualNetworkGateway{}, nil)
		mockAzureHandler.On("GetVirtualNetworkPeering", ctx, vnetName, vpnGwVnetName).Return(nil, &azcore.ResponseError{StatusCode: http.StatusNotFound})
		mockAzureHandler.On("CreateOrUpdateVnetPeeringRemoteGateway", ctx, vnetName, vpnGwVnetName, (*armnetwork.VirtualNetworkPeering)(nil), (*armnetwork.VirtualNetworkPeering)(nil)).Return(nil)

		vm.Properties.NetworkProfile = &armcompute.NetworkProfile{
			NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
				{
					ID: to.Ptr(validNicId),
				},
			},
		}

		response, err := server.CreateResource(ctx, &invisinetspb.ResourceDescription{
			Deployment:  &invisinetspb.InvisinetsDeployment{Id: "/subscriptions/123/resourceGroups/rg", Namespace: namespace},
			Name:        vmName,
			Description: desc,
		})

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, vmResourceID, response.Uri)
	})

	t.Run("TestCreateResource: Failure, invalid json", func(t *testing.T) {
		server, _, ctx := setupAzurePluginServer()
		response, err := server.CreateResource(ctx, &invisinetspb.ResourceDescription{
			Description: []byte("invalid json"),
		})

		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("TestCreateResource: Failure, No Location", func(t *testing.T) {
		desc, err := json.Marshal(armcompute.VirtualMachine{
			Properties: &armcompute.VirtualMachineProperties{},
		})
		if err != nil {
			t.Errorf("Error while marshalling description: %v", err)
		}
		server, _, ctx := setupAzurePluginServer()
		response, err := server.CreateResource(ctx, &invisinetspb.ResourceDescription{
			Description: desc,
		})

		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("TestCreateResource: Failure, Includes Network Interface", func(t *testing.T) {
		desc, err := json.Marshal(armcompute.VirtualMachine{
			Location: to.Ptr(testLocation),
			Properties: &armcompute.VirtualMachineProperties{
				NetworkProfile: &armcompute.NetworkProfile{
					NetworkInterfaces: []*armcompute.NetworkInterfaceReference{},
				},
			},
		})

		if err != nil {
			t.Errorf("Error while marshalling description: %v", err)
		}

		server, _, ctx := setupAzurePluginServer()

		response, err := server.CreateResource(ctx, &invisinetspb.ResourceDescription{
			Description: desc,
		})

		require.Error(t, err)
		require.Nil(t, response)
	})
}

func TestGetPermitList(t *testing.T) {
	fakePlRules, err := getFakePermitList()
	if err != nil {
		t.Errorf("Error while getting fake permit list: %v", err)
	}
	fakeNsgName := "test-nsg-name"
	fakeNic := getFakeNIC()
	fakeNsgID := *fakeNic.Properties.NetworkSecurityGroup.ID
	fakeNsg := getFakeNsg(fakeNsgID, fakeNsgName)

	// Set up a  resource
	fakeResourceId := getFakeVmUri()

	// Within each subtest, we recreate the setup for the azurePluginServer,
	// mockAzureHandler, context (ctx) variables.
	// This ensures that each subtest starts with a clean and isolated state.

	// Test Case 1: Successful execution and expected permit list
	t.Run("TestGetPermitList: Success", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()

		// Set up mock behavior for the Azure SDK handler
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResourceId, fakeNsgID, fakeNsgName, fakeNsg, fakeNic)

		// make suret that the GetPermitListRuleFromNSGRule is called on all the invisinets rules
		for i, rule := range fakeNsg.Properties.SecurityRules {
			if strings.HasPrefix(*rule.Name, invisinetsPrefix) {
				mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePlRules[i], nil)
			}
		}

		// Call the GetPermitList function
		request := &invisinetspb.GetPermitListRequest{Resource: fakeResourceId, Namespace: defaultNamespace}
		resp, err := server.GetPermitList(ctx, request)

		// check the results
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, fakePlRules[0], resp.Rules[0])
		require.Len(t, resp.Rules, 2)
	})

	// Test Case 2: GetAzureCredentials fails
	t.Run("TestGetPermitList: Failure while getting azure credentials", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		// Set up mock behavior for the Azure SDK handler to return an error on GetAzureCredentials call
		mockAzureHandler.On("GetAzureCredentials").Return(nil, fmt.Errorf("error while getting azure credentials"))

		// Call the GetPermitList function
		request := &invisinetspb.GetPermitListRequest{Resource: fakeResourceId, Namespace: defaultNamespace}
		response, err := server.GetPermitList(ctx, request)

		// check the error
		require.Error(t, err)
		require.Nil(t, response)
	})

	// Test Case 3: NSG get fails due to GetResourceNIC call
	t.Run("TestGetPermitList: Failed while getting NIC", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		// Set up mock behavior for the Azure SDK handler to return an error on GetResourceNIC call
		mockHandlerSetup(mockAzureHandler)
		mockAzureHandler.On("GetResourceNIC", ctx, fakeResourceId).Return(nil, fmt.Errorf("NIC get error"))

		// Call the GetPermitList function
		request := &invisinetspb.GetPermitListRequest{Resource: fakeResourceId, Namespace: defaultNamespace}
		response, err := server.GetPermitList(ctx, request)

		// check the error
		require.Error(t, err)
		require.Nil(t, response)
	})

	// Test Case 4: Fail due to a failure in getPermitList
	t.Run("TestGetPermitList: Failed while getting pl rule", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()

		// Set up mock behavior for the Azure SDK handler
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResourceId, fakeNsgID, fakeNsgName, fakeNsg, fakeNic)
		mockAzureHandler.On("GetPermitListRuleFromNSGRule", mock.Anything).Return(nil, fmt.Errorf("error while getting permit list rule"))

		request := &invisinetspb.GetPermitListRequest{Resource: fakeResourceId, Namespace: defaultNamespace}
		response, err := server.GetPermitList(ctx, request)

		// check the error
		require.Error(t, err)
		require.Nil(t, response)
	})

	// Test Case 5: Fail due to resource being in different namespace
	t.Run("TestGetPermitList: Fail due to mismatching namespace", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()

		// Set up mock behavior for the Azure SDK handler
		mockHandlerSetup(mockAzureHandler)

		// Set up NIC to be in a subnet not in the current namespace
		fakeNic.Properties.IPConfigurations[0].Properties.Subnet.ID = to.Ptr("/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Network/virtualNetworks/vnet123/subnets/subnet123")
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResourceId, fakeNsgID, fakeNsgName, fakeNsg, fakeNic)

		// Call the GetPermitList function
		request := &invisinetspb.GetPermitListRequest{Resource: fakeResourceId, Namespace: defaultNamespace}
		response, err := server.GetPermitList(ctx, request)

		// check the error
		require.Error(t, err)
		require.Nil(t, response)
	})
}

func TestAddPermitListRules(t *testing.T) {
	fakeOrchestratorServer, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.AZURE)
	if err != nil {
		t.Fatal(err)
	}
	fakeOrchestratorServer.Counter = 1

	fakeResource := getFakeVmUri()
	fakePlRules, err := getFakeNewPermitListRules()
	if err != nil {
		t.Errorf("Error while getting fake permit list: %v", err)
	}
	fakeNsgName := "test-nsg-name"
	fakeNic := getFakeNIC()
	fakeNsgID := *fakeNic.Properties.NetworkSecurityGroup.ID
	fakeResourceAddress := *fakeNic.Properties.IPConfigurations[0].Properties.PrivateIPAddress
	fakeNsg := getFakeNsg(fakeNsgID, fakeNsgName)
	fakeVnet := getFakeVnet(fakeNic.Location, validAddressSpace)
	fakeVnet.Properties = &armnetwork.VirtualNetworkPropertiesFormat{
		AddressSpace: &armnetwork.AddressSpace{
			AddressPrefixes: []*string{to.Ptr("10.0.0.0/16")},
		},
		Subnets: []*armnetwork.Subnet{
			{
				Name: to.Ptr("default"),
				Properties: &armnetwork.SubnetPropertiesFormat{
					AddressPrefix: to.Ptr("10.0.0.0/16"),
				},
			},
		},
	}

	// Successful AddPermitListRules with new rules
	t.Run("AddPermitListRules: New Rules Success", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResource, fakeNsgID, fakeNsgName, fakeNsg, fakeNic)
		mockAzureHandler.On("GetVNet", ctx, getVnetName(*fakeNic.Location, defaultNamespace)).Return(fakeVnet, nil)

		for i, rule := range fakePlRules {
			mockAzureHandler.On("CreateSecurityRule", ctx, rule, fakeNsgName, mock.Anything, fakeResourceAddress, int32(103+i)).Return(&armnetwork.SecurityRule{
				ID: to.Ptr("fake-invisinets-rule"),
			}, nil).Times(1)
		}

		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakePlRules, Namespace: defaultNamespace, Resource: fakeResource})

		mockAzureHandler.AssertExpectations(t) // this will fail if any of the calls above are not called or for different times
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	// Successful AddPermitListRules with existing rules
	t.Run("AddPermitListRules: Existing Rules Success", func(t *testing.T) {
		fakeOldPlRules, err := getFakePermitList()
		if err != nil {
			t.Errorf("Error while getting fake permit list: %v", err)
		}

		server, mockAzureHandler, ctx := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResource, fakeNsgID, fakeNsgName, fakeNsg, fakeNic)
		mockAzureHandler.On("GetVNet", ctx, getVnetName(*fakeNic.Location, defaultNamespace)).Return(fakeVnet, nil)

		for i, rule := range fakeNsg.Properties.SecurityRules {
			if strings.HasPrefix(*rule.Name, invisinetsPrefix) {
				mockAzureHandler.On("CreateSecurityRule", ctx, fakeOldPlRules[i], fakeNsgName, mock.Anything, fakeResourceAddress, *rule.Properties.Priority).Return(&armnetwork.SecurityRule{
					ID: to.Ptr("fake-invisinets-rule"),
				}, nil).Times(1)
			}
		}

		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakeOldPlRules, Namespace: defaultNamespace, Resource: fakeResource})

		mockAzureHandler.AssertExpectations(t) // this will fail if any of the calls above are not called or for different times
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	// Failed AddPermitListRules
	t.Run("AddPermitListRules: Failure while getting NSG", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResource, fakeNsgID, fakeNsgName, nil, fakeNic)
		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakePlRules, Namespace: defaultNamespace, Resource: fakeResource})
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Failed during GetAzureCredentials
	t.Run("AddPermitListRules: Failure while getting azure credential", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr
		mockAzureHandler.On("GetAzureCredentials").Return(nil, fmt.Errorf("error while getting azure credentials"))
		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakePlRules, Namespace: defaultNamespace, Resource: fakeResource})
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Failed while getting NIC
	t.Run("AddPermitListRules: Failure while getting NIC", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr
		mockHandlerSetup(mockAzureHandler)
		mockAzureHandler.On("GetResourceNIC", ctx, fakeResource).Return(nil, fmt.Errorf("error while getting NIC"))
		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakePlRules, Namespace: defaultNamespace, Resource: fakeResource})
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Failed while getting nsgName
	t.Run("AddPermitListRules: Failure while getting NSG Name", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr
		mockHandlerSetup(mockAzureHandler)
		mockAzureHandler.On("GetResourceNIC", ctx, fakeResource).Return(fakeNic, nil)
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return("", fmt.Errorf("error while getting nsgName"))
		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakePlRules, Namespace: defaultNamespace, Resource: fakeResource})
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Failure while creting the nsg rule in azure
	t.Run("AddPermitListRules: Failure when creating nsg rule", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResource, fakeNsgID, fakeNsgName, fakeNsg, fakeNic)
		mockGetVnetAndAddressSpaces(mockAzureHandler, ctx, getVnetName(*fakeNic.Location, defaultNamespace), getInvisinetsNamespacePrefix(defaultNamespace), fakeVnet, fakeAddressList)
		for i, rule := range fakeNsg.Properties.SecurityRules {
			if strings.HasPrefix(*rule.Name, invisinetsPrefix) {
				mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePlRules[i], nil)
			}
		}

		mockAzureHandler.On("CreateSecurityRule", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, fmt.Errorf("error while creating nsg rule"))

		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakePlRules, Namespace: defaultNamespace, Resource: fakeResource})
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Fail due to resource being in different namespace
	t.Run("AddPermitListRules: Fail due to mismatching namespace", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr

		// Set up mock behavior for the Azure SDK handler
		mockHandlerSetup(mockAzureHandler)

		// Setup fake NIC to belong to subnet not in current namespace
		fakeNic.Properties.IPConfigurations[0].Properties.Subnet.ID = to.Ptr("/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Network/virtualNetworks/vnet123/subnets/subnet123")
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResource, fakeNsgID, fakeNsgName, fakeNsg, fakeNic)

		// Call the GetPermitList function
		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakePlRules, Namespace: defaultNamespace, Resource: fakeResource})

		// check the error
		require.Error(t, err)
		require.Nil(t, resp)
	})
}

func TestDeleteDeletePermitListRules(t *testing.T) {
	fakePlRules, err := getFakePermitList()
	if err != nil {
		t.Errorf("Error while getting fake permit list: %v", err)
	}
	fakeRuleNames := []string{}
	for _, rule := range fakePlRules {
		fakeRuleNames = append(fakeRuleNames, rule.Name)
	}
	fakeNsgName := "test-nsg-name"
	fakeNic := getFakeNIC()
	fakeNsgID := *fakeNic.Properties.NetworkSecurityGroup.ID
	fakeNsg := getFakeNsg(fakeNsgID, fakeNsgName)
	fakeResource := getFakeVmUri()

	// The mockAzureHandler is reset for each test case to ensure that the mock is not called
	// from a previous test case and avoid conflicts between test cases

	// successful
	t.Run("DeletePermitListRules: Success", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResource, fakeNsgID, fakeNsgName, fakeNsg, fakeNic)

		mockAzureHandler.On("DeleteSecurityRule", ctx, fakeNsgName, mock.Anything).Return(nil)
		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	// Deletion error while getting resource nic
	t.Run("DeletePermitListRules: Failure while getting NIC", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockAzureHandler.On("GetResourceNIC", ctx, fakeResource).Return(nil, fmt.Errorf("nic error"))
		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Deletion error while getting azure credentials
	t.Run("DeletePermitListRules: Failure while getting azure credentials", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("GetAzureCredentials").Return(nil, fmt.Errorf("error while getting azure credentials"))
		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Failure while deleting rule
	t.Run("DeletePermitListRules: Failure while deleting security rule", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResource, fakeNsgID, fakeNsgName, fakeNsg, fakeNic)

		mockAzureHandler.On("DeleteSecurityRule", ctx, fakeNsgName, mock.Anything).Return(fmt.Errorf("error while deleting rule"))
		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Failure while getting last segment
	t.Run("DeletePermitListRules: Failure while getting last segment", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockAzureHandler.On("GetResourceNIC", ctx, fakeResource).Return(fakeNic, nil)
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return("", fmt.Errorf("error while getting last segment"))

		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test 6: Failure while getting security group
	t.Run("DeletePermitListRules: Failure while getting security group", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResource, fakeNsgID, fakeNsgName, nil, fakeNic)
		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test Case 7: Fail due to resource being in different namespace
	t.Run("DeletePermitListRules: Fail due to mismatching namespace", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()

		// Set up mock behavior for the Azure SDK handler
		mockHandlerSetup(mockAzureHandler)

		// Setup fake NIC to belong to subnet not in current namespace
		fakeNic.Properties.IPConfigurations[0].Properties.Subnet.ID = to.Ptr("/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Network/virtualNetworks/vnet123/subnets/subnet123")
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakeResource, fakeNsgID, fakeNsgName, fakeNsg, fakeNic)

		// Call the GetPermitList function
		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		// check the error
		require.Error(t, err)
		require.Nil(t, resp)
	})
}

func TestGetUsedAddressSpaces(t *testing.T) {
	server, mockAzureHandler, ctx := setupAzurePluginServer()
	mockHandlerSetup(mockAzureHandler)
	mockAzureHandler.On("GetVNetsAddressSpaces", ctx, getInvisinetsNamespacePrefix(defaultNamespace)).Return(fakeAddressList, nil)
	req := &invisinetspb.GetUsedAddressSpacesRequest{
		Deployments: []*invisinetspb.InvisinetsDeployment{
			{Id: "/subscriptions/123/resourceGroups/rg", Namespace: defaultNamespace},
		},
	}
	resp, err := server.GetUsedAddressSpaces(ctx, req)

	expectedAddressSpaceMappings := []*invisinetspb.AddressSpaceMapping{
		{
			AddressSpaces: []string{validAddressSpace},
			Cloud:         utils.AZURE,
			Namespace:     defaultNamespace,
		},
	}
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.ElementsMatch(t, expectedAddressSpaceMappings, resp.AddressSpaceMappings)
}

func TestGetUsedAsns(t *testing.T) {
	server, mockAzureHandler, ctx := setupAzurePluginServer()
	mockHandlerSetup(mockAzureHandler)
	mockAzureHandler.On("GetVirtualNetworkGateway", ctx, getVpnGatewayName(defaultNamespace)).Return(
		&armnetwork.VirtualNetworkGateway{Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{BgpSettings: &armnetwork.BgpSettings{Asn: to.Ptr(int64(64512))}}},
		nil,
	)

	usedAsnsExpected := []uint32{64512}
	req := &invisinetspb.GetUsedAsnsRequest{
		Deployments: []*invisinetspb.InvisinetsDeployment{
			{Id: "/subscriptions/123/resourceGroups/rg", Namespace: defaultNamespace},
		},
	}
	resp, err := server.GetUsedAsns(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.ElementsMatch(t, usedAsnsExpected, resp.Asns)
}

func TestGetUsedBgpPeeringIpAddresses(t *testing.T) {
	server, mockAzureHandler, ctx := setupAzurePluginServer()
	mockHandlerSetup(mockAzureHandler)
	mockAzureHandler.On("GetVirtualNetworkGateway", ctx, getVpnGatewayName(defaultNamespace)).Return(
		&armnetwork.VirtualNetworkGateway{
			Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{
				BgpSettings: &armnetwork.BgpSettings{
					BgpPeeringAddresses: []*armnetwork.IPConfigurationBgpPeeringAddress{
						{CustomBgpIPAddresses: []*string{to.Ptr("169.254.21.1")}},
						{CustomBgpIPAddresses: []*string{to.Ptr("169.254.22.1")}},
					},
				},
			},
		},
		nil,
	)

	usedBgpPeeringIpAddressExpected := []string{"169.254.21.1", "169.254.22.1"}
	req := &invisinetspb.GetUsedBgpPeeringIpAddressesRequest{
		Deployments: []*invisinetspb.InvisinetsDeployment{
			{Id: "/subscriptions/123/resourceGroups/rg", Namespace: defaultNamespace},
		},
	}
	resp, err := server.GetUsedBgpPeeringIpAddresses(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.ElementsMatch(t, usedBgpPeeringIpAddressExpected, resp.IpAddresses)
}

func TestGetAndCheckResourceNamespace(t *testing.T) {
	fakeNic := getFakeNIC()
	resourceID := "resourceID"

	server, mockAzureHandler, ctx := setupAzurePluginServer()
	mockHandlerSetup(mockAzureHandler)
	mockAzureHandler.On("GetResourceNIC", ctx, resourceID).Return(fakeNic, nil)

	err := server.getAndCheckResourceNamespace(ctx, server.mockAzureHandler, resourceID, defaultNamespace)
	require.Nil(t, err)

	err = server.getAndCheckResourceNamespace(ctx, server.mockAzureHandler, resourceID, "othernamespace")
	require.NotNil(t, err)

	err = server.getAndCheckResourceNamespace(ctx, server.mockAzureHandler, resourceID, "")
	require.NotNil(t, err)
}

func TestGetVnetFromSubnetId(t *testing.T) {
	subnetId := "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Network/virtualNetworks/vnet123/subnets/subnet123"
	expectedVnet := "vnet123"

	vnet := getVnetFromSubnetId(subnetId)
	assert.Equal(t, expectedVnet, vnet)
}

func TestGetResourceIDInfo(t *testing.T) {
	tests := []struct {
		name         string
		resourceID   string
		expectedInfo ResourceIDInfo
		expectError  bool
	}{
		{
			name:         "ValidResourceIDWithVM",
			resourceID:   getFakeVmUri(),
			expectedInfo: ResourceIDInfo{SubscriptionID: "sub123", ResourceGroupName: "rg123", ResourceName: "vm123"},
			expectError:  false,
		},
		{
			name:         "ValidResourceIDWithoutVM",
			resourceID:   "/subscriptions/sub123/resourceGroups/rg123",
			expectedInfo: ResourceIDInfo{SubscriptionID: "sub123", ResourceGroupName: "rg123", ResourceName: "rg123"},
			expectError:  false,
		},
		{
			name:         "InvalidFormatTooFewSegments",
			resourceID:   "/subscriptions/sub123",
			expectedInfo: ResourceIDInfo{},
			expectError:  true,
		},
		{
			name:         "InvalidSegment",
			resourceID:   "/subscriptions/sub123/invalidSegment/rg123/providers/Microsoft.Compute/virtualMachines/vm123",
			expectedInfo: ResourceIDInfo{},
			expectError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, err := getResourceIDInfo(test.resourceID)

			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expectedInfo, info)
			}
		})
	}
}

func TestCreateVpnGateway(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.AZURE)
	if err != nil {
		t.Fatal(err)
	}
	server, mockAzureHandler, ctx := setupAzurePluginServer()
	server.orchestratorServerAddr = fakeControllerServerAddr
	mockHandlerSetup(mockAzureHandler)

	mockAzureHandler.On("GetVirtualNetworkGateway", ctx, getVpnGatewayName(defaultNamespace)).Return(
		nil,
		&azcore.ResponseError{StatusCode: http.StatusNotFound},
	)

	fakePublicIpAddress := "172.178.88.1"
	vpnGatewayIPAddressName := getVPNGatewayIPAddressName(defaultNamespace, 0)
	mockAzureHandler.On("GetPublicIPAddress", ctx, vpnGatewayIPAddressName).Return(
		nil,
		&azcore.ResponseError{StatusCode: http.StatusNotFound},
	)
	mockAzureHandler.On("CreatePublicIPAddress", ctx, vpnGatewayIPAddressName, mock.Anything).Return(
		&armnetwork.PublicIPAddress{
			ID: to.Ptr("public-ip-address-%0"),
			Properties: &armnetwork.PublicIPAddressPropertiesFormat{
				IPAddress: to.Ptr(fakePublicIpAddress),
			},
		},
		nil,
	)

	fakeVnetName := getVnetName(vpnLocation, defaultNamespace)
	mockAzureHandler.On("GetInvisinetsVnet", ctx, fakeVnetName, vpnLocation, defaultNamespace, server.orchestratorServerAddr).Return(
		&armnetwork.VirtualNetwork{
			Name: to.Ptr(fakeVnetName),
			Properties: &armnetwork.VirtualNetworkPropertiesFormat{
				AddressSpace: &armnetwork.AddressSpace{
					AddressPrefixes: []*string{to.Ptr("10.0.0.0/16")},
				},
			},
		},
		nil,
	)

	vpnGwVnetName := getVpnGatewayVnetName(defaultNamespace)
	mockAzureHandler.On("GetSubnet", ctx, vpnGwVnetName, gatewaySubnetName).Return(
		&armnetwork.Subnet{ID: to.Ptr("gateway-subnet-id")},
		nil,
	)

	mockAzureHandler.On("CreateOrUpdateVirtualNetworkGateway", ctx, getVpnGatewayName(defaultNamespace), mock.Anything).Return(
		&armnetwork.VirtualNetworkGateway{
			Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{
				BgpSettings: &armnetwork.BgpSettings{},
				IPConfigurations: []*armnetwork.VirtualNetworkGatewayIPConfiguration{
					{ID: to.Ptr("ip-config-1")},
					{ID: to.Ptr("ip-config-2")},
				},
			},
		},
		nil,
	)

	mockAzureHandler.On("CreateOrUpdateVirtualNetworkGateway", ctx, getVpnGatewayName(defaultNamespace), mock.Anything).Return(
		&armnetwork.VirtualNetworkGateway{},
		nil,
	)

	vnetName := "vnet"
	mockAzureHandler.On("ListVirtualNetworkPeerings", ctx, vpnGwVnetName).Return(
		[]*armnetwork.VirtualNetworkPeering{
			{Properties: &armnetwork.VirtualNetworkPeeringPropertiesFormat{RemoteVirtualNetwork: &armnetwork.SubResource{ID: to.Ptr("/subscriptions/123/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/" + vnetName)}}},
		},
		nil,
	)
	mockAzureHandler.On("GetVirtualNetworkPeering", ctx, vnetName, getPeeringName(vnetName, vpnGwVnetName)).Return(
		&armnetwork.VirtualNetworkPeering{},
		nil,
	)
	mockAzureHandler.On("CreateOrUpdateVnetPeeringRemoteGateway", ctx, vnetName, vpnGwVnetName, mock.Anything, mock.Anything).Return(
		nil,
	)
	req := &invisinetspb.CreateVpnGatewayRequest{
		Deployment:            &invisinetspb.InvisinetsDeployment{Id: "/subscriptions/123/resourceGroups/rg", Namespace: defaultNamespace},
		Cloud:                 "fake-cloud",
		BgpPeeringIpAddresses: []string{"169.254.21.1", "169.254.22.1"},
	}
	resp, err := server.CreateVpnGateway(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, orchestrator.MIN_PRIVATE_ASN_2BYTE, resp.Asn)
	require.ElementsMatch(t, []string{fakePublicIpAddress}, resp.GatewayIpAddresses)
}

func TestCreateVpnConnections(t *testing.T) {
	server, mockAzureHandler, ctx := setupAzurePluginServer()
	mockHandlerSetup(mockAzureHandler)

	fakeCloudName := "fake-cloud"
	localNetworkGatewayName := getLocalNetworkGatewayName(defaultNamespace, fakeCloudName, 0)
	mockAzureHandler.On("GetLocalNetworkGateway", ctx, localNetworkGatewayName).Return(
		nil,
		&azcore.ResponseError{StatusCode: http.StatusNotFound},
	)
	mockAzureHandler.On("CreateLocalNetworkGateway", ctx, localNetworkGatewayName, mock.Anything).Return(
		&armnetwork.LocalNetworkGateway{},
		nil,
	)

	mockAzureHandler.On("GetVirtualNetworkGateway", ctx, getVpnGatewayName(defaultNamespace)).Return(
		&armnetwork.VirtualNetworkGateway{},
		nil,
	)

	virtualNetworkGatewayConnectionName := getVirtualNetworkGatewayConnectionName(defaultNamespace, fakeCloudName, 0)
	mockAzureHandler.On("GetVirtualNetworkGatewayConnection", ctx, virtualNetworkGatewayConnectionName).Return(
		nil,
		&azcore.ResponseError{StatusCode: http.StatusNotFound},
	)
	mockAzureHandler.On("CreateVirtualNetworkGatewayConnection", ctx, virtualNetworkGatewayConnectionName, mock.Anything).Return(
		&armnetwork.VirtualNetworkGatewayConnection{},
		nil,
	)

	req := &invisinetspb.CreateVpnConnectionsRequest{
		Deployment:         &invisinetspb.InvisinetsDeployment{Id: "/subscriptions/123/resourceGroups/rg", Namespace: defaultNamespace},
		Cloud:              fakeCloudName,
		Asn:                123,
		GatewayIpAddresses: []string{"1.1.1.1", "2.2.2.2"},
		BgpIpAddresses:     []string{"3.3.3.3", "4.4.4.4"},
		SharedKey:          "abc",
	}
	resp, err := server.CreateVpnConnections(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.Success)
}

/* --- Helper Functions --- */

func getFakeVmUri() string {
	return "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Compute/virtualMachines/vm123"
}

func getFakeNewPermitListRules() ([]*invisinetspb.PermitListRule, error) {
	return []*invisinetspb.PermitListRule{
		{
			Name:      "test-rule-1",
			Tags:      []string{"tag1", "tag2"},
			Targets:   []string{validAddressSpace, validAddressSpace},
			SrcPort:   8080,
			DstPort:   8080,
			Protocol:  1,
			Direction: invisinetspb.Direction_OUTBOUND,
		},
		{
			Name:      "test-rule-2",
			Tags:      []string{"tag3", "tag4"},
			Targets:   []string{validAddressSpace, validAddressSpace},
			SrcPort:   8080,
			DstPort:   8080,
			Protocol:  1,
			Direction: invisinetspb.Direction_OUTBOUND,
		},
	}, nil
}

func getFakePermitList() ([]*invisinetspb.PermitListRule, error) {
	nsg := getFakeNsg("test", "test")
	// initialize invisinets rules with the size of nsg rules
	invisinetsRules := []*invisinetspb.PermitListRule{}
	// use real implementation to get actual mapping of nsg rules to invisinets rules
	azureSDKHandler := &azureSDKHandler{}
	for i := range nsg.Properties.SecurityRules {
		if strings.HasPrefix(*nsg.Properties.SecurityRules[i].Name, invisinetsPrefix) {
			rule, err := azureSDKHandler.GetPermitListRuleFromNSGRule(nsg.Properties.SecurityRules[i])
			if err != nil {
				return nil, err
			}
			rule.Name = getRuleNameFromNSGRuleName(*nsg.Properties.SecurityRules[i].Name)
			invisinetsRules = append(invisinetsRules, rule)
		}
	}

	return invisinetsRules, nil
}

func getFakeNIC() *armnetwork.Interface {
	fakeNsgID := "test-nsg-id"
	fakeResourceAddress := "10.5.0.3"
	fakeLocation := "test-location"
	namespace := defaultNamespace
	fakeSubnetId := "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Network/virtualNetworks/" + getVnetName(fakeLocation, namespace) + "/subnets/subnet123"
	return &armnetwork.Interface{
		ID:       to.Ptr("test-nic-id"),
		Location: to.Ptr(fakeLocation),
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						PrivateIPAddress: &fakeResourceAddress,
						Subnet:           &armnetwork.Subnet{ID: to.Ptr(fakeSubnetId)},
					},
				},
			},
			NetworkSecurityGroup: &armnetwork.SecurityGroup{
				ID: to.Ptr(fakeNsgID),
			},
		},
	}
}

func getFakeNsg(nsgID string, nsgName string) *armnetwork.SecurityGroup {
	return &armnetwork.SecurityGroup{
		ID:   to.Ptr(nsgID),
		Name: to.Ptr(nsgName),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{
				{
					ID:   to.Ptr("test-rule-id-1"),
					Name: to.Ptr("invisinets-Rule-1"),
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
						DestinationAddressPrefixes: []*string{to.Ptr(validAddressSpace)},
						SourceAddressPrefixes:      []*string{to.Ptr(validAddressSpace)},
						Priority:                   to.Ptr(int32(100)),
						SourcePortRange:            to.Ptr("101"),
						DestinationPortRange:       to.Ptr("8080"),
						Protocol:                   to.Ptr(armnetwork.SecurityRuleProtocolTCP),
						Description:                to.Ptr(getRuleDescription([]string{"tag1", "tag2"})),
					},
				},
				{
					ID:   to.Ptr("test-rule-id-2"),
					Name: to.Ptr("invisinets-Rule-2"),
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
						DestinationAddressPrefixes: []*string{to.Ptr(validAddressSpace)},
						SourceAddressPrefixes:      []*string{to.Ptr(validAddressSpace)},
						Priority:                   to.Ptr(int32(101)),
						SourcePortRange:            to.Ptr("102"),
						DestinationPortRange:       to.Ptr("8080"),
						Protocol:                   to.Ptr(armnetwork.SecurityRuleProtocolTCP),
					},
				},
				{
					ID:   to.Ptr("test-rule-id-3"),
					Name: to.Ptr("not-invisinets-Rule-1"),
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
						DestinationAddressPrefixes: []*string{to.Ptr(validAddressSpace)},
						SourceAddressPrefixes:      []*string{to.Ptr(validAddressSpace)},
						Priority:                   to.Ptr(int32(102)),
						SourcePortRange:            to.Ptr("5050"),
						DestinationPortRange:       to.Ptr("8080"),
						Protocol:                   to.Ptr(armnetwork.SecurityRuleProtocolTCP),
					},
				},
				{
					ID:   to.Ptr("test-rule-id-4"),
					Name: to.Ptr("not-invisinets-Rule-2"),
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionInbound),
						DestinationAddressPrefixes: []*string{to.Ptr(validAddressSpace)},
						SourceAddressPrefixes:      []*string{to.Ptr(validAddressSpace)},
						Priority:                   to.Ptr(int32(103)),
						SourcePortRange:            to.Ptr("103"),
						DestinationPortRange:       to.Ptr("8080"),
						Protocol:                   to.Ptr(armnetwork.SecurityRuleProtocolTCP),
					},
				},
			},
		},
	}
}

func getFakeVnet(location *string, addressSpace string) *armnetwork.VirtualNetwork {
	return &armnetwork.VirtualNetwork{
		Location: location,
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{to.Ptr(addressSpace)},
			},
		},
	}
}

func mockHandlerSetup(mockAzureHandler *mockAzureSDKHandler) {
	mockAzureHandler.On("GetAzureCredentials").Return(&dummyTokenCredential{}, nil)
	mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return(nil)
	mockAzureHandler.On("SetSubIdAndResourceGroup", mock.Anything, mock.Anything).Return()
}

func mockGetSecurityGroupSetup(mockAzureHandler *mockAzureSDKHandler, ctx context.Context, associatedResrouce string, fakeNsgID string, fakeNsgName string, fakeNsg *armnetwork.SecurityGroup, fakeNic *armnetwork.Interface) {
	var nicErr error = nil
	var lastSegmentErr error = nil
	var nsgErr error = nil
	if fakeNic == nil {
		nicErr = fmt.Errorf("error while getting NIC")
	}
	if fakeNsg == nil {
		nsgErr = fmt.Errorf("error while getting NSG")
	}
	if fakeNsgName == "" {
		lastSegmentErr = fmt.Errorf("error while getting last segment")
	}
	mockAzureHandler.On("GetResourceNIC", ctx, associatedResrouce).Return(fakeNic, nicErr)
	mockAzureHandler.On("GetLastSegment", fakeNsgID).Return(fakeNsgName, lastSegmentErr)
	mockAzureHandler.On("GetSecurityGroup", ctx, fakeNsgName).Return(fakeNsg, nsgErr)
}

func mockGetVnetAndAddressSpaces(mockAzureHandler *mockAzureSDKHandler, ctx context.Context, vnetName string, vnetPrefix string, fakeVnet *armnetwork.VirtualNetwork, fakeAddressList map[string]string) {
	mockAzureHandler.On("GetVNet", ctx, vnetName).Return(fakeVnet, nil)
	mockAzureHandler.On("GetVNetsAddressSpaces", ctx, vnetPrefix).Return(fakeAddressList, nil)
}
