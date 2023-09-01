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
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var fakeAddressList = map[string]string{testLocation: validAddressSpace}

type dummyTokenCredential struct{}

func (d *dummyTokenCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

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

func (m *mockAzureSDKHandler) GetInvisinetsRuleDesc(rule *invisinetspb.PermitListRule) string {
	args := m.Called(rule)
	return args.String(0)
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

func (m *mockAzureSDKHandler) GetInvisinetsVnet(ctx context.Context, prefix string, location string, addressSpace string) (*armnetwork.VirtualNetwork, error) {
	args := m.Called(ctx, prefix, location, addressSpace)
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

func (m *mockAzureSDKHandler) CreateVnetPeering(ctx context.Context, vnet1 string, vnet2 string) error {
	args := m.Called(ctx, vnet1, vnet2)
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

func setupAzurePluginServer() (*azurePluginServer, *mockAzureSDKHandler, context.Context) {
	// Create a new instance of the azurePluginServer
	server := &azurePluginServer{}

	// Create a mock implementation of the AzureSDKHandler interface
	var mockAzureHandler AzureSDKHandler = &mockAzureSDKHandler{}
	server.azureHandler = mockAzureHandler

	// Perform a type requireion to convert the AzureSDKHandler interface value to a *mockAzureSDKHandler concrete value, allowing access to methods and fields specific to the mockAzureSDKHandler type.
	concreteMockAzureHandler := mockAzureHandler.(*mockAzureSDKHandler)

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

func TestCreateResource(t *testing.T) {
	defaultSubnetName := "default"
	defaultSubnetID := "default-subnet-id"
	vnetName := invisinetsPrefix + "-" + testLocation + "-vnet"
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
		mockAzureHandler.On("GetInvisinetsVnet", ctx, vnetName, testLocation, validAddressSpace).Return(&armnetwork.VirtualNetwork{
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
		mockAzureHandler.On("CreateVirtualMachine", ctx, vm, mock.Anything).Return(&armcompute.VirtualMachine{ID: to.Ptr(vmResourceID)}, nil)

		vm.Properties.NetworkProfile = &armcompute.NetworkProfile{
			NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
				{
					ID: to.Ptr(validNicId),
				},
			},
		}

		response, err := server.CreateResource(ctx, &invisinetspb.ResourceDescription{
			Description:  desc,
			AddressSpace: validAddressSpace,
			Id:           "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Compute/virtualMachines/vm123",
		})

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, vmResourceID, response.UpdatedResource.Id)
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
	fakePl, _, err := getFakePermitList()
	if err != nil {
		t.Errorf("Error while getting fake permit list: %v", err)
	}
	fakeNsgName := "test-nsg-name"
	fakeNic := getFakeNIC()
	fakeNsgID := *fakeNic.Properties.NetworkSecurityGroup.ID
	fakeNsg := getFakeNsg(fakeNsgID, fakeNsgName)

	// Set up a  resource
	fakeResource := &invisinetspb.ResourceID{
		Id: "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Compute/virtualMachines/vm123",
	}

	// Within each subtest, we recreate the setup for the azurePluginServer,
	// mockAzureHandler, context (ctx) variables.
	// This ensures that each subtest starts with a clean and isolated state.

	// Test Case 1: Successful execution and expected permit list
	t.Run("TestGetPermitList: Success", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()

		// Set up mock behavior for the Azure SDK handler
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakePl.GetAssociatedResource(), fakeNsgID, fakeNsgName, fakeNsg, fakeNic)

		// make suret that the GetPermitListRuleFromNSGRule is called on all the invisinets rules
		for i, rule := range fakeNsg.Properties.SecurityRules {
			if strings.HasPrefix(*rule.Name, invisinetsPrefix) {
				mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePl.GetRules()[i], nil)
			}
		}

		// Call the GetPermitList function
		permitList, err := server.GetPermitList(ctx, fakeResource)

		// check the results
		require.NoError(t, err)
		require.NotNil(t, permitList)
		require.Equal(t, fakeResource.Id, permitList.AssociatedResource)
		require.Len(t, permitList.Rules, 2) // Add the expected number of rules here
	})

	// Test Case 2: GetAzureCredentials fails
	t.Run("TestGetPermitList: Failure while getting azure credentials", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		// Set up mock behavior for the Azure SDK handler to return an error on GetAzureCredentials call
		mockAzureHandler.On("GetAzureCredentials").Return(nil, fmt.Errorf("error while getting azure credentials"))

		// Call the GetPermitList function
		permitList, err := server.GetPermitList(ctx, fakeResource)

		// check the error
		require.Error(t, err)
		require.Nil(t, permitList)
	})

	// Test Case 3: NSG get fails due to GetResourceNIC call
	t.Run("TestGetPermitList: Failed while getting NIC", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		// Set up mock behavior for the Azure SDK handler to return an error on GetResourceNIC call
		mockHandlerSetup(mockAzureHandler)
		mockAzureHandler.On("GetResourceNIC", ctx, fakeResource.GetId()).Return(nil, fmt.Errorf("NIC get error"))

		// Call the GetPermitList function
		permitList, err := server.GetPermitList(ctx, fakeResource)

		// check the error
		require.Error(t, err)
		require.Nil(t, permitList)
	})

	// Test Case 4: Fail due to a failure in getPermitList
	t.Run("TestGetPermitList: Failed while getting pl rule", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()

		// Set up mock behavior for the Azure SDK handler
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakePl.GetAssociatedResource(), fakeNsgID, fakeNsgName, fakeNsg, fakeNic)
		mockAzureHandler.On("GetPermitListRuleFromNSGRule", mock.Anything).Return(nil, fmt.Errorf("error while getting permit list rule"))

		permitList, err := server.GetPermitList(ctx, fakeResource)

		// check the error
		require.Error(t, err)
		require.Nil(t, permitList)
	})
}

func TestAddPermitListRules(t *testing.T) {
	fakePl, fakeRuleDesc, err := getFakePermitList()
	if err != nil {
		t.Errorf("Error while getting fake permit list: %v", err)
	}
	fakeNsgName := "test-nsg-name"
	fakeNic := getFakeNIC()
	fakeNsgID := *fakeNic.Properties.NetworkSecurityGroup.ID
	fakeResourceAddress := *fakeNic.Properties.IPConfigurations[0].Properties.PrivateIPAddress
	fakeNsg := getFakeNsg(fakeNsgID, fakeNsgName)
	fakeVnet := getFakeVnet(fakeNic.Location, validAddressSpace)

	// Test 1: Successful AddPermitListRules
	t.Run("AddPermitListRules: Success", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakePl.GetAssociatedResource(), fakeNsgID, fakeNsgName, fakeNsg, fakeNic)
		mockGetVnetAndAddressSpaces(mockAzureHandler, ctx, getVnetName(*fakeNic.Location), fakeNic, fakeVnet, fakeAddressList)
		for i, rule := range fakeNsg.Properties.SecurityRules {
			if strings.HasPrefix(*rule.Name, invisinetsPrefix) {
				mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePl.GetRules()[i], nil)
			}
			mockAzureHandler.On("GetInvisinetsRuleDesc", fakePl.GetRules()[i]).Return(fakeRuleDesc[i], nil)
		}

		// the only two called are the non duplicate ones
		mockAzureHandler.On("CreateSecurityRule", ctx, fakePl.GetRules()[2], fakeNsgName, mock.Anything, fakeResourceAddress, int32(103)).Return(&armnetwork.SecurityRule{
			ID: to.Ptr("fake-invisinets-rule"),
		}, nil).Times(1)

		mockAzureHandler.On("CreateSecurityRule", ctx, fakePl.GetRules()[3], fakeNsgName, mock.Anything, fakeResourceAddress, int32(101)).Return(&armnetwork.SecurityRule{
			ID: to.Ptr("fake-invisinets-rule"),
		}, nil).Times(1)

		resp, err := server.AddPermitListRules(ctx, fakePl)

		mockAzureHandler.AssertExpectations(t) // this will fail if any of the calls above are not called or for different times
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.Success)
	})

	// Test 2: Failed AddPermitListRules
	t.Run("AddPermitListRules: Failure while getting NSG", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakePl.GetAssociatedResource(), fakeNsgID, fakeNsgName, nil, fakeNic)
		resp, err := server.AddPermitListRules(ctx, fakePl)
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test 3: Failed during GetAzureCredentials
	t.Run("AddPermitListRules: Failure while getting azure credential", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("GetAzureCredentials").Return(nil, fmt.Errorf("error while getting azure credentials"))
		resp, err := server.AddPermitListRules(ctx, fakePl)
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test 4: Failed while getting NIC
	t.Run("AddPermitListRules: Failure while getting NIC", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(nil, fmt.Errorf("error while getting NIC"))
		resp, err := server.AddPermitListRules(ctx, fakePl)
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test 5: Failed while getting nsgName
	t.Run("AddPermitListRules: Failure while getting NSG Name", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(fakeNic, nil)
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return("", fmt.Errorf("error while getting nsgName"))
		resp, err := server.AddPermitListRules(ctx, fakePl)
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test 6: Failure getting pl rule from nsg rule
	t.Run("AddPermitListRules: Failure when getting pl rule", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakePl.GetAssociatedResource(), fakeNsgID, fakeNsgName, fakeNsg, fakeNic)
		mockAzureHandler.On("GetPermitListRuleFromNSGRule", mock.Anything).Return(nil, fmt.Errorf("error while getting permit list rule"))

		resp, err := server.AddPermitListRules(ctx, fakePl)
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)

	})

	// Test 7: Failure while creting the nsg rule in azure
	t.Run("AddPermitListRules: Failure when creating nsg rule", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakePl.GetAssociatedResource(), fakeNsgID, fakeNsgName, fakeNsg, fakeNic)
		mockGetVnetAndAddressSpaces(mockAzureHandler, ctx, getVnetName(*fakeNic.Location), fakeNic, fakeVnet, fakeAddressList)
		for i, rule := range fakeNsg.Properties.SecurityRules {
			if strings.HasPrefix(*rule.Name, invisinetsPrefix) {
				mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePl.GetRules()[i], nil)
			}
			mockAzureHandler.On("GetInvisinetsRuleDesc", fakePl.GetRules()[i]).Return(fakeRuleDesc[i], nil)
		}

		mockAzureHandler.On("CreateSecurityRule", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, fmt.Errorf("error while creating nsg rule"))

		resp, err := server.AddPermitListRules(ctx, fakePl)
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})
}

func TestDeleteDeletePermitListRules(t *testing.T) {
	fakePl, fakeRuleDesc, err := getFakePermitList()
	if err != nil {
		t.Errorf("Error while getting fake permit list: %v", err)
	}
	fakeNsgName := "test-nsg-name"
	fakeNic := getFakeNIC()
	fakeNsgID := *fakeNic.Properties.NetworkSecurityGroup.ID
	fakeNsg := getFakeNsg(fakeNsgID, fakeNsgName)

	// The mockAzureHandler is reset for each test case to ensure that the mock is not called
	// from a previous test case and avoid conflicts between test cases

	// Test 1: successful
	t.Run("DeletePermitListRules: Success", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakePl.GetAssociatedResource(), fakeNsgID, fakeNsgName, fakeNsg, fakeNic)
		// make suret that the GetPermitListRuleFromNSGRule is called on all the invisinets rules
		for i, rule := range fakeNsg.Properties.SecurityRules {
			mockAzureHandler.On("GetInvisinetsRuleDesc", fakePl.GetRules()[i]).Return(fakeRuleDesc[i], nil)
			if strings.HasPrefix(*rule.Name, invisinetsPrefix) {
				mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePl.GetRules()[i], nil)
			}
		}

		mockAzureHandler.On("DeleteSecurityRule", ctx, fakeNsgName, mock.Anything).Return(nil)
		resp, err := server.DeletePermitListRules(ctx, fakePl)

		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.Success)
	})

	// Test 2: Deletion error while getting resource nic
	t.Run("DeletePermitListRules: Failure while getting NIC", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(nil, fmt.Errorf("nic error"))
		resp, err := server.DeletePermitListRules(ctx, fakePl)

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test 3: Deletion error while getting azure credentials
	t.Run("DeletePermitListRules: Failure while getting azure credentials", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("GetAzureCredentials").Return(nil, fmt.Errorf("error while getting azure credentials"))
		resp, err := server.DeletePermitListRules(ctx, fakePl)

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test 4: Failure while deleting rule
	t.Run("DeletePermitListRules: Failure while deleting security rule", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakePl.GetAssociatedResource(), fakeNsgID, fakeNsgName, fakeNsg, fakeNic)
		for i, rule := range fakeNsg.Properties.SecurityRules {
			mockAzureHandler.On("GetInvisinetsRuleDesc", fakePl.GetRules()[i]).Return(fakeRuleDesc[i], nil)
			if strings.HasPrefix(*rule.Name, invisinetsPrefix) {
				mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePl.GetRules()[i], nil)
			}
		}

		mockAzureHandler.On("DeleteSecurityRule", ctx, fakeNsgName, mock.Anything).Return(fmt.Errorf("error while deleting rule"))
		resp, err := server.DeletePermitListRules(ctx, fakePl)

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test 4: Failure while getting permit list rule from NSG rule
	t.Run("DeletePermitListRules: Failure while deleting security rule", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakePl.GetAssociatedResource(), fakeNsgID, fakeNsgName, fakeNsg, fakeNic)
		mockAzureHandler.On("GetInvisinetsRuleDesc", mock.Anything).Return("", nil)
		mockAzureHandler.On("GetPermitListRuleFromNSGRule", mock.Anything).Return(nil, fmt.Errorf("error while getting permit list rule from NSG rule"))

		resp, err := server.DeletePermitListRules(ctx, fakePl)

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test 5: Failure while getting last segment
	t.Run("DeletePermitListRules: Failure while getting last segment", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(fakeNic, nil)
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return("", fmt.Errorf("error while getting last segment"))

		resp, err := server.DeletePermitListRules(ctx, fakePl)

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test 6: Failure while getting security group
	t.Run("DeletePermitListRules: Failure while getting security group", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockHandlerSetup(mockAzureHandler)
		mockGetSecurityGroupSetup(mockAzureHandler, ctx, fakePl.GetAssociatedResource(), fakeNsgID, fakeNsgName, nil, fakeNic)
		resp, err := server.DeletePermitListRules(ctx, fakePl)

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})
}

func TestGetUsedAddressSpaces(t *testing.T) {
	server, mockAzureHandler, ctx := setupAzurePluginServer()
	mockHandlerSetup(mockAzureHandler)
	mockAzureHandler.On("GetVNetsAddressSpaces", ctx, invisinetsPrefix).Return(fakeAddressList, nil)
	addressList, err := server.GetUsedAddressSpaces(ctx, &invisinetspb.InvisinetsDeployment{
		Id: "/subscriptions/123/resourceGroups/rg",
	})

	require.NoError(t, err)
	require.NotNil(t, addressList)
	require.Len(t, addressList.Mappings, 1)
	assert.Equal(t, validAddressSpace, addressList.Mappings[0].AddressSpace)
	assert.Equal(t, testLocation, addressList.Mappings[0].Region)
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
			resourceID:   "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Compute/virtualMachines/vm123",
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

func TestCheckAndCreatePeering(t *testing.T) {
	server, mockAzureHandler, ctx := setupAzurePluginServer()

	fakeResourceVnet := &armnetwork.VirtualNetwork{
		Location: to.Ptr(testLocation),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{to.Ptr(validAddressSpace)},
			},
			VirtualNetworkPeerings: []*armnetwork.VirtualNetworkPeering{
				{
					Properties: &armnetwork.VirtualNetworkPeeringPropertiesFormat{
						RemoteVirtualNetwork: &armnetwork.SubResource{
							ID: to.Ptr(getVnetName("westus")),
						},
					},
				},
			},
		},
	}

	vnetMap := map[string]string{"westus": "10.5.0.0/16", "westus2": "10.2.0.0/16"}

	// each tag will represent a test case
	fakeList := &invisinetspb.PermitListRule{Tag: []string{
		"10.0.0.1",   // A tag that matches resourceVnet's address space
		"10.1.0.0/8", // A tag that matches resourceVnet's address space but is in a CIDR format
		"10.5.3.4",   // A tag outside of the resourceVnet's address space but is in another (westus) invisinets network and has an existing peering
		"10.2.3.4",   // A tag outside of the resourceVnet's address space but is in another invisinets network and requires a new peering
	}}

	mockAzureHandler.On("CreateVnetPeering", ctx, getVnetName("westus2"), getVnetName(testLocation)).Return(nil)
	err := server.checkAndCreatePeering(ctx, fakeResourceVnet, fakeList, vnetMap)

	mockAzureHandler.AssertExpectations(t)
	assert.NoError(t, err)
}

func getFakePermitList() (*invisinetspb.PermitList, []string, error) {
	var err error
	nsg := getFakeNsg("test", "test")
	// initialize invisinets rules with the size of nsg rules
	invisinetsRules := make([]*invisinetspb.PermitListRule, len(nsg.Properties.SecurityRules))
	ruleDesc := make([]string, len(nsg.Properties.SecurityRules))
	// use real implementation to get actual mapping of nsg rules to invisinets rules
	azureSDKHandler := &azureSDKHandler{}
	for i := range invisinetsRules {
		invisinetsRules[i], err = azureSDKHandler.GetPermitListRuleFromNSGRule(nsg.Properties.SecurityRules[i])
		if err != nil {
			return nil, nil, err
		}
		ruleDesc[i] = azureSDKHandler.GetInvisinetsRuleDesc(invisinetsRules[i])
	}
	fakePl := &invisinetspb.PermitList{
		AssociatedResource: "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Compute/virtualMachines/vm123",
		Rules:              invisinetsRules,
	}

	return fakePl, ruleDesc, nil
}

func getFakeNIC() *armnetwork.Interface {
	fakeNsgID := "test-nsg-id"
	fakeResourceAddress := "10.5.0.3"
	return &armnetwork.Interface{
		ID:       to.Ptr("test-nic-id"),
		Location: to.Ptr("test-location"),
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						PrivateIPAddress: &fakeResourceAddress,
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
						SourcePortRange:            to.Ptr("100"),
						DestinationPortRange:       to.Ptr("8080"),
						Protocol:                   to.Ptr(armnetwork.SecurityRuleProtocolTCP),
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
						SourcePortRange:            to.Ptr("100"),
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
						Priority:                   to.Ptr(int32(100)),
						SourcePortRange:            to.Ptr("100"),
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

func mockGetVnetAndAddressSpaces(mockAzureHandler *mockAzureSDKHandler, ctx context.Context, vnetName string, fakeNic *armnetwork.Interface, fakeVnet *armnetwork.VirtualNetwork, fakeAddressList map[string]string) {
	mockAzureHandler.On("GetVNet", ctx, vnetName).Return(fakeVnet, nil)
	mockAzureHandler.On("GetVNetsAddressSpaces", ctx, invisinetsPrefix).Return(fakeAddressList, nil)
}
