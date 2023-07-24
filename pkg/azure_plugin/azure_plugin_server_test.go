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

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockAzureSDKHandler struct {
	mock.Mock
}

func (m *mockAzureSDKHandler) GetOrCreateNSG(ctx context.Context, nic *armnetwork.Interface) (string, error) {
	args := m.Called(ctx, nic)
	return args.String(0), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateNetworkSecurityGroup(ctx context.Context, nsgName string, location string) (*armnetwork.SecurityGroup, error) {
	args := m.Called(ctx, nsgName, location)
	nsg := args.Get(0)
	if nsg == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*armnetwork.SecurityGroup), args.Error(1)
}

func (m *mockAzureSDKHandler) InitializeClients(cred azcore.TokenCredential) {
	m.Called(cred)
}

func (m *mockAzureSDKHandler) ConnectionAzure() (azcore.TokenCredential, error) {
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

func (m *mockAzureSDKHandler) UpdateNetworkInterface(ctx context.Context, resourceNic *armnetwork.Interface, nsg *armnetwork.SecurityGroup) (*armnetwork.Interface, error) {
	args := m.Called(ctx, resourceNic, nsg)
	return args.Get(0).(*armnetwork.Interface), args.Error(1)
}

func (m *mockAzureSDKHandler) CreateSecurityRule(ctx context.Context, rule *invisinetspb.PermitListRule, nsgName string, ruleName string, resourceIpAddress string, priority int32) (*armnetwork.SecurityRule, error) {
	args := m.Called(ctx, rule, nsgName, ruleName, resourceIpAddress, priority)
	return args.Get(0).(*armnetwork.SecurityRule), args.Error(1)
}

func (m *mockAzureSDKHandler) DeleteSecurityRule(ctx context.Context, nsgName string, ruleName string) error {
	args := m.Called(ctx, nsgName, ruleName)
	return args.Error(0)
}

func (m *mockAzureSDKHandler) GetPermitListRuleFromNSGRule(rule *armnetwork.SecurityRule) *invisinetspb.PermitListRule {
	args := m.Called(rule)
	return args.Get(0).(*invisinetspb.PermitListRule)
}

func (m *mockAzureSDKHandler) GetInvisinetsRuleDesc(rule *invisinetspb.PermitListRule) string {
	args := m.Called(rule)
	return args.String(0)
}

func (m *mockAzureSDKHandler) GetSecurityGroup(ctx context.Context, nsgName string) (*armnetwork.SecurityGroup, error) {
	args := m.Called(ctx, nsgName)
	return args.Get(0).(*armnetwork.SecurityGroup), args.Error(1)
}

func (m *mockAzureSDKHandler) GetLastSegment(resourceID string) (string, error) {
	args := m.Called(resourceID)
	return args.String(0), args.Error(1)
}

type dummyTokenCredential struct{}

func (d *dummyTokenCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

func setupAzurePluginServer() (*azurePluginServer, *mockAzureSDKHandler, context.Context) {
	// Create a new instance of the azurePluginServer
	server := &azurePluginServer{}

	// Create a mock implementation of the AzureSDKHandler interface
	var mockAzureHandler AzureSDKHandler = &mockAzureSDKHandler{}
	server.azureHandler = mockAzureHandler

	// Perform a type assertion to convert the AzureSDKHandler interface value to a *mockAzureSDKHandler concrete value, allowing access to methods and fields specific to the mockAzureSDKHandler type.
	concreteMockAzureHandler := mockAzureHandler.(*mockAzureSDKHandler)

	return server, concreteMockAzureHandler, context.Background()
}

func TestGetPermitList(t *testing.T) {
	fakePl, _ := getFakePermitList()
	fakeNsgName := "test-nsg-name"
	fakeNic := getFakeNIC()
	fakeNsgID := *fakeNic.Properties.NetworkSecurityGroup.ID
	fakeNsg := getFakeNsg(fakeNsgID, fakeNsgName)

	// Set up a  resource
	fakeResource := &invisinetspb.Resource{
		Id: "test-resource-id",
	}

	// Within each subtest, we recreate the setup for the azurePluginServer,
	// mockAzureHandler, context (ctx) variables.
	// This ensures that each subtest starts with a clean and isolated state.

	// Test Case 1: Successful execution and expected permit list
	t.Run("TestGetPermitList: Success", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()

		// Set up mock behavior for the Azure SDK handler
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return()
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return(fakeNsgName, nil)
		mockAzureHandler.On("GetResourceNIC", ctx, fakeResource.GetId()).Return(fakeNic, nil)
		mockAzureHandler.On("GetSecurityGroup", ctx, fakeNsgName).Return(fakeNsg, nil)

		// make suret that the GetPermitListRuleFromNSGRule is called on all the invisinets rules
		for i, rule := range fakeNsg.Properties.SecurityRules {
			if strings.HasPrefix(*rule.Name, InvisinetsRulePrefix) {
				mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePl.GetRules()[i])
			}
		}

		// Call the GetPermitList function
		permitList, err := server.GetPermitList(ctx, fakeResource)

		// Assert the results
		assert.NoError(t, err)
		assert.NotNil(t, permitList)
		assert.Equal(t, "test-resource-id", permitList.AssociatedResource)
		assert.Len(t, permitList.Rules, 2) // Add the expected number of rules here
	})

	// Test Case 2: ConnectionAzure fails
	t.Run("TestGetPermitList: Failure while connecting to azure", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		// Set up mock behavior for the Azure SDK handler to return an error on ConnectionAzure call
		mockAzureHandler.On("ConnectionAzure").Return(nil, fmt.Errorf("connection error"))

		// Call the GetPermitList function
		permitList, err := server.GetPermitList(ctx, fakeResource)

		// Assert the error
		assert.Error(t, err)
		assert.Nil(t, permitList)
	})

	// Test Case 3: NSG get fails due to GetResourceNIC call
	t.Run("TestGetPermitList: Failed while getting NSG", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		// Set up mock behavior for the Azure SDK handler to return an error on GetResourceNIC call
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return()
		mockAzureHandler.On("GetResourceNIC", ctx, fakeResource.GetId()).Return(nil, fmt.Errorf("NIC get error"))

		// Call the GetPermitList function
		permitList, err := server.GetPermitList(ctx, fakeResource)

		// Assert the error
		assert.Error(t, err)
		assert.Nil(t, permitList)
	})
}

func getFakePermitList() (*invisinetspb.PermitList, []string) {
	nsg := getFakeNsg("test", "test")
	// initialize invisinets rules with the size of nsg rules
	invisinetsRules := make([]*invisinetspb.PermitListRule, len(nsg.Properties.SecurityRules))
	ruleDesc := make([]string, len(nsg.Properties.SecurityRules))
	// use real implementation to get actual mapping of nsg rules to invisinets rules
	azureSDKHandler := &azureSDKHandler{}
	for i := range invisinetsRules {
		invisinetsRules[i] = azureSDKHandler.GetPermitListRuleFromNSGRule(nsg.Properties.SecurityRules[i])
		ruleDesc[i] = azureSDKHandler.GetInvisinetsRuleDesc(invisinetsRules[i])
	}
	fakePl := &invisinetspb.PermitList{
		AssociatedResource: "test-resource-id",
		Rules:              invisinetsRules,
	}

	return fakePl, ruleDesc
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
						Direction:            to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
						Priority:             to.Ptr(int32(100)),
						SourcePortRange:      to.Ptr("100"),
						DestinationPortRange: to.Ptr("8080"),
						Protocol:             to.Ptr(armnetwork.SecurityRuleProtocolTCP),
					},
				},
				{
					ID:   to.Ptr("test-rule-id-2"),
					Name: to.Ptr("invisinets-Rule-2"),
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Direction:            to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
						Priority:             to.Ptr(int32(101)),
						SourcePortRange:      to.Ptr("100"),
						DestinationPortRange: to.Ptr("8080"),
						Protocol:             to.Ptr(armnetwork.SecurityRuleProtocolTCP),
					},
				},
				{
					ID:   to.Ptr("test-rule-id-3"),
					Name: to.Ptr("not-invisinets-Rule-1"),
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Direction:            to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
						Priority:             to.Ptr(int32(102)),
						SourcePortRange:      to.Ptr("100"),
						DestinationPortRange: to.Ptr("8080"),
						Protocol:             to.Ptr(armnetwork.SecurityRuleProtocolTCP),
					},
				},
				{
					ID:   to.Ptr("test-rule-id-4"),
					Name: to.Ptr("not-invisinets-Rule-2"),
					Properties: &armnetwork.SecurityRulePropertiesFormat{
						Direction:            to.Ptr(armnetwork.SecurityRuleDirectionInbound),
						Priority:             to.Ptr(int32(100)),
						SourcePortRange:      to.Ptr("100"),
						DestinationPortRange: to.Ptr("8080"),
						Protocol:             to.Ptr(armnetwork.SecurityRuleProtocolTCP),
					},
				},
			},
		},
	}
}

func TestAddPermitListRules(t *testing.T) {
	fakePl, fakeRuleDesc := getFakePermitList()
	fakeNsgName := "test-nsg-name"
	fakeNic := getFakeNIC()
	fakeNsgID := *fakeNic.Properties.NetworkSecurityGroup.ID
	fakeResourceAddress := *fakeNic.Properties.IPConfigurations[0].Properties.PrivateIPAddress
	fakeNsg := getFakeNsg(fakeNsgID, fakeNsgName)

	// Test 1: Successful AddPermitListRules
	t.Run("AddPermitListRules: Success", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return()
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(fakeNic, nil)
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return(fakeNsgName, nil)
		mockAzureHandler.On("GetSecurityGroup", ctx, fakeNsgName).Return(fakeNsg, nil)
		for i, rule := range fakeNsg.Properties.SecurityRules {
			mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePl.GetRules()[i])
			mockAzureHandler.On("GetInvisinetsRuleDesc", fakePl.GetRules()[i]).Return(fakeRuleDesc[i], nil)
		}

		// the only one called is the non duplicate one
		mockAzureHandler.On("CreateSecurityRule", ctx, fakePl.GetRules()[3], fakeNsgName, mock.Anything, fakeResourceAddress, int32(101)).Return(&armnetwork.SecurityRule{
			Name: to.Ptr("fake-invisinets-rule"),
			ID:   to.Ptr("fake-invisinets-rule-id"),
		}, nil)

		resp, err := server.AddPermitListRules(ctx, fakePl)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Success)
	})

	// Test 2: Failed AddPermitListRules
	t.Run("AddPermitListRules: Failure while getting NSG", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return()
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(fakeNic, nil)
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return(fakeNsgName, nil)
		mockAzureHandler.On("GetSecurityGroup", ctx, fakeNsgName).Return(fakeNsg, fmt.Errorf("error while getting NSG"))

		resp, err := server.AddPermitListRules(ctx, fakePl)
		assert.Error(t, err)
		assert.NotNil(t, err)
		assert.Nil(t, resp)
	})

	// Test 3: Failed during connection
	t.Run("AddPermitListRules: Failure while connecting to azure", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("ConnectionAzure").Return(nil, fmt.Errorf("error while connecting to azure"))
		resp, err := server.AddPermitListRules(ctx, fakePl)
		assert.Error(t, err)
		assert.NotNil(t, err)
		assert.Nil(t, resp)
	})

	// Test 4: Failed while getting NIC
	t.Run("AddPermitListRules: Failure while getting NIC", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return()
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(nil, fmt.Errorf("error while getting NIC"))
		resp, err := server.AddPermitListRules(ctx, fakePl)
		assert.Error(t, err)
		assert.NotNil(t, err)
		assert.Nil(t, resp)
	})

	// Test 5: Failed while getting nsgName
	t.Run("AddPermitListRules: Failure while getting NSG Name", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return()
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(fakeNic, nil)
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return("", fmt.Errorf("error while getting nsgName"))
		resp, err := server.AddPermitListRules(ctx, fakePl)
		assert.Error(t, err)
		assert.NotNil(t, err)
		assert.Nil(t, resp)
	})

	// Test 6: Success but create new NSG
	t.Run("AddPermitListRules: Success and create new nsg", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		fakeNicWithoutNSG := getFakeNIC()
		fakeNicWithoutNSG.Properties.NetworkSecurityGroup = nil
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return()
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(fakeNicWithoutNSG, nil)
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return(fakeNsgName, nil)
		mockAzureHandler.On("CreateNetworkSecurityGroup", ctx, mock.Anything, *fakeNicWithoutNSG.Location).Return(fakeNsg, nil)
		mockAzureHandler.On("UpdateNetworkInterface", ctx, fakeNicWithoutNSG, fakeNsg).Return(fakeNic, nil)
		mockAzureHandler.On("GetSecurityGroup", ctx, fakeNsgName).Return(fakeNsg, nil)
		for i, rule := range fakeNsg.Properties.SecurityRules {
			mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePl.GetRules()[i])
			mockAzureHandler.On("GetInvisinetsRuleDesc", fakePl.GetRules()[i]).Return(fakeRuleDesc[i], nil)
		}

		// the only one called is the non duplicate one
		mockAzureHandler.On("CreateSecurityRule", ctx, fakePl.GetRules()[3], fakeNsgName, mock.Anything, fakeResourceAddress, int32(101)).Return(&armnetwork.SecurityRule{
			Name: to.Ptr("fake-invisinets-rule"),
			ID:   to.Ptr("fake-invisinets-rule-id"),
		}, nil)

		resp, err := server.AddPermitListRules(ctx, fakePl)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Success)
	})

	// Test 7: failure while creating new NSG
	t.Run("AddPermitListRules: Failure when creating NSG", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		fakeNicWithoutNSG := getFakeNIC()
		fakeNicWithoutNSG.Properties.NetworkSecurityGroup = nil
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return()
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(fakeNicWithoutNSG, nil)
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return(fakeNsgName, nil)
		mockAzureHandler.On("CreateNetworkSecurityGroup", ctx, mock.Anything, *fakeNicWithoutNSG.Location).Return(nil, fmt.Errorf("error while creating new NSG"))
		resp, err := server.AddPermitListRules(ctx, fakePl)

		assert.Error(t, err)
		assert.NotNil(t, err)
		assert.Nil(t, resp)
	})
}

func TestDeleteDeletePermitListRules(t *testing.T) {
	fakePl, fakeRuleDesc := getFakePermitList()
	fakeNsgName := "test-nsg-name"
	fakeNic := getFakeNIC()
	fakeNsgID := *fakeNic.Properties.NetworkSecurityGroup.ID
	fakeNsg := getFakeNsg(fakeNsgID, fakeNsgName)

	// The mockAzureHandler is reset for each test case to ensure that the mock is not called
	// from a previous test case and avoid conflicts between test cases

	// Test 1: successful
	t.Run("DeleteDeletePermitListRules: Success", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return()
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(fakeNic, nil)
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return(fakeNsgName, nil)
		mockAzureHandler.On("GetSecurityGroup", ctx, fakeNsgName).Return(fakeNsg, nil)
		// make suret that the GetPermitListRuleFromNSGRule is called on all the invisinets rules
		for i, rule := range fakeNsg.Properties.SecurityRules {
			mockAzureHandler.On("GetInvisinetsRuleDesc", fakePl.GetRules()[i]).Return(fakeRuleDesc[i], nil)
			if strings.HasPrefix(*rule.Name, InvisinetsRulePrefix) {
				mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePl.GetRules()[i])
			}
		}

		mockAzureHandler.On("DeleteSecurityRule", ctx, fakeNsgName, mock.Anything).Return(nil)
		resp, err := server.DeletePermitListRules(ctx, fakePl)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Success)
	})

	// Test 2: Deletion error
	t.Run("DeleteDeletePermitListRules: Failure while getting NIC", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return()
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(nil, fmt.Errorf("nic error"))
		resp, err := server.DeletePermitListRules(ctx, fakePl)

		assert.Error(t, err)
		assert.NotNil(t, err)
		assert.Nil(t, resp)
	})

	// Test 3: Deletion error while connecting to azure
	t.Run("DeleteDeletePermitListRules: Failure while Connecting To Azure", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("ConnectionAzure").Return(nil, fmt.Errorf("azure error"))
		resp, err := server.DeletePermitListRules(ctx, fakePl)

		assert.Error(t, err)
		assert.NotNil(t, err)
		assert.Nil(t, resp)
	})

	// Test 4: Failure while deleting rule
	t.Run("DeleteDeletePermitListRules: Failure while deleting security rule", func(t *testing.T) {
		server, mockAzureHandler, ctx := setupAzurePluginServer()
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", &dummyTokenCredential{}).Return()
		mockAzureHandler.On("GetResourceNIC", ctx, fakePl.GetAssociatedResource()).Return(fakeNic, nil)
		mockAzureHandler.On("GetLastSegment", fakeNsgID).Return(fakeNsgName, nil)
		mockAzureHandler.On("GetSecurityGroup", ctx, fakeNsgName).Return(fakeNsg, nil)
		// make suret that the GetPermitListRuleFromNSGRule is called on all the invisinets rules
		for i, rule := range fakeNsg.Properties.SecurityRules {
			mockAzureHandler.On("GetInvisinetsRuleDesc", fakePl.GetRules()[i]).Return(fakeRuleDesc[i], nil)
			if strings.HasPrefix(*rule.Name, InvisinetsRulePrefix) {
				mockAzureHandler.On("GetPermitListRuleFromNSGRule", rule).Return(fakePl.GetRules()[i])
			}
		}

		mockAzureHandler.On("DeleteSecurityRule", ctx, fakeNsgName, mock.Anything).Return(fmt.Errorf("error while deleting rule"))
		resp, err := server.DeletePermitListRules(ctx, fakePl)

		assert.Error(t, err)
		assert.NotNil(t, err)
		assert.Nil(t, resp)
	})
}
