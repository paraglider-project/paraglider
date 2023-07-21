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

func (m *mockAzureSDKHandler) CreateSecurityRule(ctx context.Context, rule *invisinetspb.PermitListRule, nsgName string, resourceIpAddress string, priority int32, ruleNamePrefix string) (*armnetwork.SecurityRule, error) {
	args := m.Called(ctx, rule, nsgName, resourceIpAddress, priority, ruleNamePrefix)
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

func setupAzurePluginServer() (*azurePluginServer, *mockAzureSDKHandler, *invisinetspb.Resource, context.Context) {
	// Create a new instance of the azurePluginServer
	server := &azurePluginServer{}

	// Create a mock implementation of the AzureSDKHandler interface
	var mockAzureHandler AzureSDKHandler = &mockAzureSDKHandler{}
	server.azureHandler = mockAzureHandler

	// Perform a type assertion to convert the AzureSDKHandler interface value to a *mockAzureSDKHandler concrete value, allowing access to methods and fields specific to the mockAzureSDKHandler type.
	concreteMockAzureHandler := mockAzureHandler.(*mockAzureSDKHandler)

	// Set up a  resource
	resource := &invisinetspb.Resource{
		Id: "test-resource-id",
	}

	return server, concreteMockAzureHandler, resource, context.TODO()
}

func TestGetPermitList(t *testing.T) {
	// Within each subtest, we recreate the setup for the azurePluginServer,
	// mockAzureHandler, context (ctx), and resource variables.
	// This ensures that each subtest starts with a clean and isolated state.

	// Test Case 1: Successful execution and expected permit list
	t.Run("Success", func(t *testing.T) {
		server, mockAzureHandler, resource, ctx := setupAzurePluginServer()

		// Set up mock behavior for the Azure SDK handler
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", mock.Anything).Return()
		mockAzureHandler.On("GetPermitListRuleFromNSGRule", mock.Anything).Return(&invisinetspb.PermitListRule{})
		mockAzureHandler.On("GetLastSegment", mock.Anything).Return("test-resource-name", nil)
		mockAzureHandler.On("GetResourceNIC", mock.Anything, mock.Anything).Return(&armnetwork.Interface{
			Properties: &armnetwork.InterfacePropertiesFormat{
				NetworkSecurityGroup: &armnetwork.SecurityGroup{
					ID: to.Ptr("test-nsg-id"),
				},
			},
		}, nil)
		mockAzureHandler.On("GetSecurityGroup", mock.Anything, mock.Anything).Return(&armnetwork.SecurityGroup{
			Properties: &armnetwork.SecurityGroupPropertiesFormat{
				SecurityRules: []*armnetwork.SecurityRule{
					{
						Name: to.Ptr("invisinets-rule-name"),
					},
				},
			},
		}, nil)

		// Call the GetPermitList function
		permitList, err := server.GetPermitList(ctx, resource)

		// Assert the results
		assert.NoError(t, err)
		assert.NotNil(t, permitList)
		assert.Equal(t, "test-resource-id", permitList.AssociatedResource)
		assert.Len(t, permitList.Rules, 1) // Add the expected number of rules here
	})

	// Test Case 2: ConnectionAzure fails
	t.Run("ConnectionAzureFail", func(t *testing.T) {
		server, mockAzureHandler, resource, ctx := setupAzurePluginServer()
		// Set up mock behavior for the Azure SDK handler to return an error on ConnectionAzure call
		mockAzureHandler.On("ConnectionAzure").Return(nil, fmt.Errorf("connection error"))

		// Call the GetPermitList function
		permitList, err := server.GetPermitList(ctx, resource)

		// Assert the error
		assert.Error(t, err)
		assert.Nil(t, permitList)
	})

	// Test Case 3: NSG get fails due to GetResourceNIC call
	t.Run("NSGGetFail", func(t *testing.T) {
		server, mockAzureHandler, resource, ctx := setupAzurePluginServer()
		// Set up mock behavior for the Azure SDK handler to return an error on GetResourceNIC call
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", mock.Anything).Return()
		mockAzureHandler.On("GetResourceNIC", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("NIC get error"))

		// Call the GetPermitList function
		permitList, err := server.GetPermitList(ctx, resource)

		// Assert the error
		assert.Error(t, err)
		assert.Nil(t, permitList)
	})

	// Test Case 4: Some rules with names starting with Invisinets prefix and some not
	t.Run("SomeRulesWithInvisinetsPrefix", func(t *testing.T) {
		server, mockAzureHandler, resource, ctx := setupAzurePluginServer()
		// Test Case 4: Some rules with names starting with Invisinets prefix and some not
		mockAzureHandler.On("ConnectionAzure").Return(&dummyTokenCredential{}, nil)
		mockAzureHandler.On("InitializeClients", mock.Anything).Return()
		mockAzureHandler.On("GetResourceNIC", mock.Anything, mock.Anything).Return(&armnetwork.Interface{
			Properties: &armnetwork.InterfacePropertiesFormat{
				NetworkSecurityGroup: &armnetwork.SecurityGroup{
					ID: to.Ptr("test-nsg-id"),
				},
			},
		}, nil)
		mockAzureHandler.On("GetLastSegment", mock.Anything).Return("test-resource-name", nil)
		mockAzureHandler.On("GetPermitListRuleFromNSGRule", mock.Anything).Return(&invisinetspb.PermitListRule{})
		mockAzureHandler.On("GetSecurityGroup", mock.Anything, mock.Anything).Return(&armnetwork.SecurityGroup{
			Properties: &armnetwork.SecurityGroupPropertiesFormat{
				SecurityRules: []*armnetwork.SecurityRule{
					{
						Name: to.Ptr("invisinets-Rule-1"),
					},
					{
						Name: to.Ptr("Other-Rule-1"),
					},
					{
						Name: to.Ptr("Other-Rule-2"),
					},
					{
						Name: to.Ptr("invisinets-Rule-2"),
					},
				},
			},
		}, nil)

		// Call the GetPermitList function
		permitList, err := server.GetPermitList(ctx, resource)

		// Assert the results
		assert.NoError(t, err)
		assert.NotNil(t, permitList)
		assert.Equal(t, "test-resource-id", permitList.AssociatedResource)
		assert.Len(t, permitList.Rules, 2) // Add the expected number of rules here
	})
}
