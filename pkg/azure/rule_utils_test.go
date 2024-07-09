//go:build unit

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
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupDenyAllRuleWithPriority(t *testing.T) {
	denyAllRule := setupDenyAllRuleWithPriority(int32(maxPriority), inboundDirectionRule)
	assert.Equal(t, *denyAllRule.Name, denyAllNsgRulePrefix+"-inbound")
	assert.Equal(t, *denyAllRule.Properties.Access, denyRule)
	assert.Equal(t, *denyAllRule.Properties.Direction, inboundDirectionRule)
	assert.Equal(t, *denyAllRule.Properties.Priority, int32(maxPriority))
	assert.Equal(t, *denyAllRule.Properties.SourceAddressPrefix, azureSecurityRuleAsterisk)
	assert.Equal(t, *denyAllRule.Properties.DestinationAddressPrefix, azureSecurityRuleAsterisk)
	assert.Equal(t, *denyAllRule.Properties.DestinationPortRange, azureSecurityRuleAsterisk)
	assert.Equal(t, *denyAllRule.Properties.Protocol, armnetwork.SecurityRuleProtocolAsterisk)
	assert.Equal(t, *denyAllRule.Properties.SourcePortRange, azureSecurityRuleAsterisk)
}

func TestIsDenyAllRule(t *testing.T) {
	denyAllRule := setupDenyAllRuleWithPriority(maxPriority, inboundDirectionRule)
	cidr := "10.1.0.0/24"

	t.Run("TestIsDenyAllRule", func(t *testing.T) {
		assert.True(t, isDenyAllRule(denyAllRule))
	})

	t.Run("TestIsNotDenyAllRule", func(t *testing.T) {
		denyAllRule.Properties.DestinationAddressPrefix = to.Ptr(cidr)
		assert.False(t, isDenyAllRule(denyAllRule))
	})

	t.Run("TestIsDenyAllRuleWithMultipleDestPrefixes", func(t *testing.T) {
		denyAllRule.Properties.DestinationAddressPrefix = nil
		denyAllRule.Properties.DestinationAddressPrefixes = []*string{to.Ptr(cidr), to.Ptr(azureSecurityRuleAsterisk)}
		assert.True(t, isDenyAllRule(denyAllRule))
	})

	t.Run("TestIsNotDenyAllRuleWithMultipleSourcePrefixes", func(t *testing.T) {
		denyAllRule.Properties.SourceAddressPrefix = nil
		denyAllRule.Properties.SourceAddressPrefixes = []*string{to.Ptr(cidr)}
		assert.False(t, isDenyAllRule(denyAllRule))
	})
}

func TestValidateSecurityRulesConform(t *testing.T) {
	t.Run("TestValidateSecurityRulesConform: Success", func(t *testing.T) {
		inboundDenyRule := setupDenyAllRuleWithPriority(maxPriority, inboundDirectionRule)
		reservedPriorities := make(map[int32]*armnetwork.SecurityRule)
		reservedPriorities[maxPriority] = inboundDenyRule
		priority, err := validateSecurityRulesConform(reservedPriorities)
		assert.Nil(t, err)
		assert.Equal(t, priority, int32(maxPriority))
	})

	t.Run("TestValidateSecurityRulesConform: No deny all rule", func(t *testing.T) {
		// setup with deny rule and change access to allow
		inboundAllowRule := setupDenyAllRuleWithPriority(maxPriority, inboundDirectionRule)
		inboundAllowRule.Properties.Access = to.Ptr(allowRule)
		inboundAllowRule.Properties.Priority = to.Ptr(int32(minPriority))

		reservedPriorities := make(map[int32]*armnetwork.SecurityRule)
		reservedPriorities[minPriority] = inboundAllowRule
		priority, err := validateSecurityRulesConform(reservedPriorities)
		assert.NotNil(t, err)
		assert.Equal(t, priority, int32(maxPriority))
	})

	t.Run("TestValidateSecurityRulesConform: Deny rule above allow rule", func(t *testing.T) {
		outboundDenyRule := setupDenyAllRuleWithPriority(int32(200), outboundDirectionRule)
		outboundAllowRule := setupDenyAllRuleWithPriority(int32(300), outboundDirectionRule)
		outboundAllowRule.Properties.Access = to.Ptr(allowRule)

		reservedOutboundPriorities := make(map[int32]*armnetwork.SecurityRule)
		reservedOutboundPriorities[int32(200)] = outboundDenyRule
		reservedOutboundPriorities[int32(300)] = outboundAllowRule
		priority, err := validateSecurityRulesConform(reservedOutboundPriorities)
		assert.NotNil(t, err)

		// -1 is the priority returned when the rules are out of order
		assert.Equal(t, int32(-1), priority)
	})
}

func TestCheckSecurityRulesCompliance(t *testing.T) {
	serverState := &fakeServerState{
		subId:   subID,
		rgName:  rgName,
		nsg:     getFakeNsgWithRules(validSecurityGroupID, validSecurityGroupName),
		nic:     getFakeParagliderInterface(),
		subnet:  getFakeParagliderSubnet(),
		vm:      to.Ptr(getFakeVirtualMachine(true)),
		cluster: to.Ptr(getFakeCluster(true)),
	}

	fakeServer, _ := SetupFakeAzureServer(t, serverState)
	defer Teardown(fakeServer)
	handler := &AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	resp, err := CheckSecurityRulesCompliance(context.Background(), handler, serverState.nsg)
	assert.True(t, resp)
	require.NoError(t, err)
}
