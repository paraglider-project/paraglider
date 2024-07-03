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
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rpc"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetVnetsWithMatchingPrefixAddressSpaces(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vnet:   getFakeVirtualNetwork(),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("GetAllVnetsAddressSpaces: Success", func(t *testing.T) {
		addresses, err := handler.GetAllVnetsAddressSpaces(ctx, paragliderPrefix)
		require.NoError(t, err)
		require.NotNil(t, addresses)
		require.Len(t, addresses, 1)
		assert.Equal(t, addresses[testLocation], []string{validAddressSpace})
	})

	t.Run("GetAllVnetsAddressSpaces: Failure - No Vnet", func(t *testing.T) {
		fakeServerState.vnet = nil
		addresses, err := handler.GetAllVnetsAddressSpaces(ctx, paragliderPrefix)
		require.Error(t, err)
		require.Nil(t, addresses)
	})

	t.Run("GetAllVnetsAddressSpaces: Failure - wrong name", func(t *testing.T) {
		addresses, err := handler.GetAllVnetsAddressSpaces(ctx, "otherprefix")
		require.Error(t, err)
		require.Nil(t, addresses)
	})
}

func TestGetVnetAddressSpace(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vnet:   getFakeVirtualNetwork(),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("GetVnetAddressSpace: Success", func(t *testing.T) {
		address, err := handler.GetVnetAddressSpace(ctx, validParagliderVnetName)
		require.NoError(t, err)
		require.NotNil(t, address)
		require.Len(t, address, 1)
		assert.Equal(t, address, []string{validAddressSpace})
	})

	t.Run("GetVnetAddressSpace: Failure - No Vnet", func(t *testing.T) {
		fakeServerState.vnet = nil
		address, err := handler.GetVnetAddressSpace(ctx, validParagliderVnetName)
		require.Error(t, err)
		require.Nil(t, address)
	})

	t.Run("GetVnetAddressSpace: Failure - wrong name", func(t *testing.T) {
		address, err := handler.GetVnetAddressSpace(ctx, "invalidParagliderVnetName")
		require.Error(t, err)
		require.Nil(t, address)
	})
}

func TestCreateSecurityRuleFromPermitList(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
	}
	fakeServer, _ := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Subtest 1: Create security rule - Success Test
	t.Run("CreateSecurityRuleFromPermitList: Success", func(t *testing.T) {
		resp, err := handler.CreateSecurityRuleFromPermitList(context.Background(), &paragliderpb.PermitListRule{},
			validSecurityGroupName, validSecurityRuleName, "10.1.0.5", 200, allowRule)
		require.NoError(t, err)
		require.NotNil(t, resp)
	})
}

func TestCreateSecurityRule(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		nsg:    getFakeNSG(),
	}
	fakeServer, _ := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	securityRule := &armnetwork.SecurityRule{
		Name: to.Ptr(validSecurityRuleName),
		Properties: &armnetwork.SecurityRulePropertiesFormat{
			Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),
			DestinationAddressPrefix: to.Ptr(azureSecurityRuleAsterisk),
			DestinationPortRange:     to.Ptr("8080"),
			Direction:                to.Ptr(armnetwork.SecurityRuleDirectionInbound),
			Priority:                 to.Ptr(int32(100)),
			Protocol:                 to.Ptr(armnetwork.SecurityRuleProtocolTCP),
			SourceAddressPrefix:      to.Ptr(azureSecurityRuleAsterisk),
		},
	}

	t.Run("CreateSecurityRule: Success", func(t *testing.T) {
		resp, err := handler.CreateSecurityRule(context.Background(), validSecurityGroupName, validSecurityRuleName, securityRule)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, *resp.Name, validSecurityRuleName)
		assert.Equal(t, *resp.Properties.Priority, int32(100))
	})
}

func TestDeleteSecurityRule(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
	}
	fakeServer, _ := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Subtest 1: Delete security rule - Success Test
	t.Run("DeleteSecurityRule: Success", func(t *testing.T) {
		err := handler.DeleteSecurityRule(context.Background(), validSecurityGroupName, validSecurityRuleName)

		require.NoError(t, err)
	})
}

func TestGetSecurityGroup(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		nsg:    getFakeNSG(),
	}
	fakeServer, _ := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Subtest 1: Get security group - Success Test
	t.Run("GetSecurityGroup: Success", func(t *testing.T) {
		nsgSuccess, err := handler.GetSecurityGroup(context.Background(), validSecurityGroupName)

		require.NoError(t, err)
		require.NotNil(t, nsgSuccess)
		require.Equal(t, *nsgSuccess.Name, validSecurityGroupName)
	})

	// Subtest 2: Get security group - Failure Test
	t.Run("GetSecurityGroup: Failure", func(t *testing.T) {
		fakeServerState.nsg = nil
		nsgSuccess, err := handler.GetSecurityGroup(context.Background(), validSecurityGroupName)

		require.Error(t, err)
		require.Nil(t, nsgSuccess)
	})
}

func TestCreateSecurityGroup(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		nsg:    getFakeNSG(),
	}
	fakeServer, _ := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("CreateSecurityGroup: Success", func(t *testing.T) {
		prefixName1 := "cidr1"
		prefixName2 := "cidr2"
		allowedCidrs := map[string]string{prefixName1: "1.1.1.1/1", prefixName2: "2.2.2.2/2"}
		nsg, err := handler.CreateSecurityGroup(context.Background(), validResourceName, testLocation, allowedCidrs)

		require.NoError(t, err)
		assert.NotNil(t, nsg)
		assert.Contains(t, *nsg.Name, *fakeServerState.nsg.Name)
	})

	t.Run("CreateSecurityGroup: Success - none allowed", func(t *testing.T) {
		allowedCidrs := map[string]string{}
		nsg, err := handler.CreateSecurityGroup(context.Background(), validResourceName, testLocation, allowedCidrs)

		require.NoError(t, err)
		assert.NotNil(t, nsg)
		assert.Contains(t, *nsg.Name, *fakeServerState.nsg.Name)
	})
}

func TestAssociateNSGWithSubnet(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		subnet: getFakeParagliderSubnet(),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("AssociateNSGWithSubnet: Success", func(t *testing.T) {
		err := handler.AssociateNSGWithSubnet(ctx, validParagliderSubnetId, validSecurityGroupID)
		require.NoError(t, err)
	})

	t.Run("AssociateNSGWithSubnet: Failure - subnet does not exist", func(t *testing.T) {
		fakeServerState.subnet = nil
		err := handler.AssociateNSGWithSubnet(ctx, validParagliderSubnetId, validSecurityGroupID)
		require.Error(t, err)
	})
}

func TestGetSubnetById(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		subnet: getFakeParagliderSubnet(),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("GetSubnetById: Success", func(t *testing.T) {
		subnet, err := handler.GetSubnetByID(ctx, validParagliderSubnetId)

		require.NoError(t, err)
		require.NotNil(t, subnet)
	})

	t.Run("GetSubnetById: Failure", func(t *testing.T) {
		fakeServerState.subnet = nil
		subnet, err := handler.GetSubnetByID(ctx, validParagliderSubnetId)

		require.Error(t, err)
		require.Nil(t, subnet)
	})
}

func TestGetNetworkInterface(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		nic:    getFakeNIC(),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Test 1: Successful GetNetworkInterface for a VM
	t.Run("GetNetworkInterface: Success", func(t *testing.T) {
		nic, err := handler.GetNetworkInterface(ctx, validNicName)

		require.NotNil(t, nic)
		require.NoError(t, err)
	})

	// Test 2: Failed Test due to no NIC
	t.Run("GetNetworkInterface: Failure", func(t *testing.T) {
		fakeServerState.nic = nil
		nic, err := handler.GetNetworkInterface(ctx, validNicName)

		require.Error(t, err)
		require.Nil(t, nic)
	})
}

func TestGetResource(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vm:     to.Ptr(getFakeVirtualMachine(false)),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Test case: Success
	t.Run("GetResource: Success", func(t *testing.T) {
		resource, err := handler.GetResource(ctx, vmURI)

		require.NoError(t, err)
		require.NotNil(t, resource)
	})

	// Test case: Failure
	t.Run("GetResource: Failure", func(t *testing.T) {
		fakeServerState.vm = nil
		resource, err := handler.GetResource(ctx, vmURI)

		require.Error(t, err)
		require.Nil(t, resource)
	})
}

func TestCreateAKSCluster(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:   subID,
		rgName:  rgName,
		cluster: to.Ptr(getFakeCluster(false)),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Test case: Success
	t.Run("CreateAKSCluster: Success", func(t *testing.T) {
		aksCluster, err := handler.CreateAKSCluster(ctx, armcontainerservice.ManagedCluster{}, validClusterName)

		require.NoError(t, err)
		require.NotNil(t, aksCluster)
	})
}

func TestCreateVirtualMachine(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vm:     to.Ptr(getFakeVirtualMachine(false)),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Test case: Success
	t.Run("CreateVirtualMachine: Success", func(t *testing.T) {
		vm, err := handler.CreateVirtualMachine(ctx, armcompute.VirtualMachine{}, validVmName)

		require.NoError(t, err)
		require.NotNil(t, vm)
	})
}

func TestGetParagliderVnet(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vnet:   getFakeVirtualNetwork(),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.AZURE)
	if err != nil {
		t.Fatal(err)
	}

	// Test case: Success, vnet already existed
	t.Run("GetParagliderVnet: Success, vnet exists", func(t *testing.T) {
		vnet, err := handler.GetParagliderVnet(ctx, validParagliderVnetName, testLocation, "namespace", fakeOrchestratorServerAddr)
		require.NoError(t, err)
		require.NotNil(t, vnet)
	})

	// Test case: Success, vnet doesn't exist, create new one
	t.Run("GetParagliderVnet: Success, create new vnet", func(t *testing.T) {
		fakeServerState.vnet = nil
		vnet, err := handler.GetParagliderVnet(ctx, validParagliderVnetName, testLocation, "namespace", fakeOrchestratorServerAddr)
		require.NoError(t, err)
		require.NotNil(t, vnet)
	})
}

func TestAddSubnetToParagliderVnet(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vnet:   getFakeVirtualNetwork(),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.AZURE)
	if err != nil {
		t.Fatal(err)
	}

	// Test case: Success, subnet added
	t.Run("AddSubnetParagliderVnet: Success", func(t *testing.T) {
		subnet, err := handler.AddSubnetToParagliderVnet(ctx, "namespace", validParagliderVnetName, validSubnetName, fakeOrchestratorServerAddr)
		require.NoError(t, err)
		require.NotNil(t, subnet)
	})

	// Test case: Failure, error when getting new address space
	t.Run("AddSubnetParagliderVnet: Failure, error when getting address spaces", func(t *testing.T) {
		subnet, err := handler.AddSubnetToParagliderVnet(ctx, "namespace", validParagliderVnetName, validSubnetName, "bad address")
		require.Error(t, err)
		require.Nil(t, subnet)
	})
}

func TestCreateNetworkInterface(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		nic:    getFakeNIC(),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Test case: Success
	t.Run("CreateNetworkInterface: Success", func(t *testing.T) {
		// Call the function to test
		nic, err := handler.CreateNetworkInterface(ctx, "", testLocation, validNicName)

		require.NoError(t, err)
		require.NotNil(t, nic)
	})
}

func TestCreateParagliderVirtualNetwork(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vnet:   getFakeVirtualNetwork(),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Test case: Success
	t.Run("CreateParagliderVirtualNetwork: Success", func(t *testing.T) {
		// Call the function to test
		vnet, err := handler.CreateParagliderVirtualNetwork(ctx, testLocation, validParagliderVnetName, validAddressSpace)

		require.NoError(t, err)
		require.NotNil(t, vnet)
	})
}

func TestGetVnet(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vnet:   getFakeVirtualNetwork(),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Test case: Success
	t.Run("GetVnet: Success", func(t *testing.T) {
		vnet, err := handler.GetVNet(ctx, validParagliderVnetName)

		require.NoError(t, err)
		require.NotNil(t, vnet)
	})

	// Test case: Failure
	t.Run("GetVnet: Failure", func(t *testing.T) {
		fakeServerState.vnet = nil
		vnet, err := handler.GetVNet(ctx, validParagliderVnetName)

		require.Error(t, err)
		require.Nil(t, vnet)
	})
}

func TestCreateVnetPeering(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vnetPeering: &armnetwork.VirtualNetworkPeering{
			Name: to.Ptr("peeringName"),
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Test case: Success
	t.Run("CreateVnetPeering: Success", func(t *testing.T) {
		err := handler.CreateVnetPeering(ctx, validParagliderVnetName, validParagliderVnetName)

		require.NoError(t, err)
	})
}

func TestGetPermitListRuleFromNSGRule(t *testing.T) {
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	// Test case: Inbound rule
	t.Run("Inbound", func(t *testing.T) {
		inboundRule := &armnetwork.SecurityRule{
			ID:   to.Ptr("security/rule/id"),
			Name: to.Ptr("paraglider-rulename"),
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction:             to.Ptr(armnetwork.SecurityRuleDirectionInbound),
				SourcePortRange:       to.Ptr("100"),
				DestinationPortRange:  to.Ptr("8080"),
				Protocol:              to.Ptr(armnetwork.SecurityRuleProtocolTCP),
				SourceAddressPrefixes: []*string{to.Ptr("10.5.1.0"), to.Ptr("10.6.1.0")},
			},
		}

		// Call the function to test
		result, err := handler.GetPermitListRuleFromNSGRule(inboundRule)

		// Expected permit list rule
		expectedRule := &paragliderpb.PermitListRule{
			Name:      "paraglider-rulename",
			Targets:   []string{"10.5.1.0", "10.6.1.0"},
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   100,
			DstPort:   8080,
			Protocol:  6,
		}

		require.NoError(t, err)
		require.NotNil(t, result)
		// Compare the result with the expected rule
		require.Equal(t, expectedRule, result)
	})

	// Test case: Outbound rule
	t.Run("Outbound", func(t *testing.T) {
		outboundRule := &armnetwork.SecurityRule{
			ID:   to.Ptr("security/rule/id"),
			Name: to.Ptr("paraglider-rulename"),
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
				SourcePortRange:            to.Ptr("200"),
				DestinationPortRange:       to.Ptr("8080"),
				Protocol:                   to.Ptr(armnetwork.SecurityRuleProtocolUDP),
				DestinationAddressPrefixes: []*string{to.Ptr("10.3.1.0"), to.Ptr("10.2.1.0")},
			},
		}

		// Call the function to test
		result, err := handler.GetPermitListRuleFromNSGRule(outboundRule)

		// Expected permit list rule
		expectedRule := &paragliderpb.PermitListRule{
			Name:      "paraglider-rulename",
			Targets:   []string{"10.3.1.0", "10.2.1.0"},
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   200,
			DstPort:   8080,
			Protocol:  17,
		}

		require.NoError(t, err)
		require.NotNil(t, result)

		// Compare the result with the expected rule
		require.Equal(t, expectedRule, result)
	})

	// Test case: success, any port
	t.Run("Success:AnyPort", func(t *testing.T) {
		anyPortRule := &armnetwork.SecurityRule{
			ID:   to.Ptr("security/rule/id"),
			Name: to.Ptr("paraglider-rulename"),
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
				SourcePortRange:            to.Ptr("*"),
				DestinationPortRange:       to.Ptr("*"),
				Protocol:                   to.Ptr(armnetwork.SecurityRuleProtocolUDP),
				DestinationAddressPrefixes: []*string{to.Ptr("10.3.1.0"), to.Ptr("10.2.1.0")},
			},
		}

		// Call the function to test
		result, err := handler.GetPermitListRuleFromNSGRule(anyPortRule)

		// Expected permit list rule
		expectedRule := &paragliderpb.PermitListRule{
			Name:      "paraglider-rulename",
			Targets:   []string{"10.3.1.0", "10.2.1.0"},
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  17,
		}

		require.NoError(t, err)
		require.NotNil(t, result)

		// Compare the result with the expected rule
		require.Equal(t, expectedRule, result)
	})

	// Test case: success, tags included
	t.Run("Success:TagsIncluded", func(t *testing.T) {
		anyPortRule := &armnetwork.SecurityRule{
			ID:   to.Ptr("security/rule/id"),
			Name: to.Ptr("paraglider-rulename"),
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
				SourcePortRange:            to.Ptr("1"),
				DestinationPortRange:       to.Ptr("1"),
				Protocol:                   to.Ptr(armnetwork.SecurityRuleProtocolUDP),
				DestinationAddressPrefixes: []*string{to.Ptr("10.3.1.0"), to.Ptr("10.2.1.0")},
				Description:                to.Ptr(getRuleDescription([]string{"tag1", "tag2"})),
			},
		}

		// Call the function to test
		result, err := handler.GetPermitListRuleFromNSGRule(anyPortRule)

		// Expected permit list rule
		expectedRule := &paragliderpb.PermitListRule{
			Name:      "paraglider-rulename",
			Targets:   []string{"10.3.1.0", "10.2.1.0"},
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   1,
			DstPort:   1,
			Protocol:  17,
			Tags:      []string{"tag1", "tag2"},
		}

		require.NoError(t, err)
		require.NotNil(t, result)

		// Compare the result with the expected rule
		require.Equal(t, expectedRule, result)
	})
}

func TestCreateOrUpdateVirtualNetworkGateway(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vpnGw: &armnetwork.VirtualNetworkGateway{
			Name: to.Ptr(validVirtualNetworkGatewayName),
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		virtualNetworkGateway, err := handler.CreateOrUpdateVirtualNetworkGateway(ctx, validVirtualNetworkGatewayName, armnetwork.VirtualNetworkGateway{})
		require.NoError(t, err)
		require.NotNil(t, virtualNetworkGateway)
	})
}

func TestGetVirtualNetworkGateway(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vpnGw: &armnetwork.VirtualNetworkGateway{
			Name: to.Ptr(validVirtualNetworkGatewayName),
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		virtualNetworkGateway, err := handler.GetVirtualNetworkGateway(ctx, validVirtualNetworkGatewayName)
		require.NoError(t, err)
		require.NotNil(t, virtualNetworkGateway)
	})
	t.Run("Failure", func(t *testing.T) {
		fakeServerState.vpnGw = nil
		virtualNetworkGateway, err := handler.GetVirtualNetworkGateway(ctx, validVirtualNetworkGatewayName)
		require.Error(t, err)
		require.Nil(t, virtualNetworkGateway)
	})
}

func TestCreatePublicIPAddress(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		publicIP: &armnetwork.PublicIPAddress{
			Name: to.Ptr(validPublicIpAddressName),
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		publicIPAddress, err := handler.CreatePublicIPAddress(ctx, validPublicIpAddressName, armnetwork.PublicIPAddress{})
		require.NoError(t, err)
		require.NotNil(t, publicIPAddress)
	})
}

func TestCreateSubnet(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		subnet: getFakeParagliderSubnet(),
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		subnet, err := handler.CreateSubnet(ctx, validParagliderVnetName, validSubnetName, armnetwork.Subnet{})
		require.NoError(t, err)
		require.NotNil(t, subnet)
	})
}

func TestCreateLocalNetworkGateway(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		localGw: &armnetwork.LocalNetworkGateway{
			Name: to.Ptr(validLocalNetworkGatewayName),
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		localNetworkGateway, err := handler.CreateLocalNetworkGateway(ctx, validLocalNetworkGatewayName, armnetwork.LocalNetworkGateway{})
		require.NoError(t, err)
		require.NotNil(t, localNetworkGateway)
	})
}

func TestGetLocalNetworkGateway(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		localGw: &armnetwork.LocalNetworkGateway{
			Name: to.Ptr(validLocalNetworkGatewayName),
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		localNetworkGateway, err := handler.GetLocalNetworkGateway(ctx, validLocalNetworkGatewayName)
		require.NoError(t, err)
		require.NotNil(t, localNetworkGateway)
	})
	t.Run("Failure", func(t *testing.T) {
		fakeServerState.localGw = nil
		localNetworkGateway, err := handler.GetLocalNetworkGateway(ctx, validLocalNetworkGatewayName)
		require.Error(t, err)
		require.Nil(t, localNetworkGateway)
	})
}

func TestCreateVirtualNetworkGatewayConnection(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vpnConnection: &armnetwork.VirtualNetworkGatewayConnection{
			Name: to.Ptr(validVirtualNetworkGatewayConnectionName),
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		virtualNetworkGatewayConnection, err := handler.CreateVirtualNetworkGatewayConnection(ctx, validVirtualNetworkGatewayConnectionName, armnetwork.VirtualNetworkGatewayConnection{})
		require.NoError(t, err)
		require.NotNil(t, virtualNetworkGatewayConnection)
	})
}

func TestGetVirtualNetworkGatewayConnection(t *testing.T) {
	// Set up the fake Azure server
	fakeServerState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vpnConnection: &armnetwork.VirtualNetworkGatewayConnection{
			Name: to.Ptr(validVirtualNetworkGatewayConnectionName),
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, fakeServerState)
	defer Teardown(fakeServer)
	handler := AzureSDKHandler{subscriptionID: subID, resourceGroupName: rgName}
	err := handler.InitializeClients(nil)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		virtualNetworkGatewayConnection, err := handler.GetVirtualNetworkGatewayConnection(ctx, validVirtualNetworkGatewayConnectionName)
		require.NoError(t, err)
		require.NotNil(t, virtualNetworkGatewayConnection)
	})
	t.Run("Failure", func(t *testing.T) {
		fakeServerState.vpnConnection = nil
		virtualNetworkGatewayConnection, err := handler.GetVirtualNetworkGatewayConnection(ctx, validVirtualNetworkGatewayConnectionName)
		require.Error(t, err)
		require.Nil(t, virtualNetworkGatewayConnection)
	})
}

func TestGetIPs(t *testing.T) {
	// Test case 1: Inbound rule
	inboundRule := &paragliderpb.PermitListRule{
		Direction: paragliderpb.Direction_INBOUND,
		Targets:   []string{"10.0.0.1", "192.168.0.1"},
	}

	resourceIP := "192.168.1.100"
	expectedInboundSourceIP := []*string{to.Ptr("10.0.0.1"), to.Ptr("192.168.0.1")}
	expectedInboundDestIP := []*string{to.Ptr("192.168.1.100")}

	inboundSourceIP, inboundDestIP := getIPs(inboundRule, resourceIP)
	require.Equal(t, expectedInboundSourceIP, inboundSourceIP)
	require.Equal(t, expectedInboundDestIP, inboundDestIP)

	// Test case 2: Outbound rule
	outboundRule := &paragliderpb.PermitListRule{
		Direction: paragliderpb.Direction_OUTBOUND,
		Targets:   []string{"172.16.0.1", "192.168.1.1"},
	}

	expectedOutboundSourceIP := []*string{to.Ptr("192.168.1.100")}
	expectedOutboundDestIP := []*string{to.Ptr("172.16.0.1"), to.Ptr("192.168.1.1")}

	outboundSourceIP, outboundDestIP := getIPs(outboundRule, resourceIP)
	require.Equal(t, expectedOutboundSourceIP, outboundSourceIP)
	require.Equal(t, expectedOutboundDestIP, outboundDestIP)
}

func TestGetTargets(t *testing.T) {
	// Test cases for inbound rules
	t.Run("InboundRule", func(t *testing.T) {
		inboundRule := armnetwork.SecurityRule{
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionInbound),
				SourceAddressPrefixes:      []*string{to.Ptr("10.0.0.0/24"), to.Ptr("192.168.0.0/24")},
				DestinationAddressPrefixes: nil,
			},
		}

		expectedInboundTargets := []string{"10.0.0.0/24", "192.168.0.0/24"}
		inboundTargets := getTargets(&inboundRule)
		require.Equal(t, expectedInboundTargets, inboundTargets)
	})

	t.Run("OutboundRule", func(t *testing.T) {
		outboundRule := armnetwork.SecurityRule{
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
				SourceAddressPrefixes:      nil,
				DestinationAddressPrefixes: []*string{to.Ptr("172.16.0.0/16"), to.Ptr("192.168.1.0/24")},
			},
		}

		expectedOutboundTargets := []string{"172.16.0.0/16", "192.168.1.0/24"}
		outboundTargets := getTargets(&outboundRule)
		require.Equal(t, expectedOutboundTargets, outboundTargets)
	})
}

func TestGetRuleDescription(t *testing.T) {
	// Test case: no tags
	t.Run("NoTags", func(t *testing.T) {
		var tags []string
		expectedRuleDescription := nsgRuleDescriptionPrefix
		ruleDescription := getRuleDescription(tags)
		require.Equal(t, expectedRuleDescription, ruleDescription)
	})

	// Test case: tags
	t.Run("Tags", func(t *testing.T) {
		tags := []string{"tag1", "tag2"}
		expectedRuleDescription := nsgRuleDescriptionPrefix + ":" + fmt.Sprintf("%v", tags)
		ruleDescription := getRuleDescription(tags)
		require.Equal(t, expectedRuleDescription, ruleDescription)
	})
}

func TestParseDescriptionTags(t *testing.T) {
	// Test case: no tags
	t.Run("NoTags", func(t *testing.T) {
		description := nsgRuleDescriptionPrefix
		var expectedTags []string
		tags := parseDescriptionTags(&description)
		require.Equal(t, expectedTags, tags)
	})

	t.Run("Tags", func(t *testing.T) {
		originalTags := []string{"tag1", "tag2"}
		description := nsgRuleDescriptionPrefix + ":" + fmt.Sprintf("%v", originalTags)
		tags := parseDescriptionTags(&description)
		require.Equal(t, originalTags, tags)
	})
}
