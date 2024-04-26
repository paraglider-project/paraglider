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

package azure

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	fake "github.com/NetSys/invisinets/pkg/fake/orchestrator/rpc"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/orchestrator"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var fakeAddressList = map[string][]string{testLocation: []string{validAddressSpace}}

const defaultNamespace = "default"

type dummyAzureCredentialGetter struct {
	iAzureCredentialGetter
}

func (d *dummyAzureCredentialGetter) GetAzureCredentials() (azcore.TokenCredential, error) {
	return nil, nil
}

func setupAzurePluginServer() (*azurePluginServer, context.Context) {
	// Create a new instance of the azurePluginServer
	server := &azurePluginServer{}
	server.orchestratorServerAddr = "fakecontrollerserveraddr"
	server.azureCredentialGetter = &dummyAzureCredentialGetter{}

	return server, context.Background()
}

func getValidVMDescription() (armcompute.VirtualMachine, []byte, error) {
	validVm := &armcompute.VirtualMachine{
		ID:       to.Ptr("vm-id"),
		Name:     to.Ptr("vm-name"),
		Location: to.Ptr(testLocation),
		Properties: &armcompute.VirtualMachineProperties{
			HardwareProfile: &armcompute.HardwareProfile{VMSize: to.Ptr(armcompute.VirtualMachineSizeTypesStandardB1S)},
		},
	}

	validDescripton, err := json.Marshal(validVm)
	return *validVm, validDescripton, err
}

func getValidClusterDescription() (armcontainerservice.ManagedCluster, []byte, error) {
	validCluster := &armcontainerservice.ManagedCluster{
		Location: to.Ptr(testLocation),
		Properties: &armcontainerservice.ManagedClusterProperties{
			AgentPoolProfiles: []*armcontainerservice.ManagedClusterAgentPoolProfile{
				{Name: to.Ptr("agent-pool-name")},
			},
		},
	}

	validDescripton, err := json.Marshal(validCluster)
	return *validCluster, validDescripton, err
}

/* ---- Tests ---- */

func TestCreateResource(t *testing.T) {
	defaultSubnetName := "default"
	defaultSubnetID := "default-subnet-id"
	namespace := "defaultnamespace"
	t.Run("TestCreateResource: Success", func(t *testing.T) {
		// we need to recreate it for each test as it will be modified to include network interface
		vm, desc, err := getValidVMDescription()
		if err != nil {
			t.Errorf("Error while creating valid resource description: %v", err)
		}

		serverState := &fakeServerState{
			vnet: &armnetwork.VirtualNetwork{
				Properties: &armnetwork.VirtualNetworkPropertiesFormat{
					Subnets: []*armnetwork.Subnet{
						{
							Name: to.Ptr(defaultSubnetName),
							ID:   to.Ptr(defaultSubnetID),
						},
					},
				},
			},
			nic:   getFakeNIC(),
			vpnGw: &armnetwork.VirtualNetworkGateway{},
			vm:    &vm,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()

		response, err := server.CreateResource(ctx, &invisinetspb.ResourceDescription{
			Deployment:  &invisinetspb.InvisinetsDeployment{Id: "/subscriptions/123/resourceGroups/rg", Namespace: namespace},
			Name:        validVmName,
			Description: desc,
		})

		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("TestCreateResource: Failure, invalid json", func(t *testing.T) {
		server, ctx := setupAzurePluginServer()
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
		server, ctx := setupAzurePluginServer()
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

		server, ctx := setupAzurePluginServer()

		response, err := server.CreateResource(ctx, &invisinetspb.ResourceDescription{
			Description: desc,
		})

		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("TestCreateResource: Success Cluster Creation", func(t *testing.T) {
		// we need to recreate it for each test as it will be modified to include network interface
		cluster, desc, err := getValidClusterDescription()
		if err != nil {
			t.Errorf("Error while creating valid resource description: %v", err)
		}

		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			vnet: &armnetwork.VirtualNetwork{
				Properties: &armnetwork.VirtualNetworkPropertiesFormat{
					Subnets: []*armnetwork.Subnet{
						{
							Name: to.Ptr(defaultSubnetName),
							ID:   to.Ptr(defaultSubnetID),
						},
					},
				},
			},
			nic:     getFakeNIC(),
			vpnGw:   &armnetwork.VirtualNetworkGateway{},
			cluster: &cluster,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()
		_, orchAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.AZURE)
		if err != nil {
			t.Fatal(err)
		}
		server.orchestratorServerAddr = orchAddr

		response, err := server.CreateResource(ctx, &invisinetspb.ResourceDescription{
			Deployment:  &invisinetspb.InvisinetsDeployment{Id: "/subscriptions/123/resourceGroups/rg", Namespace: namespace},
			Description: desc,
			Name:        getFakeClusterName(),
		})

		require.NoError(t, err)
		require.NotNil(t, response)
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

	// Successful execution and expected permit list
	t.Run("TestGetPermitList: Success", func(t *testing.T) {
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
			nic:    fakeNic,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()

		// Call the GetPermitList function
		request := &invisinetspb.GetPermitListRequest{Resource: fakeResourceId, Namespace: defaultNamespace}
		resp, err := server.GetPermitList(ctx, request)

		// check the results
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, fakePlRules[0], resp.Rules[0])
		require.Len(t, resp.Rules, 2)
	})

	// NSG get fails due to GetNetworkInterface call
	t.Run("TestGetPermitList: Failed while getting NIC", func(t *testing.T) {
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()
		// Call the GetPermitList function
		request := &invisinetspb.GetPermitListRequest{Resource: fakeResourceId, Namespace: defaultNamespace}
		response, err := server.GetPermitList(ctx, request)

		// check the error
		require.Error(t, err)
		require.Nil(t, response)
	})

	// Fail due to resource being in different namespace
	t.Run("TestGetPermitList: Fail due to mismatching namespace", func(t *testing.T) {
		fakeNic.Properties.IPConfigurations[0].Properties.Subnet.ID = to.Ptr("/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Network/virtualNetworks/vnet123/subnets/subnet123")
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
			nic:    fakeNic,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()

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
	fakeNsg := getFakeNsg(fakeNsgID, fakeNsgName)
	fakeVnet := getFakeVnet(fakeNic.Location, validAddressSpace)
	fakeVnet.Properties = &armnetwork.VirtualNetworkPropertiesFormat{
		AddressSpace: &armnetwork.AddressSpace{
			AddressPrefixes: []*string{to.Ptr("10.0.0.0/16")},
		},
		Subnets: []*armnetwork.Subnet{
			{
				Name: to.Ptr("default"),
				ID:   fakeNic.Properties.IPConfigurations[0].Properties.Subnet.ID,
				Properties: &armnetwork.SubnetPropertiesFormat{
					AddressPrefix: to.Ptr("10.0.0.0/16"),
				},
			},
		},
	}

	// Successful AddPermitListRules with new rules
	t.Run("AddPermitListRules: New Rules Success", func(t *testing.T) {
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
			nic:    fakeNic,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr

		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakePlRules, Namespace: defaultNamespace, Resource: fakeResource})

		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	// Successful AddPermitListRules with existing rules
	t.Run("AddPermitListRules: Existing Rules Success", func(t *testing.T) {
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
			nic:    fakeNic,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		fakeOldPlRules, err := getFakePermitList()
		if err != nil {
			t.Errorf("Error while getting fake permit list: %v", err)
		}

		server, _ := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr

		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakeOldPlRules, Namespace: defaultNamespace, Resource: fakeResource})

		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	// Failed while getting NIC
	t.Run("AddPermitListRules: Failure while getting NIC", func(t *testing.T) {
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr

		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakePlRules, Namespace: defaultNamespace, Resource: fakeResource})
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Failure while creating the nsg rule in azure
	t.Run("AddPermitListRules: Failure when creating nsg rule", func(t *testing.T) {
		fakeNic.Name = to.Ptr("invalid-nic-name")
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
			nic:    fakeNic,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr

		resp, err := server.AddPermitListRules(ctx, &invisinetspb.AddPermitListRulesRequest{Rules: fakePlRules, Namespace: defaultNamespace, Resource: fakeResource})
		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Fail due to resource being in different namespace
	t.Run("AddPermitListRules: Fail due to mismatching namespace", func(t *testing.T) {
		fakeNic.Properties.IPConfigurations[0].Properties.Subnet.ID = to.Ptr("/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Network/virtualNetworks/vnet123/subnets/subnet123")
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
			nic:    fakeNic,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()
		server.orchestratorServerAddr = fakeOrchestratorServerAddr

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

	// successful
	t.Run("DeletePermitListRules: Success", func(t *testing.T) {
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
			nic:    fakeNic,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()

		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	// Deletion error while getting resource nic
	t.Run("DeletePermitListRules: Failure while getting NIC", func(t *testing.T) {
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()

		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Failure while deleting rule
	t.Run("DeletePermitListRules: Failure while deleting security rule", func(t *testing.T) {
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
			nic:    fakeNic,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()

		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test 6: Failure while getting security group
	t.Run("DeletePermitListRules: Failure while getting security group", func(t *testing.T) {
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nic:    fakeNic,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()

		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		require.Error(t, err)
		require.NotNil(t, err)
		require.Nil(t, resp)
	})

	// Test Case 7: Fail due to resource being in different namespace
	t.Run("DeletePermitListRules: Fail due to mismatching namespace", func(t *testing.T) {
		fakeNic.Properties.IPConfigurations[0].Properties.Subnet.ID = to.Ptr("/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Network/virtualNetworks/vnet123/subnets/subnet123")
		serverState := &fakeServerState{
			subId:  subID,
			rgName: rgName,
			nsg:    fakeNsg,
			nic:    fakeNic,
		}
		fakeServer, ctx := SetupFakeAzureServer(t, serverState)
		defer Teardown(fakeServer)

		server, _ := setupAzurePluginServer()

		// Call the GetPermitList function
		resp, err := server.DeletePermitListRules(ctx, &invisinetspb.DeletePermitListRulesRequest{RuleNames: fakeRuleNames, Namespace: defaultNamespace, Resource: fakeResource})

		// check the error
		require.Error(t, err)
		require.Nil(t, resp)
	})
}

func TestGetUsedAddressSpaces(t *testing.T) {
	serverState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vnet: &armnetwork.VirtualNetwork{
			Properties: &armnetwork.VirtualNetworkPropertiesFormat{
				AddressSpace: &armnetwork.AddressSpace{
					AddressPrefixes: []*string{to.Ptr(validAddressSpace)},
				},
			},
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, serverState)
	defer Teardown(fakeServer)

	server, _ := setupAzurePluginServer()

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
	serverState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vpnGw: &armnetwork.VirtualNetworkGateway{
			Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{
				BgpSettings: &armnetwork.BgpSettings{
					Asn: to.Ptr(int64(64512)),
				},
			},
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, serverState)
	defer Teardown(fakeServer)

	server, _ := setupAzurePluginServer()

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
	serverState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vpnGw: &armnetwork.VirtualNetworkGateway{
			Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{
				BgpSettings: &armnetwork.BgpSettings{
					BgpPeeringAddresses: []*armnetwork.IPConfigurationBgpPeeringAddress{
						{CustomBgpIPAddresses: []*string{to.Ptr("169.254.21.1")}},
						{CustomBgpIPAddresses: []*string{to.Ptr("169.254.22.1")}},
					},
				},
			},
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, serverState)
	defer Teardown(fakeServer)

	server, _ := setupAzurePluginServer()

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

func TestCreateVpnGateway(t *testing.T) {
	serverState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vnet: &armnetwork.VirtualNetwork{
			Properties: &armnetwork.VirtualNetworkPropertiesFormat{
				Subnets: []*armnetwork.Subnet{
					{
						Name: to.Ptr(gatewaySubnetName),
					},
				},
			},
		},
		subnet: &armnetwork.Subnet{
			ID: to.Ptr("subnet-id"),
		},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, serverState)
	defer Teardown(fakeServer)

	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.AZURE)
	if err != nil {
		t.Fatal(err)
	}
	server, _ := setupAzurePluginServer()
	server.orchestratorServerAddr = fakeControllerServerAddr

	req := &invisinetspb.CreateVpnGatewayRequest{
		Deployment:            &invisinetspb.InvisinetsDeployment{Id: "/subscriptions/123/resourceGroups/rg", Namespace: defaultNamespace},
		Cloud:                 "fake-cloud",
		BgpPeeringIpAddresses: []string{"169.254.21.1", "169.254.22.1"},
	}
	resp, err := server.CreateVpnGateway(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, orchestrator.MIN_PRIVATE_ASN_2BYTE, resp.Asn)
	require.ElementsMatch(t, []string{""}, resp.GatewayIpAddresses)
}

func TestCreateVpnConnections(t *testing.T) {
	serverState := &fakeServerState{
		subId:  subID,
		rgName: rgName,
		vpnGw:  &armnetwork.VirtualNetworkGateway{},
	}
	fakeServer, ctx := SetupFakeAzureServer(t, serverState)
	defer Teardown(fakeServer)

	server, _ := setupAzurePluginServer()

	req := &invisinetspb.CreateVpnConnectionsRequest{
		Deployment:         &invisinetspb.InvisinetsDeployment{Id: "/subscriptions/123/resourceGroups/rg", Namespace: defaultNamespace},
		Cloud:              "cloudname",
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
	return "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Compute/virtualMachines/" + validVmName
}

func getFakeClusterName() string {
	return "cluster123"
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
	azureSDKHandler := &AzureSDKHandler{}
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
	fakeNsgName := "test-nsg-name"
	fakeNsgID := "a/b/" + fakeNsgName
	fakeLocation := "test-location"
	namespace := defaultNamespace
	fakeResourceAddress := ""
	fakeSubnetId := "/subscriptions/sub123/resourceGroups/rg123/providers/Microsoft.Network/virtualNetworks/" + getVnetName(fakeLocation, namespace) + "/subnets/subnet123"
	return &armnetwork.Interface{
		ID:       to.Ptr(validNicId),
		Location: to.Ptr(fakeLocation),
		Name:     to.Ptr(validNicName),
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
				ID:   to.Ptr(fakeNsgID),
				Name: to.Ptr(fakeNsgName),
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
