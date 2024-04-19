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
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	fake "github.com/NetSys/invisinets/pkg/fake/orchestrator/rpc"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testLocation                               = "eastus"
	subID                                      = "subid-test"
	rgName                                     = "rg-test"
	vmResourceID                               = "vm-resource-id"
	vmResourceName                             = "vm-resource-name"
	invalidVmResourceID                        = "invalid-vm-resource-id"
	invalidVmResourceName                      = "invalid-vm-resource-name"
	invalidResourceID                          = "invalid-resource-id"
	validNicId                                 = "nic/id/nic-name-test"
	validNicName                               = "nic-name-test"
	invalidNicId                               = "invalid-nic-id"
	invalidNicName                             = "invalid-nic-name"
	invalidResourceType                        = "invalid-type"
	validSecurityRuleName                      = "valid-security-rule-name"
	invalidSecurityRuleName                    = "invalid-security-rule-name"
	validSecurityGroupID                       = "valid-security-group-id"
	validSecurityGroupName                     = validNicName + nsgNameSuffix
	invalidSecurityGroupName                   = "invalid-security-group-name"
	validVnetName                              = "invisinets-valid-vnet-name"
	notFoundVnetName                           = "invisinets-not-found-vnet-name"
	invalidVnetName                            = "invalid-vnet-name"
	validAddressSpace                          = "10.0.0.0/16"
	validVirtualNetworkGatewayName             = "valid-virtual-network-gateway"
	invalidVirtualNetworkGatewayName           = "invalid-virtual-network-gateway"
	validPublicIpAddressName                   = "valid-public-ip-address-name"
	invalidPublicIpAddressName                 = "invalid-public-ip-address-name"
	validSubnetName                            = "valid-subnet-name"
	invalidSubnetName                          = "invalid-subnet-name"
	validLocalNetworkGatewayName               = "valid-local-network-gateway"
	invalidLocalNetworkGatewayName             = "invalid-local-network-gateway"
	validVirtualNetworkGatewayConnectionName   = "valid-virtual-network-gateway-connection"
	invalidVirtualNetworkGatewayConnectionName = "invalid-virtual-network-gateway-connection"
)

var (
	once                sync.Once
	urlToResponse       map[string]interface{}
	azureSDKHandlerTest *azureSDKHandler
)

type dummyToken struct {
	azcore.TokenCredential
}

func (d *dummyToken) GetToken(ctx context.Context, optsWW policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

func setup() {
	urlToResponse = initializeReqRespMap()
	setupFakeServer(urlToResponse)
	azureSDKHandlerTest = &azureSDKHandler{}
	azureSDKHandlerTest.resourceGroupName = rgName
	azureSDKHandlerTest.subscriptionID = subID
	err := azureSDKHandlerTest.InitializeClients(&dummyToken{})
	if err != nil {
		log.Fatal(err)
	}
}

// GetFreePort returns a free port number that the operating system chooses dynamically.
func GetFreePort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	// Retrieve the chosen port number from the listener's network address
	address := listener.Addr().(*net.TCPAddr)
	return address.Port, nil
}

// a function for fake server setup
func setupFakeServer(reqRespMap map[string]interface{}) {
	freePort, err := GetFreePort()
	if err != nil {
		log.Fatal(err)
	}

	if entry, ok := cloud.AzurePublic.Services[cloud.ResourceManager]; ok {
		// Then we modify the copy
		entry.Endpoint = fmt.Sprintf("http://localhost:%d", freePort)

		// Then we reassign map entry
		cloud.AzurePublic.Services[cloud.ResourceManager] = entry
	}

	fakeHttpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Removing query parameters from the URL to use as the map key
		key := strings.Split(r.URL.String(), "?")[0]
		response, ok := reqRespMap[key]
		if !ok {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		} else if strings.Contains(key, notFoundVnetName) && r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}

		// Response found in the map, encode and send the response
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "500 Internal Server Error: Error encoding response.")
			return
		}
	})

	go func() {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", freePort), fakeHttpHandler))
	}()
}

func initializeReqRespMap() map[string]interface{} {
	// Define the base URLs
	nsgURL := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkSecurityGroups", subID, rgName)
	vmURL := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines", subID, rgName)
	nicURL := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkInterfaces", subID, rgName)
	nsgRuleUrl := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkSecurityGroups/%s/securityRules", subID, rgName, validSecurityGroupName)
	vnetUrl := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks", subID, rgName)
	listVnetsUrl := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks", subID, rgName)
	vnetsInRgUrl := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks", subID, rgName)
	virtualNetworkGatewayUrl := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworkGateways", subID, rgName)
	publicIpAddressUrl := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/publicIPAddresses", subID, rgName)
	subnetUrl := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s/subnets", subID, rgName, validVnetName)
	localNetworkGatewayUrl := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/localNetworkGateways", subID, rgName)
	virtualNetworkGatewayConnectionUrl := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/connections", subID, rgName)

	// Define a map of URLs to responses
	urlToResponse := map[string]interface{}{
		fmt.Sprintf("%s/%s", nsgURL, validSecurityGroupName): armnetwork.SecurityGroupsClientGetResponse{
			SecurityGroup: armnetwork.SecurityGroup{
				Name:     to.Ptr(validSecurityGroupName),
				Location: to.Ptr(testLocation),
			},
		},
		//This one is used by the GetByID req
		fmt.Sprintf("/%s", vmResourceID): armresources.ClientGetByIDResponse{
			GenericResource: armresources.GenericResource{
				Type: to.Ptr("Microsoft.Compute/virtualMachines"),
				Name: to.Ptr(vmResourceName),
			},
		},
		// this one would have a correct type but should fail when getting the vm
		fmt.Sprintf("/%s", invalidVmResourceID): armresources.ClientGetByIDResponse{
			GenericResource: armresources.GenericResource{
				Type: to.Ptr("Microsoft.Compute/virtualMachines"),
				Name: to.Ptr(invalidVmResourceName),
			},
		},
		fmt.Sprintf("/%s", invalidResourceID): armresources.ClientGetByIDResponse{
			GenericResource: armresources.GenericResource{
				Type: to.Ptr(invalidResourceType),
			},
		},
		fmt.Sprintf("%s/%s", vmURL, vmResourceName): armcompute.VirtualMachinesClientGetResponse{
			VirtualMachine: armcompute.VirtualMachine{
				Name:     to.Ptr(vmResourceName),
				Location: to.Ptr(testLocation),
				Properties: &armcompute.VirtualMachineProperties{
					NetworkProfile: &armcompute.NetworkProfile{
						NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
							{
								ID: to.Ptr(validNicId),
							},
						},
					},
				},
			},
		},
		fmt.Sprintf("%s/%s", nicURL, validNicName): armnetwork.InterfacesClientGetResponse{
			Interface: armnetwork.Interface{
				Name: to.Ptr(validNicName),
			},
		},
		fmt.Sprintf("%s/%s", nsgRuleUrl, validSecurityRuleName): armnetwork.SecurityRulesClientGetResponse{
			SecurityRule: armnetwork.SecurityRule{
				Name: to.Ptr(validSecurityRuleName),
			},
		},
		fmt.Sprintf("%s/%s", vnetUrl, validVnetName): armnetwork.VirtualNetworksClientGetResponse{
			VirtualNetwork: armnetwork.VirtualNetwork{
				Properties: &armnetwork.VirtualNetworkPropertiesFormat{
					Subnets: []*armnetwork.Subnet{
						{
							Properties: &armnetwork.SubnetPropertiesFormat{
								AddressPrefix: to.Ptr(validAddressSpace),
							},
						},
					},
				},
			},
		},
		// vnet not found but a new one is created successfully
		fmt.Sprintf("%s/%s", vnetUrl, notFoundVnetName): armnetwork.VirtualNetworksClientGetResponse{},
		listVnetsUrl: armnetwork.VirtualNetworksClientListAllResponse{
			VirtualNetworkListResult: armnetwork.VirtualNetworkListResult{
				Value: []*armnetwork.VirtualNetwork{
					{
						Name:     to.Ptr(validVnetName),
						Location: to.Ptr(testLocation),
						Properties: &armnetwork.VirtualNetworkPropertiesFormat{
							AddressSpace: &armnetwork.AddressSpace{
								AddressPrefixes: []*string{to.Ptr(validAddressSpace)},
							},
						},
					},
				},
			}},
		fmt.Sprintf("%s/%s/virtualNetworkPeerings/%s", vnetsInRgUrl, validVnetName, getPeeringName(validVnetName, validVnetName)): armnetwork.VirtualNetworkPeeringsClientGetResponse{},
		fmt.Sprintf("%s/%s", virtualNetworkGatewayUrl, validVirtualNetworkGatewayName):                                            armnetwork.VirtualNetworkGateway{},
		fmt.Sprintf("%s/%s", publicIpAddressUrl, validPublicIpAddressName):                                                        armnetwork.PublicIPAddress{},
		fmt.Sprintf("%s/%s", subnetUrl, validSubnetName):                                                                          armnetwork.Subnet{},
		fmt.Sprintf("%s/%s", localNetworkGatewayUrl, validLocalNetworkGatewayName):                                                armnetwork.LocalNetworkGateway{},
		fmt.Sprintf("%s/%s", virtualNetworkGatewayConnectionUrl, validVirtualNetworkGatewayConnectionName):                        armnetwork.VirtualNetworkGatewayConnection{},
	}
	return urlToResponse
}

func TestGetVNetsAddressSpaces(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	once.Do(setup)

	// Create a new context for the tests
	ctx := context.Background()

	// Test case: Success
	t.Run("GetVNetsAddressSpaces: Success", func(t *testing.T) {
		addresses, err := azureSDKHandlerTest.GetVNetsAddressSpaces(ctx, invisinetsPrefix)
		require.NoError(t, err)
		require.NotNil(t, addresses)
		require.Len(t, addresses, 1)
		assert.Equal(t, addresses[testLocation], validAddressSpace)
	})
}

func TestCreateSecurityRule(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	once.Do(setup)

	// Subtest 1: Create security rule - Success Test
	t.Run("CreateSecurityRule: Success", func(t *testing.T) {
		resp, err := azureSDKHandlerTest.CreateSecurityRule(context.Background(), &invisinetspb.PermitListRule{},
			validSecurityGroupName, validSecurityRuleName, "10.1.0.5", 200)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, *resp.Name, validSecurityRuleName)

	})

	// Subtest 2: Create security rule - Failure Test
	t.Run("CreateSecurityRule: Failure", func(t *testing.T) {
		resp, err := azureSDKHandlerTest.CreateSecurityRule(context.Background(), &invisinetspb.PermitListRule{},
			validSecurityGroupName, "invalid-security-rule-name", "10.10.1.0", 200)

		require.Error(t, err)
		require.Nil(t, resp)
	})
}

func TestDeleteSecurityRule(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	once.Do(setup)

	// Subtest 1: Delete security rule - Success Test
	t.Run("DeleteSecurityRule: Success", func(t *testing.T) {
		err := azureSDKHandlerTest.DeleteSecurityRule(context.Background(), validSecurityGroupName, validSecurityRuleName)

		require.NoError(t, err)
	})

	// Subtest 2: Delete security rule - Failure Test
	t.Run("DeleteSecurityRule: Failure", func(t *testing.T) {
		err := azureSDKHandlerTest.DeleteSecurityRule(context.Background(), validSecurityGroupName, invalidSecurityRuleName)

		require.Error(t, err)
	})
}

func TestGetSecurityGroup(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	once.Do(setup)

	// Subtest 1: Get security group - Success Test
	t.Run("GetSecurityGroup: Success", func(t *testing.T) {
		expectedNsgNameSuccess := validSecurityGroupName
		nsgSuccess, err := azureSDKHandlerTest.GetSecurityGroup(context.Background(), validSecurityGroupName)

		require.NoError(t, err)
		require.NotNil(t, nsgSuccess)
		require.Equal(t, *nsgSuccess.Name, expectedNsgNameSuccess)
	})

	// Subtest 2: Get security group - Failure Test
	t.Run("GetSecurityGroup: Failure", func(t *testing.T) {
		nsgFail, err := azureSDKHandlerTest.GetSecurityGroup(context.Background(), invalidSecurityGroupName)

		// Check if error is not nil and nsgFail is nil
		require.Error(t, err)
		require.Nil(t, nsgFail)
	})
}

func TestGetResourceNIC(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	once.Do(setup)

	// Create a new context for the tests
	ctx := context.Background()

	// Test 1: Successful GetResourceNIC for a VM
	t.Run("GetResourceNIC: Success VMTest", func(t *testing.T) {
		// Call the function to test
		nic, err := azureSDKHandlerTest.GetResourceNIC(ctx, vmResourceID)

		require.NotNil(t, nic)
		require.NoError(t, err)
	})

	// Test 2: Failed Test due to non VM resource type
	t.Run("GetResourceNIC: FailureNonVMTest", func(t *testing.T) {
		// Call the function to test
		nic, err := azureSDKHandlerTest.GetResourceNIC(ctx, invalidResourceID)

		require.Error(t, err)
		require.Nil(t, nic)

		// require the error message
		require.Equal(t, err.Error(), fmt.Sprintf("resource type %s is not supported", invalidResourceType))
	})

	// Test 3: Failed Test due to failed GET VM request
	t.Run("GetResourceNIC: FailureVMTest", func(t *testing.T) {
		// Call the function to test
		nic, err := azureSDKHandlerTest.GetResourceNIC(ctx, invalidVmResourceID)

		require.Error(t, err)
		require.Nil(t, nic)
	})
}

func TestCreateVirtualMachine(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	once.Do(setup)

	// Create a new context for the tests
	ctx := context.Background()

	// Test case: Success
	t.Run("CreateVirtualMachine: Success", func(t *testing.T) {
		// Call the function to test
		vm, err := azureSDKHandlerTest.CreateVirtualMachine(ctx, armcompute.VirtualMachine{}, vmResourceName)

		require.NoError(t, err)
		require.NotNil(t, vm)
	})

	// Test case: Failure
	t.Run("CreateVirtualMachine: Failure", func(t *testing.T) {
		// Call the function to test
		vm, err := azureSDKHandlerTest.CreateVirtualMachine(ctx, armcompute.VirtualMachine{}, invalidVmResourceName)

		require.Error(t, err)
		require.Nil(t, vm)
	})
}

func TestGetInvisinetsVnet(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	once.Do(setup)

	// Create a new context for the tests
	ctx := context.Background()
	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.AZURE)
	if err != nil {
		t.Fatal(err)
	}

	// Test case: Success, vnet already existed
	t.Run("GetInvisinetsVnet: Success, vnet exists", func(t *testing.T) {
		vnet, err := azureSDKHandlerTest.GetInvisinetsVnet(ctx, validVnetName, testLocation, "namespace", fakeOrchestratorServerAddr)
		require.NoError(t, err)
		require.NotNil(t, vnet)
	})

	// Test case: Success, vnet doesn't exist, create new one
	t.Run("GetInvisinetsVnet: Success, create new vnet", func(t *testing.T) {
		vnet, err := azureSDKHandlerTest.GetInvisinetsVnet(ctx, notFoundVnetName, testLocation, "namespace", fakeOrchestratorServerAddr)
		require.NoError(t, err)
		require.NotNil(t, vnet)
	})

	// Test case: Failure, error when getting vnet
	t.Run("GetInvisinetsVnet: Failure, error when getting vnet", func(t *testing.T) {
		vnet, err := azureSDKHandlerTest.GetInvisinetsVnet(ctx, invalidVnetName, testLocation, "namespace", fakeOrchestratorServerAddr)
		require.Error(t, err)
		require.Nil(t, vnet)
	})
}

func TestCreateNetworkInterface(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	once.Do(setup)

	// Create a new context for the tests
	ctx := context.Background()

	// Test case: Success
	t.Run("CreateNetworkInterface: Success", func(t *testing.T) {
		// Call the function to test
		nic, err := azureSDKHandlerTest.CreateNetworkInterface(ctx, "", testLocation, validNicName)

		require.NoError(t, err)
		require.NotNil(t, nic)
	})

	// Test case: Failure
	t.Run("CreateNetworkInterface: Failure", func(t *testing.T) {
		// Call the function to test
		nic, err := azureSDKHandlerTest.CreateNetworkInterface(ctx, "", testLocation, invalidNicName)

		require.Error(t, err)
		require.Nil(t, nic)
	})
}

func TestCreateInvisinetsVirtualNetwork(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	once.Do(setup)

	// Create a new context for the tests
	ctx := context.Background()

	// Test case: Success
	t.Run("CreateInvisinetsVirtualNetwork: Success", func(t *testing.T) {
		// Call the function to test
		vnet, err := azureSDKHandlerTest.CreateInvisinetsVirtualNetwork(ctx, testLocation, validVnetName, validAddressSpace)

		require.NoError(t, err)
		require.NotNil(t, vnet)
	})

	// Test case: Failure
	t.Run("CreateInvisinetsVirtualNetwork: Failure", func(t *testing.T) {
		// Call the function to test
		vnet, err := azureSDKHandlerTest.CreateInvisinetsVirtualNetwork(ctx, testLocation, invalidVnetName, validAddressSpace)

		require.Error(t, err)
		require.Nil(t, vnet)
	})
}

func TestGetVnet(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	once.Do(setup)

	// Create a new context for the tests
	ctx := context.Background()

	// Test case: Success
	t.Run("GetVnet: Success", func(t *testing.T) {
		// Call the function to test
		vnet, err := azureSDKHandlerTest.GetVNet(ctx, validVnetName)

		require.NoError(t, err)
		require.NotNil(t, vnet)
	})

	// Test case: Failure
	t.Run("GetVnet: Failure", func(t *testing.T) {
		// Call the function to test
		vnet, err := azureSDKHandlerTest.GetVNet(ctx, invalidVnetName)

		require.Error(t, err)
		require.Nil(t, vnet)
	})
}

func TestCreateVnetPeering(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	once.Do(setup)

	// Create a new context for the tests
	ctx := context.Background()
	// Test case: Success
	t.Run("CreateVnetPeering: Success", func(t *testing.T) {
		// Call the function to test
		err := azureSDKHandlerTest.CreateVnetPeering(ctx, validVnetName, validVnetName)

		require.NoError(t, err)
	})
}

func TestGetPermitListRuleFromNSGRule(t *testing.T) {
	azureSDKHandlerTest := &azureSDKHandler{}

	// Test case: Inbound rule
	t.Run("Inbound", func(t *testing.T) {
		inboundRule := &armnetwork.SecurityRule{
			ID:   to.Ptr("security/rule/id"),
			Name: to.Ptr("invisinets-rulename"),
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction:             to.Ptr(armnetwork.SecurityRuleDirectionInbound),
				SourcePortRange:       to.Ptr("100"),
				DestinationPortRange:  to.Ptr("8080"),
				Protocol:              to.Ptr(armnetwork.SecurityRuleProtocolTCP),
				SourceAddressPrefixes: []*string{to.Ptr("10.5.1.0"), to.Ptr("10.6.1.0")},
			},
		}

		// Call the function to test
		result, err := azureSDKHandlerTest.GetPermitListRuleFromNSGRule(inboundRule)

		// Expected permit list rule
		expectedRule := &invisinetspb.PermitListRule{
			Id:        "security/rule/id",
			Name:      "invisinets-rulename",
			Targets:   []string{"10.5.1.0", "10.6.1.0"},
			Direction: invisinetspb.Direction_INBOUND,
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
			Name: to.Ptr("invisinets-rulename"),
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
				SourcePortRange:            to.Ptr("200"),
				DestinationPortRange:       to.Ptr("8080"),
				Protocol:                   to.Ptr(armnetwork.SecurityRuleProtocolUDP),
				DestinationAddressPrefixes: []*string{to.Ptr("10.3.1.0"), to.Ptr("10.2.1.0")},
			},
		}

		// Call the function to test
		result, err := azureSDKHandlerTest.GetPermitListRuleFromNSGRule(outboundRule)

		// Expected permit list rule
		expectedRule := &invisinetspb.PermitListRule{
			Id:        "security/rule/id",
			Name:      "invisinets-rulename",
			Targets:   []string{"10.3.1.0", "10.2.1.0"},
			Direction: invisinetspb.Direction_OUTBOUND,
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
			Name: to.Ptr("invisinets-rulename"),
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
				SourcePortRange:            to.Ptr("*"),
				DestinationPortRange:       to.Ptr("*"),
				Protocol:                   to.Ptr(armnetwork.SecurityRuleProtocolUDP),
				DestinationAddressPrefixes: []*string{to.Ptr("10.3.1.0"), to.Ptr("10.2.1.0")},
			},
		}

		// Call the function to test
		result, err := azureSDKHandlerTest.GetPermitListRuleFromNSGRule(anyPortRule)

		// Expected permit list rule
		expectedRule := &invisinetspb.PermitListRule{
			Id:        "security/rule/id",
			Name:      "invisinets-rulename",
			Targets:   []string{"10.3.1.0", "10.2.1.0"},
			Direction: invisinetspb.Direction_OUTBOUND,
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
			Name: to.Ptr("invisinets-rulename"),
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
		result, err := azureSDKHandlerTest.GetPermitListRuleFromNSGRule(anyPortRule)

		// Expected permit list rule
		expectedRule := &invisinetspb.PermitListRule{
			Id:        "security/rule/id",
			Name:      "invisinets-rulename",
			Targets:   []string{"10.3.1.0", "10.2.1.0"},
			Direction: invisinetspb.Direction_OUTBOUND,
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
	once.Do(setup)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		virtualNetworkGateway, err := azureSDKHandlerTest.CreateOrUpdateVirtualNetworkGateway(ctx, validVirtualNetworkGatewayName, armnetwork.VirtualNetworkGateway{})
		require.NoError(t, err)
		require.NotNil(t, virtualNetworkGateway)
	})
	t.Run("Failure", func(t *testing.T) {
		virtualNetworkGateway, err := azureSDKHandlerTest.CreateOrUpdateVirtualNetworkGateway(ctx, invalidVirtualNetworkGatewayName, armnetwork.VirtualNetworkGateway{})
		require.Error(t, err)
		require.Nil(t, virtualNetworkGateway)
	})
}

func TestGetVirtualNetworkGateway(t *testing.T) {
	once.Do(setup)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		virtualNetworkGateway, err := azureSDKHandlerTest.GetVirtualNetworkGateway(ctx, validVirtualNetworkGatewayName)
		require.NoError(t, err)
		require.NotNil(t, virtualNetworkGateway)
	})
	t.Run("Failure", func(t *testing.T) {
		virtualNetworkGateway, err := azureSDKHandlerTest.GetVirtualNetworkGateway(ctx, invalidVirtualNetworkGatewayName)
		require.Error(t, err)
		require.Nil(t, virtualNetworkGateway)
	})
}

func TestCreatePublicIPAddress(t *testing.T) {
	once.Do(setup)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		publicIPAddress, err := azureSDKHandlerTest.CreatePublicIPAddress(ctx, validPublicIpAddressName, armnetwork.PublicIPAddress{})
		require.NoError(t, err)
		require.NotNil(t, publicIPAddress)
	})
	t.Run("Failure", func(t *testing.T) {
		publicIPAddress, err := azureSDKHandlerTest.CreatePublicIPAddress(ctx, invalidPublicIpAddressName, armnetwork.PublicIPAddress{})
		require.Error(t, err)
		require.Nil(t, publicIPAddress)
	})
}

func TestCreateSubnet(t *testing.T) {
	once.Do(setup)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		subnet, err := azureSDKHandlerTest.CreateSubnet(ctx, validVnetName, validSubnetName, armnetwork.Subnet{})
		require.NoError(t, err)
		require.NotNil(t, subnet)
	})
	t.Run("Failure", func(t *testing.T) {
		subnet, err := azureSDKHandlerTest.CreateSubnet(ctx, validVnetName, invalidSubnetName, armnetwork.Subnet{})
		require.Error(t, err)
		require.Nil(t, subnet)
	})
}

func TestCreateLocalNetworkGateway(t *testing.T) {
	once.Do(setup)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		localNetworkGateway, err := azureSDKHandlerTest.CreateLocalNetworkGateway(ctx, validLocalNetworkGatewayName, armnetwork.LocalNetworkGateway{})
		require.NoError(t, err)
		require.NotNil(t, localNetworkGateway)
	})
	t.Run("Failure", func(t *testing.T) {
		localNetworkGateway, err := azureSDKHandlerTest.CreateLocalNetworkGateway(ctx, invalidLocalNetworkGatewayName, armnetwork.LocalNetworkGateway{})
		require.Error(t, err)
		require.Nil(t, localNetworkGateway)
	})
}

func TestGetLocalNetworkGateway(t *testing.T) {
	once.Do(setup)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		localNetworkGateway, err := azureSDKHandlerTest.GetLocalNetworkGateway(ctx, validLocalNetworkGatewayName)
		require.NoError(t, err)
		require.NotNil(t, localNetworkGateway)
	})
	t.Run("Failure", func(t *testing.T) {
		localNetworkGateway, err := azureSDKHandlerTest.GetLocalNetworkGateway(ctx, invalidLocalNetworkGatewayName)
		require.Error(t, err)
		require.Nil(t, localNetworkGateway)
	})
}

func TestCreateVirtualNetworkGatewayConnection(t *testing.T) {
	once.Do(setup)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		virtualNetworkGatewayConnection, err := azureSDKHandlerTest.CreateVirtualNetworkGatewayConnection(ctx, validVirtualNetworkGatewayConnectionName, armnetwork.VirtualNetworkGatewayConnection{})
		require.NoError(t, err)
		require.NotNil(t, virtualNetworkGatewayConnection)
	})
	t.Run("Failure", func(t *testing.T) {
		virtualNetworkGatewayConnection, err := azureSDKHandlerTest.CreateVirtualNetworkGatewayConnection(ctx, invalidVirtualNetworkGatewayConnectionName, armnetwork.VirtualNetworkGatewayConnection{})
		require.Error(t, err)
		require.Nil(t, virtualNetworkGatewayConnection)
	})
}

func TestGetVirtualNetworkGatewayConnection(t *testing.T) {
	once.Do(setup)
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		virtualNetworkGatewayConnection, err := azureSDKHandlerTest.GetVirtualNetworkGatewayConnection(ctx, validVirtualNetworkGatewayConnectionName)
		require.NoError(t, err)
		require.NotNil(t, virtualNetworkGatewayConnection)
	})
	t.Run("Failure", func(t *testing.T) {
		virtualNetworkGatewayConnection, err := azureSDKHandlerTest.GetVirtualNetworkGatewayConnection(ctx, invalidVirtualNetworkGatewayConnectionName)
		require.Error(t, err)
		require.Nil(t, virtualNetworkGatewayConnection)
	})
}

func TestGetIPs(t *testing.T) {
	// Test case 1: Inbound rule
	inboundRule := &invisinetspb.PermitListRule{
		Direction: invisinetspb.Direction_INBOUND,
		Targets:   []string{"10.0.0.1", "192.168.0.1"},
	}

	resourceIP := "192.168.1.100"
	expectedInboundSourceIP := []*string{to.Ptr("10.0.0.1"), to.Ptr("192.168.0.1")}
	expectedInboundDestIP := []*string{to.Ptr("192.168.1.100")}

	inboundSourceIP, inboundDestIP := getIPs(inboundRule, resourceIP)
	require.Equal(t, expectedInboundSourceIP, inboundSourceIP)
	require.Equal(t, expectedInboundDestIP, inboundDestIP)

	// Test case 2: Outbound rule
	outboundRule := &invisinetspb.PermitListRule{
		Direction: invisinetspb.Direction_OUTBOUND,
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
