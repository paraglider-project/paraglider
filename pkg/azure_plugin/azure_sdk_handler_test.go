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
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	fake "github.com/NetSys/invisinets/pkg/fake"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO @nnomier: Setup the server only once and use it for all tests

const (
	testLocation             = "eastus"
	subID                    = "subid-test"
	rgName                   = "rg-test"
	vmResourceID             = "vm-resource-id"
	vmResourceName           = "vm-resource-name"
	invalidVmResourceID      = "invalid-vm-resource-id"
	invalidVmResourceName    = "invalid-vm-resource-name"
	invalidResourceID        = "invalid-resource-id"
	validNicId               = "nic/id/nic-name-test"
	validNicName             = "nic-name-test"
	invalidNicId             = "invalid-nic-id"
	invalidNicName           = "invalid-nic-name"
	invalidResourceType      = "invalid-type"
	validSecurityRuleName    = "valid-security-rule-name"
	invalidSecurityRuleName  = "invalid-security-rule-name"
	validSecurityGroupID     = "valid-security-group-id"
	validSecurityGroupName   = "valid-security-group-name"
	invalidSecurityGroupName = "invalid-security-group-name"
	validVnetName            = "invisinets-valid-vnet-name"
	notFoundVnetName         = "invisinets-not-found-vnet-name"
	invalidVnetName          = "invalid-vnet-name"
	validAddressSpace        = "10.1.0.0/16"
)

type dummyToken struct {
	azcore.TokenCredential
}

func (d *dummyToken) GetToken(ctx context.Context, optsWW policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
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

// a function for setup before all tests
func setup(reqRespMap map[string]interface{}) *azureSDKHandler {
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

	azureSDKHandlerTest := &azureSDKHandler{}
	azureSDKHandlerTest.resourceGroupName = rgName
	azureSDKHandlerTest.subscriptionID = subID
	err = azureSDKHandlerTest.InitializeClients(&dummyToken{})
	if err != nil {
		log.Fatal(err)
	}
	return azureSDKHandlerTest
}

func initializeReqRespMap() map[string]interface{} {
	// Define the base URLs
	nsgURL := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkSecurityGroups", subID, rgName)
	vmURL := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines", subID, rgName)
	nicURL := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkInterfaces", subID, rgName)
	nsgRuleUrl := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkSecurityGroups/%s/securityRules", subID, rgName, validSecurityGroupName)
	vnetUrl := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks", subID, rgName)
	listVnetsUrl := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Network/virtualNetworks", subID)

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
	}

	return urlToResponse
}

func TestGetVNetsAddressSpaces(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	urlToResponse := initializeReqRespMap()
	azureSDKHandlerTest := setup(urlToResponse)

	// Create a new context for the tests
	ctx := context.Background()

	// Test case: Success
	t.Run("GetVNetsAddressSpaces: Success", func(t *testing.T) {
		addresses, err := azureSDKHandlerTest.GetVNetsAddressSpaces(ctx, InvisinetsPrefix)
		require.NoError(t, err)
		require.NotNil(t, addresses)
		require.Len(t, addresses, 1)
		assert.Equal(t, addresses[testLocation], validAddressSpace)
	})
}

func TestCreateSecurityRule(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	urlToResponse := initializeReqRespMap()
	azureSDKHandlerTest := setup(urlToResponse)

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
	urlToResponse := initializeReqRespMap()
	azureSDKHandlerTest := setup(urlToResponse)

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
	urlToResponse := initializeReqRespMap()
	azureSDKHandlerTest := setup(urlToResponse)

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

func TestCreateNetworkSecurityGroup(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	urlToResponse := initializeReqRespMap()
	azureSDKHandlerTest := setup(urlToResponse)

	// Create a new context for the tests
	ctx := context.Background()

	// Subtest 1: Create Network Security Group - Success Test
	t.Run("CreateNetworkSecurityGroup: Success", func(t *testing.T) {
		expectedNsgName := validSecurityGroupName
		expectedLocation := testLocation

		// Call the function to create the network security group
		nsg, err := azureSDKHandlerTest.CreateNetworkSecurityGroup(ctx, expectedNsgName, testLocation)

		// Check if the function returns an error
		require.NoError(t, err)
		require.Equal(t, *nsg.Name, expectedNsgName)
		require.Equal(t, *nsg.Location, expectedLocation)
	})

	// Subtest 2: Create Network Security Group - Failure Test
	t.Run("CreateNetworkSecurityGroup: Failure", func(t *testing.T) {
		// Call the function to create the network security group
		nsg, err := azureSDKHandlerTest.CreateNetworkSecurityGroup(ctx, invalidSecurityGroupName, testLocation)

		require.Error(t, err)
		require.Nil(t, nsg)
	})
}

func TestGetResourceNIC(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	urlToResponse := initializeReqRespMap()
	azureSDKHandlerTest := setup(urlToResponse)

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

func TestUpdateNetworkInterface(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	urlToResponse := initializeReqRespMap()
	azureSDKHandlerTest := setup(urlToResponse)

	// Create a new context for the tests
	ctx := context.Background()

	testNsg := &armnetwork.SecurityGroup{
		ID:   to.Ptr(validSecurityGroupID),
		Name: to.Ptr(validSecurityGroupName),
	}
	testNicValid := &armnetwork.Interface{
		ID:   to.Ptr(validNicId),
		Name: to.Ptr(validNicName),

		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{},
		},
	}
	testNicInvalid := &armnetwork.Interface{
		ID:   to.Ptr(invalidNicId),
		Name: to.Ptr(invalidNicName),

		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{},
		},
	}

	// Test 1: Successful UpdateNetworkInterface
	t.Run("UpdateNetworkInterface: Success", func(t *testing.T) {
		// Call the function to test
		updatedNic, err := azureSDKHandlerTest.UpdateNetworkInterface(ctx, testNicValid, testNsg)

		require.NoError(t, err)
		require.NotNil(t, updatedNic)
	})

	// Test 2: Failed UpdateNetworkInterface due to invalid NIC
	t.Run("UpdateNetworkInterface: Failure", func(t *testing.T) {
		// Call the function to test
		updatedNic, err := azureSDKHandlerTest.UpdateNetworkInterface(ctx, testNicInvalid, testNsg)

		require.Error(t, err)
		require.Nil(t, updatedNic)
	})
}

func TestCreateVirtualMachine(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	urlToResponse := initializeReqRespMap()
	azureSDKHandlerTest := setup(urlToResponse)

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
	urlToResponse := initializeReqRespMap()
	azureSDKHandlerTest := setup(urlToResponse)
	// Create a new context for the tests
	ctx := context.Background()
	fakeControllerServerAddr, err := fake.SetupFakeControllerServer()
	if err != nil {
		t.Fatal(err)
	}

	// Test case: Success, vnet already existed
	t.Run("GetInvisinetsVnet: Success, vnet exists", func(t *testing.T) {
		vnet, err := azureSDKHandlerTest.GetInvisinetsVnet(ctx, validVnetName, testLocation, "")
		require.NoError(t, err)
		require.NotNil(t, vnet)
	})

	// Test case: Success, vnet doesn't exist, create new one
	t.Run("GetInvisinetsVnet: Success, create new vnet", func(t *testing.T) {
		vnet, err := azureSDKHandlerTest.GetInvisinetsVnet(ctx, notFoundVnetName, testLocation, fakeControllerServerAddr)
		require.NoError(t, err)
		require.NotNil(t, vnet)
	})

	// Test case: Failure, error when getting vnet
	t.Run("GetInvisinetsVnet: Failure, error when getting vnet", func(t *testing.T) {
		vnet, err := azureSDKHandlerTest.GetInvisinetsVnet(ctx, invalidVnetName, testLocation, "")
		require.Error(t, err)
		require.Nil(t, vnet)
	})
}

func TestCreateNetworkInterface(t *testing.T) {
	// Initialize and set up the test scenario with the appropriate responses
	urlToResponse := initializeReqRespMap()
	azureSDKHandlerTest := setup(urlToResponse)

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
	urlToResponse := initializeReqRespMap()
	azureSDKHandlerTest := setup(urlToResponse)

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

func TestGetPermitListRuleFromNSGRule(t *testing.T) {
	azureSDKHandlerTest := &azureSDKHandler{}

	// Test case: Inbound rule
	t.Run("Inbound", func(t *testing.T) {
		inboundRule := &armnetwork.SecurityRule{
			ID: to.Ptr("security/rule/id"),
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
			Tag:       []string{"10.5.1.0", "10.6.1.0"},
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
			ID: to.Ptr("security/rule/id"),
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
			Tag:       []string{"10.3.1.0", "10.2.1.0"},
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
}

func TestGetInvisinetsRuleDesc(t *testing.T) {
	azureSDKHandlerTest := &azureSDKHandler{}

	// Test case: Create a sample permit list rule
	rule := &invisinetspb.PermitListRule{
		Tag:       []string{"10.0.0.1", "192.168.0.1"},
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   80,
		DstPort:   8080,
		Protocol:  17,
	}

	// Expected description based on the sample rule
	expectedDescription := "10.0.0.1-192.168.0.1-0-80-8080-17"

	// Call the function to test
	result := azureSDKHandlerTest.GetInvisinetsRuleDesc(rule)

	// Compare the result with the expected description
	require.Equal(t, expectedDescription, result)
}

func TestGetIPs(t *testing.T) {
	// Test case 1: Inbound rule
	inboundRule := &invisinetspb.PermitListRule{
		Direction: invisinetspb.Direction_INBOUND,
		Tag:       []string{"10.0.0.1", "192.168.0.1"},
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
		Tag:       []string{"172.16.0.1", "192.168.1.1"},
	}

	expectedOutboundSourceIP := []*string{to.Ptr("192.168.1.100")}
	expectedOutboundDestIP := []*string{to.Ptr("172.16.0.1"), to.Ptr("192.168.1.1")}

	outboundSourceIP, outboundDestIP := getIPs(outboundRule, resourceIP)
	require.Equal(t, expectedOutboundSourceIP, outboundSourceIP)
	require.Equal(t, expectedOutboundDestIP, outboundDestIP)
}

func TestGetTag(t *testing.T) {
	// Test cases for inbound rules
	t.Run("InboundRule", func(t *testing.T) {
		inboundRule := armnetwork.SecurityRule{
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionInbound),
				SourceAddressPrefixes:      []*string{to.Ptr("10.0.0.0/24"), to.Ptr("192.168.0.0/24")},
				DestinationAddressPrefixes: nil,
			},
		}

		expectedInboundTag := []string{"10.0.0.0/24", "192.168.0.0/24"}
		inboundTag := getTag(&inboundRule)
		require.Equal(t, expectedInboundTag, inboundTag)
	})

	t.Run("OutboundRule", func(t *testing.T) {
		outboundRule := armnetwork.SecurityRule{
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction:                  to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
				SourceAddressPrefixes:      nil,
				DestinationAddressPrefixes: []*string{to.Ptr("172.16.0.0/16"), to.Ptr("192.168.1.0/24")},
			},
		}

		expectedOutboundTag := []string{"172.16.0.0/16", "192.168.1.0/24"}
		outboundTag := getTag(&outboundRule)
		require.Equal(t, expectedOutboundTag, outboundTag)
	})
}
