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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
)

const (
	urlFormat                                = "/subscriptions/%s/resourceGroups/%s/providers"
	testLocation                             = "eastus"
	subID                                    = "subid-test"
	rgName                                   = "rg-test"
	deploymentId                             = "/subscriptions/" + subID + "/resourceGroups/" + rgName
	namespace                                = "namespace"
	uriPrefix                                = deploymentId + "/providers/"
	validNicName                             = "nic-name-test"
	validNicId                               = uriPrefix + "Microsoft.Network/networkInterfaces/" + validNicName
	validSecurityRuleName                    = "valid-security-rule-name"
	validSecurityGroupID                     = uriPrefix + "Microsoft.Network/networkSecurityGroups/" + validSecurityGroupName
	validSecurityGroupName                   = validNicName + nsgNameSuffix
	validVnetName                            = paragliderPrefix + "-" + namespace + "-valid-vnet-name"
	validVnetId                              = uriPrefix + "Microsoft.Network/virtualNetworks/" + validVnetName
	validAddressSpace                        = "10.0.0.0/16"
	validVirtualNetworkGatewayName           = "valid-virtual-network-gateway"
	validPublicIpAddressName                 = "valid-public-ip-address-name"
	validPublicIpAddressId                   = uriPrefix + "Microsoft.Network/publicIPAddresses/" + validPublicIpAddressName
	validSubnetName                          = "valid-subnet-name"
	validSubnetId                            = uriPrefix + "Microsoft.Network/virtualNetworks/" + validVnetName + "/subnets/" + validSubnetName
	validLocalNetworkGatewayName             = "valid-local-network-gateway"
	validVirtualNetworkGatewayConnectionName = "valid-virtual-network-gateway-connection"
	validClusterName                         = "valid-cluster-name"
	validVmName                              = "valid-vm-name"
	validResourceName                        = "valid-resource-name"
	vmURI                                    = uriPrefix + "Microsoft.Compute/virtualMachines/" + validVmName
	aksURI                                   = uriPrefix + "Microsoft.ContainerService/managedClusters/" + validClusterName
)

func sendResponse(w http.ResponseWriter, resp any) {
	b, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "unable to marshal request: "+err.Error(), http.StatusBadRequest)
		return
	}
	_, err = w.Write(b)
	if err != nil {
		http.Error(w, "unable to write request: "+err.Error(), http.StatusBadRequest)
	}
}

func getFakeServerHandler(fakeServerState *fakeServerState) http.HandlerFunc {
	// The handler should be written as minimally as possible to minimize maintenance overhead. Modifying requests (e.g. POST, DELETE)
	// should generally not do anything other than return the operation response. Instead, initialize the fakeServerState as necessary.
	// Keep in mind these unit tests should rely as little as possible on the functionality of this fake server.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
			return
		}
		urlPrefix := fmt.Sprintf(urlFormat, fakeServerState.subId, fakeServerState.rgName)
		switch {
		// NSGs
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/networkSecurityGroups/"):
			if strings.Contains(path, "/securityRules") {
				if r.Method == "PUT" {
					rule := &armnetwork.SecurityRule{}
					err = json.Unmarshal(body, rule)
					if err != nil {
						http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
						return
					}
					if rule.ID == nil {
						rule.ID = to.Ptr("rule-id") // Add ID since would be set server-side
					}
					sendResponse(w, rule)
					return
				} else if r.Method == "DELETE" {
					w.WriteHeader(http.StatusOK)
					return
				}
			} else {
				if r.Method == "GET" {
					if fakeServerState.nsg == nil {
						http.Error(w, "nsg not found", http.StatusNotFound)
						return
					}
					sendResponse(w, fakeServerState.nsg)
					return
				}
				if r.Method == "PUT" {
					nsg := &armnetwork.SecurityGroup{}
					err = json.Unmarshal(body, nsg)
					if err != nil {
						http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
						return
					}
					sendResponse(w, fakeServerState.nsg) // Return server state NSG so that it can have server-side fields in it
					return
				}
			}
		// VMs
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Compute/virtualMachines/"):
			if r.Method == "GET" {
				if fakeServerState.vm == nil {
					http.Error(w, "vm not found", http.StatusNotFound)
					return
				}
				sendResponse(w, fakeServerState.vm)
				return
			}
			if r.Method == "PUT" {
				vm := &armcompute.VirtualMachine{}
				err = json.Unmarshal(body, vm)
				if err != nil {
					http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
					return
				}
				sendResponse(w, fakeServerState.vm) // Return server state VM so that it can have server-side fields in it
				return
			}
		// NICs
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/networkInterfaces/"):
			if r.Method == "GET" {
				if fakeServerState.nic == nil {
					http.Error(w, "nic not found", http.StatusNotFound)
					return
				}
				sendResponse(w, fakeServerState.nic)
				return
			}
			if r.Method == "PUT" {
				nic := &armnetwork.Interface{}
				err = json.Unmarshal(body, nic)
				if err != nil {
					http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
					return
				}
				sendResponse(w, nic)
				return
			}
		// Virtual Networks (and their sub-resources)
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/virtualNetworks"):
			if strings.Contains(path, "/virtualNetworkPeerings/") { // VirtualNetworkPeerings
				if r.Method == "GET" {
					if fakeServerState.vnetPeering == nil {
						http.Error(w, "vnet peering not found", http.StatusNotFound)
						return
					}
					sendResponse(w, fakeServerState.vnetPeering)
					return
				}
				if r.Method == "PUT" {
					peering := &armnetwork.VirtualNetworkPeering{}
					err = json.Unmarshal(body, peering)
					if err != nil {
						http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
						return
					}
					sendResponse(w, peering)
					return
				}
			} else if strings.Contains(path, "/subnets/") { // Subnets
				if r.Method == "GET" {
					if fakeServerState.subnet == nil {
						http.Error(w, "subnet not found", http.StatusNotFound)
						return
					}
					sendResponse(w, fakeServerState.subnet)
					return
				}
				if r.Method == "PUT" {
					subnet := &armnetwork.Subnet{}
					err = json.Unmarshal(body, subnet)
					if err != nil {
						http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
						return
					}
					sendResponse(w, fakeServerState.subnet) // Return server state subnet so that it can have server-side fields in it
					return
				}
			} else {
				if r.Method == "GET" && strings.HasSuffix(path, "/virtualNetworks") {
					if fakeServerState.vnet == nil {
						http.Error(w, "vnet not found", http.StatusNotFound)
						return
					}
					response := &armnetwork.VirtualNetworksClientListResponse{}
					response.Value = []*armnetwork.VirtualNetwork{fakeServerState.vnet}
					sendResponse(w, response)
					return
				}
				if r.Method == "GET" {
					if fakeServerState.vnet == nil {
						http.Error(w, "vnet not found", http.StatusNotFound)
						return
					}
					sendResponse(w, fakeServerState.vnet)
					return
				}
				if r.Method == "PUT" {
					vnet := &armnetwork.VirtualNetwork{}
					err = json.Unmarshal(body, vnet)
					if err != nil {
						http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
						return
					}
					sendResponse(w, fakeServerState.vnet) // Return server state vnet so that it can have server-side fields in it
					return
				}
			}
		// VirtualNetworkGateways
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/virtualNetworkGateways/"):
			if r.Method == "GET" {
				if fakeServerState.vpnGw == nil {
					http.Error(w, "gateway not found", http.StatusNotFound)
					return
				}
				sendResponse(w, fakeServerState.vpnGw)
				return
			}
			if r.Method == "PUT" {
				gateway := &armnetwork.VirtualNetworkGateway{}
				err = json.Unmarshal(body, gateway)
				if err != nil {
					http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
					return
				}
				sendResponse(w, fakeServerState.vpnGw) // Return server state gateway so that it can have server-side fields in it
				return
			}
		// PublicIPAddresses
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/publicIPAddresses/"):
			if r.Method == "GET" {
				if fakeServerState.publicIP == nil {
					http.Error(w, "public IP not found", http.StatusNotFound)
					return
				}
				sendResponse(w, fakeServerState.publicIP)
				return
			}
			if r.Method == "PUT" {
				publicIP := &armnetwork.PublicIPAddress{}
				err = json.Unmarshal(body, publicIP)
				if err != nil {
					http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
					return
				}
				sendResponse(w, fakeServerState.publicIP) // Return server state public IP so that it can have server-side fields in it
				return
			}
		// LocalNetworkGateways
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/localNetworkGateways/"):
			if r.Method == "GET" {
				if fakeServerState.localGw == nil {
					http.Error(w, "local gateway not found", http.StatusNotFound)
					return
				}
				sendResponse(w, fakeServerState.localGw)
				return
			}
			if r.Method == "PUT" {
				localGateway := &armnetwork.LocalNetworkGateway{}
				err = json.Unmarshal(body, localGateway)
				if err != nil {
					http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
					return
				}
				sendResponse(w, localGateway)
				return
			}
		// VirtualNetworkGatewayConnections
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/connections/"):
			if r.Method == "GET" {
				if fakeServerState.vpnConnection == nil {
					http.Error(w, "vpn connection not found", http.StatusNotFound)
					return
				}
				sendResponse(w, fakeServerState.vpnConnection)
				return
			}
			if r.Method == "PUT" {
				vpnConnection := &armnetwork.VirtualNetworkGatewayConnection{}
				err = json.Unmarshal(body, vpnConnection)
				if err != nil {
					http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
					return
				}
				sendResponse(w, vpnConnection)
				return
			}
		// ManagedClusters
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.ContainerService/managedClusters/"):
			if r.Method == "GET" {
				if fakeServerState.cluster == nil {
					http.Error(w, "cluster not found", http.StatusNotFound)
					return
				}
				sendResponse(w, fakeServerState.cluster)
				return
			}
			if r.Method == "PUT" {
				cluster := &armcontainerservice.ManagedCluster{}
				err = json.Unmarshal(body, cluster)
				if err != nil {
					http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
					return
				}
				sendResponse(w, fakeServerState.cluster) // Return server state cluster so that it can have server-side fields in it
				return
			}
		}
		fmt.Printf("unsupported request: %s %s\n", r.Method, path)
	})
}

// Struct to hold state for fake server
type fakeServerState struct {
	subId         string
	rgName        string
	nsg           *armnetwork.SecurityGroup
	vm            *armcompute.VirtualMachine
	nic           *armnetwork.Interface
	vnet          *armnetwork.VirtualNetwork
	publicIP      *armnetwork.PublicIPAddress
	subnet        *armnetwork.Subnet
	vpnGw         *armnetwork.VirtualNetworkGateway
	localGw       *armnetwork.LocalNetworkGateway
	vpnConnection *armnetwork.VirtualNetworkGatewayConnection
	vnetPeering   *armnetwork.VirtualNetworkPeering
	cluster       *armcontainerservice.ManagedCluster
}

// Sets up fake http server
func SetupFakeAzureServer(t *testing.T, fakeServerState *fakeServerState) (fakeServer *httptest.Server, ctx context.Context) {
	fakeServer = httptest.NewServer(getFakeServerHandler(fakeServerState))

	ctx = context.Background()

	if entry, ok := cloud.AzurePublic.Services[cloud.ResourceManager]; ok {
		// Then we modify the copy
		entry.Endpoint = fmt.Sprintf("http://%s", fakeServer.Listener.Addr().String())

		// Then we reassign map entry
		cloud.AzurePublic.Services[cloud.ResourceManager] = entry
	}

	return
}

func Teardown(fakeServer *httptest.Server) {
	fakeServer.Close()
}

func getFakeInterface() *armnetwork.Interface {
	subnet := getFakeSubnet()
	nsg := getFakeNSG()
	return &armnetwork.Interface{
		Name: to.Ptr(validNicName),
		ID:   to.Ptr(validNicId),
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Name: to.Ptr("ip-config-name"),
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						PrivateIPAddress: to.Ptr("1.1.1.1"),
						Subnet:           subnet,
					},
				},
			},
			NetworkSecurityGroup: nsg,
		},
	}
}

func getFakeNSG() *armnetwork.SecurityGroup {
	return &armnetwork.SecurityGroup{
		ID:   to.Ptr(validSecurityGroupID),
		Name: to.Ptr(validSecurityGroupName),
	}
}

func getFakeSubnet() *armnetwork.Subnet {
	return &armnetwork.Subnet{
		Name: to.Ptr(validSubnetName),
		ID:   to.Ptr(validSubnetId),
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: to.Ptr(validAddressSpace),
			NetworkSecurityGroup: &armnetwork.SecurityGroup{
				ID:   getFakeNSG().ID,
				Name: getFakeNSG().Name,
			},
		},
	}
}

func getFakeVirtualNetwork() *armnetwork.VirtualNetwork {
	return &armnetwork.VirtualNetwork{
		Name:     to.Ptr(validVnetName),
		ID:       to.Ptr(validVnetId),
		Location: to.Ptr(testLocation),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{to.Ptr(validAddressSpace)},
			},
			Subnets: []*armnetwork.Subnet{
				{
					Name: to.Ptr(validSubnetName),
					ID:   to.Ptr(validSubnetId),
				},
			},
		},
	}
}

func getFakeVirtualMachine(networkInfo bool) armcompute.VirtualMachine {
	vm := armcompute.VirtualMachine{
		Name:     to.Ptr(validVmName),
		Location: to.Ptr(testLocation),
		ID:       to.Ptr(vmURI),
		Properties: &armcompute.VirtualMachineProperties{
			HardwareProfile: &armcompute.HardwareProfile{VMSize: to.Ptr(armcompute.VirtualMachineSizeTypesStandardB1S)},
		},
	}
	if networkInfo {
		vm.Properties.NetworkProfile = &armcompute.NetworkProfile{
			NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
				{ID: getFakeInterface().ID},
			},
		}
	}
	return vm
}

func getFakeCluster(networkInfo bool) armcontainerservice.ManagedCluster {
	cluster := armcontainerservice.ManagedCluster{
		Name:     to.Ptr(validClusterName),
		Location: to.Ptr(testLocation),
		ID:       to.Ptr(aksURI),
		Properties: &armcontainerservice.ManagedClusterProperties{
			AgentPoolProfiles: []*armcontainerservice.ManagedClusterAgentPoolProfile{
				{Name: to.Ptr("agent-pool-name")},
			},
		},
	}
	if networkInfo {
		cluster.Properties.AgentPoolProfiles = []*armcontainerservice.ManagedClusterAgentPoolProfile{
			{
				VnetSubnetID: getFakeSubnet().ID,
			},
		}
		cluster.Properties.NetworkProfile = &armcontainerservice.NetworkProfile{
			ServiceCidr: to.Ptr("2.2.2.2/2"),
		}
	}
	return cluster
}

func getFakeVMGenericResource() armresources.GenericResource {
	vm := getFakeVirtualMachine(false)
	return armresources.GenericResource{
		ID:       vm.ID,
		Location: vm.Location,
		Type:     to.Ptr("Microsoft.Compute/virtualMachines"),
		Properties: map[string]interface{}{
			"networkProfile": map[string]interface{}{
				"networkInterfaces": []interface{}{
					map[string]interface{}{"id": *getFakeInterface().ID},
				},
			},
		},
	}
}

func getFakeAKSGenericResource() armresources.GenericResource {
	cluster := getFakeCluster(false)
	return armresources.GenericResource{
		ID:       cluster.ID,
		Location: cluster.Location,
		Type:     to.Ptr("Microsoft.ContainerService/managedClusters"),
		Properties: map[string]interface{}{
			"agentPoolProfiles": []interface{}{
				map[string]interface{}{"vnetSubnetID": *getFakeSubnet().ID},
			},
		},
	}
}

func getFakeVMResourceDescription(vm *armcompute.VirtualMachine) (*paragliderpb.ResourceDescription, error) {
	desc, err := json.Marshal(vm)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return &paragliderpb.ResourceDescription{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: deploymentId, Namespace: namespace},
		Name:        validVmName,
		Description: desc,
	}, nil
}

func getFakeClusterResourceDescription(cluster *armcontainerservice.ManagedCluster) (*paragliderpb.ResourceDescription, error) {
	desc, err := json.Marshal(cluster)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return &paragliderpb.ResourceDescription{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: deploymentId, Namespace: namespace},
		Name:        validClusterName,
		Description: desc,
	}, nil
}

func getFakeResourceInfo(name string) ResourceIDInfo {
	rgName := "rg-name"
	return ResourceIDInfo{
		ResourceName:      name,
		ResourceGroupName: rgName,
		SubscriptionID:    "00000000-0000-0000-0000-000000000000",
	}
}
