package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
)

const (
	urlFormat                                  = "/subscriptions/%s/resourceGroups/%s/providers/"
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
	validSubnetId                              = "valid-subnet-id"
	invalidSubnetId                            = "invalid-subnet-id"
	validSubnetURI                             = "/s/s/r/r/p/p/v/" + validVnetName + "/s/" + validSubnetName
	invalidSubnetURI                           = "/s/s/r/r/p/p/v/" + invalidVnetName + "/s/" + invalidSubnetName
	validLocalNetworkGatewayName               = "valid-local-network-gateway"
	invalidLocalNetworkGatewayName             = "invalid-local-network-gateway"
	validVirtualNetworkGatewayConnectionName   = "valid-virtual-network-gateway-connection"
	invalidVirtualNetworkGatewayConnectionName = "invalid-virtual-network-gateway-connection"
	validClusterName                           = "valid-cluster-name"
	invalidClusterName                         = "invalid-cluster-name"
	validResourceName                          = "valid-resource-name"
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
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/networkSecurityGroups/"+validSecurityGroupName):
			if strings.HasSuffix(path, "/securityRules") {
				if r.Method == "PUT" {
					rule := &armnetwork.SecurityRule{}
					err = json.Unmarshal(body, rule)
					if err != nil {
						http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
						return
					}
					sendResponse(w, rule)
					return
				} else if r.Method == "DELETE" {
					w.WriteHeader(http.StatusOK)
					return
				}
			} else {
				if r.Method == "GET" {
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
					sendResponse(w, nsg)
					return
				}
			}
		// VMs
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Compute/virtualMachines/"+vmResourceName):
			if r.Method == "GET" {
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
				sendResponse(w, vm)
			}
		// NICs
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/networkInterfaces/"+validNicName):
			if r.Method == "GET" {
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
		// VNets
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/virtualNetworks/"+validVnetName):
			if strings.Contains(path, "/virtualNetworkPeerings/") { // VirtualNetworkPeerings
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
			} else {
				if r.Method == "GET" {
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
					sendResponse(w, vnet)
					return
				}
			}
		// VirtualNetworkGateways
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/virtualNetworkGateways/"+validVirtualNetworkGatewayName):
			if r.Method == "GET" {
				sendResponse(w, fakeServerState.gateway)
				return
			}
			if r.Method == "PUT" {
				gateway := &armnetwork.VirtualNetworkGateway{}
				err = json.Unmarshal(body, gateway)
				if err != nil {
					http.Error(w, fmt.Sprintf("unable to unmarshal request: %s", err.Error()), http.StatusBadRequest)
					return
				}
				sendResponse(w, gateway)
				return
			}
		// PublicIPAddresses
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/publicIPAddresses/"+validPublicIpAddressName):
			if r.Method == "GET" {
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
				sendResponse(w, publicIP)
				return
			}
		// Subnets
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/virtualNetworks/") && strings.HasSuffix(path, "/subnets"+validSubnetName):
			if r.Method == "GET" {
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
				sendResponse(w, subnet)
				return
			}
		// LocalNetworkGateways
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/localNetworkGateways/"+validLocalNetworkGatewayName):
			if r.Method == "GET" {
				sendResponse(w, fakeServerState.vpnGw)
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
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.Network/connections/"+validVirtualNetworkGatewayConnectionName):
			if r.Method == "GET" {
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
		case strings.HasPrefix(path, urlPrefix+"/Microsoft.ContainerService/managedClusters/"+validClusterName):
			if r.Method == "GET" {
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
				sendResponse(w, cluster)
				return
			}
		}
		fmt.Printf("unsupported request: %s %s\n", r.Method, path)
		http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
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
	gateway       *armnetwork.VirtualNetworkGateway
	publicIP      *armnetwork.PublicIPAddress
	subnet        *armnetwork.Subnet
	vpnGw         *armnetwork.LocalNetworkGateway
	vpnConnection *armnetwork.VirtualNetworkGatewayConnection
	vnetPeering   *armnetwork.VirtualNetworkPeering
	cluster       *armcontainerservice.ManagedCluster
}

// Sets up fake http server and fake GCP compute clients
func SetupFakeAzureServer(t *testing.T, fakeServerState *fakeServerState) (fakeServer *httptest.Server, ctx context.Context) {
	fakeServer = httptest.NewServer(getFakeServerHandler(fakeServerState))

	freePort, err := GetFreePort()
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}

	if entry, ok := cloud.AzurePublic.Services[cloud.ResourceManager]; ok {
		// Then we modify the copy
		entry.Endpoint = fmt.Sprintf("http://localhost:%d", freePort)

		// Then we reassign map entry
		cloud.AzurePublic.Services[cloud.ResourceManager] = entry
	}

	return
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
