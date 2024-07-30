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
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

const namespaceTagKey = "paraglider-namespace"

type AzureSDKHandler struct {
	resourcesClientFactory                 *armresources.ClientFactory
	computeClientFactory                   *armcompute.ClientFactory
	networkClientFactory                   *armnetwork.ClientFactory
	containerServiceClientFactory          *armcontainerservice.ClientFactory
	dnsClientFactory                       *armprivatedns.ClientFactory
	securityGroupsClient                   *armnetwork.SecurityGroupsClient
	interfacesClient                       *armnetwork.InterfacesClient
	securityRulesClient                    *armnetwork.SecurityRulesClient
	virtualMachinesClient                  *armcompute.VirtualMachinesClient
	virtualNetworksClient                  *armnetwork.VirtualNetworksClient
	managedClustersClient                  *armcontainerservice.ManagedClustersClient
	resourcesClient                        *armresources.Client
	deploymentsClient                      *armresources.DeploymentsClient
	networkPeeringClient                   *armnetwork.VirtualNetworkPeeringsClient
	virtualNetworkGatewaysClient           *armnetwork.VirtualNetworkGatewaysClient
	publicIPAddressesClient                *armnetwork.PublicIPAddressesClient
	subnetsClient                          *armnetwork.SubnetsClient
	virtualNetworkGatewayConnectionsClient *armnetwork.VirtualNetworkGatewayConnectionsClient
	localNetworkGatewaysClient             *armnetwork.LocalNetworkGatewaysClient
	privateEndpointClient                  *armnetwork.PrivateEndpointsClient
	privateDNSZoneClient                   *armprivatedns.PrivateZonesClient
	virtualNetworkLinkClient               *armprivatedns.VirtualNetworkLinksClient
	recordSetClient                        *armprivatedns.RecordSetsClient
	subscriptionID                         string
	resourceGroupName                      string
	paragliderNamespace                    string
}

type IAzureCredentialGetter interface {
	GetAzureCredentials() (azcore.TokenCredential, error)
}

const (
	VirtualMachineResourceType = "Microsoft.Compute/virtualMachines"
	nsgNameSuffix              = "-default-nsg"
	azureSecurityRuleAsterisk  = "*"
	permitListPortAny          = -1
	denyAllNsgRulePrefix       = "paraglider-deny-all"
	nsgRuleDescriptionPrefix   = "paraglider rule"
	virtualNetworkResourceID   = "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s"
)

// mapping from IANA protocol numbers (what paraglider uses) to Azure SecurityRuleProtocol except for * which is -1 for all protocols
var paragliderToAzureprotocol = map[int32]armnetwork.SecurityRuleProtocol{
	-1: armnetwork.SecurityRuleProtocolAsterisk,
	1:  armnetwork.SecurityRuleProtocolIcmp,
	6:  armnetwork.SecurityRuleProtocolTCP,
	17: armnetwork.SecurityRuleProtocolUDP,
	50: armnetwork.SecurityRuleProtocolEsp,
	51: armnetwork.SecurityRuleProtocolAh,
}

// mapping from Azure SecurityRuleProtocol to IANA protocol numbers
var azureToParagliderProtocol = map[armnetwork.SecurityRuleProtocol]int32{
	armnetwork.SecurityRuleProtocolAsterisk: -1,
	armnetwork.SecurityRuleProtocolIcmp:     1,
	armnetwork.SecurityRuleProtocolTCP:      6,
	armnetwork.SecurityRuleProtocolUDP:      17,
	armnetwork.SecurityRuleProtocolEsp:      50,
	armnetwork.SecurityRuleProtocolAh:       51,
}

// mapping from paraglider direction to Azure SecurityRuleDirection
var paragliderToAzureDirection = map[paragliderpb.Direction]armnetwork.SecurityRuleDirection{
	paragliderpb.Direction_INBOUND:  armnetwork.SecurityRuleDirectionInbound,
	paragliderpb.Direction_OUTBOUND: armnetwork.SecurityRuleDirectionOutbound,
}

// mapping from Azure SecurityRuleDirection to paraglider direction
var azureToParagliderDirection = map[armnetwork.SecurityRuleDirection]paragliderpb.Direction{
	armnetwork.SecurityRuleDirectionInbound:  paragliderpb.Direction_INBOUND,
	armnetwork.SecurityRuleDirectionOutbound: paragliderpb.Direction_OUTBOUND,
}

// InitializeClients initializes the necessary azure clients for the necessary operations
func (h *AzureSDKHandler) InitializeClients(cred azcore.TokenCredential) error {
	var err error
	h.resourcesClientFactory, err = armresources.NewClientFactory(h.subscriptionID, cred, nil)
	if err != nil {
		return err
	}

	h.networkClientFactory, err = armnetwork.NewClientFactory(h.subscriptionID, cred, nil)
	if err != nil {
		return err
	}

	h.computeClientFactory, err = armcompute.NewClientFactory(h.subscriptionID, cred, nil)
	if err != nil {
		return err
	}

	h.containerServiceClientFactory, err = armcontainerservice.NewClientFactory(h.subscriptionID, cred, nil)
	if err != nil {
		return err
	}

	h.dnsClientFactory, err = armprivatedns.NewClientFactory(h.subscriptionID, cred, nil)
	if err != nil {
		return err
	}

	h.securityGroupsClient = h.networkClientFactory.NewSecurityGroupsClient()
	h.interfacesClient = h.networkClientFactory.NewInterfacesClient()
	h.networkPeeringClient = h.networkClientFactory.NewVirtualNetworkPeeringsClient()
	h.securityRulesClient = h.networkClientFactory.NewSecurityRulesClient()
	h.virtualNetworksClient = h.networkClientFactory.NewVirtualNetworksClient()
	h.virtualNetworkGatewaysClient = h.networkClientFactory.NewVirtualNetworkGatewaysClient()
	h.publicIPAddressesClient = h.networkClientFactory.NewPublicIPAddressesClient()
	h.subnetsClient = h.networkClientFactory.NewSubnetsClient()
	h.virtualNetworkGatewayConnectionsClient = h.networkClientFactory.NewVirtualNetworkGatewayConnectionsClient()
	h.localNetworkGatewaysClient = h.networkClientFactory.NewLocalNetworkGatewaysClient()
	h.deploymentsClient = h.resourcesClientFactory.NewDeploymentsClient()
	h.resourcesClient = h.resourcesClientFactory.NewClient()
	h.virtualMachinesClient = h.computeClientFactory.NewVirtualMachinesClient()
	h.managedClustersClient = h.containerServiceClientFactory.NewManagedClustersClient()
	h.privateEndpointClient = h.networkClientFactory.NewPrivateEndpointsClient()
	h.privateDNSZoneClient = h.dnsClientFactory.NewPrivateZonesClient()
	h.virtualNetworkLinkClient = h.dnsClientFactory.NewVirtualNetworkLinksClient()
	h.recordSetClient = h.dnsClientFactory.NewRecordSetsClient()

	return nil
}

type AzureCredentialGetter struct {
	IAzureCredentialGetter
}

// GetAzureCredentials returns an Azure credential.
// it uses the azidentity.NewDefaultAzureCredential() function to create a new Azure credential.
func (g *AzureCredentialGetter) GetAzureCredentials() (azcore.TokenCredential, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	return cred, nil
}

func (h *AzureSDKHandler) SetSubIdAndResourceGroup(subid string, resourceGroupName string) {
	h.subscriptionID = subid
	h.resourceGroupName = resourceGroupName
}

func (h *AzureSDKHandler) GetResource(ctx context.Context, resourceID string) (*armresources.GenericResource, error) {
	var apiVersion string = "2024-03-01"
	options := armresources.ClientGetByIDOptions{}

	resource, err := h.resourcesClient.GetByID(ctx, resourceID, apiVersion, &options)
	if err != nil {
		utils.Log.Printf("Failed to get resource: %v", err)
		return nil, err
	}

	return &resource.GenericResource, nil
}

func (h *AzureSDKHandler) GetNetworkInterface(ctx context.Context, nicName string) (*armnetwork.Interface, error) {
	nicResponse, err := h.interfacesClient.Get(ctx, h.resourceGroupName, nicName, &armnetwork.InterfacesClientGetOptions{Expand: nil})
	if err != nil {
		utils.Log.Printf("Failed to get NIC: %v", err)
		return nil, err
	}
	resourceNic := &nicResponse.Interface
	return resourceNic, nil
}

// GetPermitListRuleFromNSGRulecurityRule creates a new security rule in a network security group (NSG).
func (h *AzureSDKHandler) CreateSecurityRuleFromPermitList(ctx context.Context, plRule *paragliderpb.PermitListRule, nsgName string, ruleName string, resourceIpAddress string, priority int32, accessType armnetwork.SecurityRuleAccess) (*armnetwork.SecurityRule, error) {
	sourceIP, destIP := getIPs(plRule, resourceIpAddress)
	var srcPort, dstPort string

	if plRule.SrcPort == permitListPortAny {
		srcPort = azureSecurityRuleAsterisk
	} else {
		srcPort = strconv.Itoa(int(plRule.SrcPort))
	}

	if plRule.DstPort == permitListPortAny {
		dstPort = azureSecurityRuleAsterisk
	} else {
		dstPort = strconv.Itoa(int(plRule.DstPort))
	}

	securityRule := &armnetwork.SecurityRule{
		Properties: &armnetwork.SecurityRulePropertiesFormat{
			Access:                     to.Ptr(accessType),
			DestinationAddressPrefixes: destIP,
			DestinationPortRange:       to.Ptr(dstPort),
			Direction:                  to.Ptr(paragliderToAzureDirection[plRule.Direction]),
			Priority:                   to.Ptr(priority),
			Protocol:                   to.Ptr(paragliderToAzureprotocol[plRule.Protocol]),
			SourceAddressPrefixes:      sourceIP,
			SourcePortRange:            to.Ptr(srcPort),
			Description:                to.Ptr(getRuleDescription(plRule.Tags)),
		},
	}

	resp, err := h.CreateSecurityRule(ctx, nsgName, ruleName, securityRule)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (h *AzureSDKHandler) CreateSecurityRule(ctx context.Context, nsgName string, ruleName string, rule *armnetwork.SecurityRule) (*armnetwork.SecurityRule, error) {
	pollerResp, err := h.securityRulesClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, nsgName, ruleName, *rule, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create HTTP security rule: %v", err)
	}

	resp, err := pollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot get security rule create or update future response: %v", err)
	}

	return &resp.SecurityRule, nil
}

func (h *AzureSDKHandler) AssociateNSGWithSubnet(ctx context.Context, subnetID string, nsgID string) error {
	// get the subnet
	subnet, err := h.GetSubnetByID(ctx, subnetID)
	if err != nil {
		return err
	}

	// update the subnet with the nsg
	subnet.Properties.NetworkSecurityGroup = &armnetwork.SecurityGroup{
		ID: to.Ptr(nsgID),
	}

	vnetName := getVnetFromSubnetId(subnetID)

	pollerResp, err := h.subnetsClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, vnetName, *subnet.Name, *subnet, nil)
	if err != nil {
		return err
	}

	_, err = pollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	return nil
}

// DeleteSecurityRule deletes a security rule from a network security group (NSG).
func (h *AzureSDKHandler) DeleteSecurityRule(ctx context.Context, nsgName string, ruleName string) error {
	pollerResp, err := h.securityRulesClient.BeginDelete(ctx, h.resourceGroupName, nsgName, ruleName, nil)
	if err != nil {
		return err
	}

	resp, err := pollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	// resp of type SecurityRulesClientDeleteResponse is currently a placeholder in the sdk
	utils.Log.Printf("Successfully deleted security rule: %v", resp)
	return nil
}

// GetAllVnetsAddressSpaces retrieves the address spaces of all virtual networks
// in the specified namespace that are managed by Paraglider. i.e. Has the namespace tag.
//
// Returns a map where the keys are the names of the virtual networks
// and the values are slices of address prefixes associated with each virtual network.
func (h *AzureSDKHandler) GetAllVnetsAddressSpaces(ctx context.Context, namespace string) (map[string][]string, error) {
	addressSpaces := make(map[string][]string)
	pager := h.virtualNetworksClient.NewListPager(h.resourceGroupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, v := range page.Value {
			if v.Tags != nil && *v.Tags[namespaceTagKey] == namespace {
				addressPrefixes := make([]string, len(v.Properties.AddressSpace.AddressPrefixes))
				for i, addressPrefix := range v.Properties.AddressSpace.AddressPrefixes {
					addressPrefixes[i] = *addressPrefix
				}
				addressSpaces[*v.Name] = addressPrefixes
			}
		}
	}
	return addressSpaces, nil
}

func (h *AzureSDKHandler) GetVnetAddressSpace(ctx context.Context, vnetName string) ([]string, error) {
	vnet, err := h.GetVirtualNetwork(ctx, vnetName)
	if err != nil {
		return nil, err
	}
	addressSpace := make([]string, len(vnet.Properties.AddressSpace.AddressPrefixes))
	for i, prefix := range vnet.Properties.AddressSpace.AddressPrefixes {
		addressSpace[i] = *prefix
	}
	return addressSpace, nil
}

// Temporarily needed method to deal with the mess of AzureSDKHandlers
// TODO @seankimkdy: remove once AzureSDKHandler is no longer a mess
func (h *AzureSDKHandler) CreateVnetPeeringOneWay(ctx context.Context, vnet1Name string, vnet2Name string, vnet2SubscriptionID string, vnet2ResourceGroupName string) error {
	// create first link from vnet1 to vnet2
	vnet1ToVnet2PeeringParameters := armnetwork.VirtualNetworkPeering{
		Properties: &armnetwork.VirtualNetworkPeeringPropertiesFormat{
			AllowForwardedTraffic:     to.Ptr(false),
			AllowGatewayTransit:       to.Ptr(false),
			AllowVirtualNetworkAccess: to.Ptr(true),
			RemoteVirtualNetwork: &armnetwork.SubResource{
				ID: to.Ptr(fmt.Sprintf(virtualNetworkResourceID, vnet2SubscriptionID, vnet2ResourceGroupName, vnet2Name)),
			},
			UseRemoteGateways: to.Ptr(false),
		},
	}

	_, err := h.CreateOrUpdateVirtualNetworkPeering(ctx, vnet1Name, getPeeringName(vnet1Name, vnet2Name), vnet1ToVnet2PeeringParameters)
	if err != nil {
		return err
	}
	return nil
}

// Create Vnet Peering between two VNets, this is important in the case of a multi-region deployment
// For peering to work, two peering links must be created. By selecting remote virtual network, Azure will create both peering links.
func (h *AzureSDKHandler) CreateVnetPeering(ctx context.Context, vnet1Name string, vnet2Name string) error {
	// create first link from vnet1 to vnet2
	err := h.CreateVnetPeeringOneWay(ctx, vnet1Name, vnet2Name, h.subscriptionID, h.resourceGroupName)
	if err != nil {
		return fmt.Errorf("unable to create peering from %s to %s: %w", vnet1Name, vnet2Name, err)
	}
	// create second link from vnet2 to vnet1
	err = h.CreateVnetPeeringOneWay(ctx, vnet2Name, vnet1Name, h.subscriptionID, h.resourceGroupName)
	if err != nil {
		return fmt.Errorf("unable to create peering from %s to %s: %w", vnet2Name, vnet1Name, err)
	}
	return nil
}

// Creates (if not exists) or updates vnet peering to use remote gateway
func (h *AzureSDKHandler) CreateOrUpdateVnetPeeringRemoteGateway(ctx context.Context, vnetName string, gatewayVnetName string, vnetToGatewayVnetPeering *armnetwork.VirtualNetworkPeering, gatewayVnetToVnetPeering *armnetwork.VirtualNetworkPeering) error {
	// Gateway vnet to vnet peering must be created/updated first to allow gateway transit before creating/updating vnet to gateway vnet peering
	if gatewayVnetToVnetPeering == nil {
		gatewayVnetToVnetPeering = &armnetwork.VirtualNetworkPeering{
			Properties: &armnetwork.VirtualNetworkPeeringPropertiesFormat{
				AllowVirtualNetworkAccess: to.Ptr(true),
				RemoteVirtualNetwork: &armnetwork.SubResource{
					ID: to.Ptr(fmt.Sprintf(virtualNetworkResourceID, h.subscriptionID, h.resourceGroupName, vnetName)),
				},
			},
		}
	}
	gatewayVnetToVnetPeering.Properties.AllowForwardedTraffic = to.Ptr(true)
	gatewayVnetToVnetPeering.Properties.AllowGatewayTransit = to.Ptr(true)
	_, err := h.CreateOrUpdateVirtualNetworkPeering(ctx, gatewayVnetName, getPeeringName(gatewayVnetName, vnetName), *gatewayVnetToVnetPeering)
	if err != nil {
		return err
	}
	if vnetToGatewayVnetPeering == nil {
		vnetToGatewayVnetPeering = &armnetwork.VirtualNetworkPeering{
			Properties: &armnetwork.VirtualNetworkPeeringPropertiesFormat{
				AllowVirtualNetworkAccess: to.Ptr(true),
				RemoteVirtualNetwork: &armnetwork.SubResource{
					ID: to.Ptr(fmt.Sprintf(virtualNetworkResourceID, h.subscriptionID, h.resourceGroupName, gatewayVnetName)),
				},
			},
		}
	}
	vnetToGatewayVnetPeering.Properties.AllowForwardedTraffic = to.Ptr(true)
	vnetToGatewayVnetPeering.Properties.UseRemoteGateways = to.Ptr(true)
	_, err = h.CreateOrUpdateVirtualNetworkPeering(ctx, vnetName, getPeeringName(vnetName, gatewayVnetName), *vnetToGatewayVnetPeering)
	if err != nil {
		return err
	}
	return nil
}

func (h *AzureSDKHandler) CreateOrUpdateVirtualNetworkPeering(ctx context.Context, virtualNetworkName string, virtualNetworkPeeringName string, parameters armnetwork.VirtualNetworkPeering) (*armnetwork.VirtualNetworkPeering, error) {
	poller, err := h.networkPeeringClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, virtualNetworkName, virtualNetworkPeeringName, parameters, nil)
	if err != nil {
		return nil, err
	}
	resp, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualNetworkPeering, nil
}

func (h *AzureSDKHandler) GetVirtualNetworkPeering(ctx context.Context, virtualNetworkName string, virtualNetworkPeeringName string) (*armnetwork.VirtualNetworkPeering, error) {
	resp, err := h.networkPeeringClient.Get(ctx, h.resourceGroupName, virtualNetworkName, virtualNetworkPeeringName, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualNetworkPeering, nil
}

func (h *AzureSDKHandler) ListVirtualNetworkPeerings(ctx context.Context, virtualNetworkName string) ([]*armnetwork.VirtualNetworkPeering, error) {
	pager := h.networkPeeringClient.NewListPager(h.resourceGroupName, virtualNetworkName, nil)
	var virtualNetworkPeerings []*armnetwork.VirtualNetworkPeering
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		virtualNetworkPeerings = page.Value
	}
	return virtualNetworkPeerings, nil
}

// GetPermitListRuleFromNSGRule returns a permit list rule from a network security group (NSG) rule.
func (h *AzureSDKHandler) GetPermitListRuleFromNSGRule(rule *armnetwork.SecurityRule) (*paragliderpb.PermitListRule, error) {
	var srcPort, dstPort int
	var err error
	if *rule.Properties.SourcePortRange == azureSecurityRuleAsterisk {
		srcPort = permitListPortAny
	} else {
		srcPort, err = strconv.Atoi(*rule.Properties.SourcePortRange)
		if err != nil {
			return nil, fmt.Errorf("cannot convert source port range to int: %v", err)
		}
	}

	if *rule.Properties.DestinationPortRange == azureSecurityRuleAsterisk {
		dstPort = permitListPortAny
	} else {
		dstPort, err = strconv.Atoi(*rule.Properties.DestinationPortRange)
		if err != nil {
			return nil, fmt.Errorf("cannot convert destination port range to int: %v", err)
		}
	}

	// create permit list rule object
	permitListRule := &paragliderpb.PermitListRule{
		Name:      *rule.Name,
		Targets:   getTargets(rule),
		Direction: azureToParagliderDirection[*rule.Properties.Direction],
		SrcPort:   int32(srcPort),
		DstPort:   int32(dstPort),
		Protocol:  azureToParagliderProtocol[*rule.Properties.Protocol],
		Tags:      parseDescriptionTags(rule.Properties.Description),
	}
	return permitListRule, nil
}

// GetSecurityGroup reutrns the network security group object given the nsg name
func (h *AzureSDKHandler) GetSecurityGroup(ctx context.Context, nsgName string) (*armnetwork.SecurityGroup, error) {
	nsgResp, err := h.securityGroupsClient.Get(ctx, h.resourceGroupName, nsgName, &armnetwork.SecurityGroupsClientGetOptions{Expand: nil})
	if err != nil {
		return nil, err
	}

	return &nsgResp.SecurityGroup, nil
}

// GetParagliderVnet returns a valid paraglider vnet. A paraglider vnet is a vnet created by Paraglider
// with a default subnet with the same address space as the vnet and there is only one vnet per location
func (h *AzureSDKHandler) GetParagliderVnet(ctx context.Context, vnetName string, location string, namespace string, orchestratorAddr string) (*armnetwork.VirtualNetwork, error) {
	// Get the virtual network
	res, err := h.virtualNetworksClient.Get(ctx, h.resourceGroupName, vnetName, &armnetwork.VirtualNetworksClientGetOptions{Expand: nil})
	if err != nil {
		// Check if the error is Resource Not Found
		if isErrorNotFound(err) {
			// Create the virtual network if it doesn't exist
			// Get the address space from the orchestrator service
			conn, err := grpc.NewClient(orchestratorAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				utils.Log.Printf("could not dial the orchestrator")
				return nil, err
			}
			defer conn.Close()
			client := paragliderpb.NewControllerClient(conn)
			response, err := client.FindUnusedAddressSpaces(context.Background(), &paragliderpb.FindUnusedAddressSpacesRequest{})
			if err != nil {
				return nil, err
			}
			vnet, err := h.CreateParagliderVirtualNetwork(ctx, location, vnetName, response.AddressSpaces[0])
			return vnet, err
		} else {
			// Return the error if it's not ResourceNotFound
			return nil, err
		}
	}

	return &res.VirtualNetwork, nil
}

// AddSubnetToParagliderVnet adds a subnet to an paraglider vnet
func (h *AzureSDKHandler) AddSubnetToParagliderVnet(ctx context.Context, namespace string, vnetName string, subnetName string, orchestratorAddr string) (*armnetwork.Subnet, error) {
	// Get a new address space
	conn, err := grpc.NewClient(orchestratorAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		utils.Log.Printf("could not dial the orchestrator")
		return nil, err
	}
	defer conn.Close()

	client := paragliderpb.NewControllerClient(conn)
	response, err := client.FindUnusedAddressSpaces(context.Background(), &paragliderpb.FindUnusedAddressSpacesRequest{})

	if err != nil {
		return nil, err
	}

	// Add address space to the vnet
	vnet, err := h.GetVirtualNetwork(ctx, vnetName)
	if err != nil {
		return nil, err
	}
	vnet.Properties.AddressSpace.AddressPrefixes = append(vnet.Properties.AddressSpace.AddressPrefixes, to.Ptr(response.AddressSpaces[0]))
	_, err = h.virtualNetworksClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, vnetName, *vnet, nil)
	if err != nil {
		return nil, err
	}

	// Create the subnet
	subnet, err := h.CreateSubnet(ctx, vnetName, subnetName, armnetwork.Subnet{
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: to.Ptr(response.AddressSpaces[0]),
		},
	})
	return subnet, err
}

// CreateParagliderVirtualNetwork creates a new paraglider virtual network with a default subnet with the same address
// space as the vnet
func (h *AzureSDKHandler) CreateParagliderVirtualNetwork(ctx context.Context, location string, vnetName string, addressSpace string) (*armnetwork.VirtualNetwork, error) {
	// TODO @seankimkdy: delete and consolidate calls to this method with CreateParagliderVirtualNetwork
	parameters := armnetwork.VirtualNetwork{
		Location: to.Ptr(location),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{
					to.Ptr(addressSpace),
				},
			},
			Subnets: []*armnetwork.Subnet{
				{
					Name: to.Ptr("default"),
					Properties: &armnetwork.SubnetPropertiesFormat{
						AddressPrefix: to.Ptr(addressSpace),
					},
				},
			},
		},
		Tags: map[string]*string{
			namespaceTagKey: to.Ptr(h.paragliderNamespace),
		},
	}
	vnet, err := h.CreateOrUpdateVirtualNetwork(ctx, vnetName, parameters)
	if err != nil {
		return nil, err
	}

	return vnet, nil
}

// Updates properties of the virtual network (vnet) if it exists. Creates a new vnet if it doesn't exist.
func (h *AzureSDKHandler) CreateOrUpdateVirtualNetwork(ctx context.Context, name string, parameters armnetwork.VirtualNetwork) (*armnetwork.VirtualNetwork, error) {
	pollerResponse, err := h.virtualNetworksClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, name, parameters, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualNetwork, nil
}

func (h *AzureSDKHandler) GetVirtualNetwork(ctx context.Context, name string) (*armnetwork.VirtualNetwork, error) {
	resp, err := h.virtualNetworksClient.Get(ctx, h.resourceGroupName, name, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualNetwork, nil
}

func (h *AzureSDKHandler) CreatePrivateEndpoint(ctx context.Context, privateEndpointName string, parameters armnetwork.PrivateEndpoint) (*armnetwork.PrivateEndpoint, error) {
	pollerResponse, err := h.privateEndpointClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, privateEndpointName, parameters, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.PrivateEndpoint, nil
}

func (h *AzureSDKHandler) GetAllPrivateEndpoints(ctx context.Context) map[string]*armnetwork.PrivateEndpoint {
	endpoints := make(map[string]*armnetwork.PrivateEndpoint)
	pager := h.privateEndpointClient.NewListPager(h.resourceGroupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			utils.Log.Printf("Failed to get private endpoints: %v", err)
			return nil
		}
		for _, v := range page.Value {
			endpoints[*v.Name] = v
		}
	}

	return endpoints
}

func (h *AzureSDKHandler) GetPrivateEndpoint(ctx context.Context, privateEndpointName string) (*armnetwork.PrivateEndpoint, error) {
	resp, err := h.privateEndpointClient.Get(ctx, h.resourceGroupName, privateEndpointName, nil)
	if err != nil {
		return nil, err
	}
	return &resp.PrivateEndpoint, nil
}

func (h *AzureSDKHandler) CreatePrivateDNSZone(ctx context.Context, privateDNSZoneName string, parameters armprivatedns.PrivateZone) (*armprivatedns.PrivateZone, error) {
	pollerResponse, err := h.privateDNSZoneClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, privateDNSZoneName, parameters, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.PrivateZone, nil
}

func (h AzureSDKHandler) GetPrivateDNSZone(ctx context.Context, privateDNSZoneName string) (*armprivatedns.PrivateZone, error) {
	resp, err := h.privateDNSZoneClient.Get(ctx, h.resourceGroupName, privateDNSZoneName, nil)
	if err != nil {
		return nil, err
	}
	return &resp.PrivateZone, nil
}

func (h *AzureSDKHandler) CreateVirtualNetworkLink(ctx context.Context, privateZoneName, virtualNetworkLinkName string, parameters armprivatedns.VirtualNetworkLink) (*armprivatedns.VirtualNetworkLink, error) {
	pollerResponse, err := h.virtualNetworkLinkClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, privateZoneName, virtualNetworkLinkName, parameters, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualNetworkLink, nil
}

func (h *AzureSDKHandler) GetVirtualNetworkLink(ctx context.Context, privateZoneName, virtualNetworkLinkName string) (*armprivatedns.VirtualNetworkLink, error) {
	resp, err := h.virtualNetworkLinkClient.Get(ctx, h.resourceGroupName, privateZoneName, virtualNetworkLinkName, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualNetworkLink, nil
}

func (h *AzureSDKHandler) CreateDnsRecordSet(ctx context.Context, privateZoneName string, recordSetName string, parameters armprivatedns.RecordSet) (*armprivatedns.RecordSet, error) {
	// Record type "A" maps a name to an IPv4 address
	resp, err := h.recordSetClient.CreateOrUpdate(ctx, h.resourceGroupName, privateZoneName, armprivatedns.RecordTypeA, recordSetName, parameters, nil)
	if err != nil {
		return nil, err
	}
	return &resp.RecordSet, nil
}

func (h *AzureSDKHandler) GetDnsRecordSet(ctx context.Context, privateZoneName string, recordType armprivatedns.RecordType, recordSetName string) (*armprivatedns.RecordSet, error) {
	resp, err := h.recordSetClient.Get(ctx, h.resourceGroupName, privateZoneName, recordType, recordSetName, nil)
	if err != nil {
		return nil, err
	}
	return &resp.RecordSet, nil
}

func (h *AzureSDKHandler) CreateSecurityGroup(ctx context.Context, resourceName string, location string, allowedCIDRs map[string]string) (*armnetwork.SecurityGroup, error) {
	nsgParameters := armnetwork.SecurityGroup{
		Location: to.Ptr(location),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{
				setupDenyAllRuleWithPriority(int32(maxPriority), inboundDirectionRule),
				setupDenyAllRuleWithPriority(int32(maxPriority), outboundDirectionRule),
			},
		},
	}
	h.createParagliderNamespaceTag(&nsgParameters.Tags)
	i := 1
	for name, cidr := range allowedCIDRs {
		nsgParameters.Properties.SecurityRules = append(nsgParameters.Properties.SecurityRules, &armnetwork.SecurityRule{
			Name: to.Ptr("paraglider-allow-inbound-" + name),
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),
				SourceAddressPrefix:      to.Ptr(cidr),
				DestinationAddressPrefix: to.Ptr(azureSecurityRuleAsterisk),
				DestinationPortRange:     to.Ptr(azureSecurityRuleAsterisk),
				Direction:                to.Ptr(armnetwork.SecurityRuleDirectionInbound),
				Priority:                 to.Ptr(int32(maxPriority - i)),
				Protocol:                 to.Ptr(armnetwork.SecurityRuleProtocolAsterisk),
				SourcePortRange:          to.Ptr(azureSecurityRuleAsterisk),
			},
		})
		nsgParameters.Properties.SecurityRules = append(nsgParameters.Properties.SecurityRules, &armnetwork.SecurityRule{
			Name: to.Ptr("paraglider-allow-outbound-" + name),
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),
				SourceAddressPrefix:      to.Ptr(azureSecurityRuleAsterisk),
				DestinationAddressPrefix: to.Ptr(cidr),
				DestinationPortRange:     to.Ptr(azureSecurityRuleAsterisk),
				Direction:                to.Ptr(armnetwork.SecurityRuleDirectionOutbound),
				Priority:                 to.Ptr(int32(maxPriority - i)),
				Protocol:                 to.Ptr(armnetwork.SecurityRuleProtocolAsterisk),
				SourcePortRange:          to.Ptr(azureSecurityRuleAsterisk),
			},
		})
		i++
	}
	pollerResponse, err := h.securityGroupsClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, resourceName+nsgNameSuffix, nsgParameters, nil)
	if err != nil {
		return nil, err
	}

	nsgResp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &nsgResp.SecurityGroup, nil
}

// CreateNetworkInterface creates a new network interface with a dynamic private IP address
func (h *AzureSDKHandler) CreateNetworkInterface(ctx context.Context, subnetID string, location string, nicName string) (*armnetwork.Interface, error) {
	nsg, err := h.CreateSecurityGroup(ctx, nicName, location, map[string]string{})
	if err != nil {
		return nil, err
	}
	parameters := armnetwork.Interface{
		Location: to.Ptr(location),
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Name: to.Ptr("ipConfig"),
					Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
						PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodDynamic),
						Subnet: &armnetwork.Subnet{
							ID: to.Ptr(subnetID),
						},
					},
				},
			},
			NetworkSecurityGroup: &armnetwork.SecurityGroup{
				ID: nsg.ID,
			},
		},
	}
	h.createParagliderNamespaceTag(&parameters.Tags)

	nicPollerResponse, err := h.interfacesClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, nicName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := nicPollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.Interface, err
}

// CreateVirtualMachine creates a new virtual machine with the given parameters and name
func (h *AzureSDKHandler) CreateVirtualMachine(ctx context.Context, parameters armcompute.VirtualMachine, vmName string) (*armcompute.VirtualMachine, error) {
	h.createParagliderNamespaceTag(&parameters.Tags)
	pollerResponse, err := h.virtualMachinesClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, vmName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualMachine, nil
}

// CreateAKSCluster creates a new AKS cluster with the given parameters and name
func (h *AzureSDKHandler) CreateAKSCluster(ctx context.Context, parameters armcontainerservice.ManagedCluster, clusterName string) (*armcontainerservice.ManagedCluster, error) {
	h.createParagliderNamespaceTag(&parameters.Tags)
	pollerResponse, err := h.managedClustersClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, clusterName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.ManagedCluster, nil
}

// GetVnet returns the virtual network with the given name
func (h *AzureSDKHandler) GetVnet(ctx context.Context, vnetName string) (*armnetwork.VirtualNetwork, error) {
	vnet, err := h.virtualNetworksClient.Get(ctx, h.resourceGroupName, vnetName, nil)
	if err != nil {
		return nil, err
	}
	return &vnet.VirtualNetwork, nil
}

func (h *AzureSDKHandler) CreateOrUpdateVirtualNetworkGateway(ctx context.Context, name string, parameters armnetwork.VirtualNetworkGateway) (*armnetwork.VirtualNetworkGateway, error) {
	h.createParagliderNamespaceTag(&parameters.Tags)
	pollerResponse, err := h.virtualNetworkGatewaysClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, name, parameters, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualNetworkGateway, nil
}

func (h *AzureSDKHandler) GetVirtualNetworkGateway(ctx context.Context, name string) (*armnetwork.VirtualNetworkGateway, error) {
	resp, err := h.virtualNetworkGatewaysClient.Get(ctx, h.resourceGroupName, name, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualNetworkGateway, nil
}

func (h *AzureSDKHandler) CreatePublicIPAddress(ctx context.Context, name string, parameters armnetwork.PublicIPAddress) (*armnetwork.PublicIPAddress, error) {
	h.createParagliderNamespaceTag(&parameters.Tags)
	pollerResponse, err := h.publicIPAddressesClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, name, parameters, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.PublicIPAddress, nil
}

func (h *AzureSDKHandler) GetPublicIPAddress(ctx context.Context, name string) (*armnetwork.PublicIPAddress, error) {
	resp, err := h.publicIPAddressesClient.Get(ctx, h.resourceGroupName, name, nil)
	if err != nil {
		return nil, err
	}
	return &resp.PublicIPAddress, nil
}

func (h *AzureSDKHandler) CreateSubnet(ctx context.Context, virtualNetworkName string, subnetName string, parameters armnetwork.Subnet) (*armnetwork.Subnet, error) {
	pollerResponse, err := h.subnetsClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, virtualNetworkName, subnetName, parameters, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.Subnet, nil
}

func (h *AzureSDKHandler) GetSubnet(ctx context.Context, virtualNetworkName string, subnetName string) (*armnetwork.Subnet, error) {
	resp, err := h.subnetsClient.Get(ctx, h.resourceGroupName, virtualNetworkName, subnetName, nil)
	if err != nil {
		return nil, err
	}
	return &resp.Subnet, nil
}

func (h *AzureSDKHandler) GetSubnetByID(ctx context.Context, subnetID string) (*armnetwork.Subnet, error) {
	vnetName, subnetName, err := parseSubnetURI(subnetID)
	if err != nil {
		return nil, err
	}
	resp, err := h.subnetsClient.Get(ctx, h.resourceGroupName, vnetName, subnetName, nil)
	if err != nil {
		return nil, err
	}
	return &resp.Subnet, nil
}

func (h *AzureSDKHandler) CreateLocalNetworkGateway(ctx context.Context, name string, parameters armnetwork.LocalNetworkGateway) (*armnetwork.LocalNetworkGateway, error) {
	h.createParagliderNamespaceTag(&parameters.Tags)
	pollerResponse, err := h.localNetworkGatewaysClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, name, parameters, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.LocalNetworkGateway, nil
}

func (h *AzureSDKHandler) GetLocalNetworkGateway(ctx context.Context, name string) (*armnetwork.LocalNetworkGateway, error) {
	resp, err := h.localNetworkGatewaysClient.Get(ctx, h.resourceGroupName, name, nil)
	if err != nil {
		return nil, err
	}
	return &resp.LocalNetworkGateway, nil
}

func (h *AzureSDKHandler) CreateVirtualNetworkGatewayConnection(ctx context.Context, name string, parameters armnetwork.VirtualNetworkGatewayConnection) (*armnetwork.VirtualNetworkGatewayConnection, error) {
	h.createParagliderNamespaceTag(&parameters.Tags)
	pollerResponse, err := h.virtualNetworkGatewayConnectionsClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, name, parameters, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualNetworkGatewayConnection, nil
}

func (h *AzureSDKHandler) GetVirtualNetworkGatewayConnection(ctx context.Context, name string) (*armnetwork.VirtualNetworkGatewayConnection, error) {
	resp, err := h.virtualNetworkGatewayConnectionsClient.Get(ctx, h.resourceGroupName, name, nil)
	if err != nil {
		return nil, err
	}
	return &resp.VirtualNetworkGatewayConnection, nil
}

// Creates a tag for the Paraglider namespace in the "Tag" field of various resource parameters
func (h *AzureSDKHandler) createParagliderNamespaceTag(tags *map[string]*string) {
	if *tags == nil {
		*tags = make(map[string]*string)
	}
	(*tags)[namespaceTagKey] = &h.paragliderNamespace
}

func parseSubnetURI(subnetURI string) (string, string, error) {
	segments := strings.Split(subnetURI, "/")
	if len(segments) < 11 {
		return "", "", fmt.Errorf("invalid subnet URI")
	}
	return segments[8], segments[10], nil
}

// getIPs returns the source and destination IP addresses for a given permit list rule and resource IP address.
// it checks the direction of the permit list rule and sets the source IP address to the rule targets
// and the destination IP address to the resource IP address if the direction is inbound.
// If the direction is outbound, it sets the source IP address to the resource IP address and
// the destination IP address to the rule targets.
func getIPs(rule *paragliderpb.PermitListRule, resourceIP string) ([]*string, []*string) {
	var sourceIP []*string
	var destIP []*string

	if rule.Direction == paragliderpb.Direction_INBOUND {
		sourceIP = make([]*string, len(rule.Targets))
		for i, ip := range rule.Targets {
			sourceIP[i] = to.Ptr(ip)
		}
		destIP = []*string{to.Ptr(resourceIP)}
	} else {
		sourceIP = []*string{to.Ptr(resourceIP)}
		destIP = make([]*string, len(rule.Targets))
		for i, ip := range rule.Targets {
			destIP[i] = to.Ptr(ip)
		}
	}

	return sourceIP, destIP
}

// getTarget returns the paraglider targets for a given nsg rule
func getTargets(rule *armnetwork.SecurityRule) []string {
	var targets []string
	if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound {
		for _, ptr := range rule.Properties.SourceAddressPrefixes {
			targets = append(targets, *ptr)
		}
	} else if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionOutbound {
		for _, ptr := range rule.Properties.DestinationAddressPrefixes {
			targets = append(targets, *ptr)
		}
	}
	return targets
}

// Format the description to keep metadata about tags
func getRuleDescription(tags []string) string {
	if len(tags) == 0 {
		return nsgRuleDescriptionPrefix
	}
	return fmt.Sprintf("%s:%v", nsgRuleDescriptionPrefix, tags)
}

// Parses description string to get tags
func parseDescriptionTags(description *string) []string {
	var tags []string
	if description != nil && strings.HasPrefix(*description, nsgRuleDescriptionPrefix+":[") {
		trimmedDescription := strings.TrimPrefix(*description, nsgRuleDescriptionPrefix+":")
		trimmedDescription = strings.Trim(trimmedDescription, "[")
		trimmedDescription = strings.Trim(trimmedDescription, "]")
		tags = strings.Split(trimmedDescription, " ")
	}
	return tags
}

// Checks if Azure error response is a not found error
func isErrorNotFound(err error) bool {
	var azError *azcore.ResponseError
	ok := errors.As(err, &azError)
	return ok && azError.StatusCode == http.StatusNotFound
}

// Returns peering name from local vnet to remote vnet
func getPeeringName(localVnetName string, remoteVnetName string) string {
	return localVnetName + "-to-" + remoteVnetName
}

// getLastSegment returns the last segment of a resource ID.
func GetLastSegment(ID string) (string, error) {
	// TODO @nnomier: might need to use stricter validations to check if the ID is valid like a regex
	segments := strings.Split(ID, "/")
	// The smallest possible len would be 1 because in go if a string s does not contain sep and sep is not empty,
	// Split returns a slice of length 1 whose only element is s.
	if len(segments) <= 1 {
		return "", fmt.Errorf("invalid resource ID format")
	}
	return segments[len(segments)-1], nil
}
