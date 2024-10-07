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
	"net"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

const minPriority = 100
const maxPriority = 4096

type azurePluginServer struct {
	paragliderpb.UnimplementedCloudPluginServer
	orchestratorServerAddr string
	azureCredentialGetter  IAzureCredentialGetter
}

const (
	vpnLocation                = "westus" // TODO @seankimkdy: should this be configurable/dynamic?
	gatewaySubnetName          = "GatewaySubnet"
	gatewaySubnetAddressPrefix = "192.168.255.0/27"
)

func (s *azurePluginServer) setupAzureHandler(resourceIdInfo ResourceIDInfo, namespace string) (*AzureSDKHandler, error) {
	var azureHandler AzureSDKHandler
	cred, err := s.azureCredentialGetter.GetAzureCredentials()
	if err != nil {
		utils.Log.Printf("An error occured while getting azure credentials:%+v", err)
		return nil, err
	}
	azureHandler.SetSubIdAndResourceGroup(resourceIdInfo.SubscriptionID, resourceIdInfo.ResourceGroupName)
	azureHandler.paragliderNamespace = namespace
	err = azureHandler.InitializeClients(cred)
	if err != nil {
		utils.Log.Printf("An error occured while initializing azure clients: %+v", err)
		return nil, err
	}

	return &azureHandler, nil
}

// GetPermitList returns the permit list for the given resource by getting the NSG rules
// associated with the resource and filtering out the Paraglider rules
func (s *azurePluginServer) GetPermitList(ctx context.Context, req *paragliderpb.GetPermitListRequest) (*paragliderpb.GetPermitListResponse, error) {
	resourceId := req.Resource
	resourceIdInfo, err := getResourceIDInfo(resourceId)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource ID info: %+v", err)
		return nil, err
	}
	azureHandler, err := s.setupAzureHandler(resourceIdInfo, req.Namespace)
	if err != nil {
		return nil, err
	}

	netInfo, err := GetAndCheckResourceState(ctx, azureHandler, resourceId, req.Namespace)
	if err != nil {
		return nil, err
	}
	nsg := netInfo.NSG

	// initialize a list of permit list rules
	rules := []*paragliderpb.PermitListRule{}

	// get the NSG rules
	for _, rule := range nsg.Properties.SecurityRules {
		if !strings.HasPrefix(*rule.Name, denyAllNsgRulePrefix) && strings.HasPrefix(*rule.Name, paragliderPrefix) {
			plRule, err := azureHandler.GetPermitListRuleFromNSGRule(rule)
			if err != nil {
				utils.Log.Printf("An error occured while getting Paraglider rule from NSG rule: %+v", err)
				return nil, err
			}
			plRule.Name = getRuleNameFromNSGRuleName(plRule.Name)
			rules = append(rules, plRule)
		}
	}
	return &paragliderpb.GetPermitListResponse{Rules: rules}, nil
}

// AddPermitListRules does the mapping from Paraglider to Azure by creating/updating NSG for the given resource.
// It creates an NSG rule for each permit list rule and applies this NSG to the associated resource (VM)'s NIC (if it doesn't exist).
// It returns a BasicResponse that includes the nsg ID if successful and an error if it fails.
func (s *azurePluginServer) AddPermitListRules(ctx context.Context, req *paragliderpb.AddPermitListRulesRequest) (*paragliderpb.AddPermitListRulesResponse, error) {
	resourceID := req.GetResource()
	resourceIdInfo, err := getResourceIDInfo(resourceID)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource ID info: %+v", err)
		return nil, err
	}
	azureHandler, err := s.setupAzureHandler(resourceIdInfo, req.Namespace)
	if err != nil {
		return nil, err
	}

	netInfo, err := GetAndCheckResourceState(ctx, azureHandler, resourceID, req.Namespace)
	if err != nil {
		return nil, err
	}

	var existingRulePriorities map[string]int32 = make(map[string]int32)
	var reservedPrioritiesInbound map[int32]*armnetwork.SecurityRule = make(map[int32]*armnetwork.SecurityRule)
	var reservedPrioritiesOutbound map[int32]*armnetwork.SecurityRule = make(map[int32]*armnetwork.SecurityRule)
	err = setupMaps(reservedPrioritiesInbound, reservedPrioritiesOutbound, existingRulePriorities, netInfo.NSG)
	if err != nil {
		utils.Log.Printf("An error occured during setup: %+v", err)
		return nil, err
	}
	var outboundPriority int32 = 100
	var inboundPriority int32 = 100

	// Get used address spaces of all clouds
	orchestratorConn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("unable to establish connection with orchestrator: %w", err)
	}
	defer orchestratorConn.Close()
	orchestratorClient := paragliderpb.NewControllerClient(orchestratorConn)
	getUsedAddressSpacesResp, err := orchestratorClient.GetUsedAddressSpaces(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("unable to get used address spaces: %w", err)
	}

	vnetName := getVnetFromSubnetId(netInfo.SubnetID)
	// get the vnet to be able to get both the address space as well as the peering when needed
	resourceVnet, err := azureHandler.GetVnet(ctx, vnetName)
	if err != nil {
		utils.Log.Printf("An error occured while getting paraglider vnets address spaces:%+v", err)
		return nil, err
	}

	// Get subnets address spaces
	localVnetAddressSpaces := []string{}
	for _, addressSpace := range resourceVnet.Properties.AddressSpace.AddressPrefixes {
		localVnetAddressSpaces = append(localVnetAddressSpaces, *addressSpace)
	}
	if len(localVnetAddressSpaces) == 0 {
		return nil, fmt.Errorf("unable to get subnet address prefix")
	}

	// Add the rules to the NSG
	for _, rule := range req.GetRules() {
		// Get all peering cloud infos
		peeringCloudInfos, err := utils.GetPermitListRulePeeringCloudInfo(rule, getUsedAddressSpacesResp.AddressSpaceMappings)
		if err != nil {
			return nil, fmt.Errorf("unable to get peering cloud infos: %w", err)
		}

		for i, peeringCloudInfo := range peeringCloudInfos {
			if peeringCloudInfo == nil {
				// Setup NAT gateway for public IP addresses
				_, err = getOrCreateNatGateway(ctx, azureHandler, req.Namespace, *resourceVnet.Location)
				if err != nil {
					return nil, fmt.Errorf("unable to setup NAT gateway: %w", err)
				}
			} else if peeringCloudInfo.Cloud != utils.AZURE {
				address := rule.Targets[i]
				// Create VPN connections
				connectCloudsReq := &paragliderpb.ConnectCloudsRequest{
					CloudA:              utils.AZURE,
					CloudANamespace:     req.Namespace,
					CloudB:              peeringCloudInfo.Cloud,
					CloudBNamespace:     peeringCloudInfo.Namespace,
					AddressSpacesCloudA: localVnetAddressSpaces,
					AddressSpacesCloudB: []string{address},
				}
				_, err := orchestratorClient.ConnectClouds(ctx, connectCloudsReq)
				if err != nil {
					return nil, fmt.Errorf("unable to connect clouds : %w", err)
				}
			} else {
				isLocal, err := utils.IsPermitListRuleTagInAddressSpace(rule.Targets[i], localVnetAddressSpaces)
				if err != nil {
					return nil, fmt.Errorf("unable to determine if tag is in local vnet address space: %w", err)
				}
				if !isLocal {
					// Create VPC network peering (remote is in a different region or namespace)
					err = s.createPeering(ctx, *azureHandler, resourceIdInfo, vnetName, peeringCloudInfo, rule.Targets[i])
					if err != nil {
						return nil, fmt.Errorf("unable to create vnet peering: %w", err)
					}
				}
			}
		}

		// To avoid conflicted priorities, we need to check whether the priority is already used by other rules
		// if the priority is already used, we need to find the next available priority
		priority, ok := existingRulePriorities[getNSGRuleName(rule.Name)]
		if !ok {
			if rule.Direction == paragliderpb.Direction_INBOUND {
				priority = getNextAvailablePriority(reservedPrioritiesInbound, inboundPriority, maxPriority, true)
				inboundPriority = priority + 1
			} else if rule.Direction == paragliderpb.Direction_OUTBOUND {
				priority = getNextAvailablePriority(reservedPrioritiesOutbound, outboundPriority, maxPriority, true)
				outboundPriority = priority + 1
			}
		}

		// Create the NSG rule
		securityRule, err := azureHandler.CreateSecurityRuleFromPermitList(ctx, rule, *netInfo.NSG.Name, getNSGRuleName(rule.Name), netInfo.Address, priority, allowRule)
		if err != nil {
			utils.Log.Printf("An error occured while creating security rule:%+v", err)
			return nil, err
		}
		utils.Log.Printf("Successfully created network security rule: %s", *securityRule.ID)
	}

	return &paragliderpb.AddPermitListRulesResponse{}, nil
}

// DeletePermitListRules does the mapping from Paraglider to Azure by deleting NSG rules for the given resource.
func (s *azurePluginServer) DeletePermitListRules(c context.Context, req *paragliderpb.DeletePermitListRulesRequest) (*paragliderpb.DeletePermitListRulesResponse, error) {
	resourceID := req.GetResource()
	resourceIdInfo, err := getResourceIDInfo(resourceID)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource ID info: %+v", err)
		return nil, err
	}
	azureHandler, err := s.setupAzureHandler(resourceIdInfo, req.Namespace)
	if err != nil {
		return nil, err
	}

	netInfo, err := GetAndCheckResourceState(c, azureHandler, resourceID, req.Namespace)
	if err != nil {
		return nil, err
	}

	for _, rule := range req.GetRuleNames() {
		err := azureHandler.DeleteSecurityRule(c, *netInfo.NSG.Name, getNSGRuleName(rule))
		if err != nil {
			utils.Log.Printf("An error occured while deleting security rule:%+v", err)
			return nil, err
		}
		utils.Log.Printf("Successfully deleted network security rule: %s", rule)
	}

	return &paragliderpb.DeletePermitListRulesResponse{}, nil
}

// CreateResource does the mapping from Paraglider to Azure to create a paraglider enabled resource
// which means the resource should be added to a valid paraglider network, the attachement to a paraglider network
// is determined by the resource's location.
func (s *azurePluginServer) CreateResource(ctx context.Context, resourceDesc *paragliderpb.CreateResourceRequest) (*paragliderpb.CreateResourceResponse, error) {
	resourceDescInfo, err := GetResourceInfoFromResourceDesc(ctx, resourceDesc)
	if err != nil {
		utils.Log.Printf("Resource description is invalid:%+v", err)
		return nil, err
	}

	resourceIdInfo, err := getResourceIDInfo(resourceDesc.Deployment.Id)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource id info:%+v", err)
		return nil, err
	}

	azureHandler, err := s.setupAzureHandler(resourceIdInfo, resourceDesc.Deployment.Namespace)
	if err != nil {
		return nil, err
	}

	vnetName := getVnetName(resourceDescInfo.Location, resourceDesc.Deployment.Namespace)
	paragliderVnet, err := azureHandler.GetParagliderVnet(ctx, vnetName, resourceDescInfo.Location, resourceDesc.Deployment.Namespace, s.orchestratorServerAddr)
	if err != nil {
		utils.Log.Printf("An error occured while getting paraglider vnet:%+v", err)
		return nil, err
	}

	resourceSubnet := paragliderVnet.Properties.Subnets[0]
	if resourceDescInfo.RequiresSubnet {
		// Check if subnet already exists (could happen if resource provisioning failed after this step)
		subnetExists := false
		for _, subnet := range paragliderVnet.Properties.Subnets {
			if *subnet.Name == getSubnetName(resourceDescInfo.ResourceName) {
				resourceSubnet = subnet
				subnetExists = true
				break
			}
		}
		// Create subnet
		if !subnetExists {
			resourceSubnet, err = azureHandler.AddSubnetToParagliderVnet(ctx, resourceDesc.Deployment.Namespace, vnetName, getSubnetName(resourceDescInfo.ResourceName), s.orchestratorServerAddr)
			if err != nil {
				utils.Log.Printf("An error occured while creating subnet:%+v", err)
				return nil, err
			}
		}
	}

	additionalAddrs := []string{}
	if resourceDescInfo.NumAdditionalAddressSpaces > 0 {
		// Create additional address spaces
		conn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			utils.Log.Printf("Could not dial the orchestrator")
			return nil, err
		}
		defer conn.Close()
		client := paragliderpb.NewControllerClient(conn)
		reqAddressSpaces := make([]int32, resourceDescInfo.NumAdditionalAddressSpaces)
		response, err := client.FindUnusedAddressSpaces(context.Background(), &paragliderpb.FindUnusedAddressSpacesRequest{Sizes: reqAddressSpaces})
		if err != nil {
			utils.Log.Printf("Failed to find unused address spaces: %v", err)
			return nil, err
		}
		additionalAddrs = response.AddressSpaces
	}

	// Create the resource
	ip, err := ReadAndProvisionResource(ctx, resourceDesc, resourceSubnet, &resourceIdInfo, azureHandler, additionalAddrs)
	if err != nil {
		utils.Log.Printf("An error occured while creating resource:%+v", err)
		return nil, err
	}

	// Create VPN gateway vnet if not already created
	// The vnet is created even if there's no multicloud connections at the moment for ease of connection in the future.
	// Note that vnets are free, so this is not a problem.
	vpnGwVnet, err := GetOrCreateVpnGatewayVNet(ctx, azureHandler, resourceDesc.Deployment.Namespace)
	if err != nil {
		utils.Log.Printf("An error occured while getting or creating VPN gateway vnet:%+v", err)
		return nil, err
	}

	// Create peering VPN gateway vnet and VM vnet. If the VPN gateway already exists, then establish a VPN gateway transit relationship where the vnet can use the gatewayVnet's VPN gateway.
	// - This peering is created even if there's no multicloud connections at the moment for ease of connection in the future.
	// - Peerings are only charged based on amount of data transferred, so this will not incur extra charge until the VPN gateway is created.
	// - VPN gateway transit relationship cannot be established before the VPN gateway creation.
	// - If the VPN gateway hasn't been created, then the gateway transit relationship will be established on VPN gateway creation.
	err = CreateGatewayVnetPeering(ctx, azureHandler, vnetName, *vpnGwVnet.Name, resourceDesc.Deployment.Namespace)
	if err != nil {
		utils.Log.Printf("An error occured while creating VPN gateway vnet peering:%+v", err)
		return nil, err
	}

	return &paragliderpb.CreateResourceResponse{Name: resourceDescInfo.ResourceName, Uri: resourceDescInfo.ResourceID, Ip: ip}, nil
}

// GetUsedAddressSpaces returns the address spaces used by paraglider which are the address spaces of the paraglider vnets
func (s *azurePluginServer) GetUsedAddressSpaces(ctx context.Context, req *paragliderpb.GetUsedAddressSpacesRequest) (*paragliderpb.GetUsedAddressSpacesResponse, error) {
	resp := &paragliderpb.GetUsedAddressSpacesResponse{}
	resp.AddressSpaceMappings = make([]*paragliderpb.AddressSpaceMapping, len(req.Deployments))
	for i, deployment := range req.Deployments {
		resp.AddressSpaceMappings[i] = &paragliderpb.AddressSpaceMapping{
			Cloud:     utils.AZURE,
			Namespace: deployment.Namespace,
		}
		resourceIdInfo, err := getResourceIDInfo(deployment.Id)
		if err != nil {
			utils.Log.Printf("An error occured while getting resource ID info: %+v", err)
			return nil, err
		}
		azureHandler, err := s.setupAzureHandler(resourceIdInfo, deployment.Namespace)
		if err != nil {
			return nil, err
		}

		addressSpaces, err := azureHandler.GetAllVnetsAddressSpaces(ctx, deployment.Namespace)
		if err != nil {
			utils.Log.Printf("An error occured while getting address spaces:%+v", err)
			return nil, err
		}
		paragliderAddressList := []string{}
		for _, addresses := range addressSpaces {
			if addresses != nil {
				paragliderAddressList = append(paragliderAddressList, addresses...)
			}
		}
		resp.AddressSpaceMappings[i].AddressSpaces = paragliderAddressList
	}
	return resp, nil

}

func (s *azurePluginServer) GetUsedAsns(ctx context.Context, req *paragliderpb.GetUsedAsnsRequest) (*paragliderpb.GetUsedAsnsResponse, error) {
	resp := &paragliderpb.GetUsedAsnsResponse{}
	for _, deployment := range req.Deployments {
		resourceIdInfo, err := getResourceIDInfo(deployment.Id)
		if err != nil {
			utils.Log.Printf("An error occured while getting resource ID info: %+v", err)
			return nil, err
		}
		azureHandler, err := s.setupAzureHandler(resourceIdInfo, deployment.Namespace)
		if err != nil {
			return nil, err
		}

		virtualNetworkGatewayName := getVpnGatewayName(deployment.Namespace)
		virtualNetworkGateway, err := azureHandler.GetVirtualNetworkGateway(ctx, virtualNetworkGatewayName)
		if err != nil {
			if isErrorNotFound(err) {
				continue
			} else {
				return nil, fmt.Errorf("unable to get virtual network gateway: %w", err)
			}
		}
		resp.Asns = append(resp.Asns, uint32(*virtualNetworkGateway.Properties.BgpSettings.Asn))
	}
	return resp, nil
}

func (s *azurePluginServer) GetUsedBgpPeeringIpAddresses(ctx context.Context, req *paragliderpb.GetUsedBgpPeeringIpAddressesRequest) (*paragliderpb.GetUsedBgpPeeringIpAddressesResponse, error) {
	resp := &paragliderpb.GetUsedBgpPeeringIpAddressesResponse{}
	for _, deployment := range req.Deployments {
		resourceIdInfo, err := getResourceIDInfo(deployment.Id)
		if err != nil {
			utils.Log.Printf("An error occured while getting resource ID info: %+v", err)
			return nil, err
		}
		azureHandler, err := s.setupAzureHandler(resourceIdInfo, deployment.Namespace)
		if err != nil {
			return nil, err
		}

		virtualNetworkGatewayName := getVpnGatewayName(deployment.Namespace)
		virtualNetworkGateway, err := azureHandler.GetVirtualNetworkGateway(ctx, virtualNetworkGatewayName)
		if err != nil {
			if isErrorNotFound(err) {
				continue
			} else {
				return nil, fmt.Errorf("unable to get virtual network gateway: %w", err)
			}
		}
		for _, bgpPeeringAddress := range virtualNetworkGateway.Properties.BgpSettings.BgpPeeringAddresses {
			resp.IpAddresses = append(resp.IpAddresses, *bgpPeeringAddress.CustomBgpIPAddresses[0])
		}
	}
	return resp, nil
}

func (s *azurePluginServer) CreateVpnGateway(ctx context.Context, req *paragliderpb.CreateVpnGatewayRequest) (*paragliderpb.CreateVpnGatewayResponse, error) {
	resourceId := req.Deployment.Id
	namespace := req.Deployment.Namespace
	resourceIdInfo, err := getResourceIDInfo(resourceId)
	if err != nil {
		return nil, fmt.Errorf("unable to get resource ID info: %w", err)
	}
	azureHandler, err := s.setupAzureHandler(resourceIdInfo, req.Deployment.Namespace)
	if err != nil {
		return nil, fmt.Errorf("unable to setup azure handler: %w", err)
	}

	vpnNumConnections := utils.GetNumVpnConnections(req.Cloud, utils.AZURE)
	publicIPAddresses := make([]*armnetwork.PublicIPAddress, vpnNumConnections)
	virtualNetworkGatewayName := getVpnGatewayName(namespace)
	virtualNetworkGateway, err := azureHandler.GetVirtualNetworkGateway(ctx, virtualNetworkGatewayName)
	var asn uint32
	if err != nil {
		if isErrorNotFound(err) {
			// Create two public IP addresses (need a second for active-active mode)
			publicIPAddressParameters := armnetwork.PublicIPAddress{
				Location: to.Ptr(vpnLocation),
				Properties: &armnetwork.PublicIPAddressPropertiesFormat{
					PublicIPAddressVersion:   to.Ptr(armnetwork.IPVersionIPv4),
					PublicIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodStatic),
				},
				SKU: &armnetwork.PublicIPAddressSKU{
					Name: to.Ptr(armnetwork.PublicIPAddressSKUNameStandard),
				},
			}
			for i := 0; i < vpnNumConnections; i++ {
				vpnGatewayIPAddressName := getVPNGatewayIPAddressName(namespace, i)
				publicIPAddress, err := azureHandler.GetPublicIPAddress(ctx, vpnGatewayIPAddressName)
				if err != nil {
					if isErrorNotFound(err) {
						publicIPAddress, err = azureHandler.CreatePublicIPAddress(ctx, vpnGatewayIPAddressName, publicIPAddressParameters)
						if err != nil {
							return nil, fmt.Errorf("unable to create public IP address: %w", err)
						}
					} else {
						return nil, fmt.Errorf("unable to get public IP address: %w", err)
					}
				}
				publicIPAddresses[i] = publicIPAddress
			}

			// Get VPN gateway subnet
			gatewayVnetName := getVpnGatewayVnetName(namespace)
			vpnGwSubnet, err := azureHandler.GetSubnet(ctx, gatewayVnetName, gatewaySubnetName)
			if err != nil {
				return nil, fmt.Errorf("unable to get VPN gateway subnet: %w", err)
			}

			conn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return nil, fmt.Errorf("unable to establish connection with orchestrator: %w", err)
			}
			defer conn.Close()
			client := paragliderpb.NewControllerClient(conn)
			findUnusedAsnResp, err := client.FindUnusedAsn(ctx, &paragliderpb.FindUnusedAsnRequest{})
			if err != nil {
				return nil, fmt.Errorf("unable to find unused address space: %w", err)
			}
			asn = findUnusedAsnResp.Asn

			// Create VPN gateway
			virtualNetworkGatewayParameters := armnetwork.VirtualNetworkGateway{
				Location: to.Ptr(vpnLocation),
				Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{
					Active: to.Ptr(true),
					BgpSettings: &armnetwork.BgpSettings{
						Asn: to.Ptr(int64(asn)),
					},
					EnableBgp:              to.Ptr(true),
					EnablePrivateIPAddress: to.Ptr(false),
					GatewayType:            to.Ptr(armnetwork.VirtualNetworkGatewayTypeVPN),
					IPConfigurations: []*armnetwork.VirtualNetworkGatewayIPConfiguration{
						{
							Name:       to.Ptr("default"),
							Properties: &armnetwork.VirtualNetworkGatewayIPConfigurationPropertiesFormat{},
						},
					},
					SKU: &armnetwork.VirtualNetworkGatewaySKU{
						Name: to.Ptr(armnetwork.VirtualNetworkGatewaySKUNameVPNGw1),
						Tier: to.Ptr(armnetwork.VirtualNetworkGatewaySKUTierVPNGw1),
					},
					VPNGatewayGeneration: to.Ptr(armnetwork.VPNGatewayGenerationGeneration1),
					VPNType:              to.Ptr(armnetwork.VPNTypeRouteBased),
				},
			}
			virtualNetworkGatewayParameters.Properties.IPConfigurations = make([]*armnetwork.VirtualNetworkGatewayIPConfiguration, vpnNumConnections)
			ipConfigurationNames := []string{"default", "activeActive"} // TODO @seankimkdy: come up with better naming convention ... ? (these are Azure defaults so they may rely on them actually)
			for i := 0; i < vpnNumConnections; i++ {
				virtualNetworkGatewayParameters.Properties.IPConfigurations[i] = &armnetwork.VirtualNetworkGatewayIPConfiguration{
					Name: to.Ptr(ipConfigurationNames[i]),
					Properties: &armnetwork.VirtualNetworkGatewayIPConfigurationPropertiesFormat{
						PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodDynamic),
						PublicIPAddress: &armnetwork.SubResource{
							ID: publicIPAddresses[i].ID,
						},
						Subnet: &armnetwork.SubResource{
							ID: vpnGwSubnet.ID,
						},
					},
				}
			}
			virtualNetworkGateway, err = azureHandler.CreateOrUpdateVirtualNetworkGateway(ctx, virtualNetworkGatewayName, virtualNetworkGatewayParameters)
			if err != nil {
				return nil, fmt.Errorf("unable to create virtual network gateway: %w", err)
			}

			// Add BGP IP addresses
			virtualNetworkGateway.Properties.BgpSettings.BgpPeeringAddresses = make([]*armnetwork.IPConfigurationBgpPeeringAddress, vpnNumConnections)
			for i := 0; i < vpnNumConnections; i++ {
				virtualNetworkGateway.Properties.BgpSettings.BgpPeeringAddresses[i] = &armnetwork.IPConfigurationBgpPeeringAddress{
					CustomBgpIPAddresses: []*string{to.Ptr(req.BgpPeeringIpAddresses[i])},
					IPConfigurationID:    virtualNetworkGateway.Properties.IPConfigurations[i].ID,
				}
			}
			_, err = azureHandler.CreateOrUpdateVirtualNetworkGateway(ctx, virtualNetworkGatewayName, *virtualNetworkGateway)
			if err != nil {
				return nil, fmt.Errorf("unable to update virtual network gateway with BGP IP addresses: %w", err)
			}

			// Update existing peerings with gateway transit relationship
			gatewayVnetPeerings, err := azureHandler.ListVirtualNetworkPeerings(ctx, gatewayVnetName)
			if err != nil {
				return nil, fmt.Errorf("unable to get peerings of virtual gateway vnet: %w", err)
			}
			for _, gatewayVnetToVnetPeering := range gatewayVnetPeerings {
				vnetResourceIDInfo, err := getResourceIDInfo(*gatewayVnetToVnetPeering.Properties.RemoteVirtualNetwork.ID)
				if err != nil {
					return nil, fmt.Errorf("unable to parse vnet resource ID from the gateway vnet to vnet peering: %w", err)
				}
				vnetName := vnetResourceIDInfo.ResourceName
				vnetToGatewayVnetPeering, err := azureHandler.GetVirtualNetworkPeering(ctx, vnetName, getPeeringName(vnetName, gatewayVnetName))
				if err != nil {
					return nil, fmt.Errorf("unable to get vnet to gateway vnet peering: %w", err)
				}
				err = azureHandler.CreateOrUpdateVnetPeeringRemoteGateway(ctx, vnetName, gatewayVnetName, vnetToGatewayVnetPeering, gatewayVnetToVnetPeering)
				if err != nil {
					return nil, fmt.Errorf("unable to update peerings between vnet and gateway vnet for VPN gateway transit: %w", err)
				}
			}
		} else {
			return nil, fmt.Errorf("unable to get virtual network gateway: %w", err)
		}
	} else {
		// Retrieve VPN gateway ASN and IP addresses
		asn = uint32(*virtualNetworkGateway.Properties.BgpSettings.Asn)
		for i, ipConfiguration := range virtualNetworkGateway.Properties.IPConfigurations {
			publicIPAddressIdInfo, err := getResourceIDInfo(*ipConfiguration.Properties.PublicIPAddress.ID)
			if err != nil {
				return nil, fmt.Errorf("unable to get public IP address ID info: %w", err)
			}
			publicIPAddress, err := azureHandler.GetPublicIPAddress(ctx, publicIPAddressIdInfo.ResourceName)
			if err != nil {
				return nil, fmt.Errorf("unable to get public IP address: %w", err)
			}
			publicIPAddresses[i] = publicIPAddress
		}
	}

	resp := &paragliderpb.CreateVpnGatewayResponse{Asn: asn}
	resp.GatewayIpAddresses = make([]string, vpnNumConnections)
	for i := 0; i < vpnNumConnections; i++ {
		resp.GatewayIpAddresses[i] = *publicIPAddresses[i].Properties.IPAddress
	}
	return resp, nil
}

func (s *azurePluginServer) CreateVpnConnections(ctx context.Context, req *paragliderpb.CreateVpnConnectionsRequest) (*paragliderpb.CreateVpnConnectionsResponse, error) {
	resourceIdInfo, err := getResourceIDInfo(req.Deployment.Id)
	if err != nil {
		return nil, fmt.Errorf("unable to get resource ID info: %w", err)
	}
	azureHandler, err := s.setupAzureHandler(resourceIdInfo, req.Deployment.Namespace)
	if err != nil {
		return nil, fmt.Errorf("unable to setup azure handler: %w", err)
	}

	vpnNumConnections := utils.GetNumVpnConnections(req.Cloud, utils.AZURE)
	localNetworkGateways := make([]*armnetwork.LocalNetworkGateway, vpnNumConnections)
	for i := 0; i < vpnNumConnections; i++ {
		localNetworkGatewayName := getLocalNetworkGatewayName(req.Deployment.Namespace, req.Cloud, i)
		localNetworkGateway, err := azureHandler.GetLocalNetworkGateway(ctx, localNetworkGatewayName)
		if err != nil {
			if isErrorNotFound(err) {
				localNetworkGatewayParameters := armnetwork.LocalNetworkGateway{
					Properties: &armnetwork.LocalNetworkGatewayPropertiesFormat{
						GatewayIPAddress: to.Ptr(req.GatewayIpAddresses[i]),
					},
					Location: to.Ptr(vpnLocation),
				}
				if req.IsBgpDisabled {
					addresses := make([]*string, len(req.RemoteAddresses))
					for i, address := range req.RemoteAddresses {
						addresses[i] = &address
					}
					localNetworkGatewayParameters.Properties.LocalNetworkAddressSpace = &armnetwork.AddressSpace{AddressPrefixes: addresses}
				} else {
					localNetworkGatewayParameters.Properties.BgpSettings = &armnetwork.BgpSettings{
						Asn:               to.Ptr(int64(req.Asn)),
						BgpPeeringAddress: to.Ptr(req.BgpIpAddresses[i]),
						PeerWeight:        to.Ptr(int32(0)),
					}
				}
				localNetworkGateway, err = azureHandler.CreateLocalNetworkGateway(ctx, localNetworkGatewayName, localNetworkGatewayParameters)
				if err != nil {
					return nil, fmt.Errorf("unable to create local network gateway: %w", err)
				}
			} else {
				return nil, fmt.Errorf("unable to get local network gateway: %w", err)
			}
		}
		localNetworkGateways[i] = localNetworkGateway
	}

	virtualNetworkGateway, err := azureHandler.GetVirtualNetworkGateway(ctx, getVpnGatewayName(req.Deployment.Namespace))
	if err != nil {
		return nil, fmt.Errorf("unable to get virtual network gateway: %w", err)
	}

	bgpStatus := !req.IsBgpDisabled
	for i := 0; i < vpnNumConnections; i++ {
		virtualNetworkGatewayconnectionName := getVirtualNetworkGatewayConnectionName(req.Deployment.Namespace, req.Cloud, i)
		_, err := azureHandler.GetVirtualNetworkGatewayConnection(ctx, virtualNetworkGatewayconnectionName)
		if err != nil {
			if isErrorNotFound(err) {
				// Checks if a virtual network gateway connection already exists. Even though CreateOrUpdate is a PUT (i.e. idempotent),
				// a new random shared key is generated upon every call to this method from the orchestrator server. Therefore, we don't
				// want to update the shared key since some other cloud plugins (e.g. GCP) will not update the shared key due to POST
				// semantics (i.e. GCP will not update the shared key).
				virtualNetworkGatewayConnectionParameters := &armnetwork.VirtualNetworkGatewayConnection{
					Properties: &armnetwork.VirtualNetworkGatewayConnectionPropertiesFormat{
						ConnectionType:                 to.Ptr(armnetwork.VirtualNetworkGatewayConnectionTypeIPsec),
						VirtualNetworkGateway1:         virtualNetworkGateway,
						ConnectionMode:                 to.Ptr(armnetwork.VirtualNetworkGatewayConnectionModeDefault),
						ConnectionProtocol:             to.Ptr(armnetwork.VirtualNetworkGatewayConnectionProtocolIKEv2),
						DpdTimeoutSeconds:              to.Ptr(int32(45)),
						EnableBgp:                      to.Ptr(bgpStatus),
						IPSecPolicies:                  getIPSecPolicy(req.Cloud),
						LocalNetworkGateway2:           localNetworkGateways[i],
						RoutingWeight:                  to.Ptr(int32(0)),
						SharedKey:                      to.Ptr(req.SharedKey),
						TrafficSelectorPolicies:        []*armnetwork.TrafficSelectorPolicy{},
						UseLocalAzureIPAddress:         to.Ptr(false),
						UsePolicyBasedTrafficSelectors: to.Ptr(false),
					},
					Location: to.Ptr(vpnLocation),
				}
				_, err := azureHandler.CreateVirtualNetworkGatewayConnection(ctx, virtualNetworkGatewayconnectionName, *virtualNetworkGatewayConnectionParameters)
				if err != nil {
					return nil, fmt.Errorf("unable to create virtual network gateway connection: %w", err)
				}
			} else {
				return nil, fmt.Errorf("unable to get virtual network gateway connection: %w", err)
			}
		}
	}

	return &paragliderpb.CreateVpnConnectionsResponse{}, nil
}

// Peer with another virtual network
func (s *azurePluginServer) createPeering(ctx context.Context, azureHandler AzureSDKHandler, resourceIDInfo ResourceIDInfo, resourceVnetName string, peeringCloudInfo *utils.PeeringCloudInfo, permitListRuleTarget string) error {
	peeringCloudResourceIDInfo, err := getResourceIDInfo(peeringCloudInfo.Deployment)
	if err != nil {
		return fmt.Errorf("unable to get resource ID info for peering Cloud: %w", err)
	}
	peeringCloudAzureHandler, err := s.setupAzureHandler(peeringCloudResourceIDInfo, peeringCloudInfo.Namespace)
	if err != nil {
		return err
	}
	paragliderVnetsMap, err := peeringCloudAzureHandler.GetAllVnetsAddressSpaces(ctx, peeringCloudInfo.Namespace)
	if err != nil {
		return fmt.Errorf("unable to create vnets address spaces for peering cloud: %w", err)
	}
	// Find the vnet that contains the target
	contained := false
	for peeringVnetName, peeringVnetAddressSpaces := range paragliderVnetsMap {
		contained, err = utils.IsPermitListRuleTagInAddressSpace(permitListRuleTarget, peeringVnetAddressSpaces)
		if err != nil {
			return fmt.Errorf("unable to check if tag is in vnet address space")
		}
		if contained {
			// Create peering
			err = azureHandler.CreateVnetPeeringOneWay(ctx, resourceVnetName, peeringVnetName, peeringCloudResourceIDInfo.SubscriptionID, peeringCloudResourceIDInfo.ResourceGroupName)
			if err != nil {
				return fmt.Errorf("unable to create vnet peering: %w", err)
			}
			err = peeringCloudAzureHandler.CreateVnetPeeringOneWay(ctx, peeringVnetName, resourceVnetName, resourceIDInfo.SubscriptionID, resourceIDInfo.ResourceGroupName)
			if err != nil {
				return fmt.Errorf("unable to create vnet peering: %w", err)
			}
			break
		}
	}
	if !contained {
		return fmt.Errorf("unable to find vnet belonging to permit list rule target")
	}
	return nil
}

// returns an IPSec policy to configure a VPN connection that's compatible the specified cloud
func getIPSecPolicy(cloud string) []*armnetwork.IPSecPolicy {
	if cloud == utils.IBM {
		ipSecPolicies := make([]*armnetwork.IPSecPolicy, 1)
		ipSecPolicies[0] = &armnetwork.IPSecPolicy{
			DhGroup:             to.Ptr(armnetwork.DhGroupDHGroup24),
			IPSecEncryption:     to.Ptr(armnetwork.IPSecEncryptionAES256),
			IPSecIntegrity:      to.Ptr(armnetwork.IPSecIntegritySHA256),
			IkeEncryption:       to.Ptr(armnetwork.IkeEncryptionAES256),
			IkeIntegrity:        to.Ptr(armnetwork.IkeIntegritySHA384),
			PfsGroup:            to.Ptr(armnetwork.PfsGroupNone),
			SaDataSizeKilobytes: to.Ptr(int32(0)),
			SaLifeTimeSeconds:   to.Ptr(int32(27000)),
		}
		return ipSecPolicies
	}
	return nil
}

// GetNetworkAddressSpaces returns the subnets addresses of the VNet containing the specified address space
func (s *azurePluginServer) GetNetworkAddressSpaces(ctx context.Context, req *paragliderpb.GetNetworkAddressSpacesRequest) (*paragliderpb.GetNetworkAddressSpacesResponse, error) {
	// TODO Implement method
	// This is a placeholder implementation, that translates the specified address space to a CIDR, in case an IP is provided. Instead:
	// 1. locate the VNet containing the address space provided via req.AddressSpace.
	// 2. return the address spaces of all subnets in the above VNet.
	var resourceAddress string
	ip := net.ParseIP(req.AddressSpace)
	if ip != nil {
		resourceAddress = req.AddressSpace + "/32"
	} else if _, _, err := net.ParseCIDR(resourceAddress); err != nil {
		resourceAddress = req.AddressSpace
	} else {
		return nil, fmt.Errorf("failed to get addresses of subnets in Azure's VNet containing %v", req.AddressSpace)
	}

	return &paragliderpb.GetNetworkAddressSpacesResponse{AddressSpaces: []string{resourceAddress}}, nil
}

// Add an existing Azure resource to a paraglider deployment
func (s *azurePluginServer) AttachResource(ctx context.Context, attachResourceReq *paragliderpb.AttachResourceRequest) (*paragliderpb.AttachResourceResponse, error) {
	resourceId := attachResourceReq.GetResource()
	resourceIdInfo, err := getResourceIDInfo(resourceId)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource id info:%+v", err)
		return nil, err
	}

	azureHandler, err := s.setupAzureHandler(resourceIdInfo, attachResourceReq.GetNamespace())
	if err != nil {
		return nil, err
	}

	resource, networkInfo, err := ValidateResourceCompliesWithParagliderRequirements(ctx, resourceId, azureHandler, s)
	if err != nil {
		utils.Log.Printf("An error occured while validating resource:%+v", err)
		return nil, err
	}

	// Create VPN gateway vnet if not already created
	vpnGwVnet, err := GetOrCreateVpnGatewayVNet(ctx, azureHandler, namespace)
	if err != nil {
		utils.Log.Printf("An error occured while getting or creating VPN gateway vnet:%+v", err)
		return nil, err
	}

	vnetName := getVnetFromSubnetId(networkInfo.SubnetID)
	// Create peering between the VPN gateway vnet and VM vnet. If the VPN gateway already exists, then establish a VPN gateway transit relationship where the vnet can use the gatewayVnet's VPN gateway.
	err = CreateGatewayVnetPeering(ctx, azureHandler, vnetName, *vpnGwVnet.Name, namespace)
	if err != nil {
		utils.Log.Printf("An error occured while creating VPN gateway vnet peering:%+v", err)
		return nil, err
	}

	vnet, err := azureHandler.GetVirtualNetwork(ctx, vnetName)
	if err != nil {
		utils.Log.Printf("An error occured while getting vnet:%+v", err)
		return nil, err
	}

	// Add Paraglider namespace tag to the vnet
	azureHandler.createParagliderNamespaceTag(&vnet.Tags)
	_, err = azureHandler.CreateOrUpdateVirtualNetwork(ctx, vnetName, *vnet)
	if err != nil {
		utils.Log.Printf("An error occured while creating vnet:%+v", err)
		return nil, err
	}

	return &paragliderpb.AttachResourceResponse{Name: *resource.Name, Uri: *resource.ID, Ip: networkInfo.Address}, nil
}

func (s *azurePluginServer) checkResource(ctx context.Context, checkReq *paragliderpb.CheckResourceRequest) (*paragliderpb.CheckResourceResponse, error) {
	checkResponse := &paragliderpb.CheckResourceResponse{}
	resourceIdInfo, err := getResourceIDInfo(checkReq.Resource)
	if err != nil {
		return checkResponse, err
	}
	azureHandler, err := s.setupAzureHandler(resourceIdInfo, namespace)
	if err != nil {
		return checkResponse, err
	}

	// Check if the resource exists to validate the tags
	resource, err := ValidateResourceExists(ctx, azureHandler, checkReq.Resource)
	if err != nil {
		return checkResponse, err
	}

	checkResponse.Resource.Name = *resource.Name
	checkResponse.Resource.Uri = *resource.ID
	checkResponse.Resource.Ip = "" // todo: get IP address

	return checkResponse, err
}

func (s *azurePluginServer) fixResource(ctx context.Context, resourceId string, namespace string) error {
	return nil
}
	

func Setup(port int, orchestratorServerAddr string) *azurePluginServer {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	azureServer := &azurePluginServer{
		orchestratorServerAddr: orchestratorServerAddr,
		azureCredentialGetter:  &AzureCredentialGetter{},
	}
	paragliderpb.RegisterCloudPluginServer(grpcServer, azureServer)
	fmt.Println("Starting server on port: ", port)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println(err.Error())
		}
	}()
	return azureServer
}
