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
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const maxPriority = 4096

var (
	invisinetsPrefix = "invisinets"
)

type ResourceIDInfo struct {
	SubscriptionID    string
	ResourceGroupName string
	ResourceName      string
}

type azurePluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
	azureHandler AzureSDKHandler
}

// TODO @seankimkdy: replace these
const (
	vpnLocation       = "westus"
	vpnGwAsn          = int64(65515)
	vpnNumConnections = 2
	gatewaySubnetName = "GatewaySubnet"
)

var vpnGwBgpIpAddrs = []string{"169.254.21.1", "169.254.22.1"}

func init() {
	// For integration testing, add the run number to the prefix to avoid conflicts
	// if multiple runs are running at the same time to ensure each run has its own resources
	githubRunPrefix := utils.GetGitHubRunPrefix()
	invisinetsPrefix = githubRunPrefix + invisinetsPrefix
}

func (s *azurePluginServer) setupAzureHandler(resourceIdInfo ResourceIDInfo) error {
	cred, err := s.azureHandler.GetAzureCredentials()
	if err != nil {
		utils.Log.Printf("An error occured while getting azure credentials:%+v", err)
		return err
	}
	s.azureHandler.SetSubIdAndResourceGroup(resourceIdInfo.SubscriptionID, resourceIdInfo.ResourceGroupName)
	err = s.azureHandler.InitializeClients(cred)
	if err != nil {
		utils.Log.Printf("An error occured while initializing azure clients: %+v", err)
		return err
	}

	return nil
}

// GetPermitList returns the permit list for the given resource by getting the NSG rules
// associated with the resource and filtering out the Invisinets rules
func (s *azurePluginServer) GetPermitList(ctx context.Context, resourceID *invisinetspb.ResourceID) (*invisinetspb.PermitList, error) {
	resourceId := resourceID.Id
	resourceIdInfo, err := getResourceIDInfo(resourceId)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource ID info: %+v", err)
		return nil, err
	}
	err = s.setupAzureHandler(resourceIdInfo)
	if err != nil {
		return nil, err
	}

	// get the nsg associated with the resource
	nsg, err := s.getNSGFromResource(ctx, resourceId)
	if err != nil {
		utils.Log.Printf("An error occured while getting NSG for resource %s: %+v", resourceId, err)
		return nil, err
	}

	// initialize a list of permit list rules
	pl := &invisinetspb.PermitList{
		AssociatedResource: resourceID.Id,
		Rules:              []*invisinetspb.PermitListRule{},
	}

	// get the NSG rules
	for _, rule := range nsg.Properties.SecurityRules {
		if !strings.HasPrefix(*rule.Name, denyAllNsgRulePrefix) && strings.HasPrefix(*rule.Name, invisinetsPrefix) {
			plRule, err := s.azureHandler.GetPermitListRuleFromNSGRule(rule)
			if err != nil {
				utils.Log.Printf("An error occured while getting Invisinets rule from NSG rule: %+v", err)
				return nil, err
			}
			pl.Rules = append(pl.Rules, plRule)
		}
	}
	return pl, nil
}

// AddPermitListRules does the mapping from Invisinets to Azure by creating/updating NSG for the given resource.
// It creates an NSG rule for each permit list rule and applies this NSG to the associated resource (VM)'s NIC (if it doesn't exist).
// It returns a BasicResponse that includes the nsg ID if successful and an error if it fails.
func (s *azurePluginServer) AddPermitListRules(ctx context.Context, pl *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	resourceID := pl.GetAssociatedResource()
	resourceIdInfo, err := getResourceIDInfo(resourceID)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource ID info: %+v", err)
		return nil, err
	}
	err = s.setupAzureHandler(resourceIdInfo)
	if err != nil {
		return nil, err
	}

	// get the nic associated with the resource
	nic, err := s.azureHandler.GetResourceNIC(ctx, resourceID)
	if err != nil {
		utils.Log.Printf("An error occured while getting NIC for resource %s: %+v", resourceID, err)
		return nil, err
	}

	// get the NSG associated with the resource
	nsg, err := s.getNSG(ctx, nic, resourceID)

	if err != nil {
		utils.Log.Printf("An error occured while getting NSG for resource %s: %+v", resourceID, err)
		return nil, err
	}

	var reservedPrioritiesInbound map[int32]bool = make(map[int32]bool)
	var reservedPrioritiesOutbound map[int32]bool = make(map[int32]bool)
	seen := make(map[string]bool)
	err = s.setupMaps(reservedPrioritiesInbound, reservedPrioritiesOutbound, seen, nsg)
	if err != nil {
		utils.Log.Printf("An error occured during setup: %+v", err)
		return nil, err
	}
	var outboundPriority int32 = 100
	var inboundPriority int32 = 100

	resourceAddress := *nic.Properties.IPConfigurations[0].Properties.PrivateIPAddress

	// Get used address spaces of all clouds
	controllerConn, err := grpc.Dial(FrontendServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("unable to establish connection with frontend: %w", err)
	}
	defer controllerConn.Close()
	controllerClient := invisinetspb.NewControllerClient(controllerConn)
	usedAddressSpaceMappings, err := controllerClient.GetUsedAddressSpaces(context.Background(), &invisinetspb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("unable to get used address spaces: %w", err)
	}

	// get the vnet to be able to get both the address space as well as the peering when needed
	resourceVnet, err := s.azureHandler.GetVNet(ctx, getVnetName(*nic.Location))
	if err != nil {
		utils.Log.Printf("An error occured while getting resource vnet:%+v", err)
		return nil, err
	}

	// Get subnet address space
	var subnetAddressPrefix string
	for _, subnet := range resourceVnet.Properties.Subnets {
		if *subnet.Name == "default" {
			if subnet.Properties.AddressPrefix != nil {
				// Check to avoid nil pointer dereference
				subnetAddressPrefix = *subnet.Properties.AddressPrefix
			}
			break
		}
	}
	if subnetAddressPrefix == "" {
		return nil, fmt.Errorf("unable to get subnet address prefix")
	}

	invisinetsVnetsMap, err := s.azureHandler.GetVNetsAddressSpaces(ctx, invisinetsPrefix)
	if err != nil {
		utils.Log.Printf("An error occured while getting invisinets vnets address spaces:%+v", err)
		return nil, err
	}

	// Add the rules to the NSG
	for _, rule := range pl.GetRules() {
		ruleDesc := s.azureHandler.GetInvisinetsRuleDesc(rule)
		if seen[ruleDesc] {
			utils.Log.Printf("Cannot add duplicate rules: %+v", rule)
			continue
		}
		seen[ruleDesc] = true

		// TODO @seankimkdy: should we pass the subnet address prefix or the vnet adddress prefix?
		err = utils.CheckAndConnectClouds(utils.AZURE, subnetAddressPrefix, ctx, rule, usedAddressSpaceMappings, controllerClient)
		if err != nil {
			return nil, fmt.Errorf("unable to check and connect clouds: %w", err)
		}

		// TODO @seankimkdy: merge this process with the checking address spaces across all clouds to avoid duplicate checking of Azure address spaces
		err := s.checkAndCreatePeering(ctx, resourceVnet, rule, invisinetsVnetsMap)
		if err != nil {
			utils.Log.Printf("An error occured while checking network peering:%+v", err)
			return nil, err
		}

		// To avoid conflicted priorities, we need to check whether the priority is already used by other rules
		// if the priority is already used, we need to find the next available priority
		var priority int32
		if rule.Direction == invisinetspb.Direction_INBOUND {
			priority = getPriority(reservedPrioritiesInbound, inboundPriority, maxPriority)
			inboundPriority = priority + 1
		} else if rule.Direction == invisinetspb.Direction_OUTBOUND {
			priority = getPriority(reservedPrioritiesOutbound, outboundPriority, maxPriority)
			outboundPriority = priority + 1
		}

		// Create the NSG rule
		securityRule, err := s.azureHandler.CreateSecurityRule(ctx, rule, *nsg.Name, getInvisinetsResourceName("nsgrule"), resourceAddress, priority)
		if err != nil {
			utils.Log.Printf("An error occured while creating security rule:%+v", err)
			return nil, err
		}
		utils.Log.Printf("Successfully created network security rule: %s", *securityRule.ID)
	}

	return &invisinetspb.BasicResponse{Success: true, Message: "successfully added non duplicate rules if any", UpdatedResource: &invisinetspb.ResourceID{Id: resourceID}}, nil
}

// DeletePermitListRules does the mapping from Invisinets to Azure by deleting NSG rules for the given resource.
func (s *azurePluginServer) DeletePermitListRules(c context.Context, pl *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	resourceID := pl.GetAssociatedResource()
	resourceIdInfo, err := getResourceIDInfo(resourceID)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource ID info: %+v", err)
		return nil, err
	}
	err = s.setupAzureHandler(resourceIdInfo)
	if err != nil {
		return nil, err
	}

	nsg, err := s.getNSGFromResource(c, resourceID)
	if err != nil {
		utils.Log.Printf("An error occured while getting NSG for resource %s: %+v", resourceID, err)
		return nil, err
	}

	rulesToBeDeleted := make(map[string]bool)

	// build a set for the rules to be deleted
	// and then check the nsg rules if they match the set
	// then issue a delete request
	s.fillRulesSet(rulesToBeDeleted, pl.GetRules())

	for _, rule := range nsg.Properties.SecurityRules {
		if strings.HasPrefix(*rule.Name, invisinetsPrefix) {
			invisinetsRule, err := s.azureHandler.GetPermitListRuleFromNSGRule(rule)
			if err != nil {
				utils.Log.Printf("An error occured while getting permit list rule from NSG rule:%+v", err)
				return nil, err
			}
			if rulesToBeDeleted[s.azureHandler.GetInvisinetsRuleDesc(invisinetsRule)] {
				err := s.azureHandler.DeleteSecurityRule(c, *nsg.Name, *rule.Name)
				if err != nil {
					utils.Log.Printf("An error occured while deleting security rule:%+v", err)
					return nil, err
				}
				utils.Log.Printf("Successfully deleted network security rule: %s", *rule.ID)
			}
		}
	}

	return &invisinetspb.BasicResponse{Success: true, Message: "successfully deleted rules from permit list"}, nil
}

// CreateResource does the mapping from Invisinets to Azure to create an invisinets enabled resource
// which means the resource should be added to a valid invisinets network, the attachement to an invisinets network
// is determined by the resource's location.
func (s *azurePluginServer) CreateResource(c context.Context, resourceDesc *invisinetspb.ResourceDescription) (*invisinetspb.BasicResponse, error) {
	invisinetsVm, err := getVmFromResourceDesc(resourceDesc.Description)
	if err != nil {
		utils.Log.Printf("Resource description is invalid:%+v", err)
		return nil, err
	}

	resourceIdInfo, err := getResourceIDInfo(resourceDesc.Id)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource id info:%+v", err)
		return nil, err
	}

	err = s.setupAzureHandler(resourceIdInfo)
	if err != nil {
		return nil, err
	}

	invisinetsVnet, err := s.azureHandler.GetInvisinetsVnet(c, getVnetName(*invisinetsVm.Location), *invisinetsVm.Location)
	if err != nil {
		utils.Log.Printf("An error occured while getting invisinets vnet:%+v", err)
		return nil, err
	}

	nic, err := s.azureHandler.CreateNetworkInterface(c, *invisinetsVnet.Properties.Subnets[0].ID, *invisinetsVm.Location, getInvisinetsResourceName("nic"))
	if err != nil {
		utils.Log.Printf("An error occured while creating network interface:%+v", err)
		return nil, err
	}

	invisinetsVm.Properties.NetworkProfile = &armcompute.NetworkProfile{
		NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
			{
				ID: nic.ID,
			},
		},
	}

	invisinetsVm, err = s.azureHandler.CreateVirtualMachine(c, *invisinetsVm, resourceIdInfo.ResourceName)
	if err != nil {
		utils.Log.Printf("An error occured while creating the virtual machine:%+v", err)
		return nil, err
	}

	return &invisinetspb.BasicResponse{Success: true, Message: "successfully created resource", UpdatedResource: &invisinetspb.ResourceID{Id: *invisinetsVm.ID}}, nil
}

// GetUsedAddressSpaces returns the address spaces used by invisinets which are the address spaces of the invisinets vnets
func (s *azurePluginServer) GetUsedAddressSpaces(ctx context.Context, deployment *invisinetspb.InvisinetsDeployment) (*invisinetspb.AddressSpaceList, error) {
	resourceIdInfo, err := getResourceIDInfo(deployment.Id)
	if err != nil {
		utils.Log.Printf("An error occured while getting resource ID info: %+v", err)
		return nil, err
	}
	err = s.setupAzureHandler(resourceIdInfo)
	if err != nil {
		return nil, err
	}

	addressSpaces, err := s.azureHandler.GetVNetsAddressSpaces(ctx, invisinetsPrefix)
	if err != nil {
		utils.Log.Printf("An error occured while getting address spaces:%+v", err)
		return nil, err
	}
	invisinetAddressList := make([]string, len(addressSpaces))
	i := 0
	for _, address := range addressSpaces {
		invisinetAddressList[i] = address
		i++
	}
	return &invisinetspb.AddressSpaceList{AddressSpaces: invisinetAddressList}, nil
}

// getNSG returns the network security group object given the resource NIC
func (s *azurePluginServer) getNSG(ctx context.Context, nic *armnetwork.Interface, resourceID string) (*armnetwork.SecurityGroup, error) {
	var nsg *armnetwork.SecurityGroup
	if nic.Properties.NetworkSecurityGroup != nil {
		nsg = nic.Properties.NetworkSecurityGroup

		// nic.Properties.NetworkSecurityGroup returns an nsg obj with only the ID and other fields are nil
		// so this way we need to get the nsg object from the ID using nsgClient
		nsgID := *nsg.ID
		nsgName, err := s.azureHandler.GetLastSegment(nsgID)
		if err != nil {
			utils.Log.Printf("An error occured while getting NSG name for resource %s: %+v", resourceID, err)
			return nil, err
		}

		nsg, err = s.azureHandler.GetSecurityGroup(ctx, nsgName)
		if err != nil {
			utils.Log.Printf("An error occured while getting NSG for resource %s: %+v", resourceID, err)
			return nil, err
		}
	} else {
		// TODO @nnomier: should we handle this in another way?
		return nil, fmt.Errorf("resource %s does not have a default network security group", resourceID)
	}
	return nsg, nil
}

// getNSGFromResource gets the NSG associated with the given resource
// by getting the NIC associated with the resource and then getting the NSG associated with the NIC
func (s *azurePluginServer) getNSGFromResource(c context.Context, resourceID string) (*armnetwork.SecurityGroup, error) {
	// get the nic associated with the resource
	nic, err := s.azureHandler.GetResourceNIC(c, resourceID)
	if err != nil {
		utils.Log.Printf("An error occured while getting NIC for resource %s: %+v", resourceID, err)
		return nil, err
	}

	// avoid nil pointer dereference error
	if nic.Properties.NetworkSecurityGroup == nil {
		return nil, fmt.Errorf("resource %s does not have a network security group", resourceID)
	}

	nsgID := *nic.Properties.NetworkSecurityGroup.ID
	nsgName, err := s.azureHandler.GetLastSegment(nsgID)
	if err != nil {
		utils.Log.Printf("An error occured while getting NSG name for resource %s: %+v", resourceID, err)
		return nil, err
	}

	nsg, err := s.azureHandler.GetSecurityGroup(c, nsgName)
	if err != nil {
		utils.Log.Printf("An error occured while getting NSG for resource %s: %+v", resourceID, err)
		return nil, err
	}

	return nsg, nil
}

// fillRulesSet fills the given map with the rules in the given permit list as a string
func (s *azurePluginServer) fillRulesSet(rulesSet map[string]bool, rules []*invisinetspb.PermitListRule) {
	for _, rule := range rules {
		rulesSet[s.azureHandler.GetInvisinetsRuleDesc(rule)] = true
	}
}

// setupMaps fills the reservedPrioritiesInbound and reservedPrioritiesOutbound maps with the priorities of the existing rules in the NSG
// This is done to avoid priorities conflicts when creating new rules
// it also fills the seen map to avoid duplicated rules in the given list of rules
func (s *azurePluginServer) setupMaps(reservedPrioritiesInbound map[int32]bool, reservedPrioritiesOutbound map[int32]bool, seen map[string]bool, nsg *armnetwork.SecurityGroup) error {
	for _, rule := range nsg.Properties.SecurityRules {
		if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound {
			reservedPrioritiesInbound[*rule.Properties.Priority] = true
		} else if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionOutbound {
			reservedPrioritiesOutbound[*rule.Properties.Priority] = true
		}
		// skip rules that are not created by Invisinets, because some rules are added by default and have
		// different fields such as port ranges which is not supported by Invisinets at the moment
		if !strings.HasPrefix(*rule.Name, invisinetsPrefix) {
			continue
		}
		equivalentInvisinetsRule, err := s.azureHandler.GetPermitListRuleFromNSGRule(rule)
		if err != nil {
			utils.Log.Printf("An error occured while getting equivalent Invisinets rule for NSG rule %s: %+v", *rule.Name, err)
			return err
		}
		seen[s.azureHandler.GetInvisinetsRuleDesc(equivalentInvisinetsRule)] = true
	}
	return nil
}

// getPriority returns the next available priority that is not used by other rules
func getPriority(reservedPriorities map[int32]bool, start int32, end int32) int32 {
	var i int32
	for i = start; i < end; i++ {
		if !reservedPriorities[i] {
			reservedPriorities[i] = true
			break
		}
	}
	return i
}

// getVmFromResourceDesc gets the armcompute.VirtualMachine object
// from the given resource description which should be a valid resource payload for a VM
func getVmFromResourceDesc(resourceDesc []byte) (*armcompute.VirtualMachine, error) {
	vm := &armcompute.VirtualMachine{}
	err := json.Unmarshal(resourceDesc, vm)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource description:%+v", err)
	}

	// Some validations on the VM
	if vm.Location == nil || vm.Properties == nil {
		return nil, fmt.Errorf("resource description is missing location or properties")
	}

	// Reject VMs that already have network interfaces
	if vm.Properties.NetworkProfile != nil && vm.Properties.NetworkProfile.NetworkInterfaces != nil {
		return nil, fmt.Errorf("resource description cannot contain network interface")
	}

	return vm, nil
}

// getInvisinetsResourceName returns a name for the Invisinets resource
func getInvisinetsResourceName(resourceType string) string {
	// TODO @nnomier: change based on invisinets naming convention
	return invisinetsPrefix + "-" + resourceType + "-" + uuid.New().String()
}

// getResourceIDInfo parses the resourceID to extract subscriptionID and resourceGroupName (and VM name if needed)
// and returns a ResourceIDInfo object filled with the extracted values
// a valid resourceID should be in the format of '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/...'
func getResourceIDInfo(resourceID string) (ResourceIDInfo, error) {
	parts := strings.Split(resourceID, "/")
	if len(parts) < 5 {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected at least 5 parts in the format of '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/...', got %d", len(parts))
	}

	if parts[0] != "" || parts[1] != "subscriptions" || parts[3] != "resourceGroups" {
		return ResourceIDInfo{}, fmt.Errorf("invalid resource ID format: expected '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/...', got '%s'", resourceID)
	}

	info := ResourceIDInfo{
		SubscriptionID:    parts[2],
		ResourceGroupName: parts[4],
	}

	info.ResourceName = parts[len(parts)-1]

	return info, nil
}

// checkAndCreatePeering checks whether the given rule has a tag that is in the address space of any of the invisinets vnets
// and if requires a peering or not
func (s *azurePluginServer) checkAndCreatePeering(ctx context.Context, resourceVnet *armnetwork.VirtualNetwork, rule *invisinetspb.PermitListRule, invisinetsVnetsMap map[string]string) error {
	for _, tag := range rule.Tag {
		isTagInResourceAddressSpace, err := utils.IsPermitListRuleTagInAddressSpace(tag, *resourceVnet.Properties.AddressSpace.AddressPrefixes[0]) // TODO @seankimkdy: should this check for subnet address prefix (which is different due to the partitioning)
		if err != nil {
			return err
		}
		if isTagInResourceAddressSpace {
			continue
		}

		// if the tag is not in the resource address space, then check on the other invisinets vnets
		// if it matches one of them, then a peering is required (if it doesn't exist already)
		for vnetLocation, vnetAddressSpace := range invisinetsVnetsMap {
			isTagInVnetAddressSpace, err := utils.IsPermitListRuleTagInAddressSpace(tag, vnetAddressSpace)
			if err != nil {
				return err
			}
			if isTagInVnetAddressSpace {
				peeringExists := false
				for _, peeredVnet := range resourceVnet.Properties.VirtualNetworkPeerings {
					if strings.HasSuffix(*peeredVnet.Properties.RemoteVirtualNetwork.ID, getVnetName(vnetLocation)) {
						peeringExists = true
						break
					}
				}

				if !peeringExists {
					err := s.azureHandler.CreateVnetPeering(ctx, getVnetName(vnetLocation), getVnetName(*resourceVnet.Location))
					if err != nil {
						return err
					}
				}
				break // No need to continue checking other vnets
			}
		}

		// TODO @nnomier: if the tag is not in any of the invisinets vnets (peeringExists = false), this might mean it's remote (another cloud),
		// so the multicloud setup could be checked/achieved here
	}
	return nil
}

// getVnetName returns the name of the invisinets vnet in the given location
// since an invisients vnet is unique per location
func getVnetName(location string) string {
	return invisinetsPrefix + "-" + location + "-vnet"
}

func getVpnGatewayName() string {
	return invisinetsPrefix + "-vpn-gw"
}

func getVPNGatewayIPAddressName(idx int) string {
	return getVpnGatewayName() + "-ip-" + strconv.Itoa(idx)
}

func getLocalNetworkGatewayName(cloud string, idx int) string {
	return invisinetsPrefix + "-" + cloud + "-local-gw-" + strconv.Itoa(idx)
}

func getVirtualNetworkGatewayConnectionName(cloud string, idx int) string {
	return invisinetsPrefix + "-" + cloud + "-conn-" + strconv.Itoa(idx)
}

// TODO @seankimkdy: everything should be passed in as a GRPC thing
// TODO @seankimkdy: naming? Azure uses "VPN gateway" for a different meaning
// Note that this is
func (s *azurePluginServer) CreateVpnGateway(ctx context.Context, deployment *invisinetspb.InvisinetsDeployment) (*invisinetspb.CreateVpnGatewayResponse, error) {
	resourceIdInfo, err := getResourceIDInfo(deployment.Id)
	if err != nil {
		return nil, fmt.Errorf("shit hit the fan")
	}
	err = s.setupAzureHandler(resourceIdInfo)
	if err != nil {
		return nil, fmt.Errorf("shit hit the fan part 2")
	}

	// TODO @seankimkdy: check if gateway already exists and return information from there

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
	publicIPAddresses := make([]*armnetwork.PublicIPAddress, vpnNumConnections)
	for i := 0; i < vpnNumConnections; i++ {
		publicIPAddress, err := s.azureHandler.CreatePublicIPAddress(ctx, getVPNGatewayIPAddressName(i), publicIPAddressParameters)
		if err != nil {
			return nil, fmt.Errorf("unable to create public IP address: %w", err)
		}
		publicIPAddresses[i] = publicIPAddress
	}

	// Create gateway subnet
	invisinetsVnet, err := s.azureHandler.GetInvisinetsVnet(ctx, getVnetName(vpnLocation), vpnLocation)
	if err != nil {
		return nil, fmt.Errorf("unable to get invisinets vnet: %w", err)
	}
	subnetParameters := armnetwork.Subnet{
		Name:       to.Ptr(gatewaySubnetName), // TODO @seankimkdy: is this necessary?
		Properties: &armnetwork.SubnetPropertiesFormat{},
	}
	subnetAddressPrefixes, err := splitVnetAddressPrefix(*invisinetsVnet.Properties.AddressSpace.AddressPrefixes[0])
	if err != nil {
		return nil, fmt.Errorf("unable to split address prefix: %w", err)
	}
	subnetParameters.Properties.AddressPrefix = to.Ptr(subnetAddressPrefixes[1])
	gatewaySubnet, err := s.azureHandler.CreateSubnet(ctx, *invisinetsVnet.Name, gatewaySubnetName, subnetParameters)
	if err != nil {
		return nil, fmt.Errorf("unable to create gateway subnet: %w", err)
	}

	// Create virtual network gateway
	virtualNetworkGatewayParameters := armnetwork.VirtualNetworkGateway{
		Location: to.Ptr(vpnLocation),
		Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{
			Active: to.Ptr(true),
			BgpSettings: &armnetwork.BgpSettings{
				Asn: to.Ptr(vpnGwAsn),
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
			SKU: &armnetwork.VirtualNetworkGatewaySKU{ // TODO @seankimkdy: confirm with sarah
				Name: to.Ptr(armnetwork.VirtualNetworkGatewaySKUNameVPNGw1),
				Tier: to.Ptr(armnetwork.VirtualNetworkGatewaySKUTierVPNGw1),
			},
			VPNGatewayGeneration: to.Ptr(armnetwork.VPNGatewayGenerationGeneration1), // TODO @seankimkdy: confirm with sarah
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
					ID: gatewaySubnet.ID,
				},
			},
		}
	}
	_, err = s.azureHandler.CreateOrUpdateVirtualNetworkGateway(ctx, getVpnGatewayName(), virtualNetworkGatewayParameters)
	if err != nil {
		return nil, fmt.Errorf("unable to create virtual network gateway: %w", err)
	}

	resp := &invisinetspb.CreateVpnGatewayResponse{Asn: vpnGwAsn}
	resp.GatewayIpAddresses = make([]string, vpnNumConnections)
	for i := 0; i < vpnNumConnections; i++ {
		resp.GatewayIpAddresses[i] = *publicIPAddresses[i].Properties.IPAddress
	}
	return resp, nil
}

func (s *azurePluginServer) CreateVpnBgpSessions(ctx context.Context, req *invisinetspb.CreateVpnBgpSessionsRequest) (*invisinetspb.CreateVpnBgpSessionsResponse, error) {
	resourceIdInfo, err := getResourceIDInfo(req.Deployment.Id)
	if err != nil {
		return nil, fmt.Errorf("shit hit the fan")
	}
	err = s.setupAzureHandler(resourceIdInfo)
	if err != nil {
		return nil, fmt.Errorf("shit hit the fan part 2")
	}

	virtualNetworkGatewayName := getVpnGatewayName()
	virtualNetworkGateway, err := s.azureHandler.GetVirtualNetworkGateway(ctx, virtualNetworkGatewayName)
	if err != nil {
		return nil, fmt.Errorf("unable to get virtual network gateway: %w", err)
	}
	virtualNetworkGateway.Properties.BgpSettings.BgpPeeringAddresses = make([]*armnetwork.IPConfigurationBgpPeeringAddress, len(vpnGwBgpIpAddrs))
	for i := 0; i < vpnNumConnections; i++ {
		virtualNetworkGateway.Properties.BgpSettings.BgpPeeringAddresses[i] = &armnetwork.IPConfigurationBgpPeeringAddress{
			CustomBgpIPAddresses: []*string{to.Ptr(vpnGwBgpIpAddrs[i])},
			IPConfigurationID:    virtualNetworkGateway.Properties.IPConfigurations[i].ID,
		}
	}
	_, err = s.azureHandler.CreateOrUpdateVirtualNetworkGateway(ctx, virtualNetworkGatewayName, *virtualNetworkGateway)
	if err != nil {
		return nil, fmt.Errorf("unable to add bgp settings to VPN gateway: %w", err)
	}

	return &invisinetspb.CreateVpnBgpSessionsResponse{BgpIpAddresses: vpnGwBgpIpAddrs}, nil
}

func (s *azurePluginServer) CreateVpnConnections(ctx context.Context, req *invisinetspb.CreateVpnConnectionsRequest) (*invisinetspb.BasicResponse, error) {
	resourceIdInfo, err := getResourceIDInfo(req.Deployment.Id)
	if err != nil {
		return nil, fmt.Errorf("shit hit the fan")
	}
	err = s.setupAzureHandler(resourceIdInfo)
	if err != nil {
		return nil, fmt.Errorf("shit hit the fan part 2")
	}

	localNetworkGateways := make([]*armnetwork.LocalNetworkGateway, vpnNumConnections)
	for i := 0; i < vpnNumConnections; i++ {
		localNetworkGatewayName := getLocalNetworkGatewayName(req.Cloud, i)
		localNetworkGatewayParameters := armnetwork.LocalNetworkGateway{
			Properties: &armnetwork.LocalNetworkGatewayPropertiesFormat{
				BgpSettings: &armnetwork.BgpSettings{
					Asn:               to.Ptr(req.Asn),
					BgpPeeringAddress: to.Ptr(req.BgpIpAddresses[i]),
					PeerWeight:        to.Ptr(int32(0)),
				},
				GatewayIPAddress: to.Ptr(req.GatewayIpAddresses[i]),
				LocalNetworkAddressSpace: &armnetwork.AddressSpace{
					AddressPrefixes: []*string{to.Ptr(req.AddressSpace)},
				},
			},
			Location: to.Ptr(vpnLocation),
		}
		localNetworkGateway, err := s.azureHandler.CreateLocalNetworkGateway(ctx, localNetworkGatewayName, localNetworkGatewayParameters)
		if err != nil {
			return nil, fmt.Errorf("unable to create local network gateway: %w", err)
		}
		localNetworkGateways[i] = localNetworkGateway
	}

	virtualNetworkGateway, err := s.azureHandler.GetVirtualNetworkGateway(ctx, getVpnGatewayName())
	if err != nil {
		return nil, fmt.Errorf("unable to get virtual network gateway: %w", err)
	}
	for i := 0; i < vpnNumConnections; i++ {
		virtualNetworkGatewayconnectionName := getVirtualNetworkGatewayConnectionName(req.Cloud, i)
		_, err := s.azureHandler.GetVirtualNetworkGatewayConnection(ctx, virtualNetworkGatewayconnectionName)
		if err != nil {
			if isErrorNotFound(err) {
				// Checks if a virtual network gateway connection already exists. Even though CreateOrUpdate is a PUT (i.e. idempotent),
				// a new random shared key is generated upon every call to this method from the controller server. Therefore, we don't
				// want to update the shared key since some other cloud plugins (e.g. GCP) will not update the shared key due to POST
				// semantics (i.e. GCP will not update the shared key).
				virtualNetworkGatewayConnectionParameters := &armnetwork.VirtualNetworkGatewayConnection{
					Properties: &armnetwork.VirtualNetworkGatewayConnectionPropertiesFormat{
						ConnectionType:                 to.Ptr(armnetwork.VirtualNetworkGatewayConnectionTypeIPsec),
						VirtualNetworkGateway1:         virtualNetworkGateway,
						ConnectionMode:                 to.Ptr(armnetwork.VirtualNetworkGatewayConnectionModeDefault), // TODO @seankimkdy: confirm constant
						ConnectionProtocol:             to.Ptr(armnetwork.VirtualNetworkGatewayConnectionProtocolIKEv2),
						DpdTimeoutSeconds:              to.Ptr(int32(45)), // TODO @seankimkdy: confirm constant
						EnableBgp:                      to.Ptr(true),
						IPSecPolicies:                  []*armnetwork.IPSecPolicy{}, // TODO @seankimkdy: confirm constant
						LocalNetworkGateway2:           localNetworkGateways[i],
						RoutingWeight:                  to.Ptr(int32(0)), // TODO @seankimkdy: confirm constant
						SharedKey:                      to.Ptr(req.SharedKey),
						TrafficSelectorPolicies:        []*armnetwork.TrafficSelectorPolicy{}, // TODO @seankimkdy: confirm constant
						UseLocalAzureIPAddress:         to.Ptr(false),
						UsePolicyBasedTrafficSelectors: to.Ptr(false), // TODO @seankimkdy: confirm constant
					},
					Location: to.Ptr(vpnLocation),
				}
				_, err := s.azureHandler.CreateVirtualNetworkGatewayConnection(ctx, virtualNetworkGatewayconnectionName, *virtualNetworkGatewayConnectionParameters)
				if err != nil {
					return nil, fmt.Errorf("unable to create virtual network gateway connection: %w", err)
				}
			} else {
				return nil, fmt.Errorf("unable to get virtual network gateway connection: %w", err)
			}
		}
	}

	return &invisinetspb.BasicResponse{Success: true}, nil
}

func Setup(port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	azureServer := azurePluginServer{
		azureHandler: &azureSDKHandler{},
	}
	invisinetspb.RegisterCloudPluginServer(grpcServer, &azureServer)
	fmt.Println("Starting server on port :", port)
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}
