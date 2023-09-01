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
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	logger "github.com/NetSys/invisinets/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

type AzureSDKHandler interface {
	CreateNetworkSecurityGroup(ctx context.Context, nsgName string, location string) (*armnetwork.SecurityGroup, error)
	InitializeClients(cred azcore.TokenCredential) error
	GetAzureCredentials() (azcore.TokenCredential, error)
	GetResourceNIC(ctx context.Context, resourceID string) (*armnetwork.Interface, error)
	UpdateNetworkInterface(ctx context.Context, resourceNic *armnetwork.Interface, nsg *armnetwork.SecurityGroup) (*armnetwork.Interface, error)
	CreateSecurityRule(ctx context.Context, rule *invisinetspb.PermitListRule, nsgName string, ruleName string, resourceIpAddress string, priority int32) (*armnetwork.SecurityRule, error)
	DeleteSecurityRule(ctx context.Context, nsgName string, ruleName string) error
	GetInvisinetsVnet(ctx context.Context, vnetName string, location string) (*armnetwork.VirtualNetwork, error)
	CreateInvisinetsVirtualNetwork(ctx context.Context, location string, name string, addressSpace string) (*armnetwork.VirtualNetwork, error)
	CreateNetworkInterface(ctx context.Context, subnetID string, location string, nicName string) (*armnetwork.Interface, error)
	CreateVirtualMachine(ctx context.Context, parameters armcompute.VirtualMachine, vmName string) (*armcompute.VirtualMachine, error)
	GetVNetsAddressSpaces(ctx context.Context, prefix string) (map[string]string, error)
	GetPermitListRuleFromNSGRule(rule *armnetwork.SecurityRule) (*invisinetspb.PermitListRule, error)
	GetInvisinetsRuleDesc(rule *invisinetspb.PermitListRule) string
	GetSecurityGroup(ctx context.Context, nsgName string) (*armnetwork.SecurityGroup, error)
	GetLastSegment(resourceID string) (string, error)
	SetSubIdAndResourceGroup(resourceIdInfo ResourceIDInfo)
}

type azureSDKHandler struct {
	AzureSDKHandler
	resourcesClientFactory *armresources.ClientFactory
	computeClientFactory   *armcompute.ClientFactory
	networkClientFactory   *armnetwork.ClientFactory
	securityGroupsClient   *armnetwork.SecurityGroupsClient
	interfacesClient       *armnetwork.InterfacesClient
	securityRulesClient    *armnetwork.SecurityRulesClient
	virtualMachinesClient  *armcompute.VirtualMachinesClient
	virtualNetworksClient  *armnetwork.VirtualNetworksClient
	resourcesClient        *armresources.Client
	deploymentsClient      *armresources.DeploymentsClient
	subscriptionID         string
	resourceGroupName      string
}

const (
	VirtualMachineResourceType = "Microsoft.Compute/virtualMachines"
)

// mapping from IANA protocol numbers (what invisinets uses) to Azure SecurityRuleProtocol except for * which is -1 for all protocols
var invisinetsToAzureprotocol = map[int32]armnetwork.SecurityRuleProtocol{
	256: armnetwork.SecurityRuleProtocolAsterisk,
	1:   armnetwork.SecurityRuleProtocolIcmp,
	6:   armnetwork.SecurityRuleProtocolTCP,
	17:  armnetwork.SecurityRuleProtocolUDP,
	50:  armnetwork.SecurityRuleProtocolEsp,
	51:  armnetwork.SecurityRuleProtocolAh,
}

// mapping from Azure SecurityRuleProtocol to IANA protocol numbers
var azureToInvisinetsProtocol = map[armnetwork.SecurityRuleProtocol]int32{
	armnetwork.SecurityRuleProtocolAsterisk: 256,
	armnetwork.SecurityRuleProtocolIcmp:     1,
	armnetwork.SecurityRuleProtocolTCP:      6,
	armnetwork.SecurityRuleProtocolUDP:      17,
	armnetwork.SecurityRuleProtocolEsp:      50,
	armnetwork.SecurityRuleProtocolAh:       51,
}

// mapping from invisinets direction to Azure SecurityRuleDirection
var invisinetsToAzureDirection = map[invisinetspb.Direction]armnetwork.SecurityRuleDirection{
	invisinetspb.Direction_INBOUND:  armnetwork.SecurityRuleDirectionInbound,
	invisinetspb.Direction_OUTBOUND: armnetwork.SecurityRuleDirectionOutbound,
}

// mapping from Azure SecurityRuleDirection to invisinets direction
var azureToInvisinetsDirection = map[armnetwork.SecurityRuleDirection]invisinetspb.Direction{
	armnetwork.SecurityRuleDirectionInbound:  invisinetspb.Direction_INBOUND,
	armnetwork.SecurityRuleDirectionOutbound: invisinetspb.Direction_OUTBOUND,
}

// Frontend server address
var frontendServerAddr string // TODO @seankimkdy: dynamically configure with config

// CreateNetworkSecurityGroup creates a new network security group with the given name and location
// and returns the created network security group
func (h *azureSDKHandler) CreateNetworkSecurityGroup(ctx context.Context, nsgName string, location string) (*armnetwork.SecurityGroup, error) {
	logger.Log.Printf("creating a new network security group %s in location %s", nsgName, location)
	parameters := armnetwork.SecurityGroup{
		Location: to.Ptr(location),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{},
		},
	}
	pollerResponse, err := h.securityGroupsClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, nsgName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.SecurityGroup, nil
}

// InitializeClients initializes the necessary azure clients for the necessary operations
func (h *azureSDKHandler) InitializeClients(cred azcore.TokenCredential) error {
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

	h.securityGroupsClient = h.networkClientFactory.NewSecurityGroupsClient()
	h.interfacesClient = h.networkClientFactory.NewInterfacesClient()
	h.securityRulesClient = h.networkClientFactory.NewSecurityRulesClient()
	h.virtualNetworksClient = h.networkClientFactory.NewVirtualNetworksClient()
	h.resourcesClient = h.resourcesClientFactory.NewClient()
	h.virtualMachinesClient = h.computeClientFactory.NewVirtualMachinesClient()
	h.deploymentsClient = h.resourcesClientFactory.NewDeploymentsClient()
	return nil
}

// GetAzureCredentials returns an Azure credential.
// it uses the azidentity.NewDefaultAzureCredential() function to create a new Azure credential.
func (h *azureSDKHandler) GetAzureCredentials() (azcore.TokenCredential, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	return cred, nil
}

func (h *azureSDKHandler) SetSubIdAndResourceGroup(resourceIdInfo ResourceIDInfo) {
	h.subscriptionID = resourceIdInfo.SubscriptionID
	h.resourceGroupName = resourceIdInfo.ResourceGroupName
}

// GetResourceNIC returns the network interface card (NIC) for a given resource ID.
// it performs the following steps:
// 1. Get the resource by ID using the resourcesClient.GetByID() function.
// 2. If the resource is a virtual machine, get the virtual machine by name using the virtualMachinesClient.Get() function.
// 3. Get the primary NIC ID from the virtual machine's network profile and extract the NIC name from it.
// 4. Get the NIC by name using the interfacesClient.Get() function and set the return value to the NIC object.
func (h *azureSDKHandler) GetResourceNIC(ctx context.Context, resourceID string) (*armnetwork.Interface, error) {
	var resourceNic *armnetwork.Interface
	var apiVersion string = "2021-04-01"
	options := armresources.ClientGetByIDOptions{}

	// TODO @nnomier: if we just use VMs, we can use vmclient directly
	resource, err := h.resourcesClient.GetByID(ctx, resourceID, apiVersion, &options)
	if err != nil {
		logger.Log.Printf("Failed to get resource: %v", err)
		return nil, err
	}

	//TODO @nnomier: Do a solution that should work for all types
	if *resource.Type != VirtualMachineResourceType {
		err := fmt.Errorf("resource type %s is not supported", *resource.Type)
		return nil, err
	}

	vmName := *resource.Name

	// get the VM
	vm, err := h.virtualMachinesClient.Get(ctx, h.resourceGroupName, vmName, &armcompute.VirtualMachinesClientGetOptions{Expand: nil})

	if err != nil {
		logger.Log.Printf("Failed to get VM: %v", err)
		return nil, err
	}

	// get the primary NIC ID from the VM
	nicID := *vm.Properties.NetworkProfile.NetworkInterfaces[0].ID
	nicName, err := h.GetLastSegment(nicID)
	if err != nil {
		logger.Log.Printf("Failed to get NIC name from ID: %v", err)
		return nil, err
	}

	nicResponse, err := h.interfacesClient.Get(ctx, h.resourceGroupName, nicName, &armnetwork.InterfacesClientGetOptions{Expand: nil})
	if err != nil {
		logger.Log.Printf("Failed to get NIC: %v", err)
		return nil, err
	}
	resourceNic = &nicResponse.Interface
	return resourceNic, nil
}

// UpdateNetworkInterface updates a network interface card (NIC) with a new network security group (NSG).
func (h *azureSDKHandler) UpdateNetworkInterface(ctx context.Context, resourceNic *armnetwork.Interface, nsg *armnetwork.SecurityGroup) (*armnetwork.Interface, error) {
	pollerResp, err := h.interfacesClient.BeginCreateOrUpdate(
		ctx,
		h.resourceGroupName,
		*resourceNic.Name,
		armnetwork.Interface{
			Location: resourceNic.Location,
			Properties: &armnetwork.InterfacePropertiesFormat{
				IPConfigurations:     resourceNic.Properties.IPConfigurations,
				NetworkSecurityGroup: nsg,
			},
		},
		nil,
	)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	nic := &resp.Interface
	jsonData, err := json.MarshalIndent(nic, "", "  ")
	if err != nil {
		logger.Log.Printf("failed to marshal response to JSON: %v", err)
		return nil, err
	}
	logger.Log.Printf("Successfully Updated Resource NIC: %v", string(jsonData))

	return nic, nil
}

// getLastSegment returns the last segment of a resource ID.
func (h *azureSDKHandler) GetLastSegment(ID string) (string, error) {
	// TODO @nnomier: might need to use stricter validations to check if the ID is valid like a regex
	segments := strings.Split(ID, "/")
	// The smallest possible len would be 1 because in go if a string s does not contain sep and sep is not empty,
	// Split returns a slice of length 1 whose only element is s.
	if len(segments) <= 1 {
		return "", fmt.Errorf("invalid resource ID format")
	}
	return segments[len(segments)-1], nil
}

// CreateSecurityRule creates a new security rule in a network security group (NSG).
func (h *azureSDKHandler) CreateSecurityRule(ctx context.Context, rule *invisinetspb.PermitListRule, nsgName string, ruleName string, resourceIpAddress string, priority int32) (*armnetwork.SecurityRule, error) {
	sourceIP, destIP := getIPs(rule, resourceIpAddress)
	pollerResp, err := h.securityRulesClient.BeginCreateOrUpdate(ctx,
		h.resourceGroupName,
		nsgName,
		ruleName,
		armnetwork.SecurityRule{
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Access:                     to.Ptr(armnetwork.SecurityRuleAccessAllow),
				DestinationAddressPrefixes: destIP,
				DestinationPortRange:       to.Ptr(strconv.Itoa(int(rule.DstPort))),
				Direction:                  to.Ptr(invisinetsToAzureDirection[rule.Direction]),
				Priority:                   to.Ptr(priority),
				Protocol:                   to.Ptr(invisinetsToAzureprotocol[rule.Protocol]),
				SourceAddressPrefixes:      sourceIP,
				SourcePortRange:            to.Ptr(strconv.Itoa(int(rule.SrcPort))),
			},
		},
		nil)

	if err != nil {
		return nil, fmt.Errorf("cannot create HTTP security rule: %v", err)
	}

	resp, err := pollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot get security rule create or update future response: %v", err)
	}

	return &resp.SecurityRule, nil
}

// DeleteSecurityRule deletes a security rule from a network security group (NSG).
func (h *azureSDKHandler) DeleteSecurityRule(ctx context.Context, nsgName string, ruleName string) error {
	pollerResp, err := h.securityRulesClient.BeginDelete(ctx, h.resourceGroupName, nsgName, ruleName, nil)
	if err != nil {
		return err
	}

	resp, err := pollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	// resp of type SecurityRulesClientDeleteResponse is currently a placeholder in the sdk
	logger.Log.Printf("Successfully deleted security rule: %v", resp)
	return nil
}

// GetVnetAddressSpaces returns a map of location to address space for all virtual networks (VNets) with a given prefix.
func (h *azureSDKHandler) GetVNetsAddressSpaces(ctx context.Context, prefix string) (map[string]string, error) {
	addressSpaces := make(map[string]string)
	pager := h.virtualNetworksClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			if strings.HasPrefix(*v.Name, prefix) {
				// assume only one address space per vnet
				addressSpaces[*v.Location] = *v.Properties.AddressSpace.AddressPrefixes[0]
			}
		}
	}
	return addressSpaces, nil
}

// GetPermitListRuleFromNSGRule returns a permit list rule from a network security group (NSG) rule.
func (h *azureSDKHandler) GetPermitListRuleFromNSGRule(rule *armnetwork.SecurityRule) (*invisinetspb.PermitListRule, error) {
	srcPort, err := strconv.Atoi(*rule.Properties.SourcePortRange)
	if err != nil {
		return nil, err
	}
	dstPort, err := strconv.Atoi(*rule.Properties.DestinationPortRange)
	if err != nil {
		return nil, err
	}
	// create permit list rule object
	permitListRule := &invisinetspb.PermitListRule{
		Id:        *rule.ID,
		Tag:       getTag(rule),
		Direction: azureToInvisinetsDirection[*rule.Properties.Direction],
		SrcPort:   int32(srcPort),
		DstPort:   int32(dstPort),
		Protocol:  azureToInvisinetsProtocol[*rule.Properties.Protocol],
	}
	return permitListRule, nil
}

// GetNSGRuleDesc returns a description of an invisinets permit list rule for easier comparison
func (h *azureSDKHandler) GetInvisinetsRuleDesc(rule *invisinetspb.PermitListRule) string {
	return fmt.Sprintf("%s-%d-%d-%d-%d", strings.Join(rule.Tag, "-"), rule.Direction, rule.SrcPort, rule.DstPort, rule.Protocol)
}

// GetSecurityGroup reutrns the network security group object given the nsg name
func (h *azureSDKHandler) GetSecurityGroup(ctx context.Context, nsgName string) (*armnetwork.SecurityGroup, error) {
	nsgResp, err := h.securityGroupsClient.Get(ctx, h.resourceGroupName, nsgName, &armnetwork.SecurityGroupsClientGetOptions{Expand: nil})
	if err != nil {
		return nil, err
	}

	return &nsgResp.SecurityGroup, nil
}

// GetInvisinetsVnet returns a valid invisinets vnet, an invisinets vnet is a vnet with a default subnet with the same
// address space as the vnet and there is only one vnet per location
func (h *azureSDKHandler) GetInvisinetsVnet(ctx context.Context, vnetName string, location string) (*armnetwork.VirtualNetwork, error) {
	// Get the virtual network
	res, err := h.virtualNetworksClient.Get(ctx, h.resourceGroupName, vnetName, &armnetwork.VirtualNetworksClientGetOptions{Expand: nil})

	if err != nil {
		// Check if the error is Resource Not Found
		var azError *azcore.ResponseError
		if ok := errors.As(err, &azError); ok && azError.StatusCode == http.StatusNotFound {
			// Create the virtual network if it doesn't exist
			// Get the address space from the controller service
			conn, err := grpc.Dial(frontendServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			client := invisinetspb.NewControllerClient(conn)
			response, err := client.FindUnusedAddressSpace(context.Background(), &invisinetspb.Empty{})
			if err != nil {
				return nil, err
			}
			vnet, err := h.CreateInvisinetsVirtualNetwork(ctx, location, vnetName, response.Address)
			return vnet, err
		} else {
			// Return the error if it's not ResourceNotFound
			return nil, err
		}
	}

	return &res.VirtualNetwork, nil
}

// CreateInvisinetsVirtualNetwork creates a new invisinets virtual network with a default subnet with the same address
// space as the vnet
func (h *azureSDKHandler) CreateInvisinetsVirtualNetwork(ctx context.Context, location string, vnetName string, addressSpace string) (*armnetwork.VirtualNetwork, error) {
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
						// TODO @nnomier: does it make sense for the subnet to be the same as the address space?
						AddressPrefix: to.Ptr(addressSpace),
					},
				},
			},
		},
	}

	pollerResponse, err := h.virtualNetworksClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, vnetName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.VirtualNetwork, nil
}

// CreateNetworkInterface creates a new network interface with a dynamic private IP address
func (h *azureSDKHandler) CreateNetworkInterface(ctx context.Context, subnetID string, location string, nicName string) (*armnetwork.Interface, error) {
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
		},
	}

	pollerResponse, err := h.interfacesClient.BeginCreateOrUpdate(ctx, h.resourceGroupName, nicName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.Interface, err
}

// CreateVirtualMachine creates a new virtual machine with the given parameters and name
func (h *azureSDKHandler) CreateVirtualMachine(ctx context.Context, parameters armcompute.VirtualMachine, vmName string) (*armcompute.VirtualMachine, error) {
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

// getIPs returns the source and destination IP addresses for a given permit list rule and resource IP address.
// it checks the direction of the permit list rule and sets the source IP address to the rule tag
// and the destination IP address to the resource IP address if the direction is inbound.
// If the direction is outbound, it sets the source IP address to the resource IP address and
// the destination IP address to the rule tag.
func getIPs(rule *invisinetspb.PermitListRule, resourceIP string) ([]*string, []*string) {
	var sourceIP []*string
	var destIP []*string

	if rule.Direction == invisinetspb.Direction_INBOUND {
		sourceIP = make([]*string, len(rule.Tag))
		for i, ip := range rule.Tag {
			sourceIP[i] = to.Ptr(ip)
		}
		destIP = []*string{to.Ptr(resourceIP)}
	} else {
		sourceIP = []*string{to.Ptr(resourceIP)}
		destIP = make([]*string, len(rule.Tag))
		for i, ip := range rule.Tag {
			destIP[i] = to.Ptr(ip)
		}
	}

	return sourceIP, destIP
}

// getTag returns the invisiNets tag for a given nsg rule
func getTag(rule *armnetwork.SecurityRule) []string {
	var tag []string
	if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound {
		for _, ptr := range rule.Properties.SourceAddressPrefixes {
			tag = append(tag, *ptr)
		}
	} else if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionOutbound {
		for _, ptr := range rule.Properties.DestinationAddressPrefixes {
			tag = append(tag, *ptr)
		}
	}
	return tag
}
