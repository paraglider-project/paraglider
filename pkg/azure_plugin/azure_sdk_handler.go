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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/google/uuid"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

type AzureSDKHandler interface {
	GetOrCreateNSG(ctx context.Context, nic *armnetwork.Interface) (string, error)
	CreateNetworkSecurityGroup(ctx context.Context, nsgName string, location string) (*armnetwork.SecurityGroup, error)
	InitializeClients(cred azcore.TokenCredential)
	ConnectionAzure() (azcore.TokenCredential, error)
	GetResourceNIC(ctx context.Context, resourceID string) (*armnetwork.Interface, error)
	UpdateNetworkInterface(ctx context.Context, resourceNic *armnetwork.Interface, nsg *armnetwork.SecurityGroup) (*armnetwork.Interface, error)
	CreateSecurityRule(ctx context.Context, rule *invisinetspb.PermitListRule, nsgName string, resourceIpAddress string, priority int32, ruleNamePrefix string) (*armnetwork.SecurityRule, error)
	DeleteSecurityRule(ctx context.Context, nsgName string, ruleName string) error
	GetPermitListRuleFromNSGRule(rule *armnetwork.SecurityRule) *invisinetspb.PermitListRule
	GetInvisinetsRuleDesc(rule *invisinetspb.PermitListRule) string
	GetSecurityGroup(ctx context.Context, nsgName string) (*armnetwork.SecurityGroup, error)
	GetLastSegment(resourceID string) (string, error)
}

type azureSDKHandler struct {
	AzureSDKHandler
	resourcesClientFactory *armresources.ClientFactory
	computeClientFactory   *armcompute.ClientFactory
	networkClientFactory   *armnetwork.ClientFactory
	securityGroupsClient  *armnetwork.SecurityGroupsClient
	interfacesClient      *armnetwork.InterfacesClient
	securityRulesClient   *armnetwork.SecurityRulesClient
	virtualMachinesClient *armcompute.VirtualMachinesClient
	resourcesClient       *armresources.Client
}

const (
	VirtualMachineResourceType = "Microsoft.Compute/virtualMachines"
)

var (
	subscriptionID    = os.Getenv("AZURE_SUBSCRIPTION_ID")
	resourceGroupName = os.Getenv("AZURE_RESOURCE_GROUP_NAME")
)

// TODO: this is a temp mapping until decided how it should be handled
var invisinetsToAzureprotocol = map[int32]armnetwork.SecurityRuleProtocol{
	1: armnetwork.SecurityRuleProtocolAh,
	2: armnetwork.SecurityRuleProtocolAsterisk,
	3: armnetwork.SecurityRuleProtocolEsp,
	4: armnetwork.SecurityRuleProtocolIcmp,
	5: armnetwork.SecurityRuleProtocolTCP,
	6: armnetwork.SecurityRuleProtocolUDP,
}

// mapping from Azure SecurityRuleProtocol to int32
var azureToInvisinetsProtocol = map[armnetwork.SecurityRuleProtocol]int32{
	armnetwork.SecurityRuleProtocolAh:       1,
	armnetwork.SecurityRuleProtocolAsterisk: 2,
	armnetwork.SecurityRuleProtocolEsp:      3,
	armnetwork.SecurityRuleProtocolIcmp:     4,
	armnetwork.SecurityRuleProtocolTCP:      5,
	armnetwork.SecurityRuleProtocolUDP:      6,
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

// CreateNetworkSecurityGroup creates a new network security group with the given name and location
// and returns the created network security group
func (h* azureSDKHandler) CreateNetworkSecurityGroup(ctx context.Context, nsgName string, location string) (*armnetwork.SecurityGroup, error) {
	log.Printf("creating a new network security group %s in location %s", nsgName, location)
	parameters := armnetwork.SecurityGroup{
		Location: to.Ptr(location),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{},
		},
	}
	pollerResponse, err := h.securityGroupsClient.BeginCreateOrUpdate(ctx, resourceGroupName, nsgName, parameters, nil)
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
func (h* azureSDKHandler) InitializeClients(cred azcore.TokenCredential) {
	var err error
	h.resourcesClientFactory, err = armresources.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		log.Fatal(err)
	}

	h.networkClientFactory, err = armnetwork.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		log.Fatal(err)
	}

	h.computeClientFactory, err = armcompute.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		log.Fatal(err)
	}

	h.securityGroupsClient = h.networkClientFactory.NewSecurityGroupsClient()
	h.interfacesClient = h.networkClientFactory.NewInterfacesClient()
	h.securityRulesClient = h.networkClientFactory.NewSecurityRulesClient()
	h.resourcesClient = h.resourcesClientFactory.NewClient()
	h.virtualMachinesClient = h.computeClientFactory.NewVirtualMachinesClient()
}

// ConnectionAzure returns an Azure credential.
// it uses the azidentity.NewDefaultAzureCredential() function to create a new Azure credential.
func (h* azureSDKHandler) ConnectionAzure() (azcore.TokenCredential, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	return cred, nil
}

// GetResourceNIC returns the network interface card (NIC) for a given resource ID.
// it performs the following steps:
// 1. Get the resource by ID using the resourcesClient.GetByID() function.
// 2. If the resource is a virtual machine, get the virtual machine by name using the virtualMachinesClient.Get() function.
// 3. Get the primary NIC ID from the virtual machine's network profile and extract the NIC name from it.
// 4. Get the NIC by name using the interfacesClient.Get() function and set the return value to the NIC object.
func (h* azureSDKHandler) GetResourceNIC(ctx context.Context, resourceID string) (*armnetwork.Interface, error) {
	var resourceNic *armnetwork.Interface
	var apiVersion string = "2021-04-01"
	options := armresources.ClientGetByIDOptions{}

	// TODO: if we just use VMs, we can use vmclient directly
	resource, err := h.resourcesClient.GetByID(ctx, resourceID, apiVersion, &options)
	if err != nil {
		log.Printf("Failed to get resource: %v", err)
		return nil, err
	}

	if *resource.Type == VirtualMachineResourceType { //TODO: Do a solution that should work for all types
		vmName := *resource.Name

		// get the VM
		vm, err := h.virtualMachinesClient.Get(ctx, resourceGroupName, vmName, &armcompute.VirtualMachinesClientGetOptions{Expand: to.Ptr(armcompute.InstanceViewTypesUserData)})

		if err != nil {
			log.Printf("Failed to get VM: %v", err)
			return nil, err
		}

		// get the primary NIC ID from the VM
		nicID := *vm.Properties.NetworkProfile.NetworkInterfaces[0].ID
		nicName, err := h.GetLastSegment(nicID)
		if err != nil {
			log.Printf("Failed to get NIC name from ID: %v", err)
			return nil, err
		}

		nicResponse, err := h.interfacesClient.Get(ctx, resourceGroupName, nicName, &armnetwork.InterfacesClientGetOptions{Expand: nil})
		if err != nil {
			log.Printf("Failed to get NIC: %v", err)
			return nil, err
		}
		resourceNic = &nicResponse.Interface
	} else {
		err := fmt.Errorf("resource type %s is not supported", *resource.Type)
		return nil, err
	}
	return resourceNic, nil
}

// UpdateNetworkInterface updates a network interface card (NIC) with a new network security group (NSG).
func (h* azureSDKHandler) UpdateNetworkInterface(ctx context.Context, resourceNic *armnetwork.Interface, nsg *armnetwork.SecurityGroup) (*armnetwork.Interface, error) {
	pollerResp, err := h.interfacesClient.BeginCreateOrUpdate(
		ctx,
		resourceGroupName,
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
		log.Printf("failed to marshal response to JSON: %v", err)
		return nil, err
	}
	log.Printf("Successfully Updated Resource NIC: %v", string(jsonData))

	return nic, nil
}

// getLastSegment returns the last segment of a resource ID.
func (h* azureSDKHandler) GetLastSegment(ID string) (string, error) {
	// TODO: might need to use stricter validations to check if the ID is valid like a regex
	segments := strings.Split(ID, "/")
	// The smallest possible len would be 1 because in go if a string s does not contain sep and sep is not empty,
	// Split returns a slice of length 1 whose only element is s.
	if len(segments) <= 1 {
		return "", fmt.Errorf("invalid resource ID format")
	}
	return segments[len(segments)-1], nil
}

// CreateSecurityRule creates a new security rule in a network security group (NSG).
func (h* azureSDKHandler) CreateSecurityRule(ctx context.Context, rule *invisinetspb.PermitListRule, nsgName string, resourceIpAddress string, priority int32, ruleNamePrefix string) (*armnetwork.SecurityRule, error) {
	sourceIP, destIP := getIPs(rule, resourceIpAddress)

	pollerResp, err := h.securityRulesClient.BeginCreateOrUpdate(ctx,
		resourceGroupName,
		nsgName,
		fmt.Sprintf("%s-%s", ruleNamePrefix, uuid.New().String()),
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
func (h* azureSDKHandler) DeleteSecurityRule(ctx context.Context, nsgName string, ruleName string) error {
	pollerResp, err := h.securityRulesClient.BeginDelete(ctx, resourceGroupName, nsgName, ruleName, nil)
	if err != nil {
		return err
	}

	resp, err := pollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	// resp of type SecurityRulesClientDeleteResponse is currently a placeholder in the sdk
	log.Printf("Successfully deleted security rule: %v", resp)
	return nil
}

// GetPermitListRuleFromNSGRule returns a permit list rule from a network security group (NSG) rule.
func (h* azureSDKHandler) GetPermitListRuleFromNSGRule(rule *armnetwork.SecurityRule) *invisinetspb.PermitListRule {
	srcPort, _ := strconv.Atoi(*rule.Properties.SourcePortRange)
	dstPort, _ := strconv.Atoi(*rule.Properties.DestinationPortRange)
	// create permit list rule object
	permitListRule := &invisinetspb.PermitListRule{
		Id: 	   *rule.ID,
		Tag:       getTag(rule),
		Direction: azureToInvisinetsDirection[*rule.Properties.Direction],
		SrcPort:   int32(srcPort),
		DstPort:   int32(dstPort),
		Protocol:  azureToInvisinetsProtocol[*rule.Properties.Protocol],
	}
	return permitListRule
}

// GetNSGRuleDesc returns a description of an invisinets permit list rule for easier comparison
func (h* azureSDKHandler) GetInvisinetsRuleDesc(rule *invisinetspb.PermitListRule) string {
	return fmt.Sprintf("%s-%d-%d-%d-%d", strings.Join(rule.Tag, "-"), rule.Direction, rule.SrcPort, rule.DstPort, rule.Protocol)
}

// GetSecurityGroup reutrns the network security group object given the nsg name
func (h* azureSDKHandler) GetSecurityGroup(ctx context.Context, nsgName string) (*armnetwork.SecurityGroup, error) {
	nsgResp, err := h.securityGroupsClient.Get(ctx, resourceGroupName, nsgName, &armnetwork.SecurityGroupsClientGetOptions{Expand: nil})
	if err != nil {
		return nil, err
	}

	return &nsgResp.SecurityGroup, nil
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
