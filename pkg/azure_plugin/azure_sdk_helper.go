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

const (
	VirtualMachineResourceType = "Microsoft.Compute/virtualMachines"
)

var (
	subscriptionID    = os.Getenv("AZURE_SUBSCRIPTION_ID")
	resourceGroupName = os.Getenv("AZURE_RESOURCE_GROUP_NAME")
)

var (
	resourcesClientFactory *armresources.ClientFactory
	computeClientFactory   *armcompute.ClientFactory
	networkClientFactory   *armnetwork.ClientFactory
)

var (
	securityGroupsClient  *armnetwork.SecurityGroupsClient
	interfacesClient      *armnetwork.InterfacesClient
	securityRulesClient   *armnetwork.SecurityRulesClient
	virtualMachinesClient *armcompute.VirtualMachinesClient
	resourcesClient       *armresources.Client
)

// TODO: this is a temp mapping until decided how it should be handled
var protocolMap = map[int32]armnetwork.SecurityRuleProtocol{
	1: armnetwork.SecurityRuleProtocolAh,
	2: armnetwork.SecurityRuleProtocolAsterisk,
	3: armnetwork.SecurityRuleProtocolEsp,
	4: armnetwork.SecurityRuleProtocolIcmp,
	5: armnetwork.SecurityRuleProtocolTCP,
	6: armnetwork.SecurityRuleProtocolUDP,
}

// mapping from invisinets direction to Azure SecurityRuleDirection
var directionMap = map[invisinetspb.Direction]armnetwork.SecurityRuleDirection{
	invisinetspb.Direction_INBOUND:  armnetwork.SecurityRuleDirectionInbound,
	invisinetspb.Direction_OUTBOUND: armnetwork.SecurityRuleDirectionOutbound,
}

// GetSecurityGroup reutrns the network security group object given the nsg name
func GetSecurityGroup(ctx context.Context, nsgName string) (*armnetwork.SecurityGroup, error) {
    nsgResp, err := securityGroupsClient.Get(ctx, resourceGroupName, nsgName, &armnetwork.SecurityGroupsClientGetOptions{Expand: nil})
	if err != nil {
		log.Fatalf("failed to get the network security group: %v", err)
	}

    return &nsgResp.SecurityGroup, nil
}

// CreateNetworkSecurityGroup creates a new network security group with the given name and location
// and returns the created network security group
func CreateNetworkSecurityGroup(ctx context.Context, nsgName string, location string) (*armnetwork.SecurityGroup, error) {
	parameters := armnetwork.SecurityGroup{
		Location: to.Ptr(location),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: []*armnetwork.SecurityRule{},
		},
	}

	pollerResponse, err := securityGroupsClient.BeginCreateOrUpdate(ctx, resourceGroupName, nsgName, parameters, nil)
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
func InitializeClients(cred azcore.TokenCredential) {
	var err error
	resourcesClientFactory, err = armresources.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		log.Fatal(err)
	}

	networkClientFactory, err = armnetwork.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		log.Fatal(err)
	}

	computeClientFactory, err = armcompute.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		log.Fatal(err)
	}

	securityGroupsClient = networkClientFactory.NewSecurityGroupsClient()
	interfacesClient = networkClientFactory.NewInterfacesClient()
	securityRulesClient = networkClientFactory.NewSecurityRulesClient()
	resourcesClient = resourcesClientFactory.NewClient()
	virtualMachinesClient = computeClientFactory.NewVirtualMachinesClient()
}

// ConnectionAzure returns an Azure credential.
// it uses the azidentity.NewDefaultAzureCredential() function to create a new Azure credential.
func ConnectionAzure() (azcore.TokenCredential, error) {
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
func GetResourceNIC(ctx context.Context, resourceID string) (*armnetwork.Interface, error) {
	var resourceNic *armnetwork.Interface
	var apiVersion string = "2021-04-01"
	options := armresources.ClientGetByIDOptions{}

	// TODO: if we just use VMs, we can use vmclient directly
	resource, err := resourcesClient.GetByID(ctx, resourceID, apiVersion, &options)
	if err != nil {
		log.Printf("Failed to get resource: %v", err)
		return nil, err
	}

	if *resource.Type == VirtualMachineResourceType { //TODO: Do a solution that should work for all types
		vmName := *resource.Name

		// get the VM
		vm, err := virtualMachinesClient.Get(ctx, resourceGroupName, vmName, &armcompute.VirtualMachinesClientGetOptions{Expand: to.Ptr(armcompute.InstanceViewTypesUserData)})

		if err != nil {
			log.Printf("Failed to get VM: %v", err)
			return nil, err
		}

		// get the primary NIC ID from the VM
		nicID := *vm.Properties.NetworkProfile.NetworkInterfaces[0].ID
		nicName, err := GetLastSegment(nicID)
		if err != nil {
			log.Printf("Failed to get NIC name from ID: %v", err)
			return nil, err
		}

		nicResponse, err := interfacesClient.Get(ctx, resourceGroupName, nicName, &armnetwork.InterfacesClientGetOptions{Expand: nil})
		if err != nil {
			log.Printf("Failed to get NIC: %v", err)
			return nil, err
		}
		resourceNic = &nicResponse.Interface
	} else {
		err := fmt.Errorf("resource type %s is not supported", *resource.Type)
		log.Println(err)
		return nil, err
	}

	return resourceNic, nil
}

// UpdateNetworkInterface updates a network interface card (NIC) with a new network security group (NSG).
func UpdateNetworkInterface(ctx context.Context, resourceNic *armnetwork.Interface, nsgID string) (*armnetwork.Interface, error) {
	pollerResp, err := interfacesClient.BeginCreateOrUpdate(
		ctx,
		resourceGroupName,
		*resourceNic.Name,
		armnetwork.Interface{
			Location: resourceNic.Location,
			Properties: &armnetwork.InterfacePropertiesFormat{
				IPConfigurations: resourceNic.Properties.IPConfigurations,
				NetworkSecurityGroup: &armnetwork.SecurityGroup{
					ID: to.Ptr(nsgID),
				},
			},
		},
		nil,
	)
	if err != nil {
		log.Printf("Failed to update NIC: %v", err)
		return nil, err
	}

	resp, err := pollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		log.Printf("Failed to wait for completion of update operation: %v", err)
		return nil, err
	}

	nic := &resp.Interface
    jsonData, err := json.MarshalIndent(nic, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal response to JSON: %v", err)
	}
	log.Printf("Successfully Updated Resource NIC: %v", string(jsonData))

	return nic, nil
}

// getLastSegment returns the last segment of a resource ID.
func GetLastSegment(ID string) (string, error) {
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
func CreateSecurityRule(ctx context.Context, rule *invisinetspb.PermitListRule, nsgName string, resourceIpAddress string, priority int32) (*armnetwork.SecurityRule, error) {
	sourceIP, destIP := getIPs(rule, resourceIpAddress)

	pollerResp, err := securityRulesClient.BeginCreateOrUpdate(ctx,
		resourceGroupName,
		nsgName,
		fmt.Sprintf("invisinets-rule-%s", uuid.New().String()),
		armnetwork.SecurityRule{
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),
				DestinationAddressPrefixes: destIP,
				DestinationPortRange:     to.Ptr(strconv.Itoa(int(rule.DstPort))),
				Direction:                to.Ptr(directionMap[rule.Direction]),
				Priority:                 to.Ptr(priority),
				Protocol:                 to.Ptr(protocolMap[rule.Protocol]),
				SourceAddressPrefixes:    sourceIP,
				SourcePortRange:          to.Ptr(strconv.Itoa(int(rule.SrcPort))),
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

func GetNSGRuleDesc(rule *armnetwork.SecurityRule) string {
	var nsgRuleStr string
	// ruleKey := fmt.Sprintf("%s-%d-%d-%d-%d", strings.Join(rule.Tag, "-"), rule.Direction, rule.SrcPort, rule.DstPort, rule.Protocol)

	if *rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {

	}
	// type SecurityRulePropertiesFormat struct {

	// 	// REQUIRED; The direction of the rule. The direction specifies if rule will be evaluated on incoming or outgoing traffic.
	// 	Direction *SecurityRuleDirection
	
	// 	// REQUIRED; Network protocol this rule applies to.
	// 	Protocol *SecurityRuleProtocol
	
	// 	// A description for this rule. Restricted to 140 chars.
	// 	Description *string
	
	// 	// The destination address prefix. CIDR or destination IP range. Asterisk '*' can also be used to match all source IPs. Default
	// 	// tags such as 'VirtualNetwork', 'AzureLoadBalancer' and 'Internet' can also
	// 	// be used.
	// 	DestinationAddressPrefix *string
	
	// 	// The destination address prefixes. CIDR or destination IP ranges.
	// 	DestinationAddressPrefixes []*string
	
	// 	// The application security group specified as destination.
	// 	DestinationApplicationSecurityGroups []*ApplicationSecurityGroup
	
	// 	// The destination port or range. Integer or range between 0 and 65535. Asterisk '*' can also be used to match all ports.
	// 	DestinationPortRange *string
	
	// 	// The destination port ranges.
	// 	DestinationPortRanges []*string
	
	// 	// The priority of the rule. The value can be between 100 and 4096. The priority number must be unique for each rule in the
	// 	// collection. The lower the priority number, the higher the priority of the rule.
	// 	Priority *int32
	
	// 	// The CIDR or source IP range. Asterisk '*' can also be used to match all source IPs. Default tags such as 'VirtualNetwork',
	// 	// 'AzureLoadBalancer' and 'Internet' can also be used. If this is an ingress
	// 	// rule, specifies where network traffic originates from.
	// 	SourceAddressPrefix *string
	
	// 	// The CIDR or source IP ranges.
	// 	SourceAddressPrefixes []*string
	
	// 	// The application security group specified as source.
	// 	SourceApplicationSecurityGroups []*ApplicationSecurityGroup
	
	// 	// The source port or range. Integer or range between 0 and 65535. Asterisk '*' can also be used to match all ports.
	// 	SourcePortRange *string
	
	// 	// The source port ranges.
	// 	SourcePortRanges []*string
	
	// 	// READ-ONLY; The provisioning state of the security rule resource.
	// 	ProvisioningState *ProvisioningState
	// }
	
	return nsgRuleStr
}