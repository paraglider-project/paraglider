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
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/google/uuid"
)

const (
	InvisinetsRulePrefix = "invisinets"
)

type azurePluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
	azureHandler AzureSDKHandler
}

// newAzureServer creates a new instance of the Azure plugin server
func newAzureServer() *azurePluginServer {
	s := &azurePluginServer{}
	s.azureHandler = &azureSDKHandler{}
	return s
}

// GetPermitList returns the permit list for the given resource by getting the NSG rules
// associated with the resource and filtering out the Invisinets rules
func (s *azurePluginServer) GetPermitList(ctx context.Context, resourceID *invisinetspb.ResourceID) (*invisinetspb.PermitList, error) {
	cred, err := s.azureHandler.GetAzureCredentials()
	if err != nil {
		log.Printf("cannot connect to azure:%+v", err)
		return nil, err
	}
	s.azureHandler.InitializeClients(cred)

	// get the nsg associated with the resource
	nsg, err := s.getNSGFromResource(ctx, resourceID.Id)
	if err != nil {
		log.Printf("cannot get NSG for resource %s: %+v", resourceID.Id, err)
		return nil, err
	}

	// initialize a list of permit list rules
	pl := &invisinetspb.PermitList{
		AssociatedResource: resourceID.Id,
		Rules:              []*invisinetspb.PermitListRule{},
	}

	// get the NSG rules
	for _, rule := range nsg.Properties.SecurityRules {
		if strings.HasPrefix(*rule.Name, InvisinetsRulePrefix) {
			plRule, err := s.azureHandler.GetPermitListRuleFromNSGRule(rule)
			if err != nil {
				log.Printf("cannot get Invisinets rule from NSG rule: %+v", err)
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
	cred, err := s.azureHandler.GetAzureCredentials()
	if err != nil {
		log.Printf("cannot connect to azure:%+v", err)
		return nil, err
	}
	s.azureHandler.InitializeClients(cred)

	resourceID := pl.GetAssociatedResource()

	// get the nic associated with the resource
	nic, err := s.azureHandler.GetResourceNIC(ctx, resourceID)
	if err != nil {
		log.Printf("cannot get NIC for resource %s: %+v", resourceID, err)
		return nil, err
	}

	// get the NSG ID associated with the resource
	nsg, err := s.getOrCreateNSG(ctx, nic, resourceID)

	if err != nil {
		log.Printf("cannot get NSG for resource %s: %+v", resourceID, err)
		return nil, err
	}

	var reservedPrioritiesInbound map[int32]bool = make(map[int32]bool)
	var reservedPrioritiesOutbound map[int32]bool = make(map[int32]bool)
	seen := make(map[string]bool)
	err = s.setupMaps(reservedPrioritiesInbound, reservedPrioritiesOutbound, seen, nsg)
	if err != nil {
		log.Printf("cannot setup priorities: %+v", err)
		return nil, err
	}
	var outboundPriority int32 = 100
	var inboundPriority int32 = 100
	const maxPriority = 4096

	resourceAddress := *nic.Properties.IPConfigurations[0].Properties.PrivateIPAddress

	// Add the rules to the NSG
	for _, rule := range pl.GetRules() {
		ruleDesc := s.azureHandler.GetInvisinetsRuleDesc(rule)
		if seen[ruleDesc] {
			log.Printf("Cannot add this duplicate rule: %+v", rule)
			continue
		}
		seen[ruleDesc] = true

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
		ruleName := InvisinetsRulePrefix + "-" + uuid.New().String()
		securityRule, err := s.azureHandler.CreateSecurityRule(ctx, rule, *nsg.Name, ruleName, resourceAddress, priority)
		if err != nil {
			log.Printf("cannot create security rule:%+v", err)
			return nil, err
		}
		log.Printf("Created network security rule: %s", *securityRule.ID)
	}

	return &invisinetspb.BasicResponse{Success: true, Message: "successfully added non duplicate rules if any to resource with ID=" + resourceID}, nil
}

// DeletePermitListRules does the mapping from Invisinets to Azure by deleting NSG rules for the given resource.
func (s *azurePluginServer) DeletePermitListRules(c context.Context, pl *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	cred, err := s.azureHandler.GetAzureCredentials()
	if err != nil {
		log.Printf("cannot connect to azure:%+v", err)
		return nil, err
	}
	s.azureHandler.InitializeClients(cred)

	resourceID := pl.GetAssociatedResource()

	nsg, err := s.getNSGFromResource(c, resourceID)
	if err != nil {
		log.Printf("cannot get NSG for resource %s: %+v", resourceID, err)
		return nil, err
	}

	rulesToBeDeleted := make(map[string]bool)

	// build a set for the rules to be deleted
	// and then check the nsg rules if they match the set
	// then issue a delete request
	s.fillRulesSet(rulesToBeDeleted, pl.GetRules())

	for _, rule := range nsg.Properties.SecurityRules {
		if strings.HasPrefix(*rule.Name, InvisinetsRulePrefix) {
			invisinetsRule, err := s.azureHandler.GetPermitListRuleFromNSGRule(rule)
			if err != nil {
				log.Printf("cannot get permit list rule from NSG rule:%+v", err)
				return nil, err
			}
			if rulesToBeDeleted[s.azureHandler.GetInvisinetsRuleDesc(invisinetsRule)] {
				err := s.azureHandler.DeleteSecurityRule(c, *nsg.Name, *rule.Name)
				if err != nil {
					log.Printf("cannot delete security rule:%+v", err)
					return nil, err
				}
				log.Printf("Deleted network security rule: %s", *rule.ID)
			}
		}
	}

	return &invisinetspb.BasicResponse{Success: true, Message: "successfully deleted rules from permit list"}, nil
}

// GetOrCreateNSG returns the network security group object given the resource NIC
// if the network security group does not exist, it creates a new one and attach it to the NIC
func (s *azurePluginServer) getOrCreateNSG(ctx context.Context, nic *armnetwork.Interface, resourceID string) (*armnetwork.SecurityGroup, error) {
	var nsg *armnetwork.SecurityGroup
	var err error
	if nic.Properties.NetworkSecurityGroup != nil {
		nsg = nic.Properties.NetworkSecurityGroup

		// nic.Properties.NetworkSecurityGroup returns an nsg obj with only the ID and other fields are nil
		// so this way we need to get the nsg object from the ID using nsgClient
		nsgID := *nsg.ID
		nsgName, err := s.azureHandler.GetLastSegment(nsgID)
		if err != nil {
			log.Printf("cannot get NSG name for resource %s: %+v", resourceID, err)
			return nil, err
		}

		nsg, err = s.azureHandler.GetSecurityGroup(ctx, nsgName)
		if err != nil {
			log.Printf("cannot get NSG for resource %s: %+v", resourceID, err)
			return nil, err
		}
	} else {
		log.Printf("NIC %s does not have a network security group", *nic.ID)
		// create a new network security group
		nsgName := "invisnets-" + uuid.New().String() + "-nsg"
		nsg, err = s.azureHandler.CreateNetworkSecurityGroup(ctx, nsgName, *nic.Location)
		if err != nil {
			log.Printf("failed to create a new network security group: %v", err)
			return nil, err
		}
		// attach the network security group to the NIC
		nicUpdated, err := s.azureHandler.UpdateNetworkInterface(ctx, nic, nsg)
		if err != nil {
			log.Printf("failed to attach the network security group to the NIC: %v", err)
			return nil, err
		}
		log.Printf("Attached network security group %s to NIC %s", *nsg.ID, *nicUpdated.ID)
	}
	return nsg, nil
}

// getNSGFromResource gets the NSG associated with the given resource
// by getting the NIC associated with the resource and then getting the NSG associated with the NIC
func (s *azurePluginServer) getNSGFromResource(c context.Context, resourceID string) (*armnetwork.SecurityGroup, error) {
	// get the nic associated with the resource
	nic, err := s.azureHandler.GetResourceNIC(c, resourceID)
	if err != nil {
		log.Printf("cannot get NIC for resource %s: %+v", resourceID, err)
		return nil, err
	}

	// get the NSG ID associated with the resource
	nsgID := *nic.Properties.NetworkSecurityGroup.ID
	nsgName, err := s.azureHandler.GetLastSegment(nsgID)
	if err != nil {
		log.Printf("cannot get NSG name for resource %s: %+v", resourceID, err)
		return nil, err
	}

	nsg, err := s.azureHandler.GetSecurityGroup(c, nsgName)
	if err != nil {
		log.Printf("cannot get NSG for resource %s: %+v", resourceID, err)
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
		if !strings.HasPrefix(*rule.Name, InvisinetsRulePrefix) {
			continue
		}
		equivalentInvisinetsRule, err := s.azureHandler.GetPermitListRuleFromNSGRule(rule)
		if err != nil {
			log.Printf("cannot get equivalent Invisinets rule for NSG rule %s: %+v", *rule.Name, err)
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
