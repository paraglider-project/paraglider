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
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

const (
	InvisinetsRulePrefix = "invisinets"
)

type azurePluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
}

func (s *azurePluginServer) GetPermitList(ctx context.Context, resource *invisinetspb.Resource) (*invisinetspb.PermitList, error) {
	cred, err := ConnectionAzure()
	if err != nil {
		log.Printf("cannot connect to azure:%+v", err)
		return nil, err
	}
	InitializeClients(cred)

	resourceID := resource.GetId()

	// get the nic associated with the resource
	nic, err := GetResourceNIC(ctx, resourceID)
	if err != nil {
		log.Printf("cannot get NIC for resource %s: %+v", resourceID, err)
		return nil, err
	}

	// get the NSG associated with the NIC, Note that
	// nic.Properties.NetworkSecurityGroup only contains the ID field but we need
	// to retrieve the actual NSG object to get the properties
	nsgID := *nic.Properties.NetworkSecurityGroup.ID
	nsgName,_ := GetLastSegment(nsgID)
	nsg, err := GetSecurityGroup(ctx, nsgName)
	if err != nil {
		log.Printf("cannot get NSG %s: %+v", nsgName, err)
		return nil, err
	}

	// initialize a list of permit list rules 
	pl := &invisinetspb.PermitList {
		AssociatedResource: resourceID,
		Rules:              []*invisinetspb.PermitListRule{},
	}

	// get the NSG rules
	for _, rule := range nsg.Properties.SecurityRules {
		if strings.HasPrefix(*rule.Name, InvisinetsRulePrefix) {
			pl.Rules = append(pl.Rules, GetPermitListRuleFromNSGRule(rule))
		}
    }
	return pl, nil
}

// AddPermitListRules does the mapping from Invisinets to Azure by creating/updating NSG for the given resource.
// It creates an NSG rule for each permit list rule and applies this NSG to the associated resource (VM)'s NIC (if it doesn't exist).
// It returns a BasicResponse that includes the nsg ID if successful and an error if it fails.
func (s *azurePluginServer) AddPermitListRules(ctx context.Context, pl *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	cred, err := ConnectionAzure()
	if err != nil {
		log.Printf("cannot connect to azure:%+v", err)
		return nil, err
	}
	InitializeClients(cred)

	resourceID := pl.GetAssociatedResource()

	// get the nic associated with the resource
	nic, err := GetResourceNIC(ctx, resourceID)
	if err != nil {
		log.Printf("cannot get NIC for resource %s: %+v", resourceID, err)
		return nil, err
	}

	// get the NSG ID associated with the resource
	nsgID, err := GetOrCreateNSG(ctx, nic) 
	if err != nil {
		log.Printf("cannot get NSG for resource %s: %+v", resourceID, err)
		return nil, err
	}

	nsgName, err := GetLastSegment(nsgID)
	if err != nil {
		log.Printf("cannot get NSG name for resource %s: %+v", resourceID, err)
		return nil, err
	}

	nsg, err := GetSecurityGroup(ctx, nsgName)
	if err != nil {
		log.Printf("cannot get NSG for resource %s: %+v", resourceID, err)
		return nil, err
	}

	var reservedPrioritiesInbound map[int32]bool = make(map[int32]bool)
	var reservedPrioritiesOutbound map[int32]bool = make(map[int32]bool)
	seen := make(map[string]bool)
	setupMaps(reservedPrioritiesInbound, reservedPrioritiesOutbound, seen, nsg)

	var outboundPriority int32 = 100	
	var inboundPriority int32 = 100
	const maxPriority = 4096

	resourceAddress := *nic.Properties.IPConfigurations[0].Properties.PrivateIPAddress

	// Add the rules to the NSG
	for _, rule := range pl.GetRules() {
		if(isDuplicateRule(rule, seen)) {
			log.Printf("duplicate rule: %+v", rule)
			continue
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
		securityRule, err := CreateSecurityRule(ctx, rule, nsgName, resourceAddress, priority, InvisinetsRulePrefix)
		if err != nil {
			log.Printf("cannot create security rule:%+v", err)
			return nil, err
		}
		log.Printf("Created network security rule: %s", *securityRule.ID)
	}

	return &invisinetspb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully added rules to permit list with ID=%s", nsgID)}, nil
}

// DeletePermitListRules does the mapping from Invisinets to Azure by deleting NSG rules for the given resource.
func (s *azurePluginServer) DeletePermitListRules(c context.Context, pl *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	// cred, err := ConnectionAzure()
	// if err != nil {
	// 	log.Printf("cannot connect to azure:%+v", err)
	// 	return
	// }
	// InitializeClients(cred)

	// resourceID := pl.GetAssociatedResource()

	// // get the nic associated with the resource
	// nic, err := GetResourceNIC(c, resourceID)
	// if err != nil {
	// 	log.Printf("cannot get NIC for resource %s: %+v", resourceID, err)
	// 	return
	// }


	return &invisinetspb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully added rules to permit list with ID=")}, nil
}

// newAzureServer creates a new instance of the Azure plugin server
func newAzureServer() *azurePluginServer {
	s := &azurePluginServer{}
	return s
}

// setupMaps fills the reservedPrioritiesInbound and reservedPrioritiesOutbound maps with the priorities of the existing rules in the NSG
// This is done to avoid priorities conflicts when creating new rules
// it also fills the seen map to avoid duplicated rules in the given list of rules
func setupMaps(reservedPrioritiesInbound map[int32]bool, reservedPrioritiesOutbound map[int32]bool, seen map[string]bool, nsg *armnetwork.SecurityGroup) {
    for _, rule := range nsg.Properties.SecurityRules {
		// skip rules that are not created by Invisinets, because some rules are added by default and have 
		// different fields such as port ranges which is not supported by Invisinets at the moment
		if !strings.HasPrefix(*rule.Name, InvisinetsRulePrefix) {
			continue
		}
		equivalentInvisinetsRule := GetPermitListRuleFromNSGRule(rule)
		seen[GetInvisinetsRuleDesc(equivalentInvisinetsRule)] = true
        if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound {
            reservedPrioritiesInbound[*rule.Properties.Priority] = true
        } else if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionOutbound {
            reservedPrioritiesOutbound[*rule.Properties.Priority] = true
        }
    }
}

// getPriority returns the next available priority that is not used by other rules
func getPriority(reservedPriorities map[int32]bool, start int32, end int32) int32 {
    var priority int32
    for i := start; i < 65536; i++ {
        if _, ok := reservedPriorities[i]; !ok {
            priority = i
            reservedPriorities[i] = true
            break
        }
    }
    return priority
}

// isDuplicateRule checks if the given rule is a duplicate of a rule in the given set of rules (seen)
func isDuplicateRule(rule *invisinetspb.PermitListRule, seen map[string]bool) bool {
	key := GetInvisinetsRuleDesc(rule)
	if seen[key] {
		return true
	}
	seen[key] = true
    return false
}

func main() {
	// s := newAzureServer()
	// res, err := s.GetPermitList(context.Background(), &invisinetspb.Resource{Id: "subscriptions/b8cde1f1-df3f-4602-af42-6455909c6968/resourceGroups/diveg-Invisinets/providers/Microsoft.Compute/virtualMachines/vm-sdk-6"})
	// if err != nil {
	// 	log.Fatalf("failed to serve: %v", err)
	// }
	// fmt.Println(res)


	// resp, _ := s.AddPermitListRules(context.Background(), 
	// 	&invisinetspb.PermitList{AssociatedResource: "subscriptions/b8cde1f1-df3f-4602-af42-6455909c6968/resourceGroups/diveg-Invisinets/providers/Microsoft.Compute/virtualMachines/vm-sdk-6",
	// 	 Rules: []*invisinetspb.PermitListRule{&invisinetspb.PermitListRule{Tag: []string{"10.1.0.5"}, Direction: invisinetspb.Direction_OUTBOUND, SrcPort: 80, DstPort: 80, Protocol: 6}}})
	
	// log.Printf("resp: %s", resp)
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	// var opts []grpc.ServerOption
	grpcServer := grpc.NewServer()
	invisinetspb.RegisterCloudPluginServer(grpcServer, newAzureServer())
	fmt.Println("Starting server on port :50051")
	grpcServer.Serve(lis)
}