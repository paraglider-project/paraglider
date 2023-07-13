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

type azurePluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
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
	nsg, err := GetOrCreateNSG(ctx, nic) 
	if err != nil {
		log.Printf("cannot get NSG for resource %s: %+v", resourceID, err)
		return nil, err
	}

	nsgID := *nsg.ID
	nsgName, err := GetLastSegment(nsgID)
	if err != nil {
		log.Printf("cannot get NSG name for resource %s: %+v", resourceID, err)
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
		// Check if there are duplicate rules in the list of given rules
		// TODO: should also check on the pre-existing rules in the NSG by 
		// prefilling the set and reverse mapping the nsg rule to invisinets rule
		if(isDuplicateRule(rule, seen)) {
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
		securityRule, err := CreateSecurityRule(ctx, rule, nsgName, resourceAddress, priority)
		if err != nil {
			log.Printf("cannot create security rule:%+v", err)
			return nil, err
		}
		log.Printf("Created network security rule: %s", *securityRule.ID)
	}

	return &invisinetspb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully added rules to permit list with ID=%s", nsgID)}, nil
}

func (s *azurePluginServer) GetPermitList(c context.Context, r *invisinetspb.Resource) (*invisinetspb.PermitList, error) {
	return &invisinetspb.PermitList{AssociatedResource: r.Id}, nil
}

func newAzureServer() *azurePluginServer {
	s := &azurePluginServer{}
	return s
}

// setupMaps fills the reservedPrioritiesInbound and reservedPrioritiesOutbound maps with the priorities of the existing rules in the NSG
// This is done to avoid priorities conflicts when creating new rules
// it also fills the seen map to avoid duplicated rules in the given list of rules
func setupMaps(reservedPrioritiesInbound map[int32]bool, reservedPrioritiesOutbound map[int32]bool, 
														seen map[string]bool, nsg *armnetwork.SecurityGroup) {
    for _, rule := range nsg.Properties.SecurityRules {
		seen[GetNSGRuleDesc(rule)] = true
        if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound {
            reservedPrioritiesInbound[*rule.Properties.Priority] = true
        } else if *rule.Properties.Direction == armnetwork.SecurityRuleDirectionOutbound {
            reservedPrioritiesOutbound[*rule.Properties.Priority] = true
        }
    }
}

/// getPriority returns the next available priority that is not used by other rules
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

func isDuplicateRule(rule *invisinetspb.PermitListRule, seen map[string]bool) bool {
	key := fmt.Sprintf("%s-%d-%d-%d-%d", strings.Join(rule.Tag, "-"), rule.Direction, rule.SrcPort, rule.DstPort, rule.Protocol)
	if seen[key] {
		return true
	}
	seen[key] = true
    return false
}


func main() {
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
