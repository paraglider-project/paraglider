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

func (s *azurePluginServer) CreatePermitList(ctx context.Context, pl *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	cred, err := ConnectionAzure()
	if err != nil {
		log.Printf("cannot connect to azure:%+v", err)
		return nil, err
	}
	InitializeClients(cred)
	nsgName := pl.GetName()

	nsg, err := CreateNetworkSecurityGroup(ctx, nsgName, pl.GetLocation())
	if err != nil {
		log.Printf("cannot create network security group:%+v", err)
		return nil, err
	}

	nsgID := *nsg.ID
	log.Printf("Created network security group: %s", nsgID)

	associatedResource := pl.GetProperties().GetAssociatedResource()
	resourceNic, err := GetResourceNIC(ctx, associatedResource)

	if err != nil {
		log.Printf("cannot get resource NIC:%+v", err)
		return nil, err
	}

	// Associate the NSG  with the specified associated_resource
	UpdateNetworkInterface(ctx, resourceNic, nsgID)
	return &invisinetspb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully created permit list with ID=%s", nsgID)}, nil
}


func (s *azurePluginServer) CreatePermitListRule(ctx context.Context, rule *invisinetspb.PermitListRule) (*invisinetspb.BasicResponse, error) {
	cred, err := ConnectionAzure()
	if err != nil {
		log.Printf("cannot connect to azure:%+v", err)
		return nil, err
	}
	InitializeClients(cred)

	nsgID := rule.GetPermitListId()
	nsgName, err := GetLastSegment(nsgID)
	if err != nil {
		log.Printf("Failed to get NSG name from ID: %v", err)
		return nil, err
	}

	nsg, err := GetSecurityGroup(ctx, nsgName)

	// check for duplicate, if this rule already exists in the nsg rules, discard it
	ruleKey := fmt.Sprintf("%s-%d-%d-%d-%d", strings.Join(rule.Tag, "-"), rule.Direction, rule.SrcPort, rule.DstPort, rule.Protocol)
	if isDuplicateRule(ruleKey, nsg) {
		return nil, nil
	}

	// To avoid conflicted priorities, we need to check whether the priority is already used by other rules
	// if the priority is already used, we need to find the next available priority
	var reservedPrioritiesMap map[int32]bool = make(map[int32]bool)
	const minPriority = 100
	const maxPriority = 4096
	fillReservedPriorities(reservedPrioritiesMap, rule.Direction, nsg)
	priority := getPriority(reservedPrioritiesMap, minPriority, maxPriority)

	// TODO: assume for now a 1-on-1 mapping i.e each nsg is only associated to one NIC for one resource
	// This could later be resolved by adding a naming convention
	resourceIP := *nsg.Properties.NetworkInterfaces[0].Properties.IPConfigurations[0].Properties.PrivateIPAddress

	// Create the NSG rule
	securityRule, err := CreateSecurityRule(ctx, rule, nsgName, resourceIP, priority)
	if err != nil {
		log.Printf("cannot create security rule:%+v", err)
		return nil, err
	}
	nsgRuleId := *securityRule.ID
	log.Printf("Created network security rule: %s", *securityRule.ID)
	return &invisinetspb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully created permit list rule with ID=%s", nsgRuleId)}, nil
}

// // SetPermitList does the mapping from Invisinets to Azure by creating/updating NSG for the given resource.
// // It creates an NSG rule for each permit list rule and applies this NSG to the associated resource (VM)'s NIC.
// // It returns a BasicResponse that includes the pl ID if successful and an error if it fails.
// func (s *azurePluginServer) SetPermitList(ctx context.Context, pl *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
// 	cred, err := ConnectionAzure()
// 	if err != nil {
// 		log.Printf("cannot connect to azure:%+v", err)
// 		return nil, err
// 	}

// 	InitializeClients(cred)
// 	nsgName := pl.GetName()
// 	var nsgID string
// 	var reservedPrioritiesInbound map[int32]bool = make(map[int32]bool)
// 	var reservedPrioritiesOutbound map[int32]bool = make(map[int32]bool)
// 	if pl.Id != "" {
// 		if err != nil {
// 			log.Printf("cannot get NSG name from Permit List ID:%+v", err)
// 			return nil, err
// 		}
// 		nsgID = pl.Id
// 		nsg, err := GetSecurityGroup(ctx, nsgName)

// 		if err != nil {
// 			log.Printf("cannot get network security group:%+v", err)
// 			return nil, err
// 		}

// 		// this is only done when the nsg already exists and we need to avoid priorities conflicts
// 		fillReservedPriorities(reservedPrioritiesInbound, reservedPrioritiesOutbound, nsg)
// 	} else {
// 		nsg, err := CreateNetworkSecurityGroup(ctx, nsgName, pl.GetLocation())
// 		if err != nil {
// 			log.Printf("cannot create network security group:%+v", err)
// 			return nil, err
// 		}

// 		nsgID = *nsg.ID
// 		log.Printf("Created network security group: %s", nsgID)
// 	}

// 	properties := pl.GetProperties()

// 	// We need the the associated resource info before the rule to get the resource IP address
// 	associatedResource := properties.GetAssociatedResource()
// 	resourceNic, err := GetResourceNIC(ctx, associatedResource)
// 	if err != nil {
// 		log.Printf("cannot get resource NIC:%+v", err)
// 		return nil, err
// 	}

// 	// For each PermitListRule in the rules field, create a corresponding Network Security Rule in the NSG rule with the specified direction, src_port, dst_port, and protocol
// 	var outboundPriority int32 = 100	
// 	var inboundPriority int32 = 100
// 	seen := make(map[string]bool)
// 	for _, rule := range properties.GetRules() {
// 		// Check if there are duplicate rules in the list of given rules
// 		// TODO: should we also check on the pre-existing rules in the NSG?
// 		if(isDulicateRule(rule, seen)) {
// 			continue
// 		}

// 		// To avoid conflicted priorities, we need to check whether the priority is already used by other rules
// 		// if the priority is already used, we need to find the next available priority
// 		var priority int32
// 		if rule.Direction == invisinetspb.PermitList_INBOUND {
// 			priority = getPriority(reservedPrioritiesInbound, inboundPriority)
// 			inboundPriority = priority + 1
// 		} else if rule.Direction == invisinetspb.PermitList_OUTBOUND {
// 			priority = getPriority(reservedPrioritiesOutbound, outboundPriority)
// 			outboundPriority = priority + 1
// 		}

// 		// Create the NSG rule
// 		securityRule, err := CreateSecurityRule(ctx, rule, nsgName, *resourceNic.Properties.IPConfigurations[0].Properties.PrivateIPAddress, priority)
// 		if err != nil {
// 			log.Printf("cannot create security rule:%+v", err)
// 			return nil, err
// 		}
// 		log.Printf("Created network security rule: %s", *securityRule.ID)
// 	}

// 	// Associate the NSG rules with the specified associated_resource
// 	UpdateNetworkInterface(ctx, resourceNic, nsgID)

// 	return &invisinetspb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully set permit list with ID=%s", nsgID)}, nil
// }

func (s *azurePluginServer) GetPermitList(c context.Context, r *invisinetspb.Resource) (*invisinetspb.PermitList, error) {
	return &invisinetspb.PermitList{Id: r.Id}, nil
}

func newAzureServer() *azurePluginServer {
	s := &azurePluginServer{}
	return s
}

// fillReservedPriorities fills the reservedPriorities map with the priorities of the existing rules in the NSG
// This is done to avoid priorities conflicts when creating new rules
func fillReservedPriorities(reservedPriorities map[int32]bool, dir invisinetspb.Direction,nsg *armnetwork.SecurityGroup) {
    invisinetsToAzureDirection := directionMap[dir]
    for _, rule := range nsg.Properties.SecurityRules {
        if *rule.Properties.Direction == invisinetsToAzureDirection {
            reservedPriorities[*rule.Properties.Priority] = true
		}
    }
}

// getPriority returns the next available priority that is not used by other rules
func getPriority(reservedPriorities map[int32]bool, minPriority, maxPriority int32) int32 {
    var priority int32
    for i := minPriority; i < maxPriority; i++ {
        if _, ok := reservedPriorities[i]; !ok {
            priority = i
            break
        }
    }
    return priority
}

func isDuplicateRule(ruleDesc string, nsg *armnetwork.SecurityGroup) bool {
    for _, rule := range nsg.Properties.SecurityRules {
        if GetNSGRuleDesc(rule) == ruleDesc {
            return true
		}
    }
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
