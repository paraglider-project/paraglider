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

package gcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"google.golang.org/protobuf/proto"
)

type GCPPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
}

// GCP
const (
	networkInterface      = "nic0"
	vpc                   = "nw-invisinets"          // Invisinets VPC name
	networkTagPrefix      = "invisinets-permitlist-" // Prefixe for GCP tags related to invisinets
	firewallNamePrefix    = "fw-" + networkTagPrefix // Prefixe for firewall names related to invisinets
	firewallNameMaxLength = 62                       // GCP imposed max length for firewall name
)

// Maps between of GCP and Invisinets traffic direction terminologies
var (
	firewallDirectionMapGCPToInvisinets = map[string]invisinetspb.Direction{
		"INGRESS": invisinetspb.Direction_INBOUND,
		"EGRESS":  invisinetspb.Direction_OUTBOUND,
	}

	firewallDirectionMapInvisinetsToGCP = map[invisinetspb.Direction]string{
		invisinetspb.Direction_INBOUND:  "INGRESS",
		invisinetspb.Direction_OUTBOUND: "EGRESS",
	}
)

// Checks if GCP firewall rule is an Invisinets permit list rule
func isInvisinetsPermitListRule(firewall *computepb.Firewall) bool {
	return strings.Compare(*firewall.Network, vpc) == 0 && strings.HasPrefix(*firewall.Name, firewallNamePrefix)
}

// Checks if GCP firewall rule is equivalent to an Invisinets permit list rule
func isFirewallEqPermitListRule(firewall *computepb.Firewall, permitListRule *invisinetspb.PermitListRule) bool {
	return isInvisinetsPermitListRule(firewall) &&
		strings.Compare(*firewall.Direction, firewallDirectionMapInvisinetsToGCP[permitListRule.Direction]) == 0 &&
		len(firewall.Allowed) == 1 &&
		strings.Compare(*firewall.Allowed[0].IPProtocol, strconv.Itoa(int(permitListRule.Protocol))) == 0 &&
		len(firewall.Allowed[0].Ports) == 1 &&
		strings.Compare(firewall.Allowed[0].Ports[0], strconv.Itoa(int(permitListRule.DstPort))) == 0
}

// Splits a resource id in the form of {project}/{zone}/{instance}
func splitResourceId(resourceId string) (string, string, string) {
	resourceIdSplit := strings.Split(resourceId, "/")
	return resourceIdSplit[0], resourceIdSplit[1], resourceIdSplit[2]
}

// Hashes values to lowercase hex string for use in naming GCP resources
func hash(values ...string) string {
	hash := sha256.Sum256([]byte(strings.Join(values, "")))
	return strings.ToLower(hex.EncodeToString(hash[:]))
}

// Gets a GCP firewall rule name for an Invisinets permit list rule
// If two Invisinets permit list rules are equal, then they will have the same GCP firewall rule name.
func getFirewallName(permitListRule *invisinetspb.PermitListRule) string {
	return (firewallNamePrefix + hash(
		strconv.Itoa(int(permitListRule.Protocol)),
		strconv.Itoa(int(permitListRule.DstPort)),
		permitListRule.Direction.String(),
		strings.Join(permitListRule.Tag, ""),
	))[:firewallNameMaxLength]
}

func (s *GCPPluginServer) _GetPermitList(ctx context.Context, resource *invisinetspb.Resource, instancesClient *compute.InstancesClient) (*invisinetspb.PermitList, error) {
	project, zone, instance := splitResourceId(resource.Id)

	req := &computepb.GetEffectiveFirewallsInstanceRequest{
		Instance:         instance,
		NetworkInterface: networkInterface,
		Project:          project,
		Zone:             zone,
	}
	resp, err := instancesClient.GetEffectiveFirewalls(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("unable to get effective firewalls: %w", err)
	}

	permitList := &invisinetspb.PermitList{
		AssociatedResource: resource.Id,
		Rules:              []*invisinetspb.PermitListRule{},
	}

	for _, firewall := range resp.Firewalls {
		if isInvisinetsPermitListRule(firewall) {
			permitListRules := make([]*invisinetspb.PermitListRule, len(firewall.Allowed))
			for i, rule := range firewall.Allowed {
				protocolNumber, err := strconv.Atoi(*rule.IPProtocol)
				if err != nil {
					return nil, fmt.Errorf("could not convert protocol number to")
				}

				direction := firewallDirectionMapGCPToInvisinets[*firewall.Direction]

				var tag []string
				if direction == invisinetspb.Direction_INBOUND {
					tag = append(firewall.SourceRanges, firewall.SourceTags...)
				} else {
					tag = firewall.DestinationRanges
				}

				var dstPort int
				if len(rule.Ports) == 0 {
					dstPort = 0
				} else {
					dstPort, err = strconv.Atoi(rule.Ports[0])
					if err != nil {
						return nil, fmt.Errorf("could not convert port to int")
					}
				}

				permitListRules[i] = &invisinetspb.PermitListRule{
					Direction: firewallDirectionMapGCPToInvisinets[*firewall.Direction],
					DstPort:   int32(dstPort),
					Protocol:  int32(protocolNumber),
					Tag:       tag,
				} // SrcPort not specified since GCP doesn't support rules based on source ports
			}
			permitList.Rules = append(permitList.Rules, permitListRules...)
		}
	}

	return permitList, nil
}

func (s *GCPPluginServer) GetPermitList(ctx context.Context, resource *invisinetspb.Resource) (*invisinetspb.PermitList, error) {
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	defer instancesClient.Close()
	return s._GetPermitList(ctx, resource, instancesClient)
}

func (s *GCPPluginServer) _AddPermitListRules(ctx context.Context, permitList *invisinetspb.PermitList, firewallsClient *compute.FirewallsClient, instancesClient *compute.InstancesClient) (*invisinetspb.BasicResponse, error) {
	project, zone, instance := splitResourceId(permitList.AssociatedResource)
	getEffectiveFirewallsReq := &computepb.GetEffectiveFirewallsInstanceRequest{
		Instance:         instance,
		NetworkInterface: networkInterface,
		Project:          project,
		Zone:             zone,
	}
	getEffectiveFirewallsResp, err := instancesClient.GetEffectiveFirewalls(ctx, getEffectiveFirewallsReq)
	if err != nil {
		return nil, fmt.Errorf("unable to get effective firewalls: %w", err)
	}

	firewallMap := map[string]*computepb.Firewall{}
	for _, firewall := range getEffectiveFirewallsResp.Firewalls {
		firewallMap[*firewall.Name] = firewall
	}

	// Get GCP network tag corresponding to VM
	getInstanceReq := &computepb.GetInstanceRequest{
		Instance: instance,
		Project:  project,
		Zone:     zone,
	}
	getInstanceResp, err := instancesClient.Get(ctx, getInstanceReq)
	if err != nil {
		return nil, fmt.Errorf("unable to get instance: %w", err)
	}
	networkTag := networkTagPrefix + strconv.FormatUint(*getInstanceResp.Id, 10)

	for _, permitListRule := range permitList.Rules {
		// TODO @seankimkdy: should we throw an error/warning if user specifies a srcport since GCP doesn't support srcport based firewalls?
		firewallName := getFirewallName(permitListRule)

		// Skip existing permit lists rules
		if _, ok := firewallMap[getFirewallName(permitListRule)]; ok {
			continue
		}

		firewall := &computepb.Firewall{
			Allowed: []*computepb.Allowed{
				{
					IPProtocol: proto.String(strconv.Itoa(int(permitListRule.Protocol))),
					Ports:      []string{strconv.Itoa(int(permitListRule.DstPort))},
				},
			},
			Description: proto.String("Invisinets permit list"),
			Direction:   proto.String(firewallDirectionMapInvisinetsToGCP[permitListRule.Direction]),
			Name:        proto.String(firewallName),
			Network:     proto.String(vpc),
			TargetTags:  []string{networkTag},
		}
		if permitListRule.Direction == invisinetspb.Direction_INBOUND {
			// TODO @seankimkdy: use SourceTags as well once we start supporting tags
			firewall.SourceRanges = permitListRule.Tag
		} else {
			firewall.DestinationRanges = permitListRule.Tag
		}
		insertFirewallReq := &computepb.InsertFirewallRequest{
			Project:          project,
			FirewallResource: firewall,
		}
		insertFirewallOp, err := firewallsClient.Insert(ctx, insertFirewallReq)
		if err != nil {
			return nil, fmt.Errorf("unable to create firewall rule: %w", err)
		}

		if err = insertFirewallOp.Wait(ctx); err != nil {
			return nil, fmt.Errorf("unable to wait for the operation: %w", err)
		}
	}

	return &invisinetspb.BasicResponse{Success: true}, nil
}

func (s *GCPPluginServer) AddPermitListRules(ctx context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	firewallsClient, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewFirewallsRESTClient: %w", err)
	}
	defer firewallsClient.Close()

	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	defer instancesClient.Close()

	return s._AddPermitListRules(ctx, permitList, firewallsClient, instancesClient)
}

func (s *GCPPluginServer) _DeletePermitListRules(ctx context.Context, permitList *invisinetspb.PermitList, firewallsClient *compute.FirewallsClient, instancesClient *compute.InstancesClient) (*invisinetspb.BasicResponse, error) {
	project, zone, instance := splitResourceId(permitList.AssociatedResource)

	getEffectiveFirewallsReq := &computepb.GetEffectiveFirewallsInstanceRequest{
		Instance:         instance,
		NetworkInterface: networkInterface,
		Project:          project,
		Zone:             zone,
	}
	getEffectiveFirewallsResp, err := instancesClient.GetEffectiveFirewalls(ctx, getEffectiveFirewallsReq)
	if err != nil {
		return nil, fmt.Errorf("unable to get effective firewalls: %w", err)
	}

	firewallMap := map[string]*computepb.Firewall{}
	for _, firewall := range getEffectiveFirewallsResp.Firewalls {
		firewallMap[*firewall.Name] = firewall
	}

	for _, permitListRule := range permitList.Rules {
		firewall, ok := firewallMap[getFirewallName(permitListRule)]
		if ok && isInvisinetsPermitListRule(firewall) && isFirewallEqPermitListRule(firewall, permitListRule) {
			deleteFirewallReq := &computepb.DeleteFirewallRequest{
				Firewall: *firewall.Name,
				Project:  project,
			}
			deleteFirewallOp, err := firewallsClient.Delete(ctx, deleteFirewallReq)
			if err != nil {
				return nil, fmt.Errorf("unable to delete firewall: %w", err)
			}
			if err = deleteFirewallOp.Wait(ctx); err != nil {
				return nil, fmt.Errorf("unable to wait for the operation: %w", err)
			}
		}
	}

	return &invisinetspb.BasicResponse{Success: true}, nil
}

func (s *GCPPluginServer) DeletePermitListRules(ctx context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	firewallsClient, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewFirewallsRESTClient: %w", err)
	}
	defer firewallsClient.Close()

	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	defer instancesClient.Close()

	return s._DeletePermitListRules(ctx, permitList, firewallsClient, instancesClient)
}
