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

// Network interface name for all VMs
const networkInterface = "nic0"

// Invisinets VPC name
const vpc = "nw-invisinets"

// Map of GCP traffic direction terminology
var firewallDirectionMapGCPToInvisinets = map[string]invisinetspb.Direction{
	"INGRESS": invisinetspb.Direction_INBOUND,
	"EGRESS":  invisinetspb.Direction_OUTBOUND,
}

var firewallDirectionMapInvisinetsToGCP = map[invisinetspb.Direction]string{
	invisinetspb.Direction_INBOUND:  "INGRESS",
	invisinetspb.Direction_OUTBOUND: "EGRESS",
}

// Maps protocol names that can appear in GCP firewall rules to IANA numbers
// https://cloud.google.com/firewall/docs/firewalls#protocols_and_ports
var protocolNumberMap = map[string]int{
	"tcp":  6,
	"udp":  17,
	"icmp": 1,
	"esp":  50,
	"ah":   51,
	"sctp": 132,
	"ipip": 94,
}

// Prefixes for tags and firewalls related to invisinets
const tagPrefix = "invisinets-permitlist-"
const firewallNamePrefix = "fw-" + tagPrefix

// GCP imposed max length for firewall
const firewallNameMaxLength = 62
const resourceNameMaxLength = 62

// Checks if GCP firewall rule is a valid Invisinets permit list rule
func isFirewallValidPermitListRule(firewall *computepb.Firewall) bool {
	return !*firewall.Disabled && strings.Compare(*firewall.Network, vpc) == 0 && strings.HasPrefix(*firewall.Name, firewallNamePrefix)
}

// Checks if GCP firewall rule is equivalent to an Invisinets permit list rule
func isFirewallEqPermitListRule(firewall *computepb.Firewall, permitListRule *invisinetspb.PermitListRule) bool {
	return isFirewallValidPermitListRule(firewall) &&
		strings.Compare(*firewall.Direction, firewallDirectionMapInvisinetsToGCP[permitListRule.Direction]) == 0 &&
		len(firewall.Allowed) == 1 &&
		strings.Compare(*firewall.Allowed[0].IPProtocol, strconv.Itoa(int(permitListRule.Protocol))) == 0 &&
		len(firewall.Allowed[0].Ports) == 1 &&
		strings.Compare(firewall.Allowed[0].Ports[0], strconv.Itoa(int(permitListRule.DstPort))) == 0
}

// Hashes values to lowercase hex string
func hash(values ...string) string {
	hash := sha256.Sum256([]byte(strings.Join(values, "")))
	return strings.ToLower(hex.EncodeToString(hash[:]))
}

func getFirewallName(permitListRule *invisinetspb.PermitListRule) string {
	return firewallNamePrefix + hash(
		strconv.Itoa(int(permitListRule.Protocol)),
		strconv.Itoa(int(permitListRule.DstPort)),
		permitListRule.Direction.String(),
		strings.Join(permitListRule.Tag, ""),
	)[:firewallNameMaxLength-len(firewallNamePrefix)]
}

// TODO @seankimkdy: understanding reusing contexts
func (s *GCPPluginServer) GetPermitList(ctx context.Context, resource *invisinetspb.Resource) (*invisinetspb.PermitList, error) {
	client, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	defer client.Close()

	// Parse resource ID in the form of {project}/{zone}/{instance}
	resourceIdSplit := strings.Split(resource.GetId(), "/")
	project, zone, instance := resourceIdSplit[0], resourceIdSplit[1], resourceIdSplit[2]

	req := &computepb.GetEffectiveFirewallsInstanceRequest{
		Instance:         instance,
		NetworkInterface: networkInterface,
		Project:          project,
		Zone:             zone,
	}
	resp, err := client.GetEffectiveFirewalls(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("unable to get effective firewalls: %w", err)
	}

	permitList := &invisinetspb.PermitList{
		AssociatedResource: resource.Id,
		Rules:              []*invisinetspb.PermitListRule{},
	}

	for _, firewall := range resp.Firewalls {
		if isFirewallValidPermitListRule(firewall) {
			permitListRules := make([]*invisinetspb.PermitListRule, len(firewall.Allowed)+len(firewall.Denied))
			for i, rule := range firewall.Allowed {
				if err != nil {
					return nil, fmt.Errorf("could not make permit list rule: %w", err)
				}
				protocolNumber, ok := protocolNumberMap[*rule.IPProtocol]
				if !ok {
					var err error
					protocolNumber, err = strconv.Atoi(*rule.IPProtocol)
					if err != nil {
						return nil, fmt.Errorf("invalid protocol: %w", err)
					}
				}
				var tag []string
				direction := firewallDirectionMapGCPToInvisinets[*firewall.Direction]
				if direction == invisinetspb.Direction_INBOUND {
					tag = append(firewall.SourceRanges, firewall.SourceTags...)
				} else {
					tag = append(firewall.DestinationRanges)
				}
				dstPort, err := strconv.Atoi(rule.Ports[0])
				if err != nil {
					return nil, fmt.Errorf("could not convert port to int")
				}
				permitListRules[i] = &invisinetspb.PermitListRule{
					Tag:       tag,
					Direction: firewallDirectionMapGCPToInvisinets[*firewall.Direction],
					DstPort:   int32(dstPort),
					Protocol:  int32(protocolNumber),
				} // SrcPort not specified since GCP doesn't support rules based on source ports
			}
			permitList.Rules = append(permitList.Rules, permitListRules...)
		}
	}

	return permitList, nil
}

func (s *GCPPluginServer) AddPermitListRules(ctx context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	firewallsClient, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewFirewallsRESTClient: %w", err)
	}
	defer firewallsClient.Close()

	resourceIdSplit := strings.Split(permitList.AssociatedResource, "/")
	project, zone, instance := resourceIdSplit[0], resourceIdSplit[1], resourceIdSplit[2]

	tag := tagPrefix + hash(zone+instance)

	for _, permitListRule := range permitList.Rules {
		// TODO @seankimkdy: should we throw an error/warning if user specifies a srcport since GCP doesn't support srcport based firewalls
		firewallName := getFirewallName(permitListRule)
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
			TargetTags:  []string{tag},
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

	// Check and add tag to VM if first time
	// TODO @seankimkdy: this should be removed once we start handling VM instance creation and just create the tag there
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	defer instancesClient.Close()

	getInstanceReq := &computepb.GetInstanceRequest{
		Instance: instance,
		Project:  project,
		Zone:     zone,
	}
	getInstanceResp, err := instancesClient.Get(ctx, getInstanceReq)
	if err != nil {
		return nil, fmt.Errorf("unable to get instance: %w", err)
	}

	for _, existingTag := range getInstanceResp.Tags.Items {
		if strings.Compare(tag, existingTag) == 0 {
			return &invisinetspb.BasicResponse{Success: true}, nil
		}
	}

	setTagsReq := &computepb.SetTagsInstanceRequest{
		Instance: instance,
		Project:  project,
		TagsResource: &computepb.Tags{
			Items:       append(getInstanceResp.Tags.Items, tag),
			Fingerprint: getInstanceResp.Tags.Fingerprint,
		},
		Zone: zone,
	}

	setTagsOp, err := instancesClient.SetTags(ctx, setTagsReq)
	if err != nil {
		return nil, fmt.Errorf("unable to set tags: %w", err)
	}
	if err = setTagsOp.Wait(ctx); err != nil {
		return nil, fmt.Errorf("unable to wait for the operation: %w", err)
	}

	return &invisinetspb.BasicResponse{Success: true}, nil
}

func (s *GCPPluginServer) DeletePermitListRules(ctx context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	defer instancesClient.Close()

	resourceIdSplit := strings.Split(permitList.AssociatedResource, "/")
	project, zone, instance := resourceIdSplit[0], resourceIdSplit[1], resourceIdSplit[2]

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

	firewallsClient, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewFirewallsRESTClient: %w", err)
	}
	defer firewallsClient.Close()

	firewallMap := map[string]*computepb.Firewall{}
	for _, firewall := range getEffectiveFirewallsResp.Firewalls {
		firewallMap[*firewall.Name] = firewall
	}

	for _, permitListRule := range permitList.Rules {
		firewall, ok := firewallMap[getFirewallName(permitListRule)]
		if ok && isFirewallValidPermitListRule(firewall) && isFirewallEqPermitListRule(firewall, permitListRule) {
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
			return nil, nil
		}
	}

	return nil, fmt.Errorf("could not find specified firewall")
}
