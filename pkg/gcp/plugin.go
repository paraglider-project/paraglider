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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

type GCPPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
}

// GCP naming conventions
// Those declared var may be modified in init() for integration testing
// None of these should be used to define other global variables. If needed, make a separate function (like getVPCURL).
var (
	vpcName                      = "invisinets-vpc" // Invisinets VPC name
	subnetworkNamePrefix         = "invisinets-"
	networkTagPrefix             = "invisinets-permitlist-" // Prefix for GCP tags related to invisinets
	firewallNamePrefix           = "fw-" + networkTagPrefix // Prefix for firewall names related to invisinets
	vpnGwName                    = "invisinets-vpn-gw"
	routerName                   = "invisinets-router"
	peerGwNamePrefix             = "invisinets-"
	peerGwNameSuffix             = "-peer-gw"
	vpnTunnelNamePrefix          = "invisinets-"
	vpnTunnelNameSuffix          = "-tunnel-"
	vpnTunnelInterfaceNameSuffix = "-int-"
	bgpPeerNamePrefix            = "invisinets-bgp-peer-"
)

const (
	subnetworkNameSuffix  = "-subnet"
	networkInterface      = "nic0"
	firewallNameMaxLength = 62 // GCP imposed max length for firewall name
	computeURLPrefix      = "https://www.googleapis.com/compute/v1/"
	ikeVersion            = 2
)

// TODO @seankimkdy: replace these
const (
	vpnProject        = "invisinets-playground"
	vpnRegion         = "us-west1"
	vpnGwAsn          = 64512 // TODO @seankimkdy: this should not be constant and rotate incrementally everytime a new gateway is created
	vpnNumConnections = 2
)

var vpnGwBgpIpAddrs = []string{"169.254.21.2", "169.254.22.2"} // TODO @seankimkdy: change to be dynamic and dependent on peering cloud (e.g. Azure needs APIPA)

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

// Maps protocol names that can appear in GCP firewall rules to IANA numbers (see https://cloud.google.com/firewall/docs/firewalls#protocols_and_ports)
var gcpProtocolNumberMap = map[string]int{
	"tcp":  6,
	"udp":  17,
	"icmp": 1,
	"esp":  50,
	"ah":   51,
	"sctp": 132,
	"ipip": 94,
}

// Frontend server address
// TODO @seankimkdy: dynamically configure with config
// TODO @seankimkdy: temporarily exported until we figure a better way to set this from another package (e.g. multicloud tests)
var FrontendServerAddr string

func init() {
	githubRunPrefix := utils.GetGitHubRunPrefix()
	// Prefix resource names with GitHub workflow run numbers to avoid resource name clashes during integration tests
	vpcName = githubRunPrefix + vpcName
	subnetworkNamePrefix = githubRunPrefix + subnetworkNamePrefix
	networkTagPrefix = githubRunPrefix + networkTagPrefix
	firewallNamePrefix = githubRunPrefix + firewallNamePrefix
	vpnGwName = githubRunPrefix + vpnGwName
	routerName = githubRunPrefix + routerName
	peerGwNamePrefix = githubRunPrefix + peerGwNamePrefix
	vpnTunnelNamePrefix = githubRunPrefix + vpnTunnelNamePrefix
	bgpPeerNamePrefix = githubRunPrefix + bgpPeerNamePrefix
}

// Checks if GCP firewall rule is an Invisinets permit list rule
func isInvisinetsPermitListRule(firewall *computepb.Firewall) bool {
	return strings.HasSuffix(*firewall.Network, getVPCURL()) && strings.HasPrefix(*firewall.Name, firewallNamePrefix)
}

// Checks if GCP firewall rule is equivalent to an Invisinets permit list rule
func isFirewallEqPermitListRule(firewall *computepb.Firewall, permitListRule *invisinetspb.PermitListRule) bool {
	if !isInvisinetsPermitListRule(firewall) {
		return false
	}
	if *firewall.Direction != firewallDirectionMapInvisinetsToGCP[permitListRule.Direction] {
		return false
	}
	if len(firewall.Allowed) != 1 {
		return false
	}
	protocolNumber, err := getProtocolNumber(*firewall.Allowed[0].IPProtocol)
	if err != nil {
		return false
	}
	if protocolNumber != permitListRule.Protocol {
		return false
	}
	if len(firewall.Allowed[0].Ports) == 0 && permitListRule.DstPort != -1 {
		return false
	}
	if len(firewall.Allowed[0].Ports) == 1 && firewall.Allowed[0].Ports[0] != strconv.Itoa(int(permitListRule.DstPort)) {
		return false
	}
	return true
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

// Gets a GCP network tag for a GCP resource
func getGCPNetworkTag(gcpResourceId uint64) string {
	return networkTagPrefix + strconv.FormatUint(gcpResourceId, 10)
}

// Gets a GCP subnetwork name for Invisinets based on region
func getGCPSubnetworkName(region string) string {
	return subnetworkNamePrefix + region + subnetworkNameSuffix
}

// Gets protocol number from GCP specificiation (either a name like "tcp" or an int-string like "6")
func getProtocolNumber(firewallProtocol string) (int32, error) {
	protocolNumber, ok := gcpProtocolNumberMap[firewallProtocol]
	if !ok {
		var err error
		protocolNumber, err = strconv.Atoi(firewallProtocol)
		if err != nil {
			return 0, fmt.Errorf("could not convert GCP firewall protocol to protocol number")
		}
	}
	return int32(protocolNumber), nil
}

// Parses GCP compute URL for desired fields
func parseGCPURL(url string) map[string]string {
	path := strings.TrimPrefix(url, computeURLPrefix)
	parsedURL := map[string]string{}
	pathComponents := strings.Split(path, "/")
	for i := 0; i < len(pathComponents)-1; i += 2 {
		parsedURL[pathComponents[i]] = pathComponents[i+1]
	}
	return parsedURL
}

// Splits a instance id which follows the GCP URL form the form of projects/{project}/zones/{zone}/instances/{instance}
func parseInstanceId(instanceId string) (string, string, string) {
	parsedInstanceId := parseGCPURL(instanceId)
	return parsedInstanceId["projects"], parsedInstanceId["zones"], parsedInstanceId["instances"]
}

// Returns a GCP URL format of vpc
func getVPCURL() string {
	return "global/networks/" + vpcName
}

func getVpnGwUri(project, region, vpnGwName string) string {
	return computeURLPrefix + fmt.Sprintf("projects/%s/regions/%s/vpnGateways/%s", project, region, vpnGwName)
}

// Returns a full GCP URI of a VPN tunnel
func getVpnTunnelUri(project, region, vpnTunnelName string) string {
	return computeURLPrefix + fmt.Sprintf("projects/%s/regions/%s/vpnTunnels/%s", project, region, vpnTunnelName)
}

func getPeerGwUri(project, peerGwName string) string {
	return computeURLPrefix + fmt.Sprintf("projects/%s/global/externalVpnGateways/%s", project, peerGwName)
}

func getRouterUri(project, region, routerName string) string {
	return computeURLPrefix + fmt.Sprintf("projects/%s/regions/%s/routers/%s", project, region, routerName)
}

// Returns a peer gateway name when connecting to another cloud
func getPeerGwName(cloud string) string {
	return peerGwNamePrefix + cloud + peerGwNameSuffix
}

// Returns a VPN tunnel name when connecting to another cloud
func getVpnTunnelName(cloud string, tunnelIdx int) string {
	return vpnTunnelNamePrefix + cloud + vpnTunnelNameSuffix + strconv.Itoa(tunnelIdx)
}

// Returns a VPN tunnel interface name when connecting to another cloud
func getVpnTunnelInterfaceName(cloud string, tunnelIdx int, interfaceIdx int) string {
	return getVpnTunnelName(cloud, tunnelIdx) + vpnTunnelInterfaceNameSuffix + strconv.Itoa(interfaceIdx)
}

// Returns a BGP peer name
func getBgpPeerName(cloud string, peerIdx int) string {
	return bgpPeerNamePrefix + cloud + "-" + strconv.Itoa(peerIdx)
}

func (s *GCPPluginServer) _GetPermitList(ctx context.Context, resourceID *invisinetspb.ResourceID, instancesClient *compute.InstancesClient) (*invisinetspb.PermitList, error) {
	project, zone, instance := parseInstanceId(resourceID.Id)

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
		AssociatedResource: resourceID.Id,
		Rules:              []*invisinetspb.PermitListRule{},
	}

	for _, firewall := range resp.Firewalls {
		if isInvisinetsPermitListRule(firewall) {
			permitListRules := make([]*invisinetspb.PermitListRule, len(firewall.Allowed))
			for i, rule := range firewall.Allowed {
				protocolNumber, err := getProtocolNumber(*rule.IPProtocol)
				if err != nil {
					return nil, fmt.Errorf("could not get protocol number: %w", err)
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
					dstPort = -1
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

func (s *GCPPluginServer) GetPermitList(ctx context.Context, resourceID *invisinetspb.ResourceID) (*invisinetspb.PermitList, error) {
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	defer instancesClient.Close()
	return s._GetPermitList(ctx, resourceID, instancesClient)
}

func (s *GCPPluginServer) _AddPermitListRules(ctx context.Context, permitList *invisinetspb.PermitList, firewallsClient *compute.FirewallsClient, instancesClient *compute.InstancesClient) (*invisinetspb.BasicResponse, error) {
	project, zone, instance := parseInstanceId(permitList.AssociatedResource)

	// Get existing firewalls
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

	existingFirewalls := map[string]bool{}
	for _, firewall := range getEffectiveFirewallsResp.Firewalls {
		existingFirewalls[*firewall.Name] = true
	}

	// Get GCP network tag corresponding to VM (which will have been set during resource creation)
	getInstanceReq := &computepb.GetInstanceRequest{
		Instance: instance,
		Project:  project,
		Zone:     zone,
	}
	getInstanceResp, err := instancesClient.Get(ctx, getInstanceReq)
	if err != nil {
		return nil, fmt.Errorf("unable to get instance: %w", err)
	}
	networkTag := getGCPNetworkTag(*getInstanceResp.Id)

	// Get used address spaces of all clouds
	conn, err := grpc.Dial(FrontendServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("unable to establish connection with frontend: %w", err)
	}
	defer conn.Close()
	client := invisinetspb.NewControllerClient(conn)
	usedAddressSpaceMappings, err := client.GetUsedAddressSpaces(context.Background(), &invisinetspb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("unable to get used address spaces: %w", err)
	}

	for _, permitListRule := range permitList.Rules {
		// TODO @seankimkdy: should we throw an error/warning if user specifies a srcport since GCP doesn't support srcport based firewalls?
		firewallName := getFirewallName(permitListRule)

		// Skip existing permit lists rules
		if existingFirewalls[firewallName] {
			continue
		}

		// Skip public ip addresses
		for _, tag := range permitListRule.Tag {
			isPrivate, err := utils.IsAddressPrivate(tag)
			if err != nil {
				return nil, err
			}
			if isPrivate {
				var cloud string
				for _, usedAddressSpaces := range usedAddressSpaceMappings.AddressSpaceMappings {
					for _, usedAddressSpace := range usedAddressSpaces.AddressSpaces {
						contained, err := utils.IsPermitListRuleTagInAddressSpace(tag, usedAddressSpace)
						if err != nil {
							return nil, err
						}
						if contained {
							cloud = usedAddressSpaces.Cloud
							break
						}
					}
				}
				if cloud == "" {
					return nil, fmt.Errorf("permit list rule tag must belong to a specific cloud if it's a private address")
				} else if cloud != utils.GCP {
					_, err := client.ConnectClouds(ctx, &invisinetspb.ConnectCloudsRequest{CloudA: utils.GCP, CloudB: cloud})
					if err != nil {
						return nil, fmt.Errorf("unsuccessful in connecting clouds: %w", err)
					}
				}
			}
		}

		firewall := &computepb.Firewall{
			Allowed: []*computepb.Allowed{
				{
					IPProtocol: proto.String(strconv.Itoa(int(permitListRule.Protocol))),
				},
			},
			Description: proto.String("Invisinets permit list"),
			Direction:   proto.String(firewallDirectionMapInvisinetsToGCP[permitListRule.Direction]),
			Name:        proto.String(firewallName),
			Network:     proto.String(getVPCURL()),
			TargetTags:  []string{networkTag},
		}
		if permitListRule.DstPort != -1 {
			// Users must explicitly set DstPort to -1 if they want it to apply to all ports since proto can't
			// differentiate between empty and 0 for an int field. Ports of 0 are valid for protocols like TCP/UDP.
			firewall.Allowed[0].Ports = []string{strconv.Itoa(int(permitListRule.DstPort))}
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

		existingFirewalls[firewallName] = true
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
	project, zone, instance := parseInstanceId(permitList.AssociatedResource)

	// Get existing firewalls
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

	// Delete firewalls corresponding to provided permit list rules
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

func (s *GCPPluginServer) _CreateResource(ctx context.Context, resourceDescription *invisinetspb.ResourceDescription, instancesClient *compute.InstancesClient, networksClient *compute.NetworksClient, subnetworksClient *compute.SubnetworksClient) (*invisinetspb.BasicResponse, error) {
	// Validate user-provided description
	insertInstanceRequest := &computepb.InsertInstanceRequest{}
	err := json.Unmarshal(resourceDescription.Description, insertInstanceRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource description: %w", err)
	}
	if len(insertInstanceRequest.InstanceResource.NetworkInterfaces) != 0 {
		return nil, fmt.Errorf("network settings should not be specified")
	}

	project, zone := insertInstanceRequest.Project, insertInstanceRequest.Zone
	region := zone[:strings.LastIndex(zone, "-")]
	subnetName := getGCPSubnetworkName(region)
	subnetExists := false

	// Check if Invisinets specific VPC already exists
	getNetworkReq := &computepb.GetNetworkRequest{
		Network: vpcName,
		Project: project,
	}
	getNetworkResp, err := networksClient.Get(ctx, getNetworkReq)
	if err != nil {
		var e *googleapi.Error
		if ok := errors.As(err, &e); ok && e.Code == http.StatusNotFound {
			insertNetworkRequest := &computepb.InsertNetworkRequest{
				Project: project,
				NetworkResource: &computepb.Network{
					Name:                  proto.String(vpcName),
					Description:           proto.String("VPC for Invisinets"),
					AutoCreateSubnetworks: proto.Bool(false),
					RoutingConfig: &computepb.NetworkRoutingConfig{
						RoutingMode: proto.String(computepb.NetworkRoutingConfig_GLOBAL.String()),
					},
				},
			}
			insertNetworkOp, err := networksClient.Insert(ctx, insertNetworkRequest)
			if err != nil {
				return nil, fmt.Errorf("unable to insert network: %w", err)
			}
			if err = insertNetworkOp.Wait(ctx); err != nil {
				return nil, fmt.Errorf("unable to wait for the operation: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to get invisinets vpc network: %w", err)
		}
	} else {
		// Check if there is a subnet in the region that resource will be placed in
		for _, subnetURL := range getNetworkResp.Subnetworks {
			parsedSubnetURL := parseGCPURL(subnetURL)
			if subnetName == parsedSubnetURL["subnetworks"] {
				subnetExists = true
				break
			}
		}
	}

	if !subnetExists {
		// Find unused address spaces
		// TODO @seankimkdy: instead of reading the config, we could alternatively have the frontend include the IP address of the server as part of resourceDescription?
		conn, err := grpc.Dial(FrontendServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("unable to establish connection with frontend: %w", err)
		}
		defer conn.Close()
		client := invisinetspb.NewControllerClient(conn)
		response, err := client.FindUnusedAddressSpace(context.Background(), &invisinetspb.Empty{})
		if err != nil {
			return nil, fmt.Errorf("unable to find unused address space: %w", err)
		}

		insertSubnetworkRequest := &computepb.InsertSubnetworkRequest{
			Project: project,
			Region:  region,
			SubnetworkResource: &computepb.Subnetwork{
				Name:        proto.String(subnetName),
				Description: proto.String("Invisinets subnetwork for " + region),
				Network:     proto.String(getVPCURL()),
				IpCidrRange: proto.String(response.Address),
			},
		}
		insertSubnetworkOp, err := subnetworksClient.Insert(ctx, insertSubnetworkRequest)
		if err != nil {
			return nil, fmt.Errorf("unable to insert subnetwork: %w", err)
		}
		if err = insertSubnetworkOp.Wait(ctx); err != nil {
			return nil, fmt.Errorf("unable to wait for the operation: %w", err)
		}
	}

	// Configure network settings to Invisinets VPC and corresponding subnet
	insertInstanceRequest.InstanceResource.NetworkInterfaces = []*computepb.NetworkInterface{
		{
			Network:    proto.String(getVPCURL()),
			Subnetwork: proto.String("regions/" + region + "/subnetworks/" + subnetName),
		},
	}

	// Insert instance
	insertInstanceOp, err := instancesClient.Insert(ctx, insertInstanceRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to insert instance: %w", err)
	}
	if err = insertInstanceOp.Wait(ctx); err != nil {
		return nil, fmt.Errorf("unable to wait for the operation: %w", err)
	}

	// Add network tag which will be used by GCP firewall rules corresponding to Invisinets permit list rules
	// The instance is fetched again as the Id which is used to create the tag is only available after instance creation
	instance := *insertInstanceRequest.InstanceResource.Name
	getInstanceReq := &computepb.GetInstanceRequest{
		Instance: instance,
		Project:  project,
		Zone:     zone,
	}
	getInstanceResp, err := instancesClient.Get(ctx, getInstanceReq)
	if err != nil {
		return nil, fmt.Errorf("unable to get instance: %w", err)
	}
	setTagsReq := &computepb.SetTagsInstanceRequest{
		Instance: instance,
		Project:  project,
		Zone:     zone,
		TagsResource: &computepb.Tags{
			Items:       append(getInstanceResp.Tags.Items, getGCPNetworkTag(*getInstanceResp.Id)),
			Fingerprint: getInstanceResp.Tags.Fingerprint,
		},
	}
	setTagsOp, err := instancesClient.SetTags(ctx, setTagsReq)
	if err != nil {
		return nil, fmt.Errorf("unable to set tags: %w", err)
	}
	if err = setTagsOp.Wait(ctx); err != nil {
		return nil, fmt.Errorf("unable to wait for the operation")
	}

	return &invisinetspb.BasicResponse{Success: true}, nil
}

func (s *GCPPluginServer) CreateResource(ctx context.Context, resourceDescription *invisinetspb.ResourceDescription) (*invisinetspb.BasicResponse, error) {
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	defer instancesClient.Close()

	networksClient, err := compute.NewNetworksRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewNetworksRESTClient: %w", err)
	}
	defer networksClient.Close()

	subnetworksClient, err := compute.NewSubnetworksRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewSubnetworksRESTClient: %w", err)
	}
	defer subnetworksClient.Close()

	return s._CreateResource(ctx, resourceDescription, instancesClient, networksClient, subnetworksClient)
}

func (s *GCPPluginServer) _GetUsedAddressSpaces(ctx context.Context, invisinetsDeployment *invisinetspb.InvisinetsDeployment, networksClient *compute.NetworksClient, subnetworksClient *compute.SubnetworksClient) (*invisinetspb.AddressSpaceList, error) {
	project := parseGCPURL(invisinetsDeployment.Id)["projects"]
	addressSpaceList := &invisinetspb.AddressSpaceList{}

	getNetworkReq := &computepb.GetNetworkRequest{
		Network: vpcName,
		Project: project,
	}
	getNetworkResp, err := networksClient.Get(ctx, getNetworkReq)
	if err != nil {
		var e *googleapi.Error
		if ok := errors.As(err, &e); ok && e.Code == http.StatusNotFound {
			return addressSpaceList, nil
		} else {
			return nil, fmt.Errorf("failed to get invisinets vpc network: %w", err)
		}
	} else {
		addressSpaceList.AddressSpaces = make([]string, len(getNetworkResp.Subnetworks))
		for i, subnetURL := range getNetworkResp.Subnetworks {
			parsedSubnetURL := parseGCPURL(subnetURL)
			getSubnetworkRequest := &computepb.GetSubnetworkRequest{
				Project:    project,
				Region:     parsedSubnetURL["regions"],
				Subnetwork: parsedSubnetURL["subnetworks"],
			}
			getSubnetworkResp, err := subnetworksClient.Get(ctx, getSubnetworkRequest)
			if err != nil {
				return nil, fmt.Errorf("failed to get invisinets subnetwork: %w", err)
			}
			addressSpaceList.AddressSpaces[i] = *getSubnetworkResp.IpCidrRange
		}
	}

	return addressSpaceList, nil
}

func (s *GCPPluginServer) GetUsedAddressSpaces(ctx context.Context, invisinetsDeployment *invisinetspb.InvisinetsDeployment) (*invisinetspb.AddressSpaceList, error) {
	networksClient, err := compute.NewNetworksRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewNetworksRESTClient: %w", err)
	}
	defer networksClient.Close()

	subnetworksClient, err := compute.NewSubnetworksRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewSubnetworksRESTClient: %w", err)
	}
	defer subnetworksClient.Close()

	return s._GetUsedAddressSpaces(ctx, invisinetsDeployment, networksClient, subnetworksClient)
}

func (s *GCPPluginServer) _CreateVpnGateway(ctx context.Context, cloud string, vpnGatewaysClient *compute.VpnGatewaysClient, routersClient *compute.RoutersClient) (*utils.CreateVpnGatewayResponse, error) {
	// TODO @seankimkdy: check if gateway already exists and return information from there

	// Create VPN gateway
	insertVpnGatewayReq := &computepb.InsertVpnGatewayRequest{
		Project: vpnProject,
		Region:  vpnRegion,
		VpnGatewayResource: &computepb.VpnGateway{
			Name:        proto.String(vpnGwName),
			Description: proto.String("Invisinets VPN gateway for multicloud connections"),
			Network:     proto.String(getVPCURL()),
		},
	}
	insertVpnGatewayOp, err := vpnGatewaysClient.Insert(ctx, insertVpnGatewayReq)
	if err != nil {
		return nil, fmt.Errorf("unable to insert vpn gateway: %w", err)
	}
	if err = insertVpnGatewayOp.Wait(ctx); err != nil {
		return nil, fmt.Errorf("unable to wait on insert vpn gateway operation: %w", err)
	}

	// Create router
	insertRouterReq := &computepb.InsertRouterRequest{
		Project: vpnProject,
		Region:  vpnRegion,
		RouterResource: &computepb.Router{
			Name:        proto.String(routerName),
			Description: proto.String("Invisinets router for multicloud connections"),
			Network:     proto.String(getVPCURL()),
			Bgp: &computepb.RouterBgp{
				Asn: proto.Uint32(vpnGwAsn),
			},
		},
	}
	insertRouterOp, err := routersClient.Insert(ctx, insertRouterReq)
	if err != nil {
		return nil, fmt.Errorf("unable to insert router: %w", err)
	}
	if err = insertRouterOp.Wait(ctx); err != nil {
		return nil, fmt.Errorf("unable to wait on insert router operation: %w", err)
	}

	// Get gateway interface IP addresses
	getVpnGatewayReq := &computepb.GetVpnGatewayRequest{
		Project:    vpnProject,
		Region:     vpnRegion,
		VpnGateway: vpnGwName,
	}
	vpnGateway, err := vpnGatewaysClient.Get(ctx, getVpnGatewayReq)
	if err != nil {
		return nil, fmt.Errorf("unable to get vpn gateway: %w", err)
	}

	resp := &utils.CreateVpnGatewayResponse{Asn: vpnGwAsn}
	resp.InterfaceIps = make([]string, vpnNumConnections)
	for i := 0; i < vpnNumConnections; i++ {
		resp.InterfaceIps[i] = *vpnGateway.VpnInterfaces[i].IpAddress
	}

	return resp, nil
}

func (s *GCPPluginServer) CreateVpnGateway(ctx context.Context, cloud string) (*utils.CreateVpnGatewayResponse, error) {
	vpnGatewaysClient, err := compute.NewVpnGatewaysRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewVpnGatewaysRESTClient: %w", err)
	}
	defer vpnGatewaysClient.Close()
	routersClient, err := compute.NewRoutersRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewRoutersRESTClient: %w", err)
	}
	defer routersClient.Close()
	return s._CreateVpnGateway(ctx, cloud, vpnGatewaysClient, routersClient)
}

func (s *GCPPluginServer) _CreateVpnBgp(ctx context.Context, cloud string, routersClient *compute.RoutersClient) ([]string, error) {
	patchRouterReq := &computepb.PatchRouterRequest{
		Project:        vpnProject,
		Region:         vpnRegion,
		Router:         routerName,
		RouterResource: &computepb.Router{},
	}
	patchRouterReq.RouterResource.Interfaces = make([]*computepb.RouterInterface, vpnNumConnections)
	for i := 0; i < vpnNumConnections; i++ {
		patchRouterReq.RouterResource.Interfaces[i] = &computepb.RouterInterface{
			Name:            proto.String(getVpnTunnelInterfaceName(cloud, i, i)),
			IpRange:         proto.String(vpnGwBgpIpAddrs[i] + "/30"),
			LinkedVpnTunnel: proto.String(getVpnTunnelUri(vpnProject, vpnRegion, getVpnTunnelName(cloud, i))),
		}
	}
	patchRouterOp, err := routersClient.Patch(ctx, patchRouterReq)
	if err != nil {
		return nil, fmt.Errorf("unable to patch router: %w", err)
	}
	if err = patchRouterOp.Wait(ctx); err != nil {
		return nil, fmt.Errorf("unable to wait on patch router operation: %w", err)
	}

	return vpnGwBgpIpAddrs, nil
}

func (s *GCPPluginServer) CreateVpnBgp(ctx context.Context, cloud string) ([]string, error) {
	routersClient, err := compute.NewRoutersRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewRoutersRESTClient: %w", err)
	}
	defer routersClient.Close()

	return s._CreateVpnBgp(ctx, cloud, routersClient)
}

func (s *GCPPluginServer) _CreateVpnConnections(ctx context.Context, cloud string, asn int64, addressSpace string, interfaceIps []string, bgpIps []string, sharedKey string, externalVpnGatewaysClient *compute.ExternalVpnGatewaysClient, vpnTunnelsClient *compute.VpnTunnelsClient, routersClient *compute.RoutersClient) (*invisinetspb.Empty, error) {
	insertExternalVpnGatewayReq := &computepb.InsertExternalVpnGatewayRequest{
		Project: vpnProject,
		ExternalVpnGatewayResource: &computepb.ExternalVpnGateway{
			Name:           proto.String(getPeerGwName(cloud)),
			Description:    proto.String("Invisinets peer gateway to " + cloud),
			RedundancyType: proto.String(computepb.ExternalVpnGateway_TWO_IPS_REDUNDANCY.String()),
		},
	}
	if len(interfaceIps) != 1 && len(interfaceIps) != 2 && len(interfaceIps) != 4 {
		// TODO @seankimkdy: currently only 2 is supported but in the future, these will be the only ones
		return nil, fmt.Errorf("invalid number of interface IP addresses provided: %d (must be 1, 2, or 4)", len(interfaceIps))
	}
	insertExternalVpnGatewayReq.ExternalVpnGatewayResource.Interfaces = make([]*computepb.ExternalVpnGatewayInterface, len(interfaceIps))
	for i, interfaceIp := range interfaceIps {
		insertExternalVpnGatewayReq.ExternalVpnGatewayResource.Interfaces[i] = &computepb.ExternalVpnGatewayInterface{
			Id:        proto.Uint32(uint32(i)),
			IpAddress: proto.String(interfaceIp),
		}
	}
	insertExternalVpnGatewayOp, err := externalVpnGatewaysClient.Insert(ctx, insertExternalVpnGatewayReq)
	if err != nil {
		return nil, fmt.Errorf("unable to insert peer vpn gateway: %w", err)
	}
	if err = insertExternalVpnGatewayOp.Wait(ctx); err != nil {
		return nil, fmt.Errorf("unable to wait on insert peer vpn gateway operation: %w", err)
	}

	for i := 0; i < vpnNumConnections; i++ {
		insertVpnTunnelRequest := &computepb.InsertVpnTunnelRequest{
			Project: vpnProject,
			Region:  vpnRegion,
			VpnTunnelResource: &computepb.VpnTunnel{
				Name:                         proto.String(getVpnTunnelName(cloud, i)),
				Description:                  proto.String(fmt.Sprintf("Invisinets VPN tunnel to %s (interface %d)", cloud, i)),
				PeerExternalGateway:          proto.String(getPeerGwUri(vpnProject, getPeerGwName(cloud))),
				PeerExternalGatewayInterface: proto.Int32(int32(i)),
				IkeVersion:                   proto.Int32(ikeVersion),
				SharedSecret:                 proto.String(sharedKey),
				Router:                       proto.String(getRouterUri(vpnProject, vpnRegion, routerName)),
				VpnGateway:                   proto.String(getVpnGwUri(vpnProject, vpnRegion, vpnGwName)),
				VpnGatewayInterface:          proto.Int32(int32(i)), // TODO @seankimkdy: handle separately for four connections (AWS specific)?
			},
		}
		insertVpnTunnelOp, err := vpnTunnelsClient.Insert(ctx, insertVpnTunnelRequest)
		if err != nil {
			return nil, fmt.Errorf("unable to insert vpn tunnel: %w", err)
		}
		if err = insertVpnTunnelOp.Wait(ctx); err != nil {
			return nil, fmt.Errorf("unable to wait on insert vpn tunnel operation: %w", err)
		}
	}

	patchRouterRequest := &computepb.PatchRouterRequest{
		Project:        vpnProject,
		Region:         vpnRegion,
		Router:         routerName,
		RouterResource: &computepb.Router{},
	}
	patchRouterRequest.RouterResource.BgpPeers = make([]*computepb.RouterBgpPeer, vpnNumConnections)
	for i := 0; i < vpnNumConnections; i++ {
		patchRouterRequest.RouterResource.BgpPeers[i] = &computepb.RouterBgpPeer{
			Name:          proto.String(getBgpPeerName(cloud, i)),
			PeerIpAddress: proto.String(bgpIps[i]),
			PeerAsn:       proto.Uint32(uint32(asn)),
		}
	}
	patchRouterOp, err := routersClient.Patch(ctx, patchRouterRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to setup bgp sessions: %w", err)
	}
	if err = patchRouterOp.Wait(ctx); err != nil {
		return nil, fmt.Errorf("unable to wait on setting up bgp sessions operation: %w", err)
	}

	return nil, nil
}

func (s *GCPPluginServer) CreateVpnConnections(ctx context.Context, cloud string, asn int64, addressSpace string, interfaceIps []string, bgpIps []string, sharedKey string) (*invisinetspb.Empty, error) {
	externalVpnGatewaysClient, err := compute.NewExternalVpnGatewaysRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewExternalVpnGatewaysClient: %w", err)
	}
	defer externalVpnGatewaysClient.Close()
	vpnTunnelsClient, err := compute.NewVpnTunnelsRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewVpnTunnelsRESTClient: %w", err)
	}
	defer vpnTunnelsClient.Close()
	routersClient, err := compute.NewRoutersRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewRoutersRESTClient: %w", err)
	}
	defer routersClient.Close()
	return s._CreateVpnConnections(ctx, cloud, asn, addressSpace, interfaceIps, bgpIps, sharedKey, externalVpnGatewaysClient, vpnTunnelsClient, routersClient)
}

// func (s *GCPPluginServer) _SetupPeerGateway(ctx context.Context, cloud string, interfaceIps []string, externalVpnGatewaysClient *compute.ExternalVpnGatewaysClient) error {
// 	insertExternalVpnGatewayReq := &computepb.InsertExternalVpnGatewayRequest{
// 		Project: vpnProject,
// 		ExternalVpnGatewayResource: &computepb.ExternalVpnGateway{
// 			Name:        proto.String(getPeerGwName(cloud)),
// 			Description: proto.String("Invisinets peer gateway to " + cloud),
// 		},
// 	}
// 	if len(interfaceIps) != 1 || len(interfaceIps) != 2 || len(interfaceIps) != 4 {
// 		// TODO @seankimkdy: currently only 2 is supported but in the future, these will be the only ones
// 		return fmt.Errorf("invalid number of interface IP addresses provided: %d (must be 1, 2, or 4)", len(interfaceIps))
// 	}
// 	insertExternalVpnGatewayReq.ExternalVpnGatewayResource.Interfaces = make([]*computepb.ExternalVpnGatewayInterface, len(interfaceIps))
// 	for i, interfaceIp := range interfaceIps {
// 		insertExternalVpnGatewayReq.ExternalVpnGatewayResource.Interfaces[i] = &computepb.ExternalVpnGatewayInterface{
// 			Id:        proto.Uint32(uint32(i)),
// 			IpAddress: proto.String(interfaceIp),
// 		}
// 	}
// 	insertExternalVpnGatewayOp, err := externalVpnGatewaysClient.Insert(ctx, insertExternalVpnGatewayReq)
// 	if err != nil {
// 		return fmt.Errorf("unable to insert peer vpn gateway: %w", err)
// 	}
// 	if err = insertExternalVpnGatewayOp.Wait(ctx); err != nil {
// 		return fmt.Errorf("unable to wait on insert peer vpn gateway operation: %w", err)
// 	}
// 	return nil
// }

// func (s *GCPPluginServer) SetupPeerGateway(ctx context.Context, cloud string, interfaceIps []string) error {
// 	externalVpnGatewaysClient, err := compute.NewExternalVpnGatewaysRESTClient(ctx)
// 	if err != nil {
// 		return fmt.Errorf("NewExternalVpnGatewaysClient: %w", err)
// 	}
// 	return s._SetupPeerGateway(ctx, cloud, interfaceIps, externalVpnGatewaysClient)
// }

// func (s *GCPPluginServer) _SetupVpnTunnels(ctx context.Context, cloud string, numInterfaces int, sharedSecret string, vpnTunnelsClient *compute.VpnTunnelsClient) error {
// 	for i := 0; i < numInterfaces; i++ {
// 		insertVpnTunnelRequest := &computepb.InsertVpnTunnelRequest{
// 			Project: vpnProject,
// 			Region:  vpnRegion,
// 			VpnTunnelResource: &computepb.VpnTunnel{
// 				Name:                         proto.String(getVpnTunnelName(cloud, i)),
// 				Description:                  proto.String(fmt.Sprintf("Invisinets VPN tunnel to %s (interface %d)", cloud, i)),
// 				PeerExternalGateway:          proto.String(getPeerGwName(cloud)),
// 				PeerExternalGatewayInterface: proto.Int32(int32(i)),
// 				IkeVersion:                   proto.Int32(ikeVersion),
// 				SharedSecret:                 proto.String(sharedSecret),
// 				Router:                       proto.String(routerName),
// 				VpnGateway:                   proto.String(vpnGwName),
// 				VpnGatewayInterface:          proto.Int32(int32(i)), // TODO @seankimkdy: handle separately for four connections (AWS specific)?
// 			},
// 		}
// 		insertVpnTunnelOp, err := vpnTunnelsClient.Insert(ctx, insertVpnTunnelRequest)
// 		if err != nil {
// 			return fmt.Errorf("unable to insert vpn tunnel: %w", err)
// 		}
// 		if err = insertVpnTunnelOp.Wait(ctx); err != nil {
// 			return fmt.Errorf("unable to wait on insert vpn tunnel operation: %w", err)
// 		}
// 	}
// 	return nil
// }

// func (s *GCPPluginServer) SetupVpnTunnels(ctx context.Context, cloud string, numInterfaces int, sharedSecret string) error {
// 	vpnTunnelsClient, err := compute.NewVpnTunnelsRESTClient(ctx)
// 	if err != nil {
// 		return fmt.Errorf("NewVpnTunnelsRESTClient: %w", err)
// 	}
// 	return s._SetupVpnTunnels(ctx, cloud, numInterfaces, sharedSecret, vpnTunnelsClient)
// }

// func (s *GCPPluginServer) _SetupBgpSessions(ctx context.Context, peerCloud string, numInterfaces int, peerAsn int, peerIpAddrs []string, routersClient *compute.RoutersClient) error {
// 	patchRouterRequest := &computepb.PatchRouterRequest{
// 		Project: vpnProject,
// 		Region:  vpnRegion,
// 		Router:  routerName,
// 	}
// 	patchRouterRequest.RouterResource.Interfaces = make([]*computepb.RouterInterface, numInterfaces)
// 	patchRouterRequest.RouterResource.BgpPeers = make([]*computepb.RouterBgpPeer, numInterfaces)
// 	bgp_interface_ips := []string{"169.254.21.2", "169.254.22.2"} // TODO @seankimkdy: change to be dynamic and dependent on peering cloud (e.g. Azure needs APIPA)
// 	for i := 0; i < numInterfaces; i++ {
// 		// TODO @seankimkdy: may have to split up adding interfaces and adding bgp peers
// 		patchRouterRequest.RouterResource.Interfaces[i] = &computepb.RouterInterface{
// 			Name:            proto.String(getVpnTunnelInterfaceName(peerCloud, i, i)),
// 			IpRange:         proto.String(bgp_interface_ips[i] + "/30"),
// 			LinkedVpnTunnel: proto.String(getVpnTunnelUri(vpnProject, vpnRegion, getVpnTunnelName(peerCloud, i))),
// 		}
// 		patchRouterRequest.RouterResource.BgpPeers[i] = &computepb.RouterBgpPeer{
// 			Name:          proto.String(getBgpPeerName(peerCloud, i)),
// 			PeerIpAddress: proto.String(peerIpAddrs[i]),
// 			PeerAsn:       proto.Uint32(uint32(peerAsn)),
// 		}
// 	}
// 	patchRouterOp, err := routersClient.Patch(ctx, patchRouterRequest)
// 	if err != nil {
// 		return fmt.Errorf("unable to setup bgp sessions: %w", err)
// 	}
// 	if err = patchRouterOp.Wait(ctx); err != nil {
// 		return fmt.Errorf("unable to wait on setting up bgp sessions operation: %w", err)
// 	}

// 	return nil
// }

// func (s *GCPPluginServer) SetupBgpSessions(ctx context.Context, peerCloud string, numInterfaces int, peerAsn int, peerIpAddrs []string) error {
// 	routersClient, err := compute.NewRoutersRESTClient(ctx)
// 	if err != nil {
// 		return fmt.Errorf("NewRoutersRESTClient: %w", err)
// 	}
// 	return s._SetupBgpSessions(ctx, peerCloud, numInterfaces, peerAsn, peerIpAddrs, routersClient)
// }
