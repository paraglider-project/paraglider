/*
Copyright 2023 The Paraglider Authors.

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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	container "cloud.google.com/go/container/apiv1"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

type GCPPluginServer struct {
	paragliderpb.UnimplementedCloudPluginServer
	orchestratorServerAddr string
}

// GCP naming conventions
const (
	paragliderPrefix              = "para"
	firewallRuleDescriptionPrefix = "paraglider rule" // GCP firewall rule prefix for description
)

const (
	networkInterface      = "nic0"
	firewallNameMaxLength = 62 // GCP imposed max length for firewall name
	computeURLPrefix      = "https://www.googleapis.com/compute/v1/"
	containerURLPrefix    = "https://container.googleapis.com/v1beta1/"
	ikeVersion            = 2
)

// TODO @seankimkdy: replace these in the future to be not hardcoded
var vpnRegion = "us-west1" // Must be var as this is changed during unit tests

// Maps between of GCP and Paraglider traffic direction terminologies
var (
	firewallDirectionMapGCPToParaglider = map[string]paragliderpb.Direction{
		"INGRESS": paragliderpb.Direction_INBOUND,
		"EGRESS":  paragliderpb.Direction_OUTBOUND,
	}

	firewallDirectionMapParagliderToGCP = map[paragliderpb.Direction]string{
		paragliderpb.Direction_INBOUND:  "INGRESS",
		paragliderpb.Direction_OUTBOUND: "EGRESS",
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

// Checks if GCP firewall rule is a Paraglider permit list rule
func isParagliderPermitListRule(namespace string, firewall *computepb.Firewall) bool {
	return strings.HasSuffix(*firewall.Network, getVpcName(namespace)) && strings.HasPrefix(*firewall.Name, getFirewallNamePrefix(namespace))
}

// Converts a GCP firewall rule to a Paraglider permit list rule
func firewallRuleToParagliderRule(namespace string, fw *computepb.Firewall) (*paragliderpb.PermitListRule, error) {
	if len(fw.Allowed) != 1 {
		return nil, fmt.Errorf("firewall rule has more than one allowed protocol")
	}
	protocolNumber, err := getProtocolNumber(*fw.Allowed[0].IPProtocol)
	if err != nil {
		return nil, fmt.Errorf("could not get protocol number: %w", err)
	}

	direction := firewallDirectionMapGCPToParaglider[*fw.Direction]

	var targets []string
	if direction == paragliderpb.Direction_INBOUND {
		targets = append(fw.SourceRanges, fw.SourceTags...)
	} else {
		targets = fw.DestinationRanges
	}

	var dstPort int
	if len(fw.Allowed[0].Ports) == 0 {
		dstPort = -1
	} else {
		dstPort, err = strconv.Atoi(fw.Allowed[0].Ports[0])
		if err != nil {
			return nil, fmt.Errorf("could not convert port to int")
		}
	}

	var tags []string
	if fw.Description != nil {
		tags = parseDescriptionTags(*fw.Description)
	}

	rule := &paragliderpb.PermitListRule{
		Name:      parseFirewallName(namespace, *fw.Name),
		Direction: firewallDirectionMapGCPToParaglider[*fw.Direction],
		SrcPort:   -1,
		DstPort:   int32(dstPort),
		Protocol:  int32(protocolNumber),
		Targets:   targets,
		Tags:      tags,
	} // SrcPort not specified since GCP doesn't support rules based on source ports
	return rule, nil
}

// Converts a Paraglider permit list rule to a GCP firewall rule
func paragliderRuleToFirewallRule(namespace string, project string, firewallName string, networkTag string, rule *paragliderpb.PermitListRule) (*computepb.Firewall, error) {
	firewall := &computepb.Firewall{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: proto.String(strconv.Itoa(int(rule.Protocol))),
			},
		},
		Description: proto.String(getRuleDescription(rule.Tags)),
		Direction:   proto.String(firewallDirectionMapParagliderToGCP[rule.Direction]),
		Name:        proto.String(firewallName),
		Network:     proto.String(GetVpcUri(project, namespace)),
		TargetTags:  []string{networkTag},
	}
	if rule.DstPort != -1 {
		// Users must explicitly set DstPort to -1 if they want it to apply to all ports since proto can't
		// differentiate between empty and 0 for an int field. Ports of 0 are valid for protocols like TCP/UDP.
		firewall.Allowed[0].Ports = []string{strconv.Itoa(int(rule.DstPort))}
	}
	if rule.Direction == paragliderpb.Direction_INBOUND {
		// TODO @seankimkdy: use SourceTags as well once we start supporting tags
		firewall.SourceRanges = rule.Targets
	} else {
		firewall.DestinationRanges = rule.Targets
	}
	return firewall, nil
}

// Determine if a firewall rule and permit list rule are equivalent
func isFirewallEqPermitListRule(namespace string, firewall *computepb.Firewall, rule *paragliderpb.PermitListRule) (bool, error) {
	paragliderVersion, err := firewallRuleToParagliderRule(namespace, firewall)
	if err != nil {
		return false, fmt.Errorf("could not convert firewall rule to permit list rule: %w", err)
	}

	targetMap := map[string]bool{}
	for _, target := range paragliderVersion.Targets {
		targetMap[target] = true
	}

	for _, target := range rule.Targets {
		if !targetMap[target] {
			return false, nil
		}
	}

	return paragliderVersion.Name == rule.Name &&
		paragliderVersion.Direction == rule.Direction &&
		paragliderVersion.Protocol == rule.Protocol &&
		paragliderVersion.DstPort == rule.DstPort &&
		paragliderVersion.SrcPort == rule.SrcPort, nil
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

// Hashes values to lowercase hex string for use in naming GCP resources
func hash(values ...string) string {
	hash := sha256.Sum256([]byte(strings.Join(values, "")))
	return strings.ToLower(hex.EncodeToString(hash[:]))
}

/* --- RESOURCE NAME --- */

func getParagliderNamespacePrefix(namespace string) string {
	return paragliderPrefix + "-" + namespace
}

func getFirewallNamePrefix(namespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-fw"
}

// Gets a GCP firewall rule name for a Paraglider permit list rule
// If two Paraglider permit list rules are equal, then they will have the same GCP firewall rule name.
func getFirewallName(namespace string, ruleName string, resourceId string) string {
	return fmt.Sprintf("%s-%s-%s", getFirewallNamePrefix(namespace), resourceId, ruleName)
}

// Retrieve the name of the permit list rule from the GCP firewall name
func parseFirewallName(namespace string, firewallName string) string {
	fmt.Println(firewallName)
	fmt.Println(strings.TrimPrefix(firewallName, getFirewallNamePrefix(namespace)+"-"))
	return strings.SplitN(strings.TrimPrefix(firewallName, getFirewallNamePrefix(namespace)+"-"), "-", 2)[1]
}

// Gets a GCP VPC name
func getVpcName(namespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-vpc"
}

// Returns name of firewall for denying all egress traffic
func getDenyAllIngressFirewallName(namespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-deny-all-egress"
}

// Gets a GCP subnetwork name for Paraglider based on region
func getSubnetworkName(namespace string, region string) string {
	return getParagliderNamespacePrefix(namespace) + "-" + region + "-subnet"
}

func getVpnGwName(namespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-vpn-gw"
}

func getRouterName(namespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-router"
}

// Returns a peer gateway name when connecting to another cloud
func getPeerGwName(namespace string, cloud string) string {
	return getParagliderNamespacePrefix(namespace) + "-" + cloud + "-peer-gw"
}

// Returns a VPN tunnel name when connecting to another cloud
func getVpnTunnelName(namespace string, cloud string, tunnelIdx int) string {
	return getParagliderNamespacePrefix(namespace) + "-" + cloud + "-tunnel-" + strconv.Itoa(tunnelIdx)
}

// Returns a VPN tunnel interface name when connecting to another cloud
func getVpnTunnelInterfaceName(namespace string, cloud string, tunnelIdx int, interfaceIdx int) string {
	return getVpnTunnelName(namespace, cloud, tunnelIdx) + "-int-" + strconv.Itoa(interfaceIdx)
}

// Returns a BGP peer name
func getBgpPeerName(cloud string, peerIdx int) string {
	return cloud + "-bgp-peer-" + strconv.Itoa(peerIdx)
}

// Returns a VPC network peering name
func getNetworkPeeringName(namespace string, peerNamespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-" + peerNamespace + "-peering"
}

func getSubnetworkURL(project string, region string, name string) string {
	return fmt.Sprintf("projects/%s/regions/%s/subnetworks/%s", project, region, name)
}

func getRegionFromZone(zone string) string {
	return zone[:strings.LastIndex(zone, "-")]
}

/* --- RESOURCE URI --- */

// Parses GCP compute URL for desired fields
func parseGCPURL(url string) map[string]string {
	path := strings.TrimPrefix(url, computeURLPrefix)
	path = strings.TrimPrefix(path, containerURLPrefix)
	parsedURL := map[string]string{}
	pathComponents := strings.Split(path, "/")
	for i := 0; i < len(pathComponents)-1; i += 2 {
		parsedURL[pathComponents[i]] = pathComponents[i+1]
	}
	return parsedURL
}

func getInstanceUri(project, zone, instance string) string {
	return fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, zone, instance)
}

func getClusterUri(project, zone, cluster string) string {
	return fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, zone, cluster)
}

func GetVpcUri(project, namespace string) string {
	return computeURLPrefix + fmt.Sprintf("projects/%s/global/networks/%s", project, getVpcName(namespace))
}

func getVpnGwUri(project, region, vpnGwName string) string {
	return computeURLPrefix + fmt.Sprintf("projects/%s/regions/%s/vpnGateways/%s", project, region, vpnGwName)
}

func getRouterUri(project, region, routerName string) string {
	return computeURLPrefix + fmt.Sprintf("projects/%s/regions/%s/routers/%s", project, region, routerName)
}

// Returns a full GCP URI of a VPN tunnel
func getVpnTunnelUri(project, region, vpnTunnelName string) string {
	return computeURLPrefix + fmt.Sprintf("projects/%s/regions/%s/vpnTunnels/%s", project, region, vpnTunnelName)
}

func getPeerGwUri(project, peerGwName string) string {
	return computeURLPrefix + fmt.Sprintf("projects/%s/global/externalVpnGateways/%s", project, peerGwName)
}

// Checks if GCP error response is a not found error
func isErrorNotFound(err error) bool {
	var e *googleapi.Error
	ok := errors.As(err, &e)
	return ok && e.Code == http.StatusNotFound
}

// Checks if GCP error response is a duplicate error
func isErrorDuplicate(err error) bool {
	var e *googleapi.Error
	ok := errors.As(err, &e)
	return ok && e.Code == http.StatusConflict
}

// Format the description to keep metadata about tags
func getRuleDescription(tags []string) string {
	if len(tags) == 0 {
		return firewallRuleDescriptionPrefix
	}
	return fmt.Sprintf("%s:%v", firewallRuleDescriptionPrefix, tags)
}

// Parses description string to get tags
func parseDescriptionTags(description string) []string {
	var tags []string
	if strings.HasPrefix(description, firewallRuleDescriptionPrefix+":[") {
		trimmedDescription := strings.TrimPrefix(description, firewallRuleDescriptionPrefix+":")
		trimmedDescription = strings.Trim(trimmedDescription, "[")
		trimmedDescription = strings.Trim(trimmedDescription, "]")
		tags = strings.Split(trimmedDescription, " ")
	}
	return tags
}

func (s *GCPPluginServer) _GetPermitList(ctx context.Context, req *paragliderpb.GetPermitListRequest, firewallsClient *compute.FirewallsClient, instancesClient *compute.InstancesClient, clustersClient *container.ClusterManagerClient) (*paragliderpb.GetPermitListResponse, error) {
	resourceInfo, err := parseResourceUri(req.Resource)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource URI: %w", err)
	}
	resourceInfo.Namespace = req.Namespace

	_, resourceID, err := GetResourceNetworkInfo(ctx, instancesClient, clustersClient, resourceInfo)
	if err != nil {
		return nil, err
	}

	// Get firewalls for the resource
	firewalls, err := getFirewallRules(ctx, firewallsClient, resourceInfo.Project, *resourceID)
	if err != nil {
		return nil, fmt.Errorf("unable to get firewalls: %w", err)
	}

	permitListRules := []*paragliderpb.PermitListRule{}

	for _, firewall := range firewalls {
		// Exclude default deny all egress from being included since it applies to every VM
		if isParagliderPermitListRule(req.Namespace, firewall) && *firewall.Name != getDenyAllIngressFirewallName(req.Namespace) {
			rule, err := firewallRuleToParagliderRule(req.Namespace, firewall)
			if err != nil {
				return nil, fmt.Errorf("could not convert firewall rule to permit list rule: %w", err)
			}
			permitListRules = append(permitListRules, rule)
		}
	}

	return &paragliderpb.GetPermitListResponse{Rules: permitListRules}, nil
}

func (s *GCPPluginServer) GetPermitList(ctx context.Context, req *paragliderpb.GetPermitListRequest) (*paragliderpb.GetPermitListResponse, error) {
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

	clustersClient, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClusterManagerClient: %w", err)
	}
	defer clustersClient.Close()

	return s._GetPermitList(ctx, req, firewallsClient, instancesClient, clustersClient)
}

// Creates bi-directional peering between two VPC networks
func peerVpcNetwork(ctx context.Context, networksClient *compute.NetworksClient, currentProject string, currentNamespace string, peerProject string, peerNamespace string) error {
	// Check if peering already exists
	currentVpcName := getVpcName(currentNamespace)
	getNetworkReq := &computepb.GetNetworkRequest{
		Network: currentVpcName,
		Project: currentProject,
	}
	currentVpc, err := networksClient.Get(ctx, getNetworkReq)
	if err != nil {
		return fmt.Errorf("unable to get current vpc: %w", err)
	}
	networkPeeringName := getNetworkPeeringName(currentNamespace, peerNamespace)
	for _, peering := range currentVpc.Peerings {
		if *peering.Name == networkPeeringName {
			return nil
		}
	}

	// Add peering
	peerVpcUri := GetVpcUri(peerProject, peerNamespace)
	addPeeringNetworkReq := &computepb.AddPeeringNetworkRequest{
		Network: getVpcName(currentNamespace),
		Project: currentProject,
		NetworksAddPeeringRequestResource: &computepb.NetworksAddPeeringRequest{
			// Don't specify Name or PeerNetwork field here as GCP will throw an error
			NetworkPeering: &computepb.NetworkPeering{
				Name:                 proto.String(networkPeeringName),
				Network:              proto.String(peerVpcUri),
				ExchangeSubnetRoutes: proto.Bool(true),
			},
		},
	}
	addPeeringNetworkOp, err := networksClient.AddPeering(ctx, addPeeringNetworkReq)
	if err != nil {
		return fmt.Errorf("unable to add peering: %w", err)
	}
	if err = addPeeringNetworkOp.Wait(ctx); err != nil {
		return fmt.Errorf("unable to wait for the add peering operation: %w", err)
	}
	return nil
}

func (s *GCPPluginServer) _AddPermitListRules(ctx context.Context, req *paragliderpb.AddPermitListRulesRequest, firewallsClient *compute.FirewallsClient, instancesClient *compute.InstancesClient, subnetworksClient *compute.SubnetworksClient, networksClient *compute.NetworksClient, clustersClient *container.ClusterManagerClient) (*paragliderpb.AddPermitListRulesResponse, error) {
	resourceInfo, err := parseResourceUri(req.Resource)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource URI: %w", err)
	}
	resourceInfo.Namespace = req.Namespace

	_, resourceID, err := GetResourceNetworkInfo(ctx, instancesClient, clustersClient, resourceInfo)
	if err != nil {
		return nil, err
	}

	// Get existing firewalls
	firewalls, err := getFirewallRules(ctx, firewallsClient, resourceInfo.Project, *resourceID)
	if err != nil {
		return nil, fmt.Errorf("unable to get existing firewalls: %w", err)
	}

	existingFirewalls := map[string]*computepb.Firewall{}
	for _, firewall := range firewalls {
		existingFirewalls[*firewall.Name] = firewall
	}

	// Get the network tag
	networkTag := getNetworkTag(req.Namespace, resourceInfo.ResourceType, *resourceID)

	// Get used address spaces of all clouds
	orchestratorConn, err := grpc.Dial(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("unable to establish connection with orchestrator: %w", err)
	}
	defer orchestratorConn.Close()
	orchestratorClient := paragliderpb.NewControllerClient(orchestratorConn)
	getUsedAddressSpacesResp, err := orchestratorClient.GetUsedAddressSpaces(context.Background(), &paragliderpb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("unable to get used address spaces: %w", err)
	}

	for _, permitListRule := range req.Rules {
		// TODO @seankimkdy: should we throw an error/warning if user specifies a srcport since GCP doesn't support srcport based firewalls?
		firewallName := getFirewallName(req.Namespace, permitListRule.Name, *resourceID)

		patchRequired := false
		if existingFw, ok := existingFirewalls[firewallName]; ok {
			equivalent, err := isFirewallEqPermitListRule(req.Namespace, existingFw, permitListRule)
			if err != nil {
				return nil, fmt.Errorf("unable to check if firewall is equivalent to permit list rule: %w", err)
			}
			if equivalent {
				// Firewall already exists and is equivalent to the provided permit list rule
				continue
			} else {
				// Firewall already exists but is not equivalent to the provided permit list rule
				// We should patch the rule, but we need to still check if any new infrastructure is needed
				patchRequired = true
			}
		}

		// Get all peering cloud infos
		peeringCloudInfos, err := utils.GetPermitListRulePeeringCloudInfo(permitListRule, getUsedAddressSpacesResp.AddressSpaceMappings)
		if err != nil {
			return nil, fmt.Errorf("unable to get peering cloud infos: %w", err)
		}

		for _, peeringCloudInfo := range peeringCloudInfos {
			if peeringCloudInfo == nil {
				continue
			}
			if peeringCloudInfo.Cloud != utils.GCP {
				// Create VPN connections
				connectCloudsReq := &paragliderpb.ConnectCloudsRequest{
					CloudA:          utils.GCP,
					CloudANamespace: req.Namespace,
					CloudB:          peeringCloudInfo.Cloud,
					CloudBNamespace: peeringCloudInfo.Namespace,
				}
				_, err := orchestratorClient.ConnectClouds(ctx, connectCloudsReq)
				if err != nil {
					return nil, fmt.Errorf("unable to connect clouds : %w", err)
				}
			} else {
				if peeringCloudInfo.Namespace != req.Namespace {
					// Create VPC network peering (in both directions) for different namespaces
					peerProject := parseGCPURL(peeringCloudInfo.Deployment)["projects"]
					err = peerVpcNetwork(ctx, networksClient, resourceInfo.Project, req.Namespace, peerProject, peeringCloudInfo.Namespace)
					if err != nil {
						return nil, fmt.Errorf("unable to create peering from %s to %s: %w", req.Namespace, peeringCloudInfo.Namespace, err)
					}
					err = peerVpcNetwork(ctx, networksClient, peerProject, peeringCloudInfo.Namespace, resourceInfo.Project, req.Namespace)
					if err != nil {
						return nil, fmt.Errorf("unable to create peering from %s to %s: %w", peeringCloudInfo.Namespace, req.Namespace, err)
					}
				}
			}
		}

		firewall, err := paragliderRuleToFirewallRule(req.Namespace, resourceInfo.Project, firewallName, networkTag, permitListRule)
		if err != nil {
			return nil, fmt.Errorf("unable to convert permit list rule to firewall rule: %w", err)
		}

		if patchRequired {
			patchFirewallReq := &computepb.PatchFirewallRequest{
				Firewall:         firewallName,
				FirewallResource: firewall,
				Project:          resourceInfo.Project,
			}
			patchFirewallOp, err := firewallsClient.Patch(ctx, patchFirewallReq)
			if err != nil {
				return nil, fmt.Errorf("unable to modify firewall rule: %w", err)
			}
			if err = patchFirewallOp.Wait(ctx); err != nil {
				return nil, fmt.Errorf("unable to wait for the operation: %w", err)
			}
		} else {
			insertFirewallReq := &computepb.InsertFirewallRequest{
				Project:          resourceInfo.Project,
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
	}

	return &paragliderpb.AddPermitListRulesResponse{}, nil
}

func (s *GCPPluginServer) AddPermitListRules(ctx context.Context, req *paragliderpb.AddPermitListRulesRequest) (*paragliderpb.AddPermitListRulesResponse, error) {
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

	clustersClient, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClusterManagerClient: %w", err)
	}
	defer clustersClient.Close()

	subnetworksClient, err := compute.NewSubnetworksRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewSubnetworksRESTClient: %w", err)
	}
	defer subnetworksClient.Close()
	networksClient, err := compute.NewNetworksRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewNetworksRESTClient: %w", err)
	}
	defer networksClient.Close()

	return s._AddPermitListRules(ctx, req, firewallsClient, instancesClient, subnetworksClient, networksClient, clustersClient)
}

func (s *GCPPluginServer) _DeletePermitListRules(ctx context.Context, req *paragliderpb.DeletePermitListRulesRequest, firewallsClient *compute.FirewallsClient, instancesClient *compute.InstancesClient, clustersClient *container.ClusterManagerClient) (*paragliderpb.DeletePermitListRulesResponse, error) {
	resourceInfo, err := parseResourceUri(req.Resource)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource URI: %w", err)
	}
	resourceInfo.Namespace = req.Namespace

	_, resourceID, err := GetResourceNetworkInfo(ctx, instancesClient, clustersClient, resourceInfo)
	if err != nil {
		return nil, err
	}

	// Delete firewalls corresponding to provided permit list rules
	for _, ruleName := range req.RuleNames {
		deleteFirewallReq := &computepb.DeleteFirewallRequest{
			Firewall: getFirewallName(req.Namespace, ruleName, *resourceID),
			Project:  resourceInfo.Project,
		}
		deleteFirewallOp, err := firewallsClient.Delete(ctx, deleteFirewallReq)
		if err != nil {
			return nil, fmt.Errorf("unable to delete firewall: %w", err)
		}
		if err = deleteFirewallOp.Wait(ctx); err != nil {
			return nil, fmt.Errorf("unable to wait for the operation: %w", err)
		}
	}

	return &paragliderpb.DeletePermitListRulesResponse{}, nil
}

func (s *GCPPluginServer) DeletePermitListRules(ctx context.Context, req *paragliderpb.DeletePermitListRulesRequest) (*paragliderpb.DeletePermitListRulesResponse, error) {
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

	clustersClient, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClusterManagerClient: %w", err)
	}
	defer clustersClient.Close()

	return s._DeletePermitListRules(ctx, req, firewallsClient, instancesClient, clustersClient)
}

func (s *GCPPluginServer) _CreateResource(ctx context.Context, resourceDescription *paragliderpb.ResourceDescription, instancesClient *compute.InstancesClient, networksClient *compute.NetworksClient, subnetworksClient *compute.SubnetworksClient, firewallsClient *compute.FirewallsClient, clustersClient *container.ClusterManagerClient) (*paragliderpb.CreateResourceResponse, error) {
	project := parseGCPURL(resourceDescription.Deployment.Id)["projects"]

	// Read and validate user-provided description
	resourceInfo, err := IsValidResource(ctx, resourceDescription)
	if err != nil {
		return nil, fmt.Errorf("unsupported resource description: %w", err)
	}

	// Set project and instance name
	resourceInfo.Project = project
	resourceInfo.Name = resourceDescription.Name

	region := resourceInfo.Zone[:strings.LastIndex(resourceInfo.Zone, "-")]
	resourceInfo.Region = region
	resourceInfo.Namespace = resourceDescription.Deployment.Namespace

	subnetExists := false
	subnetName := getSubnetworkName(resourceDescription.Deployment.Namespace, region)

	// Check if Paraglider specific VPC already exists
	nsVpcName := getVpcName(resourceDescription.Deployment.Namespace)
	getNetworkReq := &computepb.GetNetworkRequest{
		Network: nsVpcName,
		Project: project,
	}
	getNetworkResp, err := networksClient.Get(ctx, getNetworkReq)
	if err != nil {
		if isErrorNotFound(err) {
			insertNetworkRequest := &computepb.InsertNetworkRequest{
				Project: project,
				NetworkResource: &computepb.Network{
					Name:                  proto.String(nsVpcName),
					Description:           proto.String("VPC for Paraglider"),
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
			// Deny all egress traffic since GCP implicitly allows all egress traffic
			insertFirewallReq := &computepb.InsertFirewallRequest{
				Project: project,
				FirewallResource: &computepb.Firewall{
					Denied: []*computepb.Denied{
						{
							IPProtocol: proto.String("all"),
						},
					},
					Description:       proto.String("Paraglider deny all traffic"),
					DestinationRanges: []string{"0.0.0.0/0"},
					Direction:         proto.String(computepb.Firewall_EGRESS.String()),
					Name:              proto.String(getDenyAllIngressFirewallName(resourceDescription.Deployment.Namespace)),
					Network:           proto.String(GetVpcUri(project, resourceDescription.Deployment.Namespace)),
					Priority:          proto.Int32(65534),
				},
			}
			insertFirewallOp, err := firewallsClient.Insert(ctx, insertFirewallReq)
			if err != nil {
				return nil, fmt.Errorf("unable to create firewall rule: %w", err)
			}
			if err = insertFirewallOp.Wait(ctx); err != nil {
				return nil, fmt.Errorf("unable to wait for the operation: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to get paraglider vpc network: %w", err)
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

	// Find unused address spaces
	addressSpaces := []string{}
	numAddressSpacesNeeded := int32(resourceInfo.NumAdditionalAddressSpaces)
	if !subnetExists || resourceInfo.NumAdditionalAddressSpaces > 0 {
		conn, err := grpc.Dial(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("unable to establish connection with orchestrator: %w", err)
		}
		defer conn.Close()
		client := paragliderpb.NewControllerClient(conn)

		if !subnetExists {
			numAddressSpacesNeeded += 1
		}

		response, err := client.FindUnusedAddressSpaces(context.Background(), &paragliderpb.FindUnusedAddressSpacesRequest{Num: &numAddressSpacesNeeded})

		if err != nil {
			return nil, fmt.Errorf("unable to find unused address space: %w", err)
		}

		addressSpaces = response.AddressSpaces
	}

	if !subnetExists {

		insertSubnetworkRequest := &computepb.InsertSubnetworkRequest{
			Project: project,
			Region:  region,
			SubnetworkResource: &computepb.Subnetwork{
				Name:        proto.String(subnetName),
				Description: proto.String("Paraglider subnetwork for " + region),
				Network:     proto.String(GetVpcUri(project, resourceDescription.Deployment.Namespace)),
				IpCidrRange: proto.String(addressSpaces[0]),
			},
		}
		insertSubnetworkOp, err := subnetworksClient.Insert(ctx, insertSubnetworkRequest)
		if err != nil {
			return nil, fmt.Errorf("unable to insert subnetwork: %w", err)
		}
		if err = insertSubnetworkOp.Wait(ctx); err != nil {
			return nil, fmt.Errorf("unable to wait for the operation: %w", err)
		}
		addressSpaces = addressSpaces[1:]
	}

	// Read and provision the resource
	uri, ip, err := ReadAndProvisionResource(ctx, resourceDescription, subnetName, resourceInfo, instancesClient, clustersClient, firewallsClient, addressSpaces)

	if err != nil {
		return nil, fmt.Errorf("unable to read and provision resource: %w", err)
	}
	return &paragliderpb.CreateResourceResponse{Name: resourceInfo.Name, Uri: uri, Ip: ip}, nil
}

func (s *GCPPluginServer) CreateResource(ctx context.Context, resourceDescription *paragliderpb.ResourceDescription) (*paragliderpb.CreateResourceResponse, error) {
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
	firewallsClient, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewFirewallsRESTClient: %w", err)
	}
	defer firewallsClient.Close()
	clustersClient, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClusterManagerClient: %w", err)
	}
	defer clustersClient.Close()

	return s._CreateResource(ctx, resourceDescription, instancesClient, networksClient, subnetworksClient, firewallsClient, clustersClient)
}

func (s *GCPPluginServer) _GetUsedAddressSpaces(ctx context.Context, req *paragliderpb.GetUsedAddressSpacesRequest, networksClient *compute.NetworksClient, subnetworksClient *compute.SubnetworksClient) (*paragliderpb.GetUsedAddressSpacesResponse, error) {
	resp := &paragliderpb.GetUsedAddressSpacesResponse{}
	resp.AddressSpaceMappings = make([]*paragliderpb.AddressSpaceMapping, len(req.Deployments))
	for i, deployment := range req.Deployments {
		resp.AddressSpaceMappings[i] = &paragliderpb.AddressSpaceMapping{
			Cloud:     utils.GCP,
			Namespace: deployment.Namespace,
		}
		project := parseGCPURL(deployment.Id)["projects"]

		vpcName := getVpcName(deployment.Namespace)
		getNetworkReq := &computepb.GetNetworkRequest{
			Network: vpcName,
			Project: project,
		}

		getNetworkResp, err := networksClient.Get(ctx, getNetworkReq)
		if err != nil {
			if isErrorNotFound(err) {
				continue
			} else {
				return nil, fmt.Errorf("failed to get paraglider vpc network: %w", err)
			}
		}
		resp.AddressSpaceMappings[i].AddressSpaces = []string{}
		for _, subnetURL := range getNetworkResp.Subnetworks {
			parsedSubnetURL := parseGCPURL(subnetURL)
			getSubnetworkRequest := &computepb.GetSubnetworkRequest{
				Project:    project,
				Region:     parsedSubnetURL["regions"],
				Subnetwork: parsedSubnetURL["subnetworks"],
			}
			getSubnetworkResp, err := subnetworksClient.Get(ctx, getSubnetworkRequest)
			if err != nil {
				return nil, fmt.Errorf("failed to get paraglider subnetwork: %w", err)
			}

			resp.AddressSpaceMappings[i].AddressSpaces = append(resp.AddressSpaceMappings[i].AddressSpaces, *getSubnetworkResp.IpCidrRange)
			for _, secondaryRange := range getSubnetworkResp.SecondaryIpRanges {
				resp.AddressSpaceMappings[i].AddressSpaces = append(resp.AddressSpaceMappings[i].AddressSpaces, *secondaryRange.IpCidrRange)
			}
		}
	}
	return resp, nil
}

func (s *GCPPluginServer) GetUsedAddressSpaces(ctx context.Context, req *paragliderpb.GetUsedAddressSpacesRequest) (*paragliderpb.GetUsedAddressSpacesResponse, error) {
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

	return s._GetUsedAddressSpaces(ctx, req, networksClient, subnetworksClient)
}

func (s *GCPPluginServer) _GetUsedAsns(ctx context.Context, req *paragliderpb.GetUsedAsnsRequest, routersClient *compute.RoutersClient) (*paragliderpb.GetUsedAsnsResponse, error) {
	resp := &paragliderpb.GetUsedAsnsResponse{}
	for _, deployment := range req.Deployments {
		project := parseGCPURL(deployment.Id)["projects"]

		getRouterReq := &computepb.GetRouterRequest{
			Project: project,
			Region:  vpnRegion,
			Router:  getRouterName(deployment.Namespace),
		}
		getRouterResp, err := routersClient.Get(ctx, getRouterReq)
		if err != nil {
			if isErrorNotFound(err) {
				continue
			} else {
				return nil, fmt.Errorf("unable to get router: %w", err)
			}
		}
		resp.Asns = append(resp.Asns, *getRouterResp.Bgp.Asn)
	}
	return resp, nil
}

func (s *GCPPluginServer) GetUsedAsns(ctx context.Context, req *paragliderpb.GetUsedAsnsRequest) (*paragliderpb.GetUsedAsnsResponse, error) {
	routersClient, err := compute.NewRoutersRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewRoutersRESTClient: %w", err)
	}
	return s._GetUsedAsns(ctx, req, routersClient)
}

func (s *GCPPluginServer) _GetUsedBgpPeeringIpAddresses(ctx context.Context, req *paragliderpb.GetUsedBgpPeeringIpAddressesRequest, routersClient *compute.RoutersClient) (*paragliderpb.GetUsedBgpPeeringIpAddressesResponse, error) {
	resp := &paragliderpb.GetUsedBgpPeeringIpAddressesResponse{}
	for _, deployment := range req.Deployments {
		project := parseGCPURL(deployment.Id)["projects"]

		getRouterReq := &computepb.GetRouterRequest{
			Project: project,
			Region:  vpnRegion,
			Router:  getRouterName(deployment.Namespace),
		}
		getRouterResp, err := routersClient.Get(ctx, getRouterReq)
		if err != nil {
			if isErrorNotFound(err) {
				continue
			} else {
				return nil, fmt.Errorf("unable to get router: %w", err)
			}
		}
		for _, bgpPeer := range getRouterResp.BgpPeers {
			resp.IpAddresses = append(resp.IpAddresses, *bgpPeer.IpAddress)
		}
	}
	return resp, nil
}

func (s *GCPPluginServer) GetUsedBgpPeeringIpAddresses(ctx context.Context, req *paragliderpb.GetUsedBgpPeeringIpAddressesRequest) (*paragliderpb.GetUsedBgpPeeringIpAddressesResponse, error) {
	routersClient, err := compute.NewRoutersRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewRoutersRESTClient: %w", err)
	}
	return s._GetUsedBgpPeeringIpAddresses(ctx, req, routersClient)
}

func (s *GCPPluginServer) _CreateVpnGateway(ctx context.Context, req *paragliderpb.CreateVpnGatewayRequest, vpnGatewaysClient *compute.VpnGatewaysClient, routersClient *compute.RoutersClient) (*paragliderpb.CreateVpnGatewayResponse, error) {
	project := parseGCPURL(req.Deployment.Id)["projects"]

	// Create VPN gateway
	insertVpnGatewayReq := &computepb.InsertVpnGatewayRequest{
		Project: project,
		Region:  vpnRegion,
		VpnGatewayResource: &computepb.VpnGateway{
			Name:        proto.String(getVpnGwName(req.Deployment.Namespace)),
			Description: proto.String("Paraglider VPN gateway for multicloud connections"),
			Network:     proto.String(GetVpcUri(project, req.Deployment.Namespace)),
		},
	}
	insertVpnGatewayOp, err := vpnGatewaysClient.Insert(ctx, insertVpnGatewayReq)
	if err != nil {
		if !isErrorDuplicate(err) {
			return nil, fmt.Errorf("unable to insert vpn gateway: %w (request: %v)", err, insertVpnGatewayReq)
		}
	} else {
		if err = insertVpnGatewayOp.Wait(ctx); err != nil {
			return nil, fmt.Errorf("unable to wait on insert vpn gateway operation: %w", err)
		}
	}

	// Find unused ASN
	conn, err := grpc.Dial(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("unable to establish connection with orchestrator: %w", err)
	}
	defer conn.Close()
	client := paragliderpb.NewControllerClient(conn)
	findUnusedAsnResp, err := client.FindUnusedAsn(ctx, &paragliderpb.FindUnusedAsnRequest{})
	if err != nil {
		return nil, fmt.Errorf("unable to find unused address space: %w", err)
	}
	asn := findUnusedAsnResp.Asn

	// Create router
	insertRouterReq := &computepb.InsertRouterRequest{
		Project: project,
		Region:  vpnRegion,
		RouterResource: &computepb.Router{
			Name:        proto.String(getRouterName(req.Deployment.Namespace)),
			Description: proto.String("Paraglider router for multicloud connections"),
			Network:     proto.String(GetVpcUri(project, req.Deployment.Namespace)),
			Bgp: &computepb.RouterBgp{
				Asn: proto.Uint32(asn),
			},
		},
	}
	insertRouterOp, err := routersClient.Insert(ctx, insertRouterReq)
	if err != nil {
		if !isErrorDuplicate(err) {
			return nil, fmt.Errorf("unable to insert router: %w", err)
		}
	} else {
		if err = insertRouterOp.Wait(ctx); err != nil {
			return nil, fmt.Errorf("unable to wait on insert router operation: %w", err)
		}
	}

	// Add BGP interfaces
	vpnNumConnections := utils.GetNumVpnConnections(req.Cloud, utils.GCP)
	getRouterReq := &computepb.GetRouterRequest{
		Project: project,
		Region:  vpnRegion,
		Router:  getRouterName(req.Deployment.Namespace),
	}
	getRouterResp, err := routersClient.Get(ctx, getRouterReq)
	if err != nil {
		return nil, fmt.Errorf("unable to get router: %w", err)
	}
	existingInterfaces := make(map[string]bool)
	for _, interface_ := range getRouterResp.Interfaces {
		existingInterfaces[*interface_.Name] = true
	}
	patchRouterRequest := &computepb.PatchRouterRequest{
		Project:        project,
		Region:         vpnRegion,
		Router:         getRouterName(req.Deployment.Namespace),
		RouterResource: getRouterResp, // Necessary for PATCH to work correctly on arrays
	}
	for i := 0; i < vpnNumConnections; i++ {
		interfaceName := getVpnTunnelInterfaceName(req.Deployment.Namespace, req.Cloud, i, i)
		if !existingInterfaces[interfaceName] {
			patchRouterRequest.RouterResource.Interfaces = append(
				patchRouterRequest.RouterResource.Interfaces,
				&computepb.RouterInterface{
					Name:            proto.String(interfaceName),
					IpRange:         proto.String(req.BgpPeeringIpAddresses[i] + "/30"),
					LinkedVpnTunnel: proto.String(getVpnTunnelUri(project, vpnRegion, getVpnTunnelName(req.Deployment.Namespace, req.Cloud, i))),
				},
			)
		}
	}
	patchRouterOp, err := routersClient.Patch(ctx, patchRouterRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to setup bgp sessions: %w", err)
	}
	if err = patchRouterOp.Wait(ctx); err != nil {
		return nil, fmt.Errorf("unable to wait on setting up bgp sessions operation: %w", err)
	}

	// Get VPN gateway for IP addresses
	getVpnGatewayReq := &computepb.GetVpnGatewayRequest{
		Project:    project,
		Region:     vpnRegion,
		VpnGateway: getVpnGwName(req.Deployment.Namespace),
	}
	vpnGateway, err := vpnGatewaysClient.Get(ctx, getVpnGatewayReq)
	if err != nil {
		return nil, fmt.Errorf("unable to get vpn gateway: %w", err)
	}
	resp := &paragliderpb.CreateVpnGatewayResponse{Asn: asn}
	resp.GatewayIpAddresses = make([]string, vpnNumConnections)
	for i := 0; i < vpnNumConnections; i++ {
		resp.GatewayIpAddresses[i] = *vpnGateway.VpnInterfaces[i].IpAddress
	}

	return resp, nil
}

func (s *GCPPluginServer) CreateVpnGateway(ctx context.Context, req *paragliderpb.CreateVpnGatewayRequest) (*paragliderpb.CreateVpnGatewayResponse, error) {
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
	return s._CreateVpnGateway(ctx, req, vpnGatewaysClient, routersClient)
}

func (s *GCPPluginServer) _CreateVpnConnections(ctx context.Context, req *paragliderpb.CreateVpnConnectionsRequest, externalVpnGatewaysClient *compute.ExternalVpnGatewaysClient, vpnTunnelsClient *compute.VpnTunnelsClient, routersClient *compute.RoutersClient) (*paragliderpb.BasicResponse, error) {
	project := parseGCPURL(req.Deployment.Id)["projects"]
	vpnNumConnections := utils.GetNumVpnConnections(req.Cloud, utils.GCP)

	// Insert external VPN gateway
	insertExternalVpnGatewayReq := &computepb.InsertExternalVpnGatewayRequest{
		Project: project,
		ExternalVpnGatewayResource: &computepb.ExternalVpnGateway{
			Name:           proto.String(getPeerGwName(req.Deployment.Namespace, req.Cloud)),
			Description:    proto.String("Paraglider peer gateway to " + req.Cloud),
			RedundancyType: proto.String(computepb.ExternalVpnGateway_TWO_IPS_REDUNDANCY.String()),
		},
	}
	insertExternalVpnGatewayReq.ExternalVpnGatewayResource.Interfaces = make([]*computepb.ExternalVpnGatewayInterface, vpnNumConnections)
	for i := 0; i < vpnNumConnections; i++ {
		insertExternalVpnGatewayReq.ExternalVpnGatewayResource.Interfaces[i] = &computepb.ExternalVpnGatewayInterface{
			Id:        proto.Uint32(uint32(i)),
			IpAddress: proto.String(req.GatewayIpAddresses[i]),
		}
	}
	insertExternalVpnGatewayOp, err := externalVpnGatewaysClient.Insert(ctx, insertExternalVpnGatewayReq)
	if err != nil {
		if !isErrorDuplicate(err) {
			return nil, fmt.Errorf("unable to insert external vpn gateway: %w", err)
		}
	} else {
		if err = insertExternalVpnGatewayOp.Wait(ctx); err != nil {
			return nil, fmt.Errorf("unable to wait on insert external vpn gateway operation: %w", err)
		}
	}

	// Insert VPN tunnels
	for i := 0; i < vpnNumConnections; i++ {
		insertVpnTunnelRequest := &computepb.InsertVpnTunnelRequest{
			Project: project,
			Region:  vpnRegion,
			VpnTunnelResource: &computepb.VpnTunnel{
				Name:                         proto.String(getVpnTunnelName(req.Deployment.Namespace, req.Cloud, i)),
				Description:                  proto.String(fmt.Sprintf("Paraglider VPN tunnel to %s (interface %d)", req.Cloud, i)),
				PeerExternalGateway:          proto.String(getPeerGwUri(project, getPeerGwName(req.Deployment.Namespace, req.Cloud))),
				PeerExternalGatewayInterface: proto.Int32(int32(i)),
				IkeVersion:                   proto.Int32(ikeVersion),
				SharedSecret:                 proto.String(req.SharedKey),
				Router:                       proto.String(getRouterUri(project, vpnRegion, getRouterName(req.Deployment.Namespace))),
				VpnGateway:                   proto.String(getVpnGwUri(project, vpnRegion, getVpnGwName(req.Deployment.Namespace))),
				VpnGatewayInterface:          proto.Int32(int32(i)), // TODO @seankimkdy: handle separately for four connections (AWS specific)?
			},
		}
		insertVpnTunnelOp, err := vpnTunnelsClient.Insert(ctx, insertVpnTunnelRequest)
		if err != nil {
			if !isErrorDuplicate(err) {
				return nil, fmt.Errorf("unable to insert vpn tunnel: %w", err)
			}
		} else {
			if err = insertVpnTunnelOp.Wait(ctx); err != nil {
				return nil, fmt.Errorf("unable to wait on insert vpn tunnel operation: %w", err)
			}
		}
	}

	// Add BGP peers
	getRouterReq := &computepb.GetRouterRequest{
		Project: project,
		Region:  vpnRegion,
		Router:  getRouterName(req.Deployment.Namespace),
	}
	getRouterResp, err := routersClient.Get(ctx, getRouterReq)
	if err != nil {
		return nil, fmt.Errorf("unable to get router: %w", err)
	}
	existingBgpPeers := make(map[string]bool)
	for _, bgpPeer := range getRouterResp.BgpPeers {
		existingBgpPeers[*bgpPeer.Name] = true
	}
	patchRouterRequest := &computepb.PatchRouterRequest{
		Project:        project,
		Region:         vpnRegion,
		Router:         getRouterName(req.Deployment.Namespace),
		RouterResource: getRouterResp,
	}
	for i := 0; i < vpnNumConnections; i++ {
		bgpPeerName := getBgpPeerName(req.Cloud, i)
		if !existingBgpPeers[bgpPeerName] {
			patchRouterRequest.RouterResource.BgpPeers = append(
				patchRouterRequest.RouterResource.BgpPeers,
				&computepb.RouterBgpPeer{
					Name:          proto.String(bgpPeerName),
					PeerIpAddress: proto.String(req.BgpIpAddresses[i]),
					PeerAsn:       proto.Uint32(uint32(req.Asn)),
				},
			)
		}
	}
	patchRouterOp, err := routersClient.Patch(ctx, patchRouterRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to setup bgp sessions: %w", err)
	}
	if err = patchRouterOp.Wait(ctx); err != nil {
		return nil, fmt.Errorf("unable to wait on setting up bgp sessions operation: %w", err)
	}

	return &paragliderpb.BasicResponse{Success: true}, nil
}

func (s *GCPPluginServer) CreateVpnConnections(ctx context.Context, req *paragliderpb.CreateVpnConnectionsRequest) (*paragliderpb.BasicResponse, error) {
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
	return s._CreateVpnConnections(ctx, req, externalVpnGatewaysClient, vpnTunnelsClient, routersClient)
}

func Setup(port int, orchestratorServerAddr string) *GCPPluginServer {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	gcpServer := &GCPPluginServer{}
	gcpServer.orchestratorServerAddr = orchestratorServerAddr
	paragliderpb.RegisterCloudPluginServer(grpcServer, gcpServer)
	fmt.Println("Starting server on port :", port)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println(err.Error())
		}
	}()
	return gcpServer
}
