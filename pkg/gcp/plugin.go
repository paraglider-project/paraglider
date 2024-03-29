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
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

type GCPPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
	orchestratorServerAddr string
}

// GCP naming conventions
const (
	invisinetsPrefix              = "invisinets"
	firewallNamePrefix            = "invisinets-fw-"  // Prefix for firewall names related to invisinets
	firewallRuleDescriptionPrefix = "invisinets rule" // GCP firewall rule prefix for description
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

// Checks if GCP firewall rule is an Invisinets permit list rule
func isInvisinetsPermitListRule(namespace string, firewall *computepb.Firewall) bool {
	return strings.HasSuffix(*firewall.Network, getVpcName(namespace)) && strings.HasPrefix(*firewall.Name, firewallNamePrefix)
}

// Checks if GCP firewall rule is equivalent to an Invisinets permit list rule
func isFirewallEqPermitListRule(namespace string, firewall *computepb.Firewall, permitListRule *invisinetspb.PermitListRule) bool {
	if !isInvisinetsPermitListRule(namespace, firewall) {
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

/* --- RESOURCE NAME --- */
// Gets a GCP firewall rule name for an Invisinets permit list rule
// If two Invisinets permit list rules are equal, then they will have the same GCP firewall rule name.
func getFirewallName(ruleName string, resourceId string) string {
	return (fmt.Sprintf("%s-%s-%s", firewallNamePrefix, resourceId, ruleName))
}

// Retrieve the name of the firewall rule from the GCP firewall name
func parseFirewallName(firewallName string) string {
	return strings.SplitN(firewallName, "-", 5)[4]
}

func getInvisinetsNamespacePrefix(namespace string) string {
	return invisinetsPrefix + "-" + namespace
}

// Gets a GCP VPC name
func getVpcName(namespace string) string {
	return getInvisinetsNamespacePrefix(namespace) + "-vpc"
}

// Returns name of firewall for denying all egress traffic
func getDenyAllIngressFirewallName(namespace string) string {
	return getInvisinetsNamespacePrefix(namespace) + "-deny-all-egress"
}

// Gets a GCP subnetwork name for Invisinets based on region
func getSubnetworkName(namespace string, region string) string {
	return getInvisinetsNamespacePrefix(namespace) + "-" + region + "-subnet"
}

// Gets a GCP subnetwork name for Invisinets for resources that need their own subnet
func getIndividualSubnetworkName(namespace string, region string, resource string) string {
	return getInvisinetsNamespacePrefix(namespace) + "-" + region + "-" + resource + "-subnet"
}

func getVpnGwName(namespace string) string {
	return getInvisinetsNamespacePrefix(namespace) + "-vpn-gw"
}

func getRouterName(namespace string) string {
	return getInvisinetsNamespacePrefix(namespace) + "-router"
}

// Returns a peer gateway name when connecting to another cloud
func getPeerGwName(namespace string, cloud string) string {
	return getInvisinetsNamespacePrefix(namespace) + "-" + cloud + "-peer-gw"
}

// Returns a VPN tunnel name when connecting to another cloud
func getVpnTunnelName(namespace string, cloud string, tunnelIdx int) string {
	return getInvisinetsNamespacePrefix(namespace) + "-" + cloud + "-tunnel-" + strconv.Itoa(tunnelIdx)
}

// Returns a VPN tunnel interface name when connecting to another cloud
func getVpnTunnelInterfaceName(namespace string, cloud string, tunnelIdx int, interfaceIdx int) string {
	return getVpnTunnelName(namespace, cloud, tunnelIdx) + "-int-" + strconv.Itoa(interfaceIdx)
}

// Returns a BGP peer name
func getBgpPeerName(cloud string, peerIdx int) string {
	return cloud + "-bgp-peer-" + strconv.Itoa(peerIdx)
}

/* --- RESOURCE URI --- */
// Returns VPC for Invisinets in a shortened GCP URI format
// TODO @seankimkdy: should return full URI
func GetVpcUri(namespace string) string {
	return "global/networks/" + getVpcName(namespace)
}

func getSubnetworkURL(project string, region string, name string) string {
	return fmt.Sprintf("projects/%s/regions/%s/subnetworks/%s", project, region, name)
}

func getRegionFromZone(zone string) string {
	return zone[:strings.LastIndex(zone, "-")]
}

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

func (s *GCPPluginServer) _GetPermitList(ctx context.Context, req *invisinetspb.GetPermitListRequest, firewallsClient *compute.FirewallsClient, instancesClient *compute.InstancesClient, clustersClient *container.ClusterManagerClient) (*invisinetspb.GetPermitListResponse, error) {
	resourceInfo, err := parseResourceUri(req.Resource)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource URI: %w", err)
	}
	resourceInfo.Namespace = req.Namespace

	_, resourceID, err := GetResourceInfo(ctx, instancesClient, clustersClient, resourceInfo)
	if err != nil {
		return nil, err
	}

	// Get firewalls for the resource
	firewalls, err := getFirewallRules(ctx, firewallsClient, resourceInfo.Project, *resourceID)
	if err != nil {
		return nil, fmt.Errorf("unable to get firewalls: %w", err)
	}

	permitListRules := []*invisinetspb.PermitListRule{}

	for _, firewall := range firewalls {
		// Exclude default deny all egress from being included since it applies to every VM
		if isInvisinetsPermitListRule(req.Namespace, firewall) && *firewall.Name != getDenyAllIngressFirewallName(req.Namespace) {
			rules := make([]*invisinetspb.PermitListRule, len(firewall.Allowed))
			for i, rule := range firewall.Allowed {
				protocolNumber, err := getProtocolNumber(*rule.IPProtocol)
				if err != nil {
					return nil, fmt.Errorf("could not get protocol number: %w", err)
				}

				direction := firewallDirectionMapGCPToInvisinets[*firewall.Direction]

				var targets []string
				if direction == invisinetspb.Direction_INBOUND {
					targets = append(firewall.SourceRanges, firewall.SourceTags...)
				} else {
					targets = firewall.DestinationRanges
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

				var tags []string
				if firewall.Description != nil {
					tags = parseDescriptionTags(*firewall.Description)
				}

				rules[i] = &invisinetspb.PermitListRule{
					Name:      parseFirewallName(*firewall.Name),
					Direction: firewallDirectionMapGCPToInvisinets[*firewall.Direction],
					SrcPort:   -1,
					DstPort:   int32(dstPort),
					Protocol:  int32(protocolNumber),
					Targets:   targets,
					Tags:      tags,
				} // SrcPort not specified since GCP doesn't support rules based on source ports
			}
			permitListRules = append(permitListRules, rules...)
		}
	}

	return &invisinetspb.GetPermitListResponse{Rules: permitListRules}, nil
}

func (s *GCPPluginServer) GetPermitList(ctx context.Context, req *invisinetspb.GetPermitListRequest) (*invisinetspb.GetPermitListResponse, error) {
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

func (s *GCPPluginServer) _AddPermitListRules(ctx context.Context, req *invisinetspb.AddPermitListRulesRequest, firewallsClient *compute.FirewallsClient, instancesClient *compute.InstancesClient, subnetworksClient *compute.SubnetworksClient, clustersClient *container.ClusterManagerClient) (*invisinetspb.AddPermitListRulesResponse, error) {
	utils.Log.Printf("Adding permit list rules: %v", req.Resource)
	resourceInfo, err := parseResourceUri(req.Resource)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource URI: %w", err)
	}
	resourceInfo.Namespace = req.Namespace

	utils.Log.Printf("Getting Resource INfo")
	subnet, resourceID, err := GetResourceInfo(ctx, instancesClient, clustersClient, resourceInfo)
	if err != nil {
		utils.Log.Printf("Error getting resource info: %v", err)
		return nil, err
	}

	// Get existing firewalls
	utils.Log.Printf("Getting existing firewalls")
	firewalls, err := getFirewallRules(ctx, firewallsClient, resourceInfo.Project, *resourceID) // need to change how rules are named to figure out this resourceID thing
	if err != nil {
		return nil, fmt.Errorf("unable to get existing firewalls: %w", err)
	}

	existingFirewalls := map[string]*computepb.Firewall{}
	for _, firewall := range firewalls {
		existingFirewalls[*firewall.Name] = firewall
	}

	// Get the network tag
	utils.Log.Printf("Getting the network tag")
	networkTag := getNetworkTag(req.Namespace, resourceInfo.ResourceType, *resourceID)

	// Get subnetwork address space
	utils.Log.Printf("Getting the subnet address space: %v", *subnet)
	parsedSubnetworkUri := parseGCPURL(*subnet)
	getSubnetworkReq := &computepb.GetSubnetworkRequest{
		Project:    resourceInfo.Project,
		Region:     parsedSubnetworkUri["regions"],
		Subnetwork: parsedSubnetworkUri["subnetworks"],
	}
	utils.Log.Printf("Getting the subnet address space2")
	getSubnetworkResp, err := subnetworksClient.Get(ctx, getSubnetworkReq)
	if err != nil {
		utils.Log.Printf("Error getting subnetwork: %v", err)
		return nil, fmt.Errorf("unable to get subnetwork: %w", err)
	}
	subnetworkAddressSpace := *getSubnetworkResp.IpCidrRange

	// Get used address spaces of all clouds
	utils.Log.Printf("Getting the used address spaces of all clouds")
	controllerConn, err := grpc.Dial(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("unable to establish connection with orchestrator: %w", err)
	}
	defer controllerConn.Close()
	controllerClient := invisinetspb.NewControllerClient(controllerConn)
	usedAddressSpaceMappings, err := controllerClient.GetUsedAddressSpaces(context.Background(), &invisinetspb.Namespace{Namespace: req.Namespace})
	if err != nil {
		return nil, fmt.Errorf("unable to get used address spaces: %w", err)
	}

	utils.Log.Printf("Creating firewall rules")
	for _, permitListRule := range req.Rules {
		// TODO @seankimkdy: should we throw an error/warning if user specifies a srcport since GCP doesn't support srcport based firewalls?
		firewallName := getFirewallName(permitListRule.Name, *resourceID)

		patchRequired := false
		if existingFw, ok := existingFirewalls[firewallName]; ok {
			if isFirewallEqPermitListRule(req.Namespace, existingFw, permitListRule) {
				// Firewall already exists and is equivalent to the provided permit list rule
				continue
			} else {
				// Firewall already exists but is not equivalent to the provided permit list rule
				// We should patch the rule, but we need to still check if any new infrastructure is needed
				patchRequired = true
			}
		}

		// Check and create multicloud connections as necessary
		err = utils.CheckAndConnectClouds(utils.GCP, subnetworkAddressSpace, req.Namespace, ctx, permitListRule, usedAddressSpaceMappings, controllerClient)
		if err != nil {
			return nil, fmt.Errorf("unable to check and connect clouds: %w", err)
		}

		firewall := &computepb.Firewall{
			Allowed: []*computepb.Allowed{
				{
					IPProtocol: proto.String(strconv.Itoa(int(permitListRule.Protocol))),
				},
			},
			Description: proto.String(getRuleDescription(permitListRule.Tags)),
			Direction:   proto.String(firewallDirectionMapInvisinetsToGCP[permitListRule.Direction]),
			Name:        proto.String(firewallName),
			Network:     proto.String(GetVpcUri(req.Namespace)),
			TargetTags:  []string{networkTag},
		}
		if permitListRule.DstPort != -1 {
			// Users must explicitly set DstPort to -1 if they want it to apply to all ports since proto can't
			// differentiate between empty and 0 for an int field. Ports of 0 are valid for protocols like TCP/UDP.
			firewall.Allowed[0].Ports = []string{strconv.Itoa(int(permitListRule.DstPort))}
		}
		if permitListRule.Direction == invisinetspb.Direction_INBOUND {
			// TODO @seankimkdy: use SourceTags as well once we start supporting tags
			firewall.SourceRanges = permitListRule.Targets
		} else {
			firewall.DestinationRanges = permitListRule.Targets
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

	return &invisinetspb.AddPermitListRulesResponse{}, nil
}

func (s *GCPPluginServer) AddPermitListRules(ctx context.Context, req *invisinetspb.AddPermitListRulesRequest) (*invisinetspb.AddPermitListRulesResponse, error) {
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

	return s._AddPermitListRules(ctx, req, firewallsClient, instancesClient, subnetworksClient, clustersClient)
}

func (s *GCPPluginServer) _DeletePermitListRules(ctx context.Context, req *invisinetspb.DeletePermitListRulesRequest, firewallsClient *compute.FirewallsClient, instancesClient *compute.InstancesClient, clustersClient *container.ClusterManagerClient) (*invisinetspb.DeletePermitListRulesResponse, error) {
	resourceInfo, err := parseResourceUri(req.Resource)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource URI: %w", err)
	}
	resourceInfo.Namespace = req.Namespace

	_, resourceID, err := GetResourceInfo(ctx, instancesClient, clustersClient, resourceInfo)
	if err != nil {
		return nil, err
	}

	// Delete firewalls corresponding to provided permit list rules
	for _, ruleName := range req.RuleNames {
		deleteFirewallReq := &computepb.DeleteFirewallRequest{
			Firewall: getFirewallName(ruleName, *resourceID),
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

	return &invisinetspb.DeletePermitListRulesResponse{}, nil
}

func (s *GCPPluginServer) DeletePermitListRules(ctx context.Context, req *invisinetspb.DeletePermitListRulesRequest) (*invisinetspb.DeletePermitListRulesResponse, error) {
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

func (s *GCPPluginServer) _CreateResource(ctx context.Context, resourceDescription *invisinetspb.ResourceDescription, instancesClient *compute.InstancesClient, networksClient *compute.NetworksClient, subnetworksClient *compute.SubnetworksClient, firewallsClient *compute.FirewallsClient, clustersClient *container.ClusterManagerClient) (*invisinetspb.CreateResourceResponse, error) {
	// Read and validate user-provided description
	utils.Log.Printf(fmt.Sprintf("Creating resource."))
	resourceInfo, err := IsValidResource(ctx, resourceDescription)
	if err != nil {
		utils.Log.Printf("Invalid resource description")
		return nil, fmt.Errorf("unsupported resource description: %w", err)
	}
	project, zone := resourceInfo.Project, resourceInfo.Zone
	region := zone[:strings.LastIndex(zone, "-")]
	resourceInfo.Region = region
	resourceInfo.Namespace = resourceDescription.Namespace

	subnetExists := false
	subnetName := getSubnetworkName(resourceDescription.Namespace, region)

	// Check if Invisinets specific VPC already exists
	utils.Log.Printf("Checking if the Invisinets VPC already exists.")
	nsVpcName := getVpcName(resourceDescription.Namespace)
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
					Description:           proto.String("VPC for Invisinets"),
					AutoCreateSubnetworks: proto.Bool(false),
					RoutingConfig: &computepb.NetworkRoutingConfig{
						RoutingMode: proto.String(computepb.NetworkRoutingConfig_GLOBAL.String()),
					},
				},
			}
			insertNetworkOp, err := networksClient.Insert(ctx, insertNetworkRequest)
			if err != nil {
				utils.Log.Printf("Unable to insert network %v", err)
				return nil, fmt.Errorf("unable to insert network: %w", err)
			}
			if err = insertNetworkOp.Wait(ctx); err != nil {
				utils.Log.Printf("Unable to wait for operation %v", err)
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
					Description:       proto.String("Invisinets deny all traffic"),
					DestinationRanges: []string{"0.0.0.0/0"},
					Direction:         proto.String(computepb.Firewall_EGRESS.String()),
					Name:              proto.String(getDenyAllIngressFirewallName(resourceDescription.Namespace)),
					Network:           proto.String(GetVpcUri(resourceDescription.Namespace)),
					Priority:          proto.Int32(65534),
				},
			}
			insertFirewallOp, err := firewallsClient.Insert(ctx, insertFirewallReq)
			if err != nil {
				utils.Log.Printf("Unable to insert firewall rule %v", err)
				return nil, fmt.Errorf("unable to create firewall rule: %w", err)
			}
			if err = insertFirewallOp.Wait(ctx); err != nil {
				utils.Log.Printf("Unable to wait for firewall rule%v", err)
				return nil, fmt.Errorf("unable to wait for the operation: %w", err)
			}
		} else {
			utils.Log.Printf("Failed to get invisinets vpc networ %v", err)
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

	// Find unused address spaces
	addressSpaces := []string{}
	numAddressSpacesNeeded := int32(resourceInfo.NumAdditionalAddressSpaces)
	utils.Log.Printf("Collecting needed address spaces")
	if !subnetExists || resourceInfo.NumAdditionalAddressSpaces > 0 {
		conn, err := grpc.Dial(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			utils.Log.Printf("Unable to connect to orchestrator")
			return nil, fmt.Errorf("unable to establish connection with orchestrator: %w", err)
		}
		defer conn.Close()
		client := invisinetspb.NewControllerClient(conn)

		if !subnetExists {
			numAddressSpacesNeeded += 1
		}

		response, err := client.FindUnusedAddressSpaces(context.Background(), &invisinetspb.FindUnusedAddressSpacesRequest{Namespace: resourceDescription.Namespace, Num: &numAddressSpacesNeeded})
		if err != nil {
			utils.Log.Printf("Unable to get address spaces %v", err)
			return nil, fmt.Errorf("unable to find unused address space: %w", err)
		}

		utils.Log.Printf("Address spaces: %v", response.AddressSpaces)
		utils.Log.Printf("Subnet exists: %v", subnetExists)
		addressSpaces = response.AddressSpaces
	}

	utils.Log.Printf("Create a subnet if it does not exist")
	if !subnetExists {

		insertSubnetworkRequest := &computepb.InsertSubnetworkRequest{
			Project: project,
			Region:  region,
			SubnetworkResource: &computepb.Subnetwork{
				Name:        proto.String(subnetName),
				Description: proto.String("Invisinets subnetwork for " + region),
				Network:     proto.String(GetVpcUri(resourceDescription.Namespace)),
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
	utils.Log.Printf("Read and provision the resource")
	uri, ip, err := ReadAndProvisionResource(ctx, resourceDescription, subnetName, resourceInfo, instancesClient, clustersClient, firewallsClient, addressSpaces)
	if err != nil {
		return nil, fmt.Errorf("unable to read and provision resource: %w", err)
	}
	utils.Log.Printf("Return")
	return &invisinetspb.CreateResourceResponse{Name: resourceInfo.Name, Uri: uri, Ip: ip}, nil
}

func (s *GCPPluginServer) CreateResource(ctx context.Context, resourceDescription *invisinetspb.ResourceDescription) (*invisinetspb.CreateResourceResponse, error) {
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

func (s *GCPPluginServer) _GetUsedAddressSpaces(ctx context.Context, invisinetsDeployment *invisinetspb.InvisinetsDeployment, networksClient *compute.NetworksClient, subnetworksClient *compute.SubnetworksClient) (*invisinetspb.AddressSpaceList, error) {
	project := parseGCPURL(invisinetsDeployment.Id)["projects"]
	addressSpaceList := &invisinetspb.AddressSpaceList{}

	nsVpcName := getVpcName(invisinetsDeployment.Namespace)
	getNetworkReq := &computepb.GetNetworkRequest{
		Network: nsVpcName,
		Project: project,
	}
	getNetworkResp, err := networksClient.Get(ctx, getNetworkReq)
	if err != nil {
		if isErrorNotFound(err) {
			return addressSpaceList, nil
		} else {
			return nil, fmt.Errorf("failed to get invisinets vpc network: %w", err)
		}
	} else {
		addressSpaceList.AddressSpaces = []string{}
		for _, subnetURL := range getNetworkResp.Subnetworks {
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
			addressSpaceList.AddressSpaces = append(addressSpaceList.AddressSpaces, *getSubnetworkResp.IpCidrRange)
			for _, secondaryRange := range getSubnetworkResp.SecondaryIpRanges {
				addressSpaceList.AddressSpaces = append(addressSpaceList.AddressSpaces, *secondaryRange.IpCidrRange)
			}
		}
	}
	utils.Log.Printf("Address space list: %v", addressSpaceList)

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

func (s *GCPPluginServer) _GetUsedAsns(ctx context.Context, req *invisinetspb.GetUsedAsnsRequest, routersClient *compute.RoutersClient) (*invisinetspb.GetUsedAsnsResponse, error) {
	project := parseGCPURL(req.Deployment.Id)["projects"]

	getRouterReq := &computepb.GetRouterRequest{
		Project: project,
		Region:  vpnRegion,
		Router:  getRouterName(req.Deployment.Namespace),
	}
	getRouterResp, err := routersClient.Get(ctx, getRouterReq)
	if err != nil {
		if isErrorNotFound(err) {
			return &invisinetspb.GetUsedAsnsResponse{}, nil
		} else {
			return nil, fmt.Errorf("unable to get router: %w", err)
		}
	}

	return &invisinetspb.GetUsedAsnsResponse{Asns: []uint32{*getRouterResp.Bgp.Asn}}, nil
}

func (s *GCPPluginServer) GetUsedAsns(ctx context.Context, req *invisinetspb.GetUsedAsnsRequest) (*invisinetspb.GetUsedAsnsResponse, error) {
	routersClient, err := compute.NewRoutersRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewRoutersRESTClient: %w", err)
	}
	return s._GetUsedAsns(ctx, req, routersClient)
}

func (s *GCPPluginServer) _GetUsedBgpPeeringIpAddresses(ctx context.Context, req *invisinetspb.GetUsedBgpPeeringIpAddressesRequest, routersClient *compute.RoutersClient) (*invisinetspb.GetUsedBgpPeeringIpAddressesResponse, error) {
	project := parseGCPURL(req.Deployment.Id)["projects"]

	resp := &invisinetspb.GetUsedBgpPeeringIpAddressesResponse{}
	getRouterReq := &computepb.GetRouterRequest{
		Project: project,
		Region:  vpnRegion,
		Router:  getRouterName(req.Deployment.Namespace),
	}
	getRouterResp, err := routersClient.Get(ctx, getRouterReq)
	if err != nil {
		if isErrorNotFound(err) {
			return resp, nil
		} else {
			return nil, fmt.Errorf("unable to get router: %w", err)
		}
	}

	resp.IpAddresses = make([]string, len(getRouterResp.BgpPeers))
	for i, bgpPeer := range getRouterResp.BgpPeers {
		resp.IpAddresses[i] = *bgpPeer.IpAddress
	}
	return resp, nil
}

func (s *GCPPluginServer) GetUsedBgpPeeringIpAddresses(ctx context.Context, req *invisinetspb.GetUsedBgpPeeringIpAddressesRequest) (*invisinetspb.GetUsedBgpPeeringIpAddressesResponse, error) {
	routersClient, err := compute.NewRoutersRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewRoutersRESTClient: %w", err)
	}
	return s._GetUsedBgpPeeringIpAddresses(ctx, req, routersClient)
}

func (s *GCPPluginServer) _CreateVpnGateway(ctx context.Context, req *invisinetspb.CreateVpnGatewayRequest, vpnGatewaysClient *compute.VpnGatewaysClient, routersClient *compute.RoutersClient) (*invisinetspb.CreateVpnGatewayResponse, error) {
	project := parseGCPURL(req.Deployment.Id)["projects"]

	// Create VPN gateway
	insertVpnGatewayReq := &computepb.InsertVpnGatewayRequest{
		Project: project,
		Region:  vpnRegion,
		VpnGatewayResource: &computepb.VpnGateway{
			Name:        proto.String(getVpnGwName(req.Deployment.Namespace)),
			Description: proto.String("Invisinets VPN gateway for multicloud connections"),
			Network:     proto.String(GetVpcUri(req.Deployment.Namespace)),
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
		return nil, fmt.Errorf("unable to establish connection with frontend: %w", err)
	}
	defer conn.Close()
	client := invisinetspb.NewControllerClient(conn)
	findUnusedAsnResp, err := client.FindUnusedAsn(ctx, &invisinetspb.FindUnusedAsnRequest{Namespace: req.Deployment.Namespace})
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
			Description: proto.String("Invisinets router for multicloud connections"),
			Network:     proto.String(GetVpcUri(req.Deployment.Namespace)),
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
	resp := &invisinetspb.CreateVpnGatewayResponse{Asn: asn}
	resp.GatewayIpAddresses = make([]string, vpnNumConnections)
	for i := 0; i < vpnNumConnections; i++ {
		resp.GatewayIpAddresses[i] = *vpnGateway.VpnInterfaces[i].IpAddress
	}

	return resp, nil
}

func (s *GCPPluginServer) CreateVpnGateway(ctx context.Context, req *invisinetspb.CreateVpnGatewayRequest) (*invisinetspb.CreateVpnGatewayResponse, error) {
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

func (s *GCPPluginServer) _CreateVpnConnections(ctx context.Context, req *invisinetspb.CreateVpnConnectionsRequest, externalVpnGatewaysClient *compute.ExternalVpnGatewaysClient, vpnTunnelsClient *compute.VpnTunnelsClient, routersClient *compute.RoutersClient) (*invisinetspb.BasicResponse, error) {
	project := parseGCPURL(req.Deployment.Id)["projects"]
	vpnNumConnections := utils.GetNumVpnConnections(req.Cloud, utils.GCP)

	// Insert external VPN gateway
	insertExternalVpnGatewayReq := &computepb.InsertExternalVpnGatewayRequest{
		Project: project,
		ExternalVpnGatewayResource: &computepb.ExternalVpnGateway{
			Name:           proto.String(getPeerGwName(req.Deployment.Namespace, req.Cloud)),
			Description:    proto.String("Invisinets peer gateway to " + req.Cloud),
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
				Description:                  proto.String(fmt.Sprintf("Invisinets VPN tunnel to %s (interface %d)", req.Cloud, i)),
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

	return &invisinetspb.BasicResponse{Success: true}, nil
}

func (s *GCPPluginServer) CreateVpnConnections(ctx context.Context, req *invisinetspb.CreateVpnConnectionsRequest) (*invisinetspb.BasicResponse, error) {
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
	invisinetspb.RegisterCloudPluginServer(grpcServer, gcpServer)
	fmt.Println("Starting server on port :", port)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println(err.Error())
		}
	}()
	return gcpServer
}
