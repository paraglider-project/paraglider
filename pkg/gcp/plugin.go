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
	"fmt"
	"net"
	"os"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type GCPPluginServer struct {
	paragliderpb.UnimplementedCloudPluginServer
	orchestratorServerAddr string
}

func (s *GCPPluginServer) GetPermitList(ctx context.Context, req *paragliderpb.GetPermitListRequest) (*paragliderpb.GetPermitListResponse, error) {
	// Lazy client initialization since necessary clients vary depending on the resource
	clients := &GCPClients{}
	defer clients.Close()

	return s._GetPermitList(ctx, req, clients)
}

func (s *GCPPluginServer) _GetPermitList(ctx context.Context, req *paragliderpb.GetPermitListRequest, clients *GCPClients) (*paragliderpb.GetPermitListResponse, error) {
	resourceInfo, err := parseResourceUrl(req.Resource)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource URL: %w", err)
	}
	resourceInfo.Namespace = req.Namespace

	netInfo, err := GetResourceNetworkInfo(ctx, resourceInfo, clients)
	if err != nil {
		return nil, err
	}

	// Get firewalls for the resource
	firewalls, err := getFirewallRules(ctx, resourceInfo.Project, netInfo.ResourceID, clients)
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

func (s *GCPPluginServer) AddPermitListRules(ctx context.Context, req *paragliderpb.AddPermitListRulesRequest) (*paragliderpb.AddPermitListRulesResponse, error) {
	// Lazy client initialization since necessary clients vary depending on the resource
	clients := &GCPClients{}
	defer clients.Close()

	return s._AddPermitListRules(ctx, req, clients)
}

func (s *GCPPluginServer) _AddPermitListRules(ctx context.Context, req *paragliderpb.AddPermitListRulesRequest, clients *GCPClients) (*paragliderpb.AddPermitListRulesResponse, error) {
	resourceInfo, err := parseResourceUrl(req.Resource)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource URL: %w", err)
	}
	resourceInfo.Namespace = req.Namespace

	netInfo, err := GetResourceNetworkInfo(ctx, resourceInfo, clients)
	if err != nil {
		return nil, err
	}

	// Get existing firewalls
	firewalls, err := getFirewallRules(ctx, resourceInfo.Project, netInfo.ResourceID, clients)
	if err != nil {
		return nil, fmt.Errorf("unable to get existing firewalls: %w", err)
	}

	existingFirewalls := map[string]*computepb.Firewall{}
	for _, firewall := range firewalls {
		existingFirewalls[*firewall.Name] = firewall
	}

	// Get the firewall target (tag or IP depending on the resource)
	target, err := GetFirewallTarget(ctx, resourceInfo, netInfo)
	if err != nil {
		return nil, fmt.Errorf("unable to get firewall target: %w", err)
	}

	// Get used address spaces of all clouds
	orchestratorConn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("unable to establish connection with orchestrator: %w", err)
	}
	defer orchestratorConn.Close()
	orchestratorClient := paragliderpb.NewControllerClient(orchestratorConn)
	getUsedAddressSpacesResp, err := orchestratorClient.GetUsedAddressSpaces(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("unable to get used address spaces: %w", err)
	}

	for _, permitListRule := range req.Rules {
		// TODO @seankimkdy: should we throw an error/warning if user specifies a srcport since GCP doesn't support srcport based firewalls?
		firewallName := getFirewallName(req.Namespace, permitListRule.Name, netInfo.ResourceID)

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
					networksClient, err := clients.GetNetworksClient(ctx)
					if err != nil {
						return nil, fmt.Errorf("unable to get networks client: %w", err)
					}

					peerProject := parseUrl(peeringCloudInfo.Deployment)["projects"]
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

		firewall, err := paragliderRuleToFirewallRule(req.Namespace, resourceInfo.Project, firewallName, *target, permitListRule)
		if err != nil {
			return nil, fmt.Errorf("unable to convert permit list rule to firewall rule: %w", err)
		}

		firewallsClient, err := clients.GetFirewallsClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get firewalls client: %w", err)
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

func (s *GCPPluginServer) DeletePermitListRules(ctx context.Context, req *paragliderpb.DeletePermitListRulesRequest) (*paragliderpb.DeletePermitListRulesResponse, error) {
	// Lazy client initialization since necessary clients vary depending on the resource
	clients := &GCPClients{}
	defer clients.Close()

	return s._DeletePermitListRules(ctx, req, clients)
}

func (s *GCPPluginServer) _DeletePermitListRules(ctx context.Context, req *paragliderpb.DeletePermitListRulesRequest, clients *GCPClients) (*paragliderpb.DeletePermitListRulesResponse, error) {
	resourceInfo, err := parseResourceUrl(req.Resource)
	if err != nil {
		return nil, fmt.Errorf("unable to parse resource URL: %w", err)
	}
	resourceInfo.Namespace = req.Namespace

	netInfo, err := GetResourceNetworkInfo(ctx, resourceInfo, clients)
	if err != nil {
		return nil, err
	}

	// Delete firewalls corresponding to provided permit list rules
	firewallsClient, err := clients.GetFirewallsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get firewalls client: %w", err)
	}

	for _, ruleName := range req.RuleNames {
		deleteFirewallReq := &computepb.DeleteFirewallRequest{
			Firewall: getFirewallName(req.Namespace, ruleName, netInfo.ResourceID),
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

func (s *GCPPluginServer) CreateResource(ctx context.Context, resourceDescription *paragliderpb.CreateResourceRequest) (*paragliderpb.CreateResourceResponse, error) {
	// Lazy client initialization since necessary clients vary depending on the resource
	clients := &GCPClients{}
	defer clients.Close()

	return s._CreateResource(ctx, resourceDescription, clients)
}

func (s *GCPPluginServer) _CreateResource(ctx context.Context, resourceDescription *paragliderpb.CreateResourceRequest, clients *GCPClients) (*paragliderpb.CreateResourceResponse, error) {
	project := parseUrl(resourceDescription.Deployment.Id)["projects"]

	// Read and validate user-provided description
	resourceInfo, err := IsValidResource(ctx, resourceDescription)
	if err != nil {
		return nil, fmt.Errorf("unsupported resource description: %w", err)
	}

	// Set project and namespace in resourceInfo
	resourceInfo.Project = project
	resourceInfo.Namespace = resourceDescription.Deployment.Namespace

	subnetExists := false
	subnetName := getSubnetworkName(resourceDescription.Deployment.Namespace, resourceInfo.Region)

	// Get the networks client
	networksClient, err := clients.GetNetworksClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get networks client: %w", err)
	}

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
			firewallsClient, err := clients.GetFirewallsClient(ctx)
			if err != nil {
				return nil, fmt.Errorf("unable to get firewalls client: %w", err)
			}

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
					Network:           proto.String(GetVpcUrl(project, resourceDescription.Deployment.Namespace)),
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
			parsedSubnetURL := parseUrl(subnetURL)
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
		conn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
		subnetworksClient, err := clients.GetSubnetworksClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get subnetworks client: %w", err)
		}

		insertSubnetworkRequest := &computepb.InsertSubnetworkRequest{
			Project: project,
			Region:  resourceInfo.Region,
			SubnetworkResource: &computepb.Subnetwork{
				Name:        proto.String(subnetName),
				Description: proto.String("Paraglider subnetwork for " + resourceInfo.Region),
				Network:     proto.String(GetVpcUrl(project, resourceDescription.Deployment.Namespace)),
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
	url, ip, err := ReadAndProvisionResource(ctx, resourceDescription, subnetName, resourceInfo, addressSpaces, clients)

	if err != nil {
		return nil, fmt.Errorf("unable to read and provision resource: %w", err)
	}
	return &paragliderpb.CreateResourceResponse{Name: resourceInfo.Name, Uri: url, Ip: ip}, nil
}

func (s *GCPPluginServer) GetUsedAddressSpaces(ctx context.Context, req *paragliderpb.GetUsedAddressSpacesRequest) (*paragliderpb.GetUsedAddressSpacesResponse, error) {
	clients := &GCPClients{}
	networksClient, err := clients.GetNetworksClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get networks client: %w", err)
	}
	subnetworksClient, err := clients.GetSubnetworksClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get subnetworks client: %w", err)
	}
	addressesClient, err := clients.GetAddressesClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get addresses client: %w", err)
	}
	defer clients.Close()
	return s._GetUsedAddressSpaces(ctx, req, networksClient, subnetworksClient, addressesClient)
}

func (s *GCPPluginServer) _GetUsedAddressSpaces(ctx context.Context, req *paragliderpb.GetUsedAddressSpacesRequest, networksClient *compute.NetworksClient, subnetworksClient *compute.SubnetworksClient, addressesClient *compute.AddressesClient) (*paragliderpb.GetUsedAddressSpacesResponse, error) {
	resp := &paragliderpb.GetUsedAddressSpacesResponse{}
	resp.AddressSpaceMappings = make([]*paragliderpb.AddressSpaceMapping, len(req.Deployments))
	for i, deployment := range req.Deployments {
		resp.AddressSpaceMappings[i] = &paragliderpb.AddressSpaceMapping{
			Cloud:     utils.GCP,
			Namespace: deployment.Namespace,
		}
		project := parseUrl(deployment.Id)["projects"]

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
			parsedSubnetURL := parseUrl(subnetURL)
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

		// Get addresses not associated with the vpc (might be used for PSCs)
		listAddressesReq := &computepb.ListAddressesRequest{
			Project: project,
			Filter:  proto.String(fmt.Sprintf("labels.paraglider_ns eq %s", deployment.Namespace)), // TODO NOW: make the label name a constant
		}
		listAddressesResp := addressesClient.List(ctx, listAddressesReq)
		if err != nil {
			return nil, fmt.Errorf("unable to list addresses: %w", err)
		}
		for {
			address, err := listAddressesResp.Next()
			if address == nil {
				break
			}
			if err != nil {
				return nil, err
			}
			resp.AddressSpaceMappings[i].AddressSpaces = append(resp.AddressSpaceMappings[i].AddressSpaces, *address.Address)
		}
	}
	return resp, nil
}

func (s *GCPPluginServer) GetUsedAsns(ctx context.Context, req *paragliderpb.GetUsedAsnsRequest) (*paragliderpb.GetUsedAsnsResponse, error) {
	clients := &GCPClients{}
	routersClient, err := clients.GetRoutersClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get routers client: %w", err)
	}
	defer clients.Close()

	return s._GetUsedAsns(ctx, req, routersClient)
}

func (s *GCPPluginServer) _GetUsedAsns(ctx context.Context, req *paragliderpb.GetUsedAsnsRequest, routersClient *compute.RoutersClient) (*paragliderpb.GetUsedAsnsResponse, error) {
	resp := &paragliderpb.GetUsedAsnsResponse{}
	for _, deployment := range req.Deployments {
		project := parseUrl(deployment.Id)["projects"]

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

func (s *GCPPluginServer) GetUsedBgpPeeringIpAddresses(ctx context.Context, req *paragliderpb.GetUsedBgpPeeringIpAddressesRequest) (*paragliderpb.GetUsedBgpPeeringIpAddressesResponse, error) {
	clients := &GCPClients{}
	routersClient, err := clients.GetRoutersClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get routers client: %w", err)
	}
	defer clients.Close()
	return s._GetUsedBgpPeeringIpAddresses(ctx, req, routersClient)
}

func (s *GCPPluginServer) _GetUsedBgpPeeringIpAddresses(ctx context.Context, req *paragliderpb.GetUsedBgpPeeringIpAddressesRequest, routersClient *compute.RoutersClient) (*paragliderpb.GetUsedBgpPeeringIpAddressesResponse, error) {
	resp := &paragliderpb.GetUsedBgpPeeringIpAddressesResponse{}
	for _, deployment := range req.Deployments {
		project := parseUrl(deployment.Id)["projects"]

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

func (s *GCPPluginServer) CreateVpnGateway(ctx context.Context, req *paragliderpb.CreateVpnGatewayRequest) (*paragliderpb.CreateVpnGatewayResponse, error) {
	clients := &GCPClients{}

	vpnGatewaysClient, err := clients.GetVpnGatewaysClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get vpn gateways client: %w", err)
	}
	routersClient, err := clients.GetRoutersClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get routers client: %w", err)
	}
	defer clients.Close()

	return s._CreateVpnGateway(ctx, req, vpnGatewaysClient, routersClient)
}

func (s *GCPPluginServer) _CreateVpnGateway(ctx context.Context, req *paragliderpb.CreateVpnGatewayRequest, vpnGatewaysClient *compute.VpnGatewaysClient, routersClient *compute.RoutersClient) (*paragliderpb.CreateVpnGatewayResponse, error) {
	project := parseUrl(req.Deployment.Id)["projects"]

	// Create VPN gateway
	insertVpnGatewayReq := &computepb.InsertVpnGatewayRequest{
		Project: project,
		Region:  vpnRegion,
		VpnGatewayResource: &computepb.VpnGateway{
			Name:        proto.String(getVpnGwName(req.Deployment.Namespace)),
			Description: proto.String("Paraglider VPN gateway for multicloud connections"),
			Network:     proto.String(GetVpcUrl(project, req.Deployment.Namespace)),
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
	conn, err := grpc.NewClient(s.orchestratorServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
			Network:     proto.String(GetVpcUrl(project, req.Deployment.Namespace)),
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
					LinkedVpnTunnel: proto.String(getVpnTunnelUrl(project, vpnRegion, getVpnTunnelName(req.Deployment.Namespace, req.Cloud, i))),
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

func (s *GCPPluginServer) CreateVpnConnections(ctx context.Context, req *paragliderpb.CreateVpnConnectionsRequest) (*paragliderpb.CreateVpnConnectionsResponse, error) {
	clients := &GCPClients{}
	externalVpnGatewaysClient, err := clients.GetExternalVpnGatewaysClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get external vpn gateways client: %w", err)
	}
	vpnTunnelsClient, err := clients.GetVpnTunnelsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get vpn tunnels client: %w", err)
	}
	routersClient, err := clients.GetRoutersClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get routers client: %w", err)
	}
	defer clients.Close()
	return s._CreateVpnConnections(ctx, req, externalVpnGatewaysClient, vpnTunnelsClient, routersClient)
}

func (s *GCPPluginServer) _CreateVpnConnections(ctx context.Context, req *paragliderpb.CreateVpnConnectionsRequest, externalVpnGatewaysClient *compute.ExternalVpnGatewaysClient, vpnTunnelsClient *compute.VpnTunnelsClient, routersClient *compute.RoutersClient) (*paragliderpb.CreateVpnConnectionsResponse, error) {
	project := parseUrl(req.Deployment.Id)["projects"]
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
				PeerExternalGateway:          proto.String(getPeerGatewayUrl(project, getPeerGwName(req.Deployment.Namespace, req.Cloud))),
				PeerExternalGatewayInterface: proto.Int32(int32(i)),
				IkeVersion:                   proto.Int32(ikeVersion),
				SharedSecret:                 proto.String(req.SharedKey),
				Router:                       proto.String(getRouterUrl(project, vpnRegion, getRouterName(req.Deployment.Namespace))),
				VpnGateway:                   proto.String(getVpnGatewayUrl(project, vpnRegion, getVpnGwName(req.Deployment.Namespace))),
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

	return &paragliderpb.CreateVpnConnectionsResponse{}, nil
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
