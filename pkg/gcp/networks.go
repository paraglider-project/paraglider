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

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/protobuf/proto"
)

// Gets a GCP VPC name
func getVpcName(namespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-vpc"
}

// Gets a GCP subnetwork name for Paraglider based on region
func getSubnetworkName(namespace string, region string) string {
	return getParagliderNamespacePrefix(namespace) + "-" + region + "-subnet"
}

// Returns a VPC network peering name
func getNetworkPeeringName(namespace string, peerNamespace string) string {
	return getParagliderNamespacePrefix(namespace) + "-" + peerNamespace + "-peering"
}

// getSubnetworkUrl returns a fully qualified URL for a subnetwork
func getSubnetworkUrl(project string, region string, name string) string {
	return computeUrlPrefix + fmt.Sprintf("projects/%s/regions/%s/subnetworks/%s", project, region, name)
}

// getVpcUrl returns a fully qualified URL for a VPC network
func getVpcUrl(project string, namespace string) string {
	return computeUrlPrefix + fmt.Sprintf("projects/%s/global/networks/%s", project, getVpcName(namespace))
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
	peerVpcUrl := getVpcUrl(peerProject, peerNamespace)
	addPeeringNetworkReq := &computepb.AddPeeringNetworkRequest{
		Network: getVpcName(currentNamespace),
		Project: currentProject,
		NetworksAddPeeringRequestResource: &computepb.NetworksAddPeeringRequest{
			// Don't specify Name or PeerNetwork field here as GCP will throw an error
			NetworkPeering: &computepb.NetworkPeering{
				Name:                 proto.String(networkPeeringName),
				Network:              proto.String(peerVpcUrl),
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

// setupNatGateway creates a NAT gateway if it doesn't already exist.
func setupNatGateway(ctx context.Context, routersClient *compute.RoutersClient, project string, namespace string) error {
	getRouterReq := &computepb.GetRouterRequest{
		Project: project,
		Region:  vpnRegion,
		Router:  getRouterName(namespace),
	}
	router, err := routersClient.Get(ctx, getRouterReq)
	nat := &computepb.RouterNat{
		Name:                          proto.String(getNatName(namespace)),
		NatIpAllocateOption:           proto.String(computepb.RouterNat_AUTO_ONLY.String()),
		SourceSubnetworkIpRangesToNat: proto.String(computepb.RouterNat_ALL_SUBNETWORKS_ALL_IP_RANGES.String()),
	}
	if err != nil {
		if isErrorNotFound(err) {
			// Create router if it doesn't already exist
			insertRouterReq := &computepb.InsertRouterRequest{
				Project: project,
				Region:  vpnRegion, // Same router with router that manages BGP for VPN gateways
				RouterResource: &computepb.Router{
					Name:        proto.String(getRouterName(namespace)),
					Description: proto.String("Paraglider router for BGP peering"),
					Network:     proto.String(getVpcUrl(project, namespace)),
					Nats:        []*computepb.RouterNat{nat},
				},
			}
			insertRouterOp, err := routersClient.Insert(ctx, insertRouterReq)
			if err != nil {
				return fmt.Errorf("unable to insert router: %w", err)
			}
			if err = insertRouterOp.Wait(ctx); err != nil {
				return fmt.Errorf("unable to wait for the operation: %w", err)
			}
		} else {
			return fmt.Errorf("unable to get router: %w", err)
		}
	} else {
		// Router already exists
		if router.Nats == nil || len(router.Nats) == 0 {
			// NAT doesn't exist
			patchRouterReq := &computepb.PatchRouterRequest{
				Project:        project,
				Region:         vpnRegion,
				Router:         getRouterName(namespace),
				RouterResource: router,
			}
			patchRouterReq.RouterResource.Nats = []*computepb.RouterNat{nat}
			patchRouterOp, err := routersClient.Patch(ctx, patchRouterReq)
			if err != nil {
				return fmt.Errorf("unable to modify router: %w", err)
			}
			if err = patchRouterOp.Wait(ctx); err != nil {
				return fmt.Errorf("unable to wait for the operation: %w", err)
			}
		} else if len(router.Nats) == 1 && *router.Nats[0].Name == getNatName(namespace) {
			// NAT already exists
			return nil
		} else {
			return fmt.Errorf("unexpected NAT configuration")
		}
	}
	return nil
}
