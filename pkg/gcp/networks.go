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

func getSubnetworkURL(project string, region string, name string) string {
	return fmt.Sprintf("projects/%s/regions/%s/subnetworks/%s", project, region, name)
}

func GetVpcUri(project, namespace string) string {
	return computeURLPrefix + fmt.Sprintf("projects/%s/global/networks/%s", project, getVpcName(namespace))
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
