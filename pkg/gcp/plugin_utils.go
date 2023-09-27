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
	"fmt"
	"os"
	"strings"
	"testing"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	networkmanagement "cloud.google.com/go/networkmanagement/apiv1"
	"cloud.google.com/go/networkmanagement/apiv1/networkmanagementpb"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type GcpTestTeardownInfo struct {
	Project               string
	InsertInstanceReqs    []*computepb.InsertInstanceRequest
	ConnectivityTestNames []string
}

func GetGcpProject() string {
	project := os.Getenv("INVISINETS_GCP_PROJECT")
	if project == "" {
		panic("INVISINETS_GCP_PROJECT must be set")
	}
	return project
}

func teardownPanic(msg string, err error) {
	const docstringMsg = "see docstring of TeardownGcpTesting on how to manually delete resources"
	panic(fmt.Sprintf("%s (%s): %v", msg, docstringMsg, err))
}

// Cleans up any resources that were created
// If you got a panic while the tests ran, you may need to manually clean up resources.
// Here is the order for deleting resources when deleting through the console
// - instances, VPN tunnels, VPN gateway + peer/external VPN gateways + router, VPC
func TeardownGcpTesting(teardownInfo *GcpTestTeardownInfo) {
	ctx := context.Background()

	// Instances
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		teardownPanic("unable to create instances client", err)
	}
	defer instancesClient.Close()
	for _, insertInstanceReq := range teardownInfo.InsertInstanceReqs {
		deleteInstanceReq := &computepb.DeleteInstanceRequest{
			Project:  insertInstanceReq.Project,
			Zone:     insertInstanceReq.Zone,
			Instance: *insertInstanceReq.InstanceResource.Name,
		}
		deleteInstanceReqOp, err := instancesClient.Delete(ctx, deleteInstanceReq)
		if err != nil {
			if !isErrorNotFound(err) {
				teardownPanic("unable to delete instance", err)
			}
		} else {
			if err = deleteInstanceReqOp.Wait(ctx); err != nil {
				teardownPanic("unable to wait on delete instance operation", err)
			}
		}
	}

	// Subnetworks
	networksClient, err := compute.NewNetworksRESTClient(ctx)
	if err != nil {
		teardownPanic("unable to create networks client", err)
	}
	defer networksClient.Close()
	subnetworksClient, err := compute.NewSubnetworksRESTClient(ctx)
	if err != nil {
		teardownPanic("unable to create subnetworks client", err)
	}
	defer subnetworksClient.Close()
	deletedSubnetworkRegions := map[string]bool{}
	for _, insertInstanceReq := range teardownInfo.InsertInstanceReqs {
		region := insertInstanceReq.Zone[:strings.LastIndex(insertInstanceReq.Zone, "-")]
		if !deletedSubnetworkRegions[region] {
			deleteSubnetworkReq := &computepb.DeleteSubnetworkRequest{
				Project:    teardownInfo.Project,
				Region:     region,
				Subnetwork: getGCPSubnetworkName(region),
			}
			deleteSubnetworkOp, err := subnetworksClient.Delete(ctx, deleteSubnetworkReq)
			if err != nil {
				if !isErrorNotFound(err) {
					teardownPanic("unable to delete subnetwork", err)
				}
			} else {
				if err = deleteSubnetworkOp.Wait(ctx); err != nil {
					teardownPanic("unable to wait on delete subnetwork operation", err)
				}
			}
			deletedSubnetworkRegions[region] = true
		}
	}

	// Firewalls
	getEffectiveFirewallsReq := &computepb.GetEffectiveFirewallsNetworkRequest{
		Project: teardownInfo.Project,
		Network: vpcName,
	}
	getEffectiveFirewallsResp, err := networksClient.GetEffectiveFirewalls(ctx, getEffectiveFirewallsReq)
	if err != nil {
		teardownPanic("unable to get effective firewalls", err)
	}
	firewallsClient, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		teardownPanic("unable to create firewalls client", err)
	}
	defer firewallsClient.Close()
	for _, firewall := range getEffectiveFirewallsResp.Firewalls {
		deleteFirewallReq := &computepb.DeleteFirewallRequest{
			Firewall: *firewall.Name,
			Project:  teardownInfo.Project,
		}
		deleteFirewallOp, err := firewallsClient.Delete(ctx, deleteFirewallReq)
		if err != nil {
			if !isErrorNotFound(err) {
				teardownPanic("unable to delete firewall", err)
			}
		} else {
			if err = deleteFirewallOp.Wait(ctx); err != nil {
				teardownPanic("unable to wait on delete firewall operation", err)
			}
		}
	}

	// VPN tunnels, router
	routersClient, err := compute.NewRoutersRESTClient(ctx)
	if err != nil {
		teardownPanic("unable to create routers client", err)
	}
	defer routersClient.Close()
	externalVpnGatewayNames := map[string]bool{}
	getRouterReq := &computepb.GetRouterRequest{
		Project: teardownInfo.Project,
		Region:  vpnRegion,
		Router:  routerName,
	}
	router, err := routersClient.Get(ctx, getRouterReq)
	if err != nil {
		if !isErrorNotFound(err) {
			teardownPanic("unable to get router", err)
		}
	} else {
		vpnTunnelsClient, err := compute.NewVpnTunnelsRESTClient(ctx)
		if err != nil {
			teardownPanic("unable to create vpn tunnels client", err)
		}
		defer vpnTunnelsClient.Close()
		for _, routerInterface := range router.Interfaces {
			vpnTunnelName := parseGCPURL(*routerInterface.LinkedVpnTunnel)["vpnTunnels"]
			fmt.Println(vpnTunnelName)
			getVpnTunnelReq := &computepb.GetVpnTunnelRequest{
				Project:   teardownInfo.Project,
				Region:    vpnRegion,
				VpnTunnel: vpnTunnelName,
			}
			vpnTunnel, err := vpnTunnelsClient.Get(ctx, getVpnTunnelReq)
			if err != nil {
				// No ErrorNotFound checking here since vpn tunnel is expected to exist according to the router
				teardownPanic("unable to get vpn tunnel", err)
			}
			// TODO @seankimkdy: use parseGCPURL once it's fixed to work with global resources since external vpn gateways are global
			externalVpnGatewayUriSplit := strings.Split(*vpnTunnel.PeerExternalGateway, "/")
			externalVpnGatewayName := externalVpnGatewayUriSplit[len(externalVpnGatewayUriSplit)-1]
			if externalVpnGatewayName != "" && !externalVpnGatewayNames[externalVpnGatewayName] {
				externalVpnGatewayNames[externalVpnGatewayName] = true
			}
			deleteVpnTunnelReq := &computepb.DeleteVpnTunnelRequest{
				Project:   teardownInfo.Project,
				Region:    vpnRegion,
				VpnTunnel: vpnTunnelName,
			}
			deleteVpnTunnelOp, err := vpnTunnelsClient.Delete(ctx, deleteVpnTunnelReq)
			if err != nil {
				teardownPanic("unable to delete vpn tunnel", err)
			}
			if err = deleteVpnTunnelOp.Wait(ctx); err != nil {
				teardownPanic("unable to wait on delete vpn tunnel operation", err)
			}
		}

		deleteRouterReq := &computepb.DeleteRouterRequest{
			Project: teardownInfo.Project,
			Region:  vpnRegion,
			Router:  routerName,
		}
		deleteRouterOp, err := routersClient.Delete(ctx, deleteRouterReq)
		if err != nil {
			// No ErrorNotFound checking here since the GET request for router succeeded
			teardownPanic("unable to delete router", err)
		}
		if err = deleteRouterOp.Wait(ctx); err != nil {
			teardownPanic("unable to wait on delete router operation", err)
		}
	}

	// External VPN gateway
	externalVpnGatewaysClient, err := compute.NewExternalVpnGatewaysRESTClient(ctx)
	if err != nil {
		teardownPanic("unable to create external vpn gateways client", err)
	}
	defer externalVpnGatewaysClient.Close()
	for externalVpnGatewayName := range externalVpnGatewayNames {
		deleteExternalVpnGatewayReq := &computepb.DeleteExternalVpnGatewayRequest{
			Project:            teardownInfo.Project,
			ExternalVpnGateway: externalVpnGatewayName,
		}
		fmt.Println(externalVpnGatewayName)
		deleteExternalVpnGatewayOp, err := externalVpnGatewaysClient.Delete(ctx, deleteExternalVpnGatewayReq)
		if err != nil {
			// No ErrorNotFound checking here since external vpn gateway definitvely exists
			teardownPanic("unable to delete external vpn gateway", err)
		}
		if err = deleteExternalVpnGatewayOp.Wait(ctx); err != nil {
			teardownPanic("unable to wait on delete external vpn gateway operation", err)
		}
	}

	// VPN gateway
	vpnGatewaysClient, err := compute.NewVpnGatewaysRESTClient(ctx)
	if err != nil {
		teardownPanic("unable to create vpn gateways client", err)
	}
	defer vpnGatewaysClient.Close()
	deleteVpnGatewayReq := &computepb.DeleteVpnGatewayRequest{
		Project:    teardownInfo.Project,
		Region:     vpnRegion,
		VpnGateway: vpnGwName,
	}
	deleteVpnGatewayOp, err := vpnGatewaysClient.Delete(ctx, deleteVpnGatewayReq)
	if err != nil {
		if !isErrorNotFound(err) {
			teardownPanic("unable to delete vpn gateway", err)
		}
	} else {
		if err = deleteVpnGatewayOp.Wait(ctx); err != nil {
			teardownPanic("unable to wait on delete vpn gateway operation", err)
		}
	}

	// VPC
	deleteNetworkReq := &computepb.DeleteNetworkRequest{
		Project: teardownInfo.Project,
		Network: vpcName,
	}
	deleteNetworkOp, err := networksClient.Delete(ctx, deleteNetworkReq)
	if err != nil {
		if !isErrorNotFound(err) {
			teardownPanic("unable to delete network", err)
		}
	} else {
		if err = deleteNetworkOp.Wait(ctx); err != nil {
			teardownPanic("unable to wait on delete network operation", err)
		}
	}

	// Connectivity tests
	reachabilityClient, err := networkmanagement.NewReachabilityClient(ctx) // Can't use REST client for some reason (filed as bug within Google internally)
	if err != nil {
		teardownPanic("unable to create reachability client", err)
	}
	for _, connectivityTestName := range teardownInfo.ConnectivityTestNames {
		deleteConnectivityTestReq := &networkmanagementpb.DeleteConnectivityTestRequest{Name: connectivityTestName}
		deleteConnectivityTestOp, err := reachabilityClient.DeleteConnectivityTest(ctx, deleteConnectivityTestReq)
		if err != nil {
			teardownPanic("unable to delete connectivity test", err)
		}
		if err = deleteConnectivityTestOp.Wait(ctx); err != nil {
			teardownPanic("unable to wait on delete connectivity test operation", err)
		}
	}
}

func GetTestVmParameters(project string, zone string, name string) *computepb.InsertInstanceRequest {
	return &computepb.InsertInstanceRequest{
		Project: project,
		Zone:    zone,
		InstanceResource: &computepb.Instance{
			Name:        proto.String(name),
			MachineType: proto.String("zones/" + zone + "/machineTypes/f1-micro"),
			Disks: []*computepb.AttachedDisk{
				{
					InitializeParams: &computepb.AttachedDiskInitializeParams{
						DiskSizeGb:  proto.Int64(10),
						SourceImage: proto.String("projects/debian-cloud/global/images/family/debian-10"),
					},
					AutoDelete: proto.Bool(true),
					Boot:       proto.Bool(true),
					Type:       proto.String(computepb.AttachedDisk_PERSISTENT.String()),
				},
			},
		},
	}
}

func GetInstanceIpAddress(project string, zone string, instanceName string) (string, error) {
	ctx := context.Background()
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return "", fmt.Errorf("NewInstancesRESTClient: %w", err)
	}
	getInstanceReq := &computepb.GetInstanceRequest{
		Instance: instanceName,
		Project:  project,
		Zone:     zone,
	}
	instance, err := instancesClient.Get(ctx, getInstanceReq)
	if err != nil {
		return "", fmt.Errorf("unable to get instance: %w", err)
	}
	return *instance.NetworkInterfaces[0].NetworkIP, nil
}

// Runs connectivity test between two endpoints
func RunPingConnectivityTest(t *testing.T, teardownInfo *GcpTestTeardownInfo, project string, name string, srcEndpoint *networkmanagementpb.Endpoint, dstEndpoint *networkmanagementpb.Endpoint) {
	ctx := context.Background()
	reachabilityClient, err := networkmanagement.NewReachabilityClient(ctx) // Can't use REST client for some reason (filed as bug within Google internally)
	if err != nil {
		t.Fatal(err)
	}
	connectivityTestId := utils.GetGitHubRunPrefix() + "connectivity-test-" + name
	createConnectivityTestReq := &networkmanagementpb.CreateConnectivityTestRequest{
		Parent: "projects/" + project + "/locations/global",
		TestId: connectivityTestId,
		Resource: &networkmanagementpb.ConnectivityTest{
			Name:        "projects/" + project + "/locations/global/connectivityTests" + connectivityTestId,
			Protocol:    "ICMP",
			Source:      srcEndpoint,
			Destination: dstEndpoint,
		},
	}
	createConnectivityTestOp, err := reachabilityClient.CreateConnectivityTest(ctx, createConnectivityTestReq)
	if err != nil {
		t.Fatal(err)
	}
	connectivityTest, err := createConnectivityTestOp.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	teardownInfo.ConnectivityTestNames = append(teardownInfo.ConnectivityTestNames, connectivityTest.Name)

	reachable := connectivityTest.ReachabilityDetails.Result == networkmanagementpb.ReachabilityDetails_REACHABLE
	// Retry up to five times
	for i := 0; i < 5 && !reachable; i++ {
		rerunConnectivityReq := &networkmanagementpb.RerunConnectivityTestRequest{
			Name: connectivityTest.Name,
		}
		rerunConnectivityTestOp, err := reachabilityClient.RerunConnectivityTest(ctx, rerunConnectivityReq)
		if err != nil {
			t.Fatal(err)
		}
		connectivityTest, err = rerunConnectivityTestOp.Wait(ctx)
		if err != nil {
			t.Fatal(err)
		}
		reachable = connectivityTest.ReachabilityDetails.Result == networkmanagementpb.ReachabilityDetails_REACHABLE
	}

	require.True(t, reachable)
}

// Returns VPC for Invisinets in a shortened GCP URI format
// TODO @seankimkdy: should return full URI
func GetVpcUri() string {
	return "global/networks/" + vpcName
}
