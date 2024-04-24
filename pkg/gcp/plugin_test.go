//go:build unit

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
	"encoding/json"
	"fmt"
	"testing"

	computepb "cloud.google.com/go/compute/apiv1/computepb"
	containerpb "cloud.google.com/go/container/apiv1/containerpb"
	fake "github.com/NetSys/invisinets/pkg/fake/orchestrator/rpc"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/orchestrator"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestGetPermitList(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true),
		firewallMap: map[string]*computepb.Firewall{
			*fakeFirewallRule1.Name: fakeFirewallRule1,
			*fakeFirewallRule2.Name: fakeFirewallRule2,
			"fw-allow-icmp": {
				Allowed: []*computepb.Allowed{
					{
						IPProtocol: proto.String("1"),
						Ports:      []string{},
					},
				},
				Direction:  proto.String(computepb.Firewall_INGRESS.String()),
				Name:       proto.String("fw-allow-icmp"),
				Network:    proto.String(GetVpcUri(fakeProject, fakeNamespace)),
				TargetTags: []string{"0.0.0.0/0"},
			},
		},
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	s := &GCPPluginServer{}
	request := &invisinetspb.GetPermitListRequest{Resource: fakeResourceId, Namespace: fakeNamespace}

	responseActual, err := s._GetPermitList(ctx, request, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.clusterClient)
	require.NoError(t, err)
	responseExpected := &invisinetspb.GetPermitListResponse{
		Rules: []*invisinetspb.PermitListRule{fakePermitListRule1, fakePermitListRule2},
	}
	require.NotNil(t, responseActual)
	assert.ElementsMatch(t, responseExpected.Rules, responseActual.Rules)
}

func TestGetPermitListMissingInstance(t *testing.T) {
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &fakeServerState{})
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	s := &GCPPluginServer{}
	request := &invisinetspb.GetPermitListRequest{Resource: fakeMissingResourceId, Namespace: fakeNamespace}

	resp, err := s._GetPermitList(ctx, request, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.clusterClient)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestGetPermitListWrongNamespace(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true),
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)
	s := &GCPPluginServer{}
	request := &invisinetspb.GetPermitListRequest{Resource: fakeResourceId, Namespace: "wrongnamespace"}

	resp, err := s._GetPermitList(ctx, request, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.clusterClient)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestAddPermitListRules(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true),
		subnetwork: &computepb.Subnetwork{
			IpCidrRange: proto.String("10.0.0.0/16"),
		},
		network: &computepb.Network{
			Name: proto.String(getVpcName(fakeNamespace)),
		},
	}
	fakeServerState.instance.NetworkInterfaces = []*computepb.NetworkInterface{
		{
			Subnetwork: proto.String(fmt.Sprintf("regions/%s/subnetworks/%s", fakeRegion, "invisinets-"+fakeRegion+"-subnet")),
			Network:    proto.String(GetVpcUri(fakeProject, fakeNamespace)),
		},
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	fakeOrchestratorServer, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	fakeOrchestratorServer.Counter = 1
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	request := &invisinetspb.AddPermitListRulesRequest{
		Resource: fakeResourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   443,
				Protocol:  6,
				Targets:   []string{"10.0.0.1"},
			},
			{
				Direction: invisinetspb.Direction_OUTBOUND,
				SrcPort:   -1,
				DstPort:   8080,
				Protocol:  6,
				Targets:   []string{"10.0.0.2"},
				Tags:      []string{"tag"},
			},
		},
		Namespace: fakeNamespace,
	}

	resp, err := s._AddPermitListRules(ctx, request, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.subnetworksClient, fakeClients.networksClient, fakeClients.clusterClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAddPermitListRulesMissingInstance(t *testing.T) {
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &fakeServerState{})
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	request := &invisinetspb.AddPermitListRulesRequest{
		Resource: fakeMissingResourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   443,
				Protocol:  6,
				Targets:   []string{"10.5.6.0/24"},
			},
		},
		Namespace: fakeNamespace,
	}

	resp, err := s._AddPermitListRules(ctx, request, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.subnetworksClient, fakeClients.networksClient, fakeClients.clusterClient)

	require.Error(t, err)
	require.Nil(t, resp)
}

func TestAddPermitListRulesWrongNamespace(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true),
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	s := &GCPPluginServer{}
	request := &invisinetspb.AddPermitListRulesRequest{
		Resource: fakeMissingResourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_INBOUND,
				SrcPort:   -1,
				DstPort:   443,
				Protocol:  6,
				Targets:   []string{"10.5.6.0/24"},
			},
		},
		Namespace: "wrongnamespace",
	}

	resp, err := s._AddPermitListRules(ctx, request, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.subnetworksClient, fakeClients.networksClient, fakeClients.clusterClient)

	require.Error(t, err)
	require.Nil(t, resp)
}

func TestAddPermitListRulesExistingRule(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true),
		subnetwork: &computepb.Subnetwork{
			IpCidrRange: proto.String("10.0.0.0/16"),
		},
		firewallMap: map[string]*computepb.Firewall{
			*fakeFirewallRule1.Name: fakeFirewallRule1,
			*fakeFirewallRule2.Name: fakeFirewallRule2,
		},
		network: &computepb.Network{
			Name: proto.String(getVpcName(fakeNamespace)),
		},
	}
	fakeServerState.instance.NetworkInterfaces = []*computepb.NetworkInterface{
		{
			Subnetwork: proto.String(fmt.Sprintf("regions/%s/subnetworks/%s", fakeRegion, "invisinets-"+fakeRegion+"-subnet")),
			Network:    proto.String(GetVpcUri(fakeProject, fakeNamespace)),
		},
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	fakeOrchestratorServer, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	fakeOrchestratorServer.Counter = 1
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	newRule := &invisinetspb.PermitListRule{
		Name:      fakePermitListRule1.Name,
		Direction: fakePermitListRule1.Direction,
		SrcPort:   fakePermitListRule1.SrcPort,
		DstPort:   fakePermitListRule1.DstPort + 1,
		Protocol:  fakePermitListRule1.Protocol,
		Targets:   []string{"10.0.0.1"},
		Tags:      fakePermitListRule1.Tags,
	}
	request := &invisinetspb.AddPermitListRulesRequest{
		Resource:  fakeResourceId,
		Rules:     []*invisinetspb.PermitListRule{newRule},
		Namespace: fakeNamespace,
	}

	resp, err := s._AddPermitListRules(ctx, request, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.subnetworksClient, fakeClients.networksClient, fakeClients.clusterClient)

	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestDeletePermitListRules(t *testing.T) {
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &fakeServerState{instance: getFakeInstance(true)})
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	s := &GCPPluginServer{}
	request := &invisinetspb.DeletePermitListRulesRequest{
		Resource:  fakeResourceId,
		RuleNames: []string{fakePermitListRule1.Name, fakePermitListRule2.Name},
		Namespace: fakeNamespace,
	}

	resp, err := s._DeletePermitListRules(ctx, request, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.clusterClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestDeletePermitListRulesMissingInstance(t *testing.T) {
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &fakeServerState{})
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	s := &GCPPluginServer{}
	request := &invisinetspb.DeletePermitListRulesRequest{
		Resource:  fakeMissingResourceId,
		RuleNames: []string{fakePermitListRule1.Name},
		Namespace: fakeNamespace,
	}

	resp, err := s._DeletePermitListRules(ctx, request, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.clusterClient)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestDeletePermitListRulesWrongNamespace(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true),
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	s := &GCPPluginServer{}
	request := &invisinetspb.DeletePermitListRulesRequest{
		Resource:  fakeMissingResourceId,
		RuleNames: []string{"Name"},
		Namespace: "wrongnamespace",
	}

	resp, err := s._DeletePermitListRules(ctx, request, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.clusterClient)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestCreateResource(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true), // Include instance in server state since CreateResource will fetch after creating to add the tag
		network: &computepb.Network{
			Name:        proto.String(getVpcName(fakeNamespace)),
			Subnetworks: []string{fmt.Sprintf("regions/%s/subnetworks/%s", fakeRegion, "invisinets-"+fakeRegion+"-subnet")},
		},
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	description, err := json.Marshal(&computepb.InsertInstanceRequest{
		Project:          fakeProject,
		Zone:             fakeZone,
		InstanceResource: getFakeInstance(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	resource := &invisinetspb.ResourceDescription{
		Deployment:  &invisinetspb.InvisinetsDeployment{Id: "projects/" + fakeProject, Namespace: fakeNamespace},
		Name:        fakeInstanceName,
		Description: description,
	}

	resp, err := s._CreateResource(ctx, resource, fakeClients.instancesClient, fakeClients.networksClient, fakeClients.subnetworksClient, fakeClients.firewallsClient, fakeClients.clusterClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceCluster(t *testing.T) {
	fakeServerState := &fakeServerState{
		cluster: getFakeCluster(true), // Include cluster in server state since CreateResource will fetch after creating to add the tag
		network: &computepb.Network{
			Name:        proto.String(getVpcName(fakeNamespace)),
			Subnetworks: []string{fmt.Sprintf("regions/%s/subnetworks/%s", fakeRegion, "invisinets-"+fakeRegion+"-subnet")},
		},
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	description, err := json.Marshal(&containerpb.CreateClusterRequest{
		Cluster: getFakeCluster(false),
		Parent:  fmt.Sprintf("projects/%s/locations/%s", fakeProject, fakeZone),
	})
	if err != nil {
		t.Fatal(err)
	}
	resource := &invisinetspb.ResourceDescription{
		Deployment:  &invisinetspb.InvisinetsDeployment{Id: "projects/" + fakeProject, Namespace: fakeNamespace},
		Name:        fakeClusterName,
		Description: description,
	}

	resp, err := s._CreateResource(ctx, resource, fakeClients.instancesClient, fakeClients.networksClient, fakeClients.subnetworksClient, fakeClients.firewallsClient, fakeClients.clusterClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceMissingNetwork(t *testing.T) {
	// Include instance in server state since CreateResource will fetch after creating to add the tag
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, &fakeServerState{instance: getFakeInstance(true)})
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	description, err := json.Marshal(&computepb.InsertInstanceRequest{
		Project:          fakeProject,
		Zone:             fakeZone,
		InstanceResource: getFakeInstance(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	resource := &invisinetspb.ResourceDescription{
		Deployment:  &invisinetspb.InvisinetsDeployment{Id: "projects/" + fakeProject, Namespace: fakeNamespace},
		Name:        fakeInstanceName,
		Description: description,
	}

	resp, err := s._CreateResource(ctx, resource, fakeClients.instancesClient, fakeClients.networksClient, fakeClients.subnetworksClient, fakeClients.firewallsClient, fakeClients.clusterClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceMissingSubnetwork(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true), // Include instance in server state since CreateResource will fetch after creating to add the tag
		network:  &computepb.Network{Name: proto.String(getVpcName(fakeNamespace))},
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}

	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	description, err := json.Marshal(&computepb.InsertInstanceRequest{
		Project:          fakeProject,
		Zone:             fakeZone,
		InstanceResource: getFakeInstance(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	resource := &invisinetspb.ResourceDescription{
		Deployment:  &invisinetspb.InvisinetsDeployment{Id: "projects/" + fakeProject, Namespace: fakeNamespace},
		Name:        fakeInstanceName,
		Description: description,
	}

	resp, err := s._CreateResource(ctx, resource, fakeClients.instancesClient, fakeClients.networksClient, fakeClients.subnetworksClient, fakeClients.firewallsClient, fakeClients.clusterClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestGetUsedAddressSpaces(t *testing.T) {
	fakeServerState := &fakeServerState{
		network: &computepb.Network{
			Name: proto.String(getVpcName(fakeNamespace)),
			Subnetworks: []string{
				"https://www.googleapis.com/compute/v1/projects/invisinets-playground/regions/us-fake1/subnetworks/invisinets-us-fake1-subnet",
			},
		},
		subnetwork: &computepb.Subnetwork{
			IpCidrRange: proto.String("10.1.2.0/24"),
		},
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	s := &GCPPluginServer{}

	expectedAddressSpaceMappings := []*invisinetspb.AddressSpaceMapping{
		{
			AddressSpaces: []string{"10.1.2.0/24"},
			Cloud:         utils.GCP,
			Namespace:     fakeNamespace,
		},
	}
	req := &invisinetspb.GetUsedAddressSpacesRequest{
		Deployments: []*invisinetspb.InvisinetsDeployment{
			{Id: "projects/" + fakeProject, Namespace: fakeNamespace},
		},
	}
	resp, err := s._GetUsedAddressSpaces(ctx, req, fakeClients.networksClient, fakeClients.subnetworksClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.ElementsMatch(t, expectedAddressSpaceMappings, resp.AddressSpaceMappings)
}

func TestGetUsedAsns(t *testing.T) {
	fakeServerState := &fakeServerState{
		router: &computepb.Router{
			Bgp: &computepb.RouterBgp{
				Asn: proto.Uint32(64512),
			},
		},
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	s := &GCPPluginServer{}
	vpnRegion = fakeRegion

	usedAsnsExpected := []uint32{64512}
	req := &invisinetspb.GetUsedAsnsRequest{
		Deployments: []*invisinetspb.InvisinetsDeployment{
			{Id: "projects/" + fakeProject, Namespace: fakeNamespace},
		},
	}
	resp, err := s._GetUsedAsns(ctx, req, fakeClients.routersClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.ElementsMatch(t, usedAsnsExpected, resp.Asns)
}

func TestGetUsedBgpPeeringIpAddresses(t *testing.T) {
	fakeServerState := &fakeServerState{
		router: &computepb.Router{
			BgpPeers: []*computepb.RouterBgpPeer{
				{IpAddress: proto.String("169.254.21.1")},
				{IpAddress: proto.String("169.254.22.1")},
			},
		},
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	s := &GCPPluginServer{}
	vpnRegion = fakeRegion

	usedBgpPeeringIpAddressExpected := []string{"169.254.21.1", "169.254.22.1"}
	req := &invisinetspb.GetUsedBgpPeeringIpAddressesRequest{
		Deployments: []*invisinetspb.InvisinetsDeployment{
			{Id: "projects/" + fakeProject, Namespace: fakeNamespace},
		},
	}
	resp, err := s._GetUsedBgpPeeringIpAddresses(ctx, req, fakeClients.routersClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.ElementsMatch(t, usedBgpPeeringIpAddressExpected, resp.IpAddresses)
}

func TestCreateVpnGateway(t *testing.T) {
	fakeServerState := &fakeServerState{
		router: &computepb.Router{},
		vpnGateway: &computepb.VpnGateway{
			VpnInterfaces: []*computepb.VpnGatewayVpnGatewayInterface{
				{IpAddress: proto.String("1.1.1.1")},
			},
		},
	}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	vpnRegion = fakeRegion

	req := &invisinetspb.CreateVpnGatewayRequest{
		Deployment:            &invisinetspb.InvisinetsDeployment{Id: fmt.Sprintf("projects/%s/regions/%s", fakeProject, fakeRegion)},
		Cloud:                 "fakecloud",
		BgpPeeringIpAddresses: []string{"169.254.21.1", "169.254.22.1"},
	}
	resp, err := s._CreateVpnGateway(ctx, req, fakeClients.vpnGatewaysClient, fakeClients.routersClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, orchestrator.MIN_PRIVATE_ASN_2BYTE, resp.Asn)
	require.ElementsMatch(t, []string{"1.1.1.1"}, resp.GatewayIpAddresses)
}

func TestCreateVpnConnections(t *testing.T) {
	fakeServerState := &fakeServerState{router: &computepb.Router{}}
	fakeServer, ctx, fakeClients, fakeGRPCServer := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients, fakeGRPCServer)

	s := &GCPPluginServer{}
	vpnRegion = fakeRegion

	req := &invisinetspb.CreateVpnConnectionsRequest{
		Deployment:         &invisinetspb.InvisinetsDeployment{Id: fmt.Sprintf("projects/%s/regions/%s", fakeProject, fakeRegion)},
		Cloud:              "fakecloud",
		Asn:                65555,
		GatewayIpAddresses: []string{"1.1.1.1"},
		BgpIpAddresses:     []string{"3.3.3.3"},
		SharedKey:          "abcd",
	}
	resp, err := s._CreateVpnConnections(ctx, req, fakeClients.externalVpnGatewaysClient, fakeClients.vpnTunnelsClient, fakeClients.routersClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.Success)
}
