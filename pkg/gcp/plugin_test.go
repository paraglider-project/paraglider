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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	fake "github.com/NetSys/invisinets/pkg/fake/controller/rpc"
	"github.com/NetSys/invisinets/pkg/frontend"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/proto"
)

// Fake project and resource
const (
	fakeProject      = "invisinets-fake"
	fakeRegion       = "us-fake1"
	fakeZone         = fakeRegion + "-a"
	fakeInstanceName = "vm-invisinets-fake"
	fakeInstanceId   = uint64(1234)
	fakeResourceId   = "projects/" + fakeProject + "/zones/" + fakeZone + "/instances/" + fakeInstanceName
	fakeNamespace    = "defaultnamespace"

	// Missing resources not registered in fake server
	fakeMissingInstance   = "vm-invisinets-missing"
	fakeMissingResourceId = "projects/" + fakeProject + "/zones/" + fakeZone + "/instances/" + fakeMissingInstance

	// Overarching dummy operation name
	fakeOperation = "operation-fake"
)

// Fake tag for fake resource
var fakeNetworkTag = getNetworkTag(fakeNamespace, fakeInstanceId)

// Fake firewalls and permitlists
var (
	fakePermitListRule1 = &invisinetspb.PermitListRule{
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   -1,
		DstPort:   80,
		Protocol:  6,
		Targets:   []string{"10.1.2.0/24"},
		Tags:      []string{"tag1", "tag2"},
	}
	fakeFirewallRule1 = &computepb.Firewall{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: proto.String("6"),
				Ports:      []string{"80"},
			},
		},
		Direction:    proto.String(computepb.Firewall_INGRESS.String()),
		Name:         proto.String(getFirewallName(fakePermitListRule1, 1)),
		Network:      proto.String(GetVpcUri(fakeNamespace)),
		SourceRanges: []string{"10.1.2.0/24"},
		TargetTags:   []string{fakeNetworkTag},
		Description:  proto.String(getRuleDescription([]string{"tag1", "tag2"})),
	}
	fakePermitListRule2 = &invisinetspb.PermitListRule{
		Direction: invisinetspb.Direction_OUTBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  17,
		Targets:   []string{"10.3.4.0/24"},
	}
	fakeFirewallRule2 = &computepb.Firewall{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: proto.String("17"),
				Ports:      []string{},
			},
		},
		DestinationRanges: []string{"10.3.4.0/24"},
		Direction:         proto.String(computepb.Firewall_EGRESS.String()),
		Name:              proto.String(getFirewallName(fakePermitListRule2, 2)),
		Network:           proto.String(GetVpcUri(fakeNamespace)),
		TargetTags:        []string{fakeNetworkTag},
	}
)

// Fake instance
func getFakeInstance(includeNetwork bool) *computepb.Instance {
	instance := &computepb.Instance{
		Id:   proto.Uint64(fakeInstanceId),
		Name: proto.String(fakeInstanceName),
		Tags: &computepb.Tags{Items: []string{fakeNetworkTag}},
	}
	if includeNetwork {
		instance.NetworkInterfaces = []*computepb.NetworkInterface{
			&computepb.NetworkInterface{
				NetworkIP: proto.String("10.1.1.1"),
				Network:   proto.String(GetVpcUri(fakeNamespace)),
			}}
	}
	return instance
}

// Portions of GCP API URLs
var (
	urlProject  = "/compute/v1/projects/" + fakeProject
	urlZone     = "/zones/" + fakeZone
	urlRegion   = "/regions/" + fakeRegion
	urlInstance = "/instances/" + fakeInstanceName
)

func sendResponse(w http.ResponseWriter, resp any) {
	b, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "unable to marshal request: "+err.Error(), http.StatusBadRequest)
		return
	}
	_, err = w.Write(b)
	if err != nil {
		http.Error(w, "unable to write request: "+err.Error(), http.StatusBadRequest)
	}
}

func sendResponseFakeOperation(w http.ResponseWriter) {
	sendResponse(w, &computepb.Operation{Name: proto.String(fakeOperation)})
}

func sendResponseDoneOperation(w http.ResponseWriter) {
	sendResponse(w, &computepb.Operation{Status: computepb.Operation_DONE.Enum()})
}

func getFakeServerHandler(fakeServerState *fakeServerState) http.HandlerFunc {
	// The handler should be written as minimally as possible to minimize maintenance overhead. Modifying requests (e.g. POST, DELETE)
	// should generally not do anything other than return the operation response. Instead, initialize the fakeServerState as necessary.
	// Keep in mind these unit tests should rely as little as possible on the functionality of this fake server.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		// Instances
		case path == urlProject+urlZone+urlInstance+"/getEffectiveFirewalls":
			if r.Method == "GET" {
				firewalls := make([]*computepb.Firewall, 0, len(fakeServerState.firewallMap))
				for _, value := range fakeServerState.firewallMap {
					firewalls = append(firewalls, value)
				}
				sendResponse(w, &computepb.InstancesGetEffectiveFirewallsResponse{
					FirewallPolicys: nil,
					Firewalls:       firewalls,
				})
				return
			}
		case path == urlProject+urlZone+urlInstance+"/setTags":
			if r.Method == "POST" {
				sendResponseFakeOperation(w)
				return
			}
		case path == urlProject+urlZone+urlInstance:
			if r.Method == "GET" {
				sendResponse(w, fakeServerState.instance)
				return
			}
		case path == urlProject+urlZone+"/instances":
			if r.Method == "POST" {
				sendResponseFakeOperation(w)
				return
			}
		// Firewalls
		case strings.HasPrefix(path, urlProject+"/global/firewalls"):
			if r.Method == "POST" {
				sendResponseFakeOperation(w)
				return
			} else if r.Method == "DELETE" {
				sendResponseFakeOperation(w)
				return
			}
		// Networks
		case strings.HasPrefix(path, urlProject+"/global/networks"):
			if r.Method == "GET" {
				if fakeServerState.network != nil {
					sendResponse(w, fakeServerState.network)
				} else {
					http.Error(w, "no network found", http.StatusNotFound)
				}
				return
			} else if r.Method == "POST" {
				sendResponseFakeOperation(w)
				return
			}
		case strings.HasPrefix(path, urlProject+urlRegion+"/subnetworks"):
			if r.Method == "GET" {
				if fakeServerState.subnetwork != nil {
					sendResponse(w, fakeServerState.subnetwork)
				} else {
					http.Error(w, "no subnetwork found", http.StatusNotFound)
				}
				return
			} else if r.Method == "POST" {
				sendResponseFakeOperation(w)
				return
			}
		// VPN Gateways
		case strings.HasPrefix(path, urlProject+urlRegion+"/vpnGateways"):
			if r.Method == "GET" {
				if fakeServerState.vpnGateway != nil {
					sendResponse(w, fakeServerState.vpnGateway)
				} else {
					http.Error(w, "no vpn gateway found", http.StatusNotFound)
				}
				return
			} else if r.Method == "POST" {
				sendResponseFakeOperation(w)
				return
			}
		// External VPN Gateways
		case strings.HasPrefix(path, urlProject+"/global/externalVpnGateways"):
			if r.Method == "POST" {
				sendResponseFakeOperation(w)
				return
			}
		// VPN Tunnels
		case strings.HasPrefix(path, urlProject+urlRegion+"/vpnTunnels"):
			if r.Method == "POST" {
				sendResponseFakeOperation(w)
				return
			}
		// Routers
		case strings.HasPrefix(path, urlProject+urlRegion+"/routers"):
			if r.Method == "POST" || r.Method == "PATCH" {
				sendResponseFakeOperation(w)
				return
			} else if r.Method == "GET" {
				if fakeServerState.router != nil {
					sendResponse(w, fakeServerState.router)
				} else {
					http.Error(w, "no router found", http.StatusNotFound)
				}
				return
			}
		// Operations
		case path == urlProject+"/global/operations/"+fakeOperation:
			if r.Method == "GET" {
				sendResponseDoneOperation(w)
				return
			}
		case path == urlProject+"/regions/"+fakeRegion+"/operations/"+fakeOperation:
			if r.Method == "GET" {
				sendResponseDoneOperation(w)
				return
			}
		case path == urlProject+"/zones/"+fakeZone+"/operations/"+fakeOperation:
			if r.Method == "GET" {
				sendResponseDoneOperation(w)
				return
			}
		}
		fmt.Printf("unsupported request: %s %s\n", r.Method, path)
		http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
	})
}

// Struct to hold state for fake server
type fakeServerState struct {
	firewallMap map[string]*computepb.Firewall
	instance    *computepb.Instance
	network     *computepb.Network
	router      *computepb.Router
	subnetwork  *computepb.Subnetwork
	vpnGateway  *computepb.VpnGateway
}

// Struct to hold fake clients
type fakeClients struct {
	externalVpnGatewaysClient *compute.ExternalVpnGatewaysClient
	firewallsClient           *compute.FirewallsClient
	instancesClient           *compute.InstancesClient
	networksClient            *compute.NetworksClient
	routersClient             *compute.RoutersClient
	subnetworksClient         *compute.SubnetworksClient
	vpnGatewaysClient         *compute.VpnGatewaysClient
	vpnTunnelsClient          *compute.VpnTunnelsClient
}

// Sets up fake http server and fake GCP compute clients
func setup(t *testing.T, fakeServerState *fakeServerState) (fakeServer *httptest.Server, ctx context.Context, fakeClients fakeClients) {
	fakeServer = httptest.NewServer(getFakeServerHandler(fakeServerState))

	ctx = context.Background()

	clientOptions := []option.ClientOption{option.WithoutAuthentication(), option.WithEndpoint(fakeServer.URL)}
	var err error
	fakeClients.externalVpnGatewaysClient, err = compute.NewExternalVpnGatewaysRESTClient(ctx, clientOptions...)
	if err != nil {
		t.Fatal(err)
	}

	fakeClients.firewallsClient, err = compute.NewFirewallsRESTClient(ctx, clientOptions...)
	if err != nil {
		t.Fatal(err)
	}

	fakeClients.instancesClient, err = compute.NewInstancesRESTClient(ctx, clientOptions...)
	if err != nil {
		t.Fatal(err)
	}

	fakeClients.networksClient, err = compute.NewNetworksRESTClient(ctx, clientOptions...)
	if err != nil {
		t.Fatal(err)
	}

	fakeClients.routersClient, err = compute.NewRoutersRESTClient(ctx, clientOptions...)
	if err != nil {
		t.Fatal(err)
	}

	fakeClients.subnetworksClient, err = compute.NewSubnetworksRESTClient(ctx, clientOptions...)
	if err != nil {
		t.Fatal(err)
	}

	fakeClients.vpnGatewaysClient, err = compute.NewVpnGatewaysRESTClient(ctx, clientOptions...)
	if err != nil {
		t.Fatal(err)
	}

	fakeClients.vpnTunnelsClient, err = compute.NewVpnTunnelsRESTClient(ctx, clientOptions...)
	if err != nil {
		t.Fatal(err)
	}

	return
}

// Cleans up fake http server and fake GCP compute clients
func teardown(fakeServer *httptest.Server, fakeClients fakeClients) {
	fakeServer.Close()
	if fakeClients.firewallsClient != nil {
		fakeClients.firewallsClient.Close()
	}
	if fakeClients.instancesClient != nil {
		fakeClients.instancesClient.Close()
	}
	if fakeClients.networksClient != nil {
		fakeClients.networksClient.Close()
	}
	if fakeClients.subnetworksClient != nil {
		fakeClients.subnetworksClient.Close()
	}
}

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
				Network:    proto.String(GetVpcUri(fakeNamespace)),
				TargetTags: []string{"0.0.0.0/0"},
			},
		},
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

	s := &GCPPluginServer{}
	resource := &invisinetspb.ResourceID{Id: fakeResourceId, Namespace: fakeNamespace}

	permitListActual, err := s._GetPermitList(ctx, resource, fakeClients.instancesClient)
	require.NoError(t, err)
	permitListExpected := &invisinetspb.PermitList{
		AssociatedResource: fakeResourceId,
		Rules:              []*invisinetspb.PermitListRule{fakePermitListRule1, fakePermitListRule2},
	}
	require.NotNil(t, permitListActual)
	assert.Equal(t, permitListExpected.AssociatedResource, permitListActual.AssociatedResource)
	assert.ElementsMatch(t, permitListExpected.Rules, permitListActual.Rules)
}

func TestGetPermitListMissingInstance(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, &fakeServerState{})
	defer teardown(fakeServer, fakeClients)

	s := &GCPPluginServer{}
	resource := &invisinetspb.ResourceID{Id: fakeMissingResourceId}

	resp, err := s._GetPermitList(ctx, resource, fakeClients.instancesClient)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestGetPermitListWrongNamespace(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true),
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

	s := &GCPPluginServer{}
	resource := &invisinetspb.ResourceID{Id: fakeResourceId, Namespace: "wrongnamespace"}

	resp, err := s._GetPermitList(ctx, resource, fakeClients.instancesClient)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestAddPermitListRules(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true),
		subnetwork: &computepb.Subnetwork{
			IpCidrRange: proto.String("10.0.0.0/16"),
		},
	}
	fakeServerState.instance.NetworkInterfaces = []*computepb.NetworkInterface{
		{Subnetwork: proto.String(fmt.Sprintf("regions/%s/subnetworks/%s", fakeRegion, "invisinets-"+fakeRegion+"-subnet")), Network: proto.String(GetVpcUri(fakeNamespace))},
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

	fakeControllerServer, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	fakeControllerServer.Counter = 1
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeResourceId,
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

	resp, err := s._AddPermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.subnetworksClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

func TestAddPermitListRulesMissingInstance(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, &fakeServerState{})
	defer teardown(fakeServer, fakeClients)

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeMissingResourceId,
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

	resp, err := s._AddPermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.subnetworksClient)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestAddPermitListRulesWrongNamespace(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true),
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

	s := &GCPPluginServer{}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeMissingResourceId,
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

	resp, err := s._AddPermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.subnetworksClient)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestAddPermitListRulesDuplicate(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance:    getFakeInstance(true),
		firewallMap: map[string]*computepb.Firewall{*fakeFirewallRule1.Name: fakeFirewallRule1},
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

	_, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{orchestratorServerAddr: fakeOrchestratorServerAddr}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeMissingResourceId,
		Rules:              []*invisinetspb.PermitListRule{fakePermitListRule1},
	}

	resp, err := s._AddPermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient, fakeClients.subnetworksClient)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestDeletePermitListRules(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, &fakeServerState{instance: getFakeInstance(true)})
	defer teardown(fakeServer, fakeClients)

	s := &GCPPluginServer{}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeResourceId,
		Rules:              []*invisinetspb.PermitListRule{fakePermitListRule1, fakePermitListRule2},
		Namespace:          fakeNamespace,
	}

	resp, err := s._DeletePermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

func TestDeletePermitListRulesMissingInstance(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, &fakeServerState{})
	defer teardown(fakeServer, fakeClients)

	s := &GCPPluginServer{}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeMissingResourceId,
		Rules:              []*invisinetspb.PermitListRule{fakePermitListRule1},
	}

	resp, err := s._DeletePermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestDeletePermitListRulesWrongNamespace(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true),
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

	s := &GCPPluginServer{}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeMissingResourceId,
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

	resp, err := s._DeletePermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient)
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
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

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
	resource := &invisinetspb.ResourceDescription{Description: description, Namespace: fakeNamespace}

	resp, err := s._CreateResource(ctx, resource, fakeClients.instancesClient, fakeClients.networksClient, fakeClients.subnetworksClient, fakeClients.firewallsClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceMissingNetwork(t *testing.T) {
	// Include instance in server state since CreateResource will fetch after creating to add the tag
	fakeServer, ctx, fakeClients := setup(t, &fakeServerState{instance: getFakeInstance(true)})
	defer teardown(fakeServer, fakeClients)

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
	resource := &invisinetspb.ResourceDescription{Description: description}

	resp, err := s._CreateResource(ctx, resource, fakeClients.instancesClient, fakeClients.networksClient, fakeClients.subnetworksClient, fakeClients.firewallsClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceMissingSubnetwork(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true), // Include instance in server state since CreateResource will fetch after creating to add the tag
		network:  &computepb.Network{Name: proto.String(getVpcName(fakeNamespace))},
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

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
	resource := &invisinetspb.ResourceDescription{Description: description, Namespace: fakeNamespace}

	resp, err := s._CreateResource(ctx, resource, fakeClients.instancesClient, fakeClients.networksClient, fakeClients.subnetworksClient, fakeClients.firewallsClient)
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
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

	s := &GCPPluginServer{}

	usedAddressSpacesExpected := []string{"10.1.2.0/24"}
	addressSpaceList, err := s._GetUsedAddressSpaces(ctx, &invisinetspb.InvisinetsDeployment{Id: "projects/" + fakeProject, Namespace: fakeNamespace}, fakeClients.networksClient, fakeClients.subnetworksClient)
	require.NoError(t, err)
	require.NotNil(t, addressSpaceList)
	assert.ElementsMatch(t, usedAddressSpacesExpected, addressSpaceList.AddressSpaces)
}

func TestGetUsedAsns(t *testing.T) {
	fakeServerState := &fakeServerState{
		router: &computepb.Router{
			Bgp: &computepb.RouterBgp{
				Asn: proto.Uint32(64512),
			},
		},
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

	s := &GCPPluginServer{}
	vpnRegion = fakeRegion

	usedAsnsExpected := []uint32{64512}
	resp, err := s._GetUsedAsns(ctx, &invisinetspb.GetUsedAsnsRequest{Deployment: &invisinetspb.InvisinetsDeployment{Id: "projects/" + fakeProject, Namespace: fakeNamespace}}, fakeClients.routersClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.ElementsMatch(t, usedAsnsExpected, resp.Asns)
}

func TestCreateVpnGateway(t *testing.T) {
	fakeVpnGatewayIpAddresses := []string{"1.1.1.1", "2.2.2.2"}
	fakeServerState := &fakeServerState{
		vpnGateway: &computepb.VpnGateway{
			VpnInterfaces: []*computepb.VpnGatewayVpnGatewayInterface{
				{IpAddress: proto.String(fakeVpnGatewayIpAddresses[0])},
				{IpAddress: proto.String(fakeVpnGatewayIpAddresses[1])},
			},
		},
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

	_, fakeControllerServerAddr, err := fake.SetupFakeControllerServer(utils.GCP)
	if err != nil {
		t.Fatal(err)
	}
	s := &GCPPluginServer{frontendServerAddr: fakeControllerServerAddr}
	vpnRegion = fakeRegion

	req := &invisinetspb.CreateVpnGatewayRequest{
		Deployment: &invisinetspb.InvisinetsDeployment{Id: fmt.Sprintf("projects/%s/regions/%s", fakeProject, fakeRegion)},
		Cloud:      "fakecloud",
	}
	resp, err := s._CreateVpnGateway(ctx, req, fakeClients.vpnGatewaysClient, fakeClients.routersClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, frontend.MIN_PRIVATE_ASN_2BYTE, resp.Asn)
	require.ElementsMatch(t, fakeVpnGatewayIpAddresses, resp.GatewayIpAddresses)
	require.ElementsMatch(t, vpnGwBgpIpAddrs, resp.BgpIpAddresses)
}

func TestCreateVpnConnections(t *testing.T) {
	fakeServerState := &fakeServerState{router: &computepb.Router{}}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

	s := &GCPPluginServer{}
	vpnRegion = fakeRegion

	req := &invisinetspb.CreateVpnConnectionsRequest{
		Deployment:         &invisinetspb.InvisinetsDeployment{Id: fmt.Sprintf("projects/%s/regions/%s", fakeProject, fakeRegion)},
		Cloud:              "fakecloud",
		Asn:                65555,
		GatewayIpAddresses: []string{"1.1.1.1", "2.2.2.2"},
		BgpIpAddresses:     []string{"3.3.3.3", "4.4.4.4"},
		SharedKey:          "abcd",
	}
	resp, err := s._CreateVpnConnections(ctx, req, fakeClients.externalVpnGatewaysClient, fakeClients.vpnTunnelsClient, fakeClients.routersClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.Success)
}

func TestCheckResourceNamespace(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: getFakeInstance(true),
		network: &computepb.Network{
			Name:        proto.String(getVpcName(fakeNamespace)),
			Subnetworks: []string{fmt.Sprintf("regions/%s/subnetworks/%s", fakeRegion, "invisinets-"+fakeRegion+"-subnet")},
		},
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState)
	defer teardown(fakeServer, fakeClients)

	s := &GCPPluginServer{}

	err := s.checkInstanceNamespace(ctx, fakeClients.instancesClient, fakeInstanceName, fakeProject, fakeZone, fakeNamespace)
	require.NoError(t, err)

	err = s.checkInstanceNamespace(ctx, fakeClients.instancesClient, fakeInstanceName, fakeProject, fakeZone, "othernamespace")
	require.Error(t, err)

	err = s.checkInstanceNamespace(ctx, fakeClients.instancesClient, fakeInstanceName, fakeProject, fakeZone, "")
	require.Error(t, err)
}
