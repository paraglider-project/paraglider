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
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Fake project and resource
const (
	fakeProject      = "invisinets-fake"
	fakeRegion       = "us-fake1"
	fakeZone         = fakeRegion + "-a"
	fakeInstanceName = "vm-invisinets-fake"
	fakeInstanceId   = uint64(1234)
	fakeResourceId   = fakeProject + "/" + fakeZone + "/" + fakeInstanceName

	// Missing resources not registered in fake server
	fakeMissingInstance   = "vm-invisinets-missing"
	fakeMissingResourceId = fakeProject + "/" + fakeZone + "/" + fakeMissingInstance

	// Overarching dummy operation name
	fakeOperation = "operation-fake"
)

// Fake tag for fake resource
var fakeNetworkTag = networkTagPrefix + strconv.FormatUint(fakeInstanceId, 10)

// Fake firewalls and permitlists
var (
	fakePermitListRule1 = &invisinetspb.PermitListRule{
		Direction: invisinetspb.Direction_INBOUND,
		DstPort:   80,
		Protocol:  6,
		Tag:       []string{"10.1.2.0/24"},
	}
	fakeFirewallRule1 = &computepb.Firewall{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: proto.String("6"),
				Ports:      []string{"80"},
			},
		},
		Direction:    proto.String(computepb.Firewall_INGRESS.String()),
		Name:         proto.String(getFirewallName(fakePermitListRule1)),
		Network:      proto.String(vpcURL),
		SourceRanges: []string{"10.1.2.0/24"},
		TargetTags:   []string{fakeNetworkTag},
	}
	fakePermitListRule2 = &invisinetspb.PermitListRule{
		Direction: invisinetspb.Direction_OUTBOUND,
		DstPort:   0,
		Protocol:  17,
		Tag:       []string{"10.3.4.0/24"},
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
		Name:              proto.String(getFirewallName(fakePermitListRule2)),
		Network:           proto.String(vpcURL),
		TargetTags:        []string{fakeNetworkTag},
	}
)

// Fake instance
var fakeInstance = &computepb.Instance{
	Id:   proto.Uint64(fakeInstanceId),
	Tags: &computepb.Tags{Items: []string{fakeNetworkTag}},
}

// Portions of GCP API URLs
var (
	urlProjectPrefix = fmt.Sprintf("/compute/v1/projects/%v", fakeProject)
	urlZoneInstance  = fmt.Sprintf("/zones/%v/instances/%v", fakeZone, fakeInstanceName)
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

func getFakeServerHandler(fakeServerState *fakeServerState) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch path := r.URL.Path; path {
		case urlProjectPrefix + "/global/firewalls":
			if r.Method == "POST" {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, "unable to read body of request: "+err.Error(), http.StatusBadRequest)
					return
				}
				var firewall computepb.Firewall
				unm := protojson.UnmarshalOptions{AllowPartial: true, DiscardUnknown: true}
				if err = unm.Unmarshal(body, &firewall); err != nil {
					http.Error(w, "unable to unmarshal body of request: "+err.Error(), http.StatusBadRequest)
					return
				}
				fakeServerState.firewallMap[*firewall.Name] = &firewall
				sendResponse(w, &computepb.Operation{Name: proto.String(fakeOperation)})
				return
			}
		case urlProjectPrefix + "/global/firewalls/" + *fakeFirewallRule1.Name:
			if r.Method == "DELETE" {
				delete(fakeServerState.firewallMap, *fakeFirewallRule1.Name)
				sendResponse(w, &computepb.Operation{Name: proto.String(fakeOperation)})
				return
			}
		case urlProjectPrefix + urlZoneInstance + "/getEffectiveFirewalls":
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
		case urlProjectPrefix + urlZoneInstance:
			if r.Method == "GET" {
				sendResponse(w, fakeServerState.instance)
				return
			}
		case urlProjectPrefix + "/zones/" + fakeZone + "/instances": // TODO @seankimkdy: fix this better with above case
			if r.Method == "POST" {
				fakeInstance.Tags = &computepb.Tags{} // No tags since resource creation wouldn't have been able to set tags yet
				fakeServerState.instance = fakeInstance
				sendResponse(w, &computepb.Operation{Name: proto.String(fakeOperation)})
				return
			}
		case urlProjectPrefix + urlZoneInstance + "/setTags":
			if r.Method == "POST" {
				// TODO @seankimkdy: maybe this doesn't need to exist if we just insert the instance
				fakeServerState.instance.Tags.Items = append(fakeServerState.instance.Tags.Items, getGCPNetworkTag(*fakeServerState.instance.Id))
				sendResponse(w, &computepb.Operation{Name: proto.String(fakeOperation)}) // TODO @seankimkdy: consolidate
				return
			}
		// Networks
		case urlProjectPrefix + "/global/networks/" + vpcName:
			if r.Method == "GET" {
				if fakeServerState.network != nil {
					sendResponse(w, fakeServerState.network)
				} else {
					http.Error(w, "no network found", http.StatusNotFound)
				}
				return
			}
		case urlProjectPrefix + "/global/networks":
			if r.Method == "POST" {
				// TODO @seankimkdy: consolidate reading in body
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, "unable to read body of request: "+err.Error(), http.StatusBadRequest)
					return
				}
				var network computepb.Network
				unm := protojson.UnmarshalOptions{AllowPartial: true, DiscardUnknown: true}
				if err = unm.Unmarshal(body, &network); err != nil {
					http.Error(w, "unable to unmarshal body of request: "+err.Error(), http.StatusBadRequest)
					return
				}
				fakeServerState.network = &network
				sendResponse(w, &computepb.Operation{Name: proto.String(fakeOperation)})
				return
			}
		case urlProjectPrefix + "/regions/" + fakeRegion + "/subnetworks":
			if r.Method == "POST" {
				sendResponse(w, &computepb.Operation{Name: proto.String(fakeOperation)})
				return
			}
		// Operations
		case urlProjectPrefix + "/global/operations/" + fakeOperation:
			if r.Method == "GET" {
				sendResponse(w, &computepb.Operation{Status: computepb.Operation_DONE.Enum()})
				return
			}
		case urlProjectPrefix + "/regions/" + fakeRegion + "/operations/" + fakeOperation:
			if r.Method == "GET" {
				sendResponse(w, &computepb.Operation{Status: computepb.Operation_DONE.Enum()})
				return
			}
		case urlProjectPrefix + "/zones/" + fakeZone + "/operations/" + fakeOperation:
			if r.Method == "GET" {
				sendResponse(w, &computepb.Operation{Status: computepb.Operation_DONE.Enum()})
				return
			}
		default:
			fmt.Println(r.Method)
			fmt.Println(path)
			http.Error(w, "unsupported URL and/or method", http.StatusBadRequest)
			return
		}
	})
}

// Struct to hold state for fake server
type fakeServerState struct {
	firewallMap map[string]*computepb.Firewall
	instance    *computepb.Instance
	network     *computepb.Network
	subnetwork  *computepb.Subnetwork
}

// Struct to hold fake clients
type fakeClients struct {
	firewallsClient   *compute.FirewallsClient
	instancesClient   *compute.InstancesClient
	networksClient    *compute.NetworksClient
	subnetworksClient *compute.SubnetworksClient
}

// Generates fake server state (used for each test case independently)
func generateFakeServerState() *fakeServerState {
	return &fakeServerState{
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
				Network:    proto.String(vpcURL),
				TargetTags: []string{"0.0.0.0/0"},
			},
		},
		instance: fakeInstance,
	}
}

func setup(t *testing.T, neededClients map[string]bool) (fakeServer *httptest.Server, ctx context.Context, fakeClients fakeClients) {
	fakeServer = httptest.NewServer(getFakeServerHandler(generateFakeServerState()))

	ctx = context.Background()

	clientOptions := []option.ClientOption{option.WithoutAuthentication(), option.WithEndpoint(fakeServer.URL)}
	var err error
	if neededClients["firewalls"] {
		fakeClients.firewallsClient, err = compute.NewFirewallsRESTClient(ctx, clientOptions...)
		if err != nil {
			t.Fatal(err)
		}
	}
	if neededClients["instances"] {
		fakeClients.instancesClient, err = compute.NewInstancesRESTClient(ctx, clientOptions...)
		if err != nil {
			t.Fatal(err)
		}
	}
	if neededClients["networks"] {
		fakeClients.networksClient, err = compute.NewNetworksRESTClient(ctx, clientOptions...)
		if err != nil {
			t.Fatal(err)
		}
	}
	if neededClients["subnetworks"] {
		fakeClients.subnetworksClient, err = compute.NewSubnetworksRESTClient(ctx, clientOptions...)
		if err != nil {
			t.Fatal(err)
		}
	}

	return
}

func teardown(fakeServer *httptest.Server, fakeClients fakeClients) {
	fakeServer.Close()
	if fakeClients.firewallsClient != nil {
		fakeClients.firewallsClient.Close()
	}
	if fakeClients.instancesClient != nil {
		fakeClients.instancesClient.Close()
	}
}

func TestGetPermitList(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, map[string]bool{"instances": true})

	s := &GCPPluginServer{}
	resource := &invisinetspb.Resource{Id: fakeResourceId}

	permitListActual, err := s._GetPermitList(ctx, resource, fakeClients.instancesClient)
	require.NoError(t, err)
	permitListExpected := &invisinetspb.PermitList{
		AssociatedResource: fakeResourceId,
		Rules:              []*invisinetspb.PermitListRule{fakePermitListRule1, fakePermitListRule2},
	}
	require.NotNil(t, permitListActual)
	assert.Equal(t, permitListExpected.AssociatedResource, permitListActual.AssociatedResource)
	assert.ElementsMatch(t, permitListExpected.Rules, permitListActual.Rules)

	teardown(fakeServer, fakeClients)
}

func TestGetPermitListMissingInstance(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, map[string]bool{"instances": true})

	s := &GCPPluginServer{}
	resource := &invisinetspb.Resource{Id: fakeMissingResourceId}

	resp, err := s._GetPermitList(ctx, resource, fakeClients.instancesClient)
	require.Error(t, err)
	require.Nil(t, resp)

	teardown(fakeServer, fakeClients)
}

func TestAddPermitListRules(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, map[string]bool{"instances": true, "firewalls": true})

	s := &GCPPluginServer{}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeResourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_INBOUND,
				DstPort:   443,
				Protocol:  6,
				Tag:       []string{"10.5.6.0/24"},
			},
			{
				Direction: invisinetspb.Direction_OUTBOUND,
				DstPort:   8080,
				Protocol:  6,
				Tag:       []string{"10.7.8.0/24"},
			},
		},
	}

	resp, err := s._AddPermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)

	teardown(fakeServer, fakeClients)
}

func TestAddPermitListRulesMissingInstance(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, map[string]bool{"instances": true, "firewalls": true})

	s := &GCPPluginServer{}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeMissingResourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_INBOUND,
				DstPort:   443,
				Protocol:  6,
				Tag:       []string{"10.5.6.0/24"},
			},
		},
	}

	resp, err := s._AddPermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient)
	require.Error(t, err)
	require.Nil(t, resp)

	teardown(fakeServer, fakeClients)
}

func TestAddPermitListRulesDuplicate(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, map[string]bool{"instances": true, "firewalls": true})

	s := &GCPPluginServer{}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeMissingResourceId,
		Rules:              []*invisinetspb.PermitListRule{fakePermitListRule1},
	}

	resp, err := s._AddPermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient)
	require.Error(t, err)
	require.Nil(t, resp)

	teardown(fakeServer, fakeClients)
}

func TestDeletePermitListRules(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, map[string]bool{"instances": true, "firewalls": true})

	s := &GCPPluginServer{}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeResourceId,
		Rules:              []*invisinetspb.PermitListRule{fakePermitListRule1, fakePermitListRule2},
	}

	resp, err := s._DeletePermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)

	teardown(fakeServer, fakeClients)
}

func TestDeletePermitListRulesMissingInstance(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, map[string]bool{"instances": true, "firewalls": true})

	s := &GCPPluginServer{}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeMissingResourceId,
		Rules:              []*invisinetspb.PermitListRule{fakePermitListRule1},
	}

	resp, err := s._DeletePermitListRules(ctx, permitList, fakeClients.firewallsClient, fakeClients.instancesClient)
	require.Error(t, err)
	require.Nil(t, resp)

	teardown(fakeServer, fakeClients)
}

func TestCreateResource(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, map[string]bool{"instances": true, "networks": true, "subnetworks": true})

	s := &GCPPluginServer{}
	resource := &invisinetspb.Resource{Id: fakeResourceId} // TODO @seankimkdy: update after sarah merges

	resp, err := s._CreateResource(ctx, resource, fakeClients.instancesClient, fakeClients.networksClient, fakeClients.subnetworksClient)
	require.NoError(t, err)
	require.NotNil(t, resp)

	teardown(fakeServer, fakeClients)
}
