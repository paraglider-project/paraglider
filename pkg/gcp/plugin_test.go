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
	"strconv"
	"strings"
	"testing"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
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
	Name: proto.String(fakeInstanceName),
	Tags: &computepb.Tags{Items: []string{fakeNetworkTag}},
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
	subnetwork  *computepb.Subnetwork
}

// Struct to hold fake clients
type fakeClients struct {
	firewallsClient   *compute.FirewallsClient
	instancesClient   *compute.InstancesClient
	networksClient    *compute.NetworksClient
	subnetworksClient *compute.SubnetworksClient
}

// Sets up fake http server and fake GCP compute clients
func setup(t *testing.T, fakeServerState *fakeServerState, neededClients map[string]bool) (fakeServer *httptest.Server, ctx context.Context, fakeClients fakeClients) {
	fakeServer = httptest.NewServer(getFakeServerHandler(fakeServerState))

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
		instance: fakeInstance,
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
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState, map[string]bool{"instances": true})

	s := &GCPPluginServer{}
	resource := &invisinetspb.ResourceID{Id: fakeResourceId}

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
	fakeServer, ctx, fakeClients := setup(t, &fakeServerState{}, map[string]bool{"instances": true})

	s := &GCPPluginServer{}
	resource := &invisinetspb.ResourceID{Id: fakeMissingResourceId}

	resp, err := s._GetPermitList(ctx, resource, fakeClients.instancesClient)
	require.Error(t, err)
	require.Nil(t, resp)

	teardown(fakeServer, fakeClients)
}

func TestAddPermitListRules(t *testing.T) {
	fakeServer, ctx, fakeClients := setup(t, &fakeServerState{instance: fakeInstance}, map[string]bool{"instances": true, "firewalls": true})

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
	fakeServer, ctx, fakeClients := setup(t, &fakeServerState{}, map[string]bool{"instances": true, "firewalls": true})

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
	fakeServerState := &fakeServerState{
		instance:    fakeInstance,
		firewallMap: map[string]*computepb.Firewall{*fakeFirewallRule1.Name: fakeFirewallRule1},
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState, map[string]bool{"instances": true, "firewalls": true})

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
	fakeServer, ctx, fakeClients := setup(t, &fakeServerState{instance: fakeInstance}, map[string]bool{"instances": true, "firewalls": true})

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
	fakeServer, ctx, fakeClients := setup(t, &fakeServerState{}, map[string]bool{"instances": true, "firewalls": true})

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
	fakeServerState := &fakeServerState{
		instance: fakeInstance, // Include instance in server state since CreateResource will fetch after creating to add the tag
		network: &computepb.Network{
			Name:        proto.String(vpcName),
			Subnetworks: []string{fmt.Sprintf("regions/%s/subnetworks/%s", fakeRegion, "invisinets-"+fakeRegion+"-subnet")},
		},
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState, map[string]bool{"instances": true, "networks": true, "subnetworks": true})

	s := &GCPPluginServer{}
	description, err := json.Marshal(&computepb.InsertInstanceRequest{
		Project:          fakeProject,
		Zone:             fakeZone,
		InstanceResource: fakeInstance,
	})
	if err != nil {
		t.Fatal(err)
	}
	resource := &invisinetspb.ResourceDescription{Description: description, AddressSpace: "10.1.2.0/24"}

	resp, err := s._CreateResource(ctx, resource, fakeClients.instancesClient, fakeClients.networksClient, fakeClients.subnetworksClient)
	require.NoError(t, err)
	require.NotNil(t, resp)

	teardown(fakeServer, fakeClients)
}

func TestCreateResourceMissingNetwork(t *testing.T) {
	// Include instance in server state since CreateResource will fetch after creating to add the tag
	fakeServer, ctx, fakeClients := setup(t, &fakeServerState{instance: fakeInstance}, map[string]bool{"instances": true, "networks": true, "subnetworks": true})

	s := &GCPPluginServer{}
	description, err := json.Marshal(&computepb.InsertInstanceRequest{
		Project:          fakeProject,
		Zone:             fakeZone,
		InstanceResource: fakeInstance,
	})
	if err != nil {
		t.Fatal(err)
	}
	resource := &invisinetspb.ResourceDescription{Description: description, AddressSpace: "10.1.2.0/24"}

	resp, err := s._CreateResource(ctx, resource, fakeClients.instancesClient, fakeClients.networksClient, fakeClients.subnetworksClient)
	require.NoError(t, err)
	require.NotNil(t, resp)

	teardown(fakeServer, fakeClients)
}

func TestCreateResourceMissingSubnetwork(t *testing.T) {
	fakeServerState := &fakeServerState{
		instance: fakeInstance, // Include instance in server state since CreateResource will fetch after creating to add the tag
		network:  &computepb.Network{Name: proto.String(vpcName)},
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState, map[string]bool{"instances": true, "networks": true, "subnetworks": true})

	s := &GCPPluginServer{}
	description, err := json.Marshal(&computepb.InsertInstanceRequest{
		Project:          fakeProject,
		Zone:             fakeZone,
		InstanceResource: fakeInstance,
	})
	if err != nil {
		t.Fatal(err)
	}
	resource := &invisinetspb.ResourceDescription{Description: description, AddressSpace: "10.1.2.0/24"}

	resp, err := s._CreateResource(ctx, resource, fakeClients.instancesClient, fakeClients.networksClient, fakeClients.subnetworksClient)
	require.NoError(t, err)
	require.NotNil(t, resp)

	teardown(fakeServer, fakeClients)
}

func TestGetUsedAddressSpaces(t *testing.T) {
	fakeServerState := &fakeServerState{
		network: &computepb.Network{
			Name: proto.String(vpcName),
			Subnetworks: []string{
				"https://www.googleapis.com/compute/v1/projects/invisinets-playground/regions/us-fake1/subnetworks/invisinets-us-fake1-subnet",
			},
		},
		subnetwork: &computepb.Subnetwork{
			IpCidrRange: proto.String("10.1.2.0/24"),
		},
	}
	fakeServer, ctx, fakeClients := setup(t, fakeServerState, map[string]bool{"networks": true, "subnetworks": true})

	s := &GCPPluginServer{}

	usedAddressSpacesExpected := []*invisinetspb.RegionAddressSpaceMap{{Region: "us-fake1", AddressSpace: "10.1.2.0/24"}}
	addressSpaceList, err := s._GetUsedAddressSpaces(ctx, &invisinetspb.InvisinetsDeployment{Id: fakeProject}, fakeClients.networksClient, fakeClients.subnetworksClient)
	require.NoError(t, err)
	require.NotNil(t, addressSpaceList)
	assert.ElementsMatch(t, usedAddressSpacesExpected, addressSpaceList.Mappings)

	teardown(fakeServer, fakeClients)
}
