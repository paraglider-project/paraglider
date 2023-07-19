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
	"testing"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const fakeProject = "invisinets-test"
const fakeZone = "us-west1-a"
const fakeInstance = "vm-invisinets-test"
const fakeResourceId = fakeProject + "/" + fakeZone + "/" + fakeInstance

const fakeTag = "invisinets-permitlist-1dcfb54806337196becb956a7566c9b4a1de9cd40"

type fakeServerState struct {
	firewallMap map[string]*computepb.Firewall
}

func getFakeServerHandler(fakeServerState *fakeServerState) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO @seankimkdy: cleanup duplicate code regarding marshalling/unmarshaling
		fmt.Printf("%+v\n", r.URL)
		switch path := r.URL.Path; path {
		case "/compute/v1/projects/invisinets-test/global/firewalls":
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
				resp := &computepb.Operation{}
				b, err := json.Marshal(resp)
				if err != nil {
					http.Error(w, "unable to marshal request: "+err.Error(), http.StatusBadRequest)
					return
				}
				w.Write(b)
				return
			}
		// TODO @seankimkdy: don't hardcode and figure out how to regex match
		case "/compute/v1/projects/invisinets-test/global/firewalls/fw-invisinets-permitlist-a48c81a983da600d848e5d35d8ad05cc90b41":
			if r.Method == "DELETE" {
				delete(fakeServerState.firewallMap, "fw-invisinets-permitlist-a48c81a983da600d848e5d35d8ad05cc90b41")
				resp := &computepb.Operation{}
				b, err := json.Marshal(resp)
				if err != nil {
					http.Error(w, "unable to marshal request: "+err.Error(), http.StatusBadRequest)
					return
				}
				w.Write(b)
				return
			}
		case fmt.Sprintf("/compute/v1/projects/%v/zones/%v/instances/%v/getEffectiveFirewalls", fakeProject, fakeZone, fakeInstance):
			if r.Method == "GET" {
				firewalls := make([]*computepb.Firewall, 0, len(fakeServerState.firewallMap))
				for _, value := range fakeServerState.firewallMap {
					firewalls = append(firewalls, value)
				}
				resp := &computepb.InstancesGetEffectiveFirewallsResponse{
					FirewallPolicys: nil,
					Firewalls:       firewalls,
				}
				b, err := json.Marshal(resp)
				if err != nil {
					http.Error(w, "unable to marshal request: "+err.Error(), http.StatusBadRequest)
					return
				}
				w.Write(b)
				return
			}
		case fmt.Sprintf("/compute/v1/projects/%v/zones/%v/instances/%v", fakeProject, fakeZone, fakeInstance):
			if r.Method == "GET" {
				resp := &computepb.Instance{Tags: &computepb.Tags{Items: []string{fakeTag}}}
				b, err := json.Marshal(resp)
				if err != nil {
					http.Error(w, "unable to marshal request: "+err.Error(), http.StatusBadRequest)
					return
				}
				w.Write(b)
				return
			}
		case fmt.Sprintf("/compute/v1/projects/%v/global/operations/", fakeProject):
			// TODO @seankimkdy: add comment about operation not having a name here?
			if r.Method == "GET" {
				resp := &computepb.Operation{
					Status: computepb.Operation_DONE.Enum(),
				}
				b, err := json.Marshal(resp)
				if err != nil {
					http.Error(w, "unable to marshal request: "+err.Error(), http.StatusBadRequest)
					return
				}
				w.Write(b)
				return
			}
		default:
			http.Error(w, "unsupported URL and/or method", http.StatusBadRequest)
			return
		}
	})
}

func generateFakeServerState() *fakeServerState {
	return &fakeServerState{
		firewallMap: map[string]*computepb.Firewall{
			"fw-invisinets-permitlist-a48c81a983da600d848e5d35d8ad05cc90b41": {
				Allowed: []*computepb.Allowed{
					{
						IPProtocol: proto.String("6"),
						Ports:      []string{"80"},
					},
				},
				Direction:    proto.String(computepb.Firewall_INGRESS.String()),
				Name:         proto.String("fw-invisinets-permitlist-a48c81a983da600d848e5d35d8ad05cc90b41"), // generated by getFirewallName
				Network:      proto.String("nw-invisinets"),
				SourceRanges: []string{"10.1.2.0/24"},
				TargetTags:   []string{fakeTag},
				// TODO @seankimkdy: add SourceTags test once we start supporting tags
			},
			"fw-invisinets-permitlist-cc2ee3ff1e19a62b32c07e54c23c42ebbdb32": {
				Allowed: []*computepb.Allowed{
					{
						IPProtocol: proto.String("17"),
						Ports:      []string{},
					},
				},
				DestinationRanges: []string{"10.3.4.0/24"},
				Direction:         proto.String(computepb.Firewall_EGRESS.String()),
				Name:              proto.String("fw-invisinets-permitlist-cc2ee3ff1e19a62b32c07e54c23c42ebbdb32"), // generated by getFirewallName
				Network:           proto.String("nw-invisinets"),
				TargetTags:        []string{fakeTag},
			},
			"fw-invisinets-permitlist-allow-ssh": {
				Allowed: []*computepb.Allowed{
					{
						IPProtocol: proto.String("6"),
						Ports:      []string{"22"},
					},
				},
				Direction:  proto.String(computepb.Firewall_INGRESS.String()),
				Name:       proto.String("fw-invisinets-permitlist-allow-ssh"),
				Network:    proto.String("global/networks/default"),
				TargetTags: []string{"0.0.0.0/0"},
			},
			"fw-allow-icmp": {
				Allowed: []*computepb.Allowed{
					{
						IPProtocol: proto.String("1"),
						Ports:      []string{},
					},
				},
				Direction:  proto.String(computepb.Firewall_INGRESS.String()),
				Name:       proto.String("fw-allow-icmp"),
				Network:    proto.String("nw-invisinets"),
				TargetTags: []string{"0.0.0.0/0"},
			},
		},
	}
}

func TestGetPermitList(t *testing.T) {
	fakeServerState := generateFakeServerState()
	fakeServer := httptest.NewServer(getFakeServerHandler(fakeServerState))
	defer fakeServer.Close()

	ctx := context.Background()
	fakeInstancesClient, err := compute.NewInstancesRESTClient(ctx, option.WithEndpoint(fakeServer.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer fakeInstancesClient.Close()

	s := &GCPPluginServer{}
	resource := &invisinetspb.Resource{Id: fakeResourceId}

	got, err := s._GetPermitList(ctx, resource, fakeInstancesClient)
	if err != nil {
		t.Fatal(err)
	}

	want := &invisinetspb.PermitList{
		AssociatedResource: fakeResourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_INBOUND,
				DstPort:   80,
				Protocol:  6,
				Tag:       []string{"10.1.2.0/24"},
			},
			{
				Direction: invisinetspb.Direction_OUTBOUND,
				DstPort:   0,
				Protocol:  17,
				Tag:       []string{"10.3.4.0/24"},
			},
		},
	}

	require.True(t, proto.Equal(got, want))
}

func TestAddPermitListRules(t *testing.T) {
	fakeServerState := generateFakeServerState()
	fakeServer := httptest.NewServer(getFakeServerHandler(fakeServerState))
	defer fakeServer.Close()

	ctx := context.Background()
	fakeFirewallsClient, err := compute.NewFirewallsRESTClient(ctx, option.WithEndpoint(fakeServer.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer fakeFirewallsClient.Close()
	fakeInstancesClient, err := compute.NewInstancesRESTClient(ctx, option.WithEndpoint(fakeServer.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer fakeInstancesClient.Close()

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
		},
	}

	prevFakeFirewallsCnt := len(fakeServerState.firewallMap)
	resp, err := s._AddPermitListRules(ctx, permitList, fakeFirewallsClient, fakeInstancesClient)
	if err != nil {
		t.Fatal(err)
	}
	require.NotNil(t, resp)
	require.True(t, resp.Success)
	require.Equal(t, len(fakeServerState.firewallMap), prevFakeFirewallsCnt+1)
	require.True(t, proto.Equal(fakeServerState.firewallMap["fw-invisinets-permitlist-afa8915cd5cadea6b17d59caf16df4deb8a36"], &computepb.Firewall{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: proto.String("6"),
				Ports:      []string{"443"},
			},
		},
		Description:  proto.String("Invisinets permit list"),
		Direction:    proto.String(computepb.Firewall_INGRESS.String()),
		Name:         proto.String("fw-invisinets-permitlist-afa8915cd5cadea6b17d59caf16df4deb8a36"),
		Network:      proto.String("nw-invisinets"),
		SourceRanges: []string{"10.5.6.0/24"},
		TargetTags:   []string{fakeTag},
	}))
}

func TestDeletePermitListRules(t *testing.T) {
	fakeServerState := generateFakeServerState()
	fakeServer := httptest.NewServer(getFakeServerHandler(fakeServerState))
	defer fakeServer.Close()

	ctx := context.Background()
	fakeFirewallsClient, err := compute.NewFirewallsRESTClient(ctx, option.WithEndpoint(fakeServer.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer fakeFirewallsClient.Close()
	fakeInstancesClient, err := compute.NewInstancesRESTClient(ctx, option.WithEndpoint(fakeServer.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer fakeInstancesClient.Close()

	s := &GCPPluginServer{}
	permitList := &invisinetspb.PermitList{
		AssociatedResource: fakeResourceId,
		Rules: []*invisinetspb.PermitListRule{
			{
				Direction: invisinetspb.Direction_INBOUND,
				DstPort:   80,
				Protocol:  6,
				Tag:       []string{"10.1.2.0/24"},
			},
		},
	}

	prevFakeFirewallsCnt := len(fakeServerState.firewallMap)
	resp, err := s._DeletePermitListRules(ctx, permitList, fakeFirewallsClient, fakeInstancesClient)
	if err != nil {
		t.Fatal(err)
	}
	require.NotNil(t, resp)
	require.True(t, resp.Success)
	require.Equal(t, len(fakeServerState.firewallMap), prevFakeFirewallsCnt-1)
	_, ok := fakeServerState.firewallMap["fw-invisinets-permitlist-a48c81a983da600d848e5d35d8ad05cc90b41"]
	if ok {
		t.Errorf("desired firewall was not deleted")
	}
}
