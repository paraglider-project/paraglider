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
	"google.golang.org/protobuf/proto"
)

const fakeResourceId = "invisinets-test/us-west1-a/vm-invisinets-test"

var fakeFirewalls = []*computepb.Firewall{
	{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: proto.String("6"),
				Ports:      []string{"80"},
			},
		},
		Direction:    proto.String(computepb.Firewall_INGRESS.String()),
		Disabled:     proto.Bool(false),
		Name:         proto.String("fw-invisinets-permitlist-a48c81a983da600d848e5d35d8ad05cc90b41"),
		Network:      proto.String("nw-invisinets"),
		SourceRanges: []string{"10.1.2.0/24"},
		TargetTags:   []string{"invisinets-permitlist-1dcfb54806337196becb956a7566c9b4a1de9cd40"}, // TODO @seankimkdy: update to actual
		// TODO @seankimkdy: add SourceTags test once we start supporting tags
	},
	{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: proto.String("17"),
				Ports:      []string{},
			},
		},
		DestinationRanges: []string{"10.3.4.0/24"},
		Direction:         proto.String(computepb.Firewall_EGRESS.String()),
		Disabled:          proto.Bool(false),
		Name:              proto.String("fw-invisinets-permitlist-cc2ee3ff1e19a62b32c07e54c23c42ebbdb32"), // TODO @seankimkdy: update to actual name
		Network:           proto.String("nw-invisinets"),
		TargetTags:        []string{"invisinets-permitlist-1dcfb54806337196becb956a7566c9b4a1de9cd40"},
	},
	{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: proto.String("6"),
				Ports:      []string{"22"},
			},
		},
		Direction:  proto.String(computepb.Firewall_INGRESS.String()),
		Disabled:   proto.Bool(false),
		Name:       proto.String("fw-invisinets-permitlist-allow-ssh"),
		Network:    proto.String("global/networks/default"),
		TargetTags: []string{"0.0.0.0/0"},
	},
	{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: proto.String("1"),
				Ports:      []string{},
			},
		},
		Direction:  proto.String(computepb.Firewall_INGRESS.String()),
		Disabled:   proto.Bool(false),
		Name:       proto.String("fw-allow-icmp"),
		Network:    proto.String("nw-invisinets"),
		TargetTags: []string{"0.0.0.0/0"},
	},
}

var fakeServerHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("%s\n", r.URL.Path)
	switch path := r.URL.Path; path {
	case "/compute/v1/projects/invisinets-test/global/firewalls":
		if r.Method == "POST" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "could not read body of request: "+err.Error(), http.StatusBadRequest)
				return
			}
			fmt.Printf("Byte array inside server looks like:\n%v\n", body)
			var f computepb.Firewall
			err = json.Unmarshal(body, &f)
			if err != nil {
				http.Error(w, "unable to unmarshal request body: "+err.Error(), http.StatusBadRequest)
				return
			}
			fmt.Printf("%+v\n", &f)
			fakeFirewalls = append(fakeFirewalls, &f)
		}
		return
	case "/compute/v1/projects/invisinets-test/zones/us-west1-a/instances/vm-invisinets-test/getEffectiveFirewalls":
		resp := &computepb.InstancesGetEffectiveFirewallsResponse{
			FirewallPolicys: nil,
			Firewalls:       fakeFirewalls,
		}
		b, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "unable to marshal request: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Write(b)
		return
	default:
		http.Error(w, "unrecognized URL for test", http.StatusBadRequest)
		return
	}
})

func TestGetPermitList(t *testing.T) {
	fakeServer := httptest.NewServer(fakeServerHandler)
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

	require.Equal(t, got, want)
}

func TestAddPermitListrules(t *testing.T) {
	fakeServer := httptest.NewServer(fakeServerHandler)
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

	fmt.Printf(getFirewallName(permitList.Rules[0]))

	prevFakeFirewallsCnt := len(fakeFirewalls)
	resp, err := s._AddPermitListRules(ctx, permitList, fakeFirewallsClient, fakeInstancesClient)
	require.NotNil(t, resp)
	require.True(t, resp.Success)
	require.Equal(t, len(fakeFirewalls), prevFakeFirewallsCnt+1)
	require.Equal(t, fakeFirewalls[len(fakeFirewalls)-1], &computepb.Firewall{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: proto.String("6"),
				Ports:      []string{"443"},
			},
		},
		Direction: proto.String(computepb.Firewall_INGRESS.String()),
		Disabled:  proto.Bool(false),
		Name:      proto.String("fw-invisinets-permitlist-afa8915cd5cadea6b17d59caf16df4deb8a36"),
		Network:   proto.String("nw-invisinets"),
	})
}
