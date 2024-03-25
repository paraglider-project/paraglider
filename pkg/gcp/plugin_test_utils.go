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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	container "cloud.google.com/go/container/apiv1"
	containerpb "cloud.google.com/go/container/apiv1/containerpb"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// Fake project and resource
const (
	fakeProject      = "invisinets-fake"
	fakeRegion       = "us-fake1"
	fakeZone         = fakeRegion + "-a"
	fakeInstanceName = "vm-invisinets-fake"
	fakeClusterName  = "cluster-invisinets-fake"
	fakeClusterId    = "1234"
	fakeInstanceId   = uint64(1234)
	fakeResourceId   = "projects/" + fakeProject + "/zones/" + fakeZone + "/instances/" + fakeInstanceName
	fakeNamespace    = "defaultnamespace"
	fakeSubnetId     = "projects/" + fakeProject + "/zones/" + fakeZone + "/subnetworks/subnet-invisinets-fake"

	// Missing resources not registered in fake server
	fakeMissingInstance   = "vm-invisinets-missing"
	fakeMissingResourceId = "projects/" + fakeProject + "/zones/" + fakeZone + "/instances/" + fakeMissingInstance

	// Overarching dummy operation name
	fakeOperation = "operation-fake"
)

// Fake tag for fake resource
var fakeNetworkTag = getNetworkTag(fakeNamespace, instanceTypeName, convertInstanceIdToString(fakeInstanceId))

// Portions of GCP API URLs
var (
	urlProject  = "/compute/v1/projects/" + fakeProject
	urlZone     = "/zones/" + fakeZone
	urlRegion   = "/regions/" + fakeRegion
	urlInstance = "/instances/" + fakeInstanceName
	urlCluster  = "/v1/projects/" + fakeProject + "/zones/" + fakeRegion + "/clusters/"
)

// Fake firewalls and permitlists
var (
	fakePermitListRule1 = &invisinetspb.PermitListRule{
		Name:      "rule-name1",
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
		Name:         proto.String(getFirewallName(fakePermitListRule1.Name, convertInstanceIdToString(fakeInstanceId))),
		Network:      proto.String(GetVpcUri(fakeNamespace)),
		SourceRanges: []string{"10.1.2.0/24"},
		TargetTags:   []string{fakeNetworkTag},
		Description:  proto.String(getRuleDescription([]string{"tag1", "tag2"})),
	}
	fakePermitListRule2 = &invisinetspb.PermitListRule{
		Name:      "rule-name2",
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
		Name:              proto.String(getFirewallName(fakePermitListRule2.Name, convertInstanceIdToString(fakeInstanceId))),
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
			{
				NetworkIP:  proto.String("10.1.1.1"),
				Network:    proto.String(GetVpcUri(fakeNamespace)),
				Subnetwork: proto.String(fakeSubnetId),
			},
		}
	}
	return instance
}

// Fake cluster
func getFakeCluster(includeNetwork bool) *containerpb.Cluster {
	cluster := &containerpb.Cluster{
		Name: fakeClusterName,
		Id:   fakeClusterId,
		NodePools: []*containerpb.NodePool{
			{
				Name: "default-pool",
				Config: &containerpb.NodeConfig{
					Tags: []string{fakeNetworkTag},
				},
			},
		},
	}
	if includeNetwork {
		cluster.Subnetwork = fakeSubnetId
		cluster.Network = GetVpcUri(fakeNamespace)
	}
	return cluster
}

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
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
			return
		}
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
			} else if r.Method == "PATCH" {
				req := &computepb.Firewall{}
				err := json.Unmarshal(body, req)
				if err != nil {
					http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
					return
				}
				if _, ok := fakeServerState.firewallMap[*req.Name]; !ok {
					http.Error(w, fmt.Sprintf("error unmarshalling request body: %s", err), http.StatusBadRequest)
					return
				}
				sendResponseFakeOperation(w)
				return
			} else if r.Method == "GET" {
				firewalls := make([]*computepb.Firewall, 0, len(fakeServerState.firewallMap))
				for _, value := range fakeServerState.firewallMap {
					firewalls = append(firewalls, value)
				}
				test := &computepb.FirewallList{Items: firewalls}
				sendResponse(w, test)
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
			// // Clusters
			// case strings.HasPrefix(path, urlCluster):
			// 	if r.Method == "GET" {
			// 		if fakeServerState.cluster != nil {
			// 			sendResponse(w, fakeServerState.cluster)
			// 		} else {
			// 			http.Error(w, "no cluster found", http.StatusNotFound)
			// 		}
			// 		return
			// 	} else if r.Method == "POST" {
			// 		sendResponseFakeOperation(w)
			// 		return
			// 	}
		}
		fmt.Printf("unsupported request: %s %s\n", r.Method, path)
		http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
	})
}

type fakeClusterManagerServer struct {
	containerpb.UnimplementedClusterManagerServer
}

func (f *fakeClusterManagerServer) GetCluster(ctx context.Context, req *containerpb.GetClusterRequest) (*containerpb.Cluster, error) {
	if strings.Contains(req.Name, fakeClusterName) {
		return getFakeCluster(true), nil
	}
	return nil, fmt.Errorf("cluster not found")
}

func (f *fakeClusterManagerServer) CreateCluster(ctx context.Context, req *containerpb.CreateClusterRequest) (*containerpb.Operation, error) {
	return &containerpb.Operation{Name: fakeOperation}, nil
}

func (f *fakeClusterManagerServer) UpdateCluster(ctx context.Context, req *containerpb.UpdateClusterRequest) (*containerpb.Operation, error) {
	return &containerpb.Operation{Name: fakeOperation}, nil
}

// Struct to hold state for fake server
type fakeServerState struct {
	firewallMap map[string]*computepb.Firewall
	instance    *computepb.Instance
	network     *computepb.Network
	router      *computepb.Router
	subnetwork  *computepb.Subnetwork
	vpnGateway  *computepb.VpnGateway
	cluster     *containerpb.Cluster
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
	clusterClient             *container.ClusterManagerClient
}

// Sets up fake http server and fake GCP compute clients
func setup(t *testing.T, fakeServerState *fakeServerState) (fakeServer *httptest.Server, ctx context.Context, fakeClients fakeClients, gsrv *grpc.Server) {
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

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	fakeGRPCServer := &fakeClusterManagerServer{}
	gsrv = grpc.NewServer()
	containerpb.RegisterClusterManagerServer(gsrv, fakeGRPCServer)
	serverAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err)
		}
	}()

	clusterClientOptions := []option.ClientOption{option.WithoutAuthentication(), option.WithEndpoint(serverAddr), option.WithGRPCDialOption(grpc.WithInsecure())}
	fakeClients.clusterClient, err = container.NewClusterManagerClient(ctx, clusterClientOptions...)
	if err != nil {
		t.Fatal(err)
	}

	return
}

// Cleans up fake http server and fake GCP compute clients
func teardown(fakeServer *httptest.Server, fakeClients fakeClients, fakeGRPCServer *grpc.Server) {
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
	if fakeClients.clusterClient != nil {
		fakeClients.clusterClient.Close()
	}
	if fakeGRPCServer != nil {
		fakeGRPCServer.Stop()
	}
}
