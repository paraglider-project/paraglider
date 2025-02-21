//go:build unit

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

package ibm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	k8sv1 "github.com/IBM-Cloud/container-services-go-sdk/kubernetesserviceapiv1"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/IBM/platform-services-go-sdk/globaltaggingv1"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/stretchr/testify/require"

	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rpc"
	"github.com/paraglider-project/paraglider/pkg/kvstore"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
)

const (
	fakeRegion     = "us-east"  // Primary region used for tests
	fakeConRegion  = "us-south" // Region used to test VPC connectivity across regions
	fakeZone       = fakeRegion + "-a"
	fakeInstance   = "vm-paraglider-fake"
	fakeCluster    = "cluster-paraglider-fake"
	fakeEndpoint   = "vpe-paraglider-fake"
	fakeImage      = "fake-image"
	fakeVPC        = "paraglider-fake-vpc"
	fakeID         = "12345"
	fakeID2        = "123452"
	fakeRuleName1  = "fake-rule1"
	fakeRuleName2  = "fake-rule2"
	fakeCRN        = "crn:" + fakeID
	fakeCRN2       = "crn:" + fakeID2
	fakeSubnet     = "paraglider-fake-subnet"
	fakeSG         = "paraglider-fake-sg"
	fakeGW         = "paraglider-fake-gw"
	fakeIP         = "10.0.0.2"
	fakeSubnet1    = "10.0.0.0/16"
	fakeSubnet2    = "10.1.0.0/16"
	fakeProfile    = "bx2-2x8"
	fakeWorkerPool = "fake"

	fakeDeploymentID = "/resourcegroup/" + fakeID
	fakeInstanceID   = "/resourcegroup/" + fakeID + "/zone/" + fakeZone + "/instance/" + fakeID
	fakeNamespace    = "paraglider-namespace"
	wrongNamespace   = "wrong-pg-namespace"
)

var (
	fakeInstanceOptions = vpcv1.CreateInstanceOptions{
		InstancePrototype: &vpcv1.InstancePrototypeInstanceByImage{
			Image:   &vpcv1.ImageIdentityByID{ID: core.StringPtr(fakeImage)},
			Zone:    &vpcv1.ZoneIdentityByName{Name: core.StringPtr(fakeZone)},
			Profile: &vpcv1.InstanceProfileIdentityByName{Name: core.StringPtr(fakeProfile)},
		},
	}

	fakeClusterOptions = k8sv1.VpcCreateClusterOptions{
		WorkerPool: &k8sv1.VPCCreateClusterWorkerPool{
			Name:   core.StringPtr(fakeWorkerPool),
			Flavor: core.StringPtr(fakeProfile),
			Zones: []k8sv1.VPCCreateClusterWorkerPoolZone{
				{
					ID: core.StringPtr(fakeZone),
				},
			},
		},
	}

	fakeEndpointGatewayOptions = vpcv1.CreateEndpointGatewayOptions{
		Target: &vpcv1.EndpointGatewayTargetPrototype{
			ResourceType: core.StringPtr(vpcv1.EndpointGatewayTargetPrototypeProviderInfrastructureServiceIdentityResourceTypeProviderCloudServiceConst),
			Name:         core.StringPtr("ibm-ntp-server"),
		},
	}

	fakePermitListVPC = []*paragliderpb.PermitListRule{
		{
			Name:      fakeRuleName1,
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   443,
			DstPort:   443,
			Protocol:  6,
			Targets:   []string{"10.0.0.0/18"},
		},
		{
			Name:      fakeRuleName2,
			Direction: paragliderpb.Direction_OUTBOUND,
			SrcPort:   -1,
			DstPort:   -1,
			Protocol:  -1,
			Targets:   []string{"10.0.64.1"},
		},
	}
	fakePermitListMultiVPC = []*paragliderpb.PermitListRule{
		{
			Name:      fakeRuleName1,
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   443,
			DstPort:   443,
			Protocol:  6,
			Targets:   []string{"10.1.1.5"},
		},
	}
	fakePermitListPublic = []*paragliderpb.PermitListRule{
		{
			Name:      fakeRuleName1,
			Direction: paragliderpb.Direction_INBOUND,
			SrcPort:   443,
			DstPort:   443,
			Protocol:  6,
			Targets:   []string{"169.18.0.2"},
		},
	}
)

type fakeClusterState struct {
	clusterID  string
	clusterCRN string
	subnetID   string
}

// State of the fake IBM server
// It contains only the necessary items needed to test.
type fakeIBMServerState struct {
	VPCs          []*vpcv1.VPC
	Instance      *vpcv1.Instance
	SecurityGroup *vpcv1.SecurityGroup
	clusterState  fakeClusterState
	subnetVPC     map[string]string // VPC to Subnet CIDR mapping
	rules         int
	publicGateway bool
}

func sendFakeResponse(w http.ResponseWriter, response interface{}) {
	jsonResp, err := json.Marshal(response)
	if err != nil {
		fmt.Printf("Failed to marshal")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonResp)
	if err != nil {
		http.Error(w, "unable to write request: "+err.Error(), http.StatusBadRequest)
	}
}

// Creates a fake VM Instance.
func createFakeInstance() *vpcv1.Instance {
	return &vpcv1.Instance{
		CRN:    core.StringPtr(fakeCRN),
		Name:   core.StringPtr(fakeInstance),
		ID:     core.StringPtr(fakeID),
		Status: core.StringPtr(vpcv1.InstanceStatusRunningConst),
		NetworkInterfaces: []vpcv1.NetworkInterfaceInstanceContextReference{
			{
				PrimaryIP: &vpcv1.ReservedIPReference{Address: core.StringPtr(fakeIP)},
			},
		},
		VPC: &vpcv1.VPCReference{
			ID:  core.StringPtr(fakeID),
			CRN: core.StringPtr(fakeCRN),
		},
		Zone: &vpcv1.ZoneReference{Name: core.StringPtr(fakeZone)},
	}
}

// Creates a fake VPC. If connectVPC is set to true, creates another VPC which will be used in multi-VPC test
func createFakeVPC(connectVPC bool) []*vpcv1.VPC {
	var vpcs []*vpcv1.VPC
	vpc := vpcv1.VPC{
		CRN:  core.StringPtr(fakeCRN),
		Name: core.StringPtr(fakeVPC),
		ID:   core.StringPtr(fakeID),
	}
	vpcs = append(vpcs, &vpc)
	if connectVPC {
		vpc2 := vpcv1.VPC{
			CRN:  core.StringPtr(fakeCRN2),
			Name: core.StringPtr(fakeVPC),
			ID:   core.StringPtr(fakeID2),
		}
		vpcs = append(vpcs, &vpc2)
	}
	return vpcs
}

// Creates fake security group. If addRules is set to true, it adds fakePermitListVPC's rules to it.
func createFakeSecurityGroup(addRules bool) *vpcv1.SecurityGroup {
	sg := vpcv1.SecurityGroup{
		CRN:  core.StringPtr(fakeCRN),
		Name: core.StringPtr(fakeSG),
		ID:   core.StringPtr(fakeID),
	}

	if addRules {
		sgRules := []vpcv1.SecurityGroupRuleIntf{
			&vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp{
				ID:        core.StringPtr(fakeID),
				Direction: core.StringPtr("inbound"),
				Protocol:  core.StringPtr("tcp"),
				PortMin:   core.Int64Ptr(443),
				PortMax:   core.Int64Ptr(443),
				Remote:    &vpcv1.SecurityGroupRuleRemoteCIDR{CIDRBlock: core.StringPtr("10.0.0.0/18")},
			},
			&vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAll{
				ID:        core.StringPtr(fakeID2),
				Direction: core.StringPtr("outbound"),
				Protocol:  core.StringPtr("all"),
				Remote:    &vpcv1.SecurityGroupRuleRemoteIP{Address: core.StringPtr("10.0.64.1")},
			},
		}
		sg.Rules = sgRules
	}

	return &sg
}

// getFakeIBMServerHandler returns the handler with a fake implementation of the IBM Cloud SDK that can be mounted on a URL.
func getFakeIBMServerHandler(fakeIBMServerState *fakeIBMServerState) http.HandlerFunc {
	// The handler should be written as minimally as possible to minimize maintenance overhead. Modifying requests (e.g. POST, DELETE)
	// should generally not do anything other than return the operation response. Instead, initialize the fakeIBMServerState as necessary.
	// Keep in mind these unit tests should rely as little as possible on the functionality of this fake server.

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
			return
		}
		switch {
		case path == "/v3/resources/search":
			if r.Method == http.MethodPost { // Search resources like VPC, Security-group, instance, etc
				var req map[string]interface{}
				err := json.Unmarshal(body, &req)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				res := ""
				tags := []string{}
				var searchResult globalsearchv2.ScanResult
				// Parse the query to extract resource "type" and "tags" to search
				for _, tokens := range strings.Split(req["query"].(string), "AND") {
					keys := strings.Split(tokens, ":")
					switch strings.TrimSpace(keys[0]) {
					case "type":
						res = strings.TrimSpace(keys[1])
					case "tags":
						tags = append(tags, strings.TrimSpace(keys[1]))
					}
				}
				// Search the corresponding resource
				switch taggedResourceType(res) {
				case VM:
					if fakeIBMServerState.Instance != nil {
						wrongNS := false // Namespace is passed in as tags in the query
						for _, tag := range tags {
							if tag == wrongNamespace {
								wrongNS = true // If the wrong namespace is passed, the query shouldn't return the instance
							}
						}
						if !wrongNS {
							var resultItem globalsearchv2.ResultItem
							resultItem.CRN = fakeIBMServerState.Instance.CRN
							searchResult.Items = append(searchResult.Items, resultItem)
						}
					}
				case SG:
					if fakeIBMServerState.SecurityGroup != nil {
						var resultItem globalsearchv2.ResultItem
						resultItem.CRN = fakeIBMServerState.SecurityGroup.CRN
						searchResult.Items = append(searchResult.Items, resultItem)
					}
				case VPC:
					if fakeIBMServerState.VPCs != nil {
						for i, fakeVPC := range fakeIBMServerState.VPCs {
							var resultItem globalsearchv2.ResultItem
							resultItem.CRN = fakeVPC.CRN
							// First VPC uses the primary region
							resultItem.SetProperty("region", fakeRegion)
							if i == 1 {
								// Second VPC uses the region used to test cross region connectivity
								resultItem.SetProperty("region", fakeConRegion)
							}
							searchResult.Items = append(searchResult.Items, resultItem)
						}
					}
				case SUBNET:
					if fakeIBMServerState.subnetVPC != nil {
						for _, subnet := range fakeIBMServerState.subnetVPC {
							var resultItem globalsearchv2.ResultItem
							resultItem.SetProperty("region", fakeRegion)
							resultItem.CRN = core.StringPtr("crn:" + subnet)
							searchResult.Items = append(searchResult.Items, resultItem)
						}
					}
				case PGATEWAY:
					if fakeIBMServerState.publicGateway {
						var resultItem globalsearchv2.ResultItem
						resultItem.SetProperty("region", fakeRegion)
						resultItem.CRN = core.StringPtr(fakeCRN)
						searchResult.Items = append(searchResult.Items, resultItem)
					}
				case GATEWAY:
					// Not Implemented
				}

				sendFakeResponse(w, searchResult)
				return
			}
		case path == "/vpcs":
			if r.Method == http.MethodPost { // Create VPC
				newVPC := vpcv1.VPC{
					CRN:  core.StringPtr(fakeVPC),
					Name: core.StringPtr(fakeVPC),
					ID:   core.StringPtr(fakeID),
				}
				sendFakeResponse(w, newVPC)
				return
			}
		case path == "/v3/tags/attach":
			if r.Method == http.MethodPost { // Attach tag to a resource
				tagResult := globaltaggingv1.TagResults{
					Results: []globaltaggingv1.TagResultsItem{
						{
							IsError: core.BoolPtr(false),
						},
					},
				}
				sendFakeResponse(w, tagResult)
				return
			}
		case path == "/vpcs/"+fakeID+"/address_prefixes":
			if r.Method == http.MethodPost { // Create Address Prefix
				var newVPCPrefix vpcv1.AddressPrefix
				sendFakeResponse(w, newVPCPrefix)
				return
			}
		case path == "/vpcs/"+fakeID+"/default_security_group":
			if r.Method == http.MethodGet { // Get default security group
				sg := vpcv1.DefaultSecurityGroup{
					ID:  core.StringPtr(fakeID),
					CRN: core.StringPtr(fakeCRN),
				}
				sendFakeResponse(w, sg)
				return
			}
		case path == "/vpcs/"+fakeID2:
			if r.Method == http.MethodGet { // Get VPC
				vpc := vpcv1.VPC{
					CRN:  core.StringPtr(fakeCRN2),
					Name: core.StringPtr(fakeVPC),
					ID:   core.StringPtr(fakeID2),
				}
				sendFakeResponse(w, vpc)
				return
			}
		case path == "/subnets":
			if r.Method == http.MethodPost { // Create Subnet
				subnet := vpcv1.Subnet{
					CRN: core.StringPtr(fakeSubnet),
					ID:  core.StringPtr(fakeID),
				}
				fakeIBMServerState.clusterState.subnetID = fakeID
				sendFakeResponse(w, subnet)
				return
			}
			if r.Method == http.MethodGet { // Get Subnets in a VPC
				var subnets vpcv1.SubnetCollection
				if fakeIBMServerState.subnetVPC != nil {
					if cidrBlock, ok := fakeIBMServerState.subnetVPC[r.URL.Query().Get("vpc.id")]; ok {
						subnets.Subnets = []vpcv1.Subnet{
							{
								ID:            core.StringPtr(r.URL.Query().Get("vpc.id")),
								Ipv4CIDRBlock: &cidrBlock,
								Zone: &vpcv1.ZoneReference{
									Name: core.StringPtr(fakeZone),
								},
							},
						}
					}
				}
				if fakeIBMServerState.clusterState.subnetID == fakeID {
					subnets.Subnets = []vpcv1.Subnet{
						{
							Zone: &vpcv1.ZoneReference{
								Name: core.StringPtr(fakeZone),
							},
						},
					}
				}
				sendFakeResponse(w, subnets)
				return
			}
		case strings.Contains(path, "reserved_ips"):
			if r.Method == http.MethodPost {
				reservedIP := vpcv1.ReservedIP{ID: core.StringPtr(fakeID)}
				sendFakeResponse(w, reservedIP)
				return
			}
		case strings.Contains(path, "/subnets/"):
			if r.Method == http.MethodGet { // Get Subnet Info for a VPC
				index := strings.LastIndex(path, "/")
				if cidrBlock, ok := fakeIBMServerState.subnetVPC[path[index+1:]]; ok {
					subnet := vpcv1.Subnet{
						Ipv4CIDRBlock: &cidrBlock,
						Name:          core.StringPtr(fakeZone),
					}
					sendFakeResponse(w, subnet)
					return
				}
				// In case of cluster's subnet check its state
				if fakeIBMServerState.clusterState.subnetID == fakeID {
					subnet := vpcv1.Subnet{Ipv4CIDRBlock: core.StringPtr(fakeSubnet1)}
					sendFakeResponse(w, subnet)
					return
				}
			}
			if r.Method == http.MethodPut && strings.Contains(path, "public_gateway") { // Attach subnet to public gateway
				w.WriteHeader(http.StatusOK)
				return
			}
		case path == "/keys":
			if r.Method == http.MethodPost { // Create Key
				key := vpcv1.Key{ID: core.StringPtr(fakeID)}
				sendFakeResponse(w, key)
				return
			}
		case path == "/security_groups":
			if r.Method == http.MethodPost { // Create a security group
				sg := vpcv1.SecurityGroup{
					CRN: core.StringPtr(fakeSG),
					ID:  core.StringPtr(fakeID),
				}
				sendFakeResponse(w, sg)
				return
			}
		case path == "/security_groups/"+fakeID+"/rules":
			if r.Method == http.MethodGet { // Get rules of a security group
				if fakeIBMServerState.SecurityGroup == nil {
					http.Error(w, "Security Group not found", http.StatusNotFound)
					return
				}
				sg := vpcv1.SecurityGroupRuleCollection{
					Rules: fakeIBMServerState.SecurityGroup.Rules,
				}
				sendFakeResponse(w, sg)
				return
			}
			if r.Method == http.MethodPost { // Add rules to a security group
				sg := vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAll{
					ID:       core.StringPtr(fakeID),
					Protocol: core.StringPtr(vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAllProtocolAllConst),
				}
				if fakeIBMServerState.rules != 0 {
					// Return another rule ID for the second rule added
					sg.ID = core.StringPtr(fakeID2)
				}
				fakeIBMServerState.rules++
				sendFakeResponse(w, sg)
				return
			}
		case strings.Contains(path, "/security_groups/"+fakeID+"/rules/"):
			if r.Method == http.MethodDelete { // Delete a rule
				w.WriteHeader(http.StatusOK)
				return
			}
		case path == "/instances":
			if r.Method == http.MethodPost { // Create an instance
				fakeIBMServerState.Instance = createFakeInstance()
				sendFakeResponse(w, fakeIBMServerState.Instance)
				return
			}
			if r.Method == http.MethodGet { // List instances
				var instanceCol vpcv1.InstanceCollection
				instanceCol.Instances = make([]vpcv1.Instance, 0)
				if fakeIBMServerState.Instance != nil {
					instanceCol.Instances = append(instanceCol.Instances, *fakeIBMServerState.Instance)
				}
				sendFakeResponse(w, instanceCol)
				return
			}
		case path == "/instances/"+fakeID: // Get an instance
			if r.Method == http.MethodGet {
				if fakeIBMServerState.Instance == nil {
					http.Error(w, "Instance not found", http.StatusNotFound)
					return
				}
				sendFakeResponse(w, fakeIBMServerState.Instance)
				return
			}
		case path == "/instances/"+fakeID+"/network_interfaces":
			if r.Method == http.MethodGet { // List an Instance's network interfaces
				if fakeIBMServerState.Instance == nil {
					http.Error(w, "Instance not found", http.StatusNotFound)
					return
				}
				var netIntf vpcv1.NetworkInterfaceUnpaginatedCollection
				netIntf.NetworkInterfaces = []vpcv1.NetworkInterface{
					{
						SecurityGroups: []vpcv1.SecurityGroupReference{
							{
								Name: fakeIBMServerState.SecurityGroup.Name,
								ID:   fakeIBMServerState.SecurityGroup.ID,
							},
						},
					},
				}
				sendFakeResponse(w, netIntf)
				return
			}
		case path == "/v2/vpc/createCluster":
			if r.Method == http.MethodPost { // Create a k8s Cluster
				fakeIBMServerState.clusterState.clusterID = fakeID
				fakeIBMServerState.clusterState.clusterCRN = fakeCRN
				cluster := k8sv1.CreateClusterResponse{
					ClusterID: core.StringPtr(fakeID),
				}
				sendFakeResponse(w, cluster)
				return
			}

		case path == "/v2/vpc/getCluster":
			if r.Method == http.MethodGet { // Get a cluster
				cluster := k8sv1.GetClusterResponse{
					ID:    core.StringPtr(fakeID),
					Crn:   core.StringPtr(fakeCRN),
					State: core.StringPtr(ClusterReadyState),
				}
				sendFakeResponse(w, cluster)
				return
			}
		case path == "/endpoint_gateways":
			if r.Method == http.MethodPost { // Create an endpoint gateway
				vpe := vpcv1.EndpointGateway{
					ID:   core.StringPtr(fakeID),
					CRN:  core.StringPtr(fakeCRN),
					Name: core.StringPtr(fakeEndpoint),
				}
				sendFakeResponse(w, vpe)
				return
			}
		case path == "/endpoint_gateways/"+fakeID:
			if r.Method == http.MethodGet { // Get an endpoint gateway
				vpe := vpcv1.EndpointGateway{
					ID:             core.StringPtr(fakeID),
					CRN:            core.StringPtr(fakeCRN),
					Name:           core.StringPtr(fakeEndpoint),
					LifecycleState: core.StringPtr(endpointReadyState),
					Ips: []vpcv1.ReservedIPReference{
						{
							Address: core.StringPtr(fakeIP),
						},
					},
				}
				sendFakeResponse(w, vpe)
				return
			}
		case path == "/transit_gateways":
			if r.Method == http.MethodPost { // Create transit gateway
				gw := transitgatewayapisv1.TransitGateway{
					Name: core.StringPtr(fakeGW),
					ID:   core.StringPtr(fakeID),
					Crn:  core.StringPtr(fakeCRN),
				}
				sendFakeResponse(w, gw)
				return
			}
		case path == "/transit_gateways/"+fakeID+"/connections":
			if r.Method == http.MethodPost { // Create a transit gateway connection
				conn := transitgatewayapisv1.TransitGatewayConnectionCust{
					ID:        core.StringPtr(fakeID),
					Name:      core.StringPtr(fakeGW),
					NetworkID: core.StringPtr("vpc"),
				}
				sendFakeResponse(w, conn)
				return
			}
		case path == "/floating_ips":
			if r.Method == http.MethodPost { // Create a floating ip
				fip := vpcv1.FloatingIP{
					ID: core.StringPtr(fakeID),
				}
				sendFakeResponse(w, fip)
				return
			}
		case path == "/public_gateways":
			if r.Method == http.MethodPost { // Create a public gateway
				gw := vpcv1.PublicGateway{
					ID:  core.StringPtr(fakeID),
					CRN: core.StringPtr(fakeCRN),
				}
				sendFakeResponse(w, gw)
				return
			}
		}
		fmt.Printf("unsupported request: %s %s\n", r.Method, path)
		http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
	})
}

// Creates a http test server, and attaches the fake IBM SDK Handler to it
func setup(t *testing.T, fakeIBMServerState *fakeIBMServerState) (fakeServer *httptest.Server, ctx context.Context, fakeClient *CloudClient) {
	var err error
	fakeServer = httptest.NewServer(getFakeIBMServerHandler(fakeIBMServerState))
	ctx = context.Background()
	fakeClient, err = FakeIBMCloudClient(fakeServer.URL, fakeID, fakeRegion)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestSetFlags(t *testing.T) {
	s := &IBMPluginServer{
		flags: &paragliderpb.PluginFlags{PrivateEndpointsEnabled: false, KubernetesClustersEnabled: false},
	}
	resp, err := s.SetFlags(context.Background(),
		&paragliderpb.SetFlagsRequest{Flags: &paragliderpb.PluginFlags{PrivateEndpointsEnabled: true,
			KubernetesClustersEnabled: true}})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, s.flags.PrivateEndpointsEnabled)
	require.True(t, s.flags.KubernetesClustersEnabled)
}

func TestCreateResourceInstanceNewVPC(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with no state to have a clean slate resource creation
	fakeIBMServerState := &fakeIBMServerState{}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		flags: &paragliderpb.PluginFlags{PrivateEndpointsEnabled: false, KubernetesClustersEnabled: false},
	}

	description, err := json.Marshal(fakeInstanceOptions)
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: fakeDeploymentID, Namespace: fakeNamespace},
		Name:        fakeInstance,
		Description: description,
	}
	resp, err := s.CreateResource(ctx, resource)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceInstanceExistingVPCSubnet(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with an existing VPC, and subnet
	fakeIBMServerState := &fakeIBMServerState{
		VPCs: createFakeVPC(false),
		subnetVPC: map[string]string{
			fakeID: fakeSubnet1,
		},
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		flags: &paragliderpb.PluginFlags{PrivateEndpointsEnabled: false, KubernetesClustersEnabled: false},
	}

	description, err := json.Marshal(fakeInstanceOptions)
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: fakeDeploymentID, Namespace: fakeNamespace},
		Name:        fakeInstance,
		Description: description,
	}
	resp, err := s.CreateResource(ctx, resource)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceExistingVPCMissingSubnet(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with an existing VPC, but no subnet
	fakeIBMServerState := &fakeIBMServerState{
		VPCs: createFakeVPC(false),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		flags: &paragliderpb.PluginFlags{PrivateEndpointsEnabled: false, KubernetesClustersEnabled: false},
	}

	description, err := json.Marshal(fakeInstanceOptions)
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: fakeDeploymentID, Namespace: fakeNamespace},
		Name:        fakeInstance,
		Description: description,
	}
	resp, err := s.CreateResource(ctx, resource)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceCluster(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with no states
	fakeIBMServerState := &fakeIBMServerState{
		VPCs: createFakeVPC(false),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		flags: &paragliderpb.PluginFlags{KubernetesClustersEnabled: true},
	}

	description, err := json.Marshal(fakeClusterOptions)
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: fakeDeploymentID, Namespace: fakeNamespace},
		Name:        fakeCluster,
		Description: description,
	}
	resp, err := s.CreateResource(ctx, resource)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceClusterDisabled(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with no states
	fakeIBMServerState := &fakeIBMServerState{
		VPCs: createFakeVPC(false),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		flags: &paragliderpb.PluginFlags{KubernetesClustersEnabled: false},
	}

	description, err := json.Marshal(fakeClusterOptions)
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: fakeDeploymentID, Namespace: fakeNamespace},
		Name:        fakeCluster,
		Description: description,
	}
	resp, err := s.CreateResource(ctx, resource)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestCreateResourceClusterExistingVPC(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with no states
	fakeIBMServerState := &fakeIBMServerState{
		VPCs: createFakeVPC(false),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		flags: &paragliderpb.PluginFlags{KubernetesClustersEnabled: true},
	}

	description, err := json.Marshal(fakeClusterOptions)
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: fakeDeploymentID, Namespace: fakeNamespace},
		Name:        fakeCluster,
		Description: description,
	}
	resp, err := s.CreateResource(ctx, resource)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceEndpointGatewayNewVPC(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with no state to have a clean slate resource creation
	fakeIBMServerState := &fakeIBMServerState{}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		flags: &paragliderpb.PluginFlags{PrivateEndpointsEnabled: true},
	}

	description, err := json.Marshal(fakeEndpointGatewayOptions)
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: fakeDeploymentID, Namespace: fakeNamespace},
		Name:        fakeEndpoint,
		Description: description,
	}
	resp, err := s.CreateResource(ctx, resource)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceEndpointGatewayDisabled(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with no state to have a clean slate resource creation
	fakeIBMServerState := &fakeIBMServerState{}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		flags: &paragliderpb.PluginFlags{PrivateEndpointsEnabled: false},
	}

	description, err := json.Marshal(fakeEndpointGatewayOptions)
	require.NoError(t, err)

	resource := &paragliderpb.CreateResourceRequest{
		Deployment:  &paragliderpb.ParagliderDeployment{Id: fakeDeploymentID, Namespace: fakeNamespace},
		Name:        fakeEndpoint,
		Description: description,
	}
	resp, err := s.CreateResource(ctx, resource)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestGetUsedAddressSpaces(t *testing.T) {
	// fakeIBMServerState with an existing VPC and subnet
	fakeIBMServerState := &fakeIBMServerState{
		VPCs: createFakeVPC(false),
		subnetVPC: map[string]string{
			fakeID: fakeSubnet1,
		},
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		}}

	deployment := &paragliderpb.GetUsedAddressSpacesRequest{
		Deployments: []*paragliderpb.ParagliderDeployment{
			{Id: fakeDeploymentID, Namespace: fakeNamespace},
		},
	}

	resp, err := s.GetUsedAddressSpaces(ctx, deployment)
	require.NoError(t, err)
	require.NotEmpty(t, resp)
	require.ElementsMatch(t, resp.AddressSpaceMappings[0].AddressSpaces, []string{fakeSubnet1})
}

func TestGetUsedAddressSpacesMultipleVPC(t *testing.T) {
	// fakeIBMServerState with two VPCs (and subnets) across regions
	fakeIBMServerState := &fakeIBMServerState{
		VPCs: createFakeVPC(true),
		subnetVPC: map[string]string{
			fakeID:  fakeSubnet1,
			fakeID2: fakeSubnet2,
		},
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion):    fakeClient,
			getClientMapKey(fakeID, fakeConRegion): fakeClient,
		}}

	deployment := &paragliderpb.GetUsedAddressSpacesRequest{
		Deployments: []*paragliderpb.ParagliderDeployment{
			{Id: fakeInstanceID, Namespace: fakeNamespace},
		},
	}

	resp, err := s.GetUsedAddressSpaces(ctx, deployment)
	require.NoError(t, err)
	require.NotEmpty(t, resp)
	require.ElementsMatch(t, resp.AddressSpaceMappings[0].AddressSpaces, []string{fakeSubnet1, fakeSubnet2})
}

func TestAddPermitListRules(t *testing.T) {
	fakeOrchestratorServer, fakeOrchestratorServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	fakeOrchestratorServer.Counter = 1
	// fakeIBMServerState with an existing VPC, subnet, instance and a security group
	fakeIBMServerState := &fakeIBMServerState{
		VPCs:          createFakeVPC(false),
		Instance:      createFakeInstance(),
		SecurityGroup: createFakeSecurityGroup(false),
		subnetVPC: map[string]string{
			fakeID: fakeSubnet1,
		},
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeOrchestratorServerAddr,
	}

	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
		Rules:     fakePermitListVPC,
	}

	resp, err := s.AddPermitListRules(ctx, addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAddPermitListRulesExisting(t *testing.T) {
	store := map[string]string{
		kvstore.GetFullKey(fakePermitListVPC[0].Name, utils.IBM, fakeNamespace): fakeID2,
	}
	fakeOrchestratorServer, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServerWithStore(utils.IBM, store)
	if err != nil {
		t.Fatal(err)
	}
	fakeOrchestratorServer.Counter = 1
	// fakeIBMServerState with an existing VPC, subnet, instance and a security group
	// with existing rules in fakePermitListVPC
	fakeIBMServerState := &fakeIBMServerState{
		VPCs:          createFakeVPC(false),
		Instance:      createFakeInstance(),
		SecurityGroup: createFakeSecurityGroup(true),
		subnetVPC: map[string]string{
			fakeID: fakeSubnet1,
		},
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
		Rules:     fakePermitListVPC,
	}

	resp, err := s.AddPermitListRules(ctx, addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAddPermitListRulesMissingInstance(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with empty state without any instance
	fakeIBMServerState := &fakeIBMServerState{}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
		Rules:     fakePermitListVPC,
	}

	resp, err := s.AddPermitListRules(ctx, addRulesRequest)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestAddPermitListRulesMissingSecurityGroup(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with instance, VPC but no security group created
	fakeIBMServerState := &fakeIBMServerState{
		VPCs:     createFakeVPC(false),
		Instance: createFakeInstance(),
		subnetVPC: map[string]string{
			fakeID: fakeSubnet1,
		},
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
		Rules:     fakePermitListVPC,
	}

	resp, err := s.AddPermitListRules(ctx, addRulesRequest)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestAddPermitListRulesWrongNamespace(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with instance, VPC,  security group and multiple subnets initialized.
	fakeIBMServerState := &fakeIBMServerState{
		VPCs:          createFakeVPC(false),
		Instance:      createFakeInstance(),
		SecurityGroup: createFakeSecurityGroup(false),
		subnetVPC: map[string]string{
			fakeID:  fakeSubnet1,
			fakeID2: fakeSubnet2,
		},
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()

	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: wrongNamespace,
		Resource:  fakeInstanceID,
		Rules:     fakePermitListVPC,
	}

	resp, err := s.AddPermitListRules(ctx, addRulesRequest)
	require.Error(t, err)
	require.Nil(t, resp)
}
func TestAddPermitListRulesTransitGateway(t *testing.T) {
	fakeControllerServer, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	fakeControllerServer.Counter = 2
	// fakeIBMServerState with two VPCs (and subnets) across regions
	fakeIBMServerState := &fakeIBMServerState{
		VPCs:          createFakeVPC(true),
		Instance:      createFakeInstance(),
		SecurityGroup: createFakeSecurityGroup(false),
		subnetVPC: map[string]string{
			fakeID:  fakeSubnet1,
			fakeID2: fakeSubnet2,
		},
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()
	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion):    fakeClient,
			getClientMapKey(fakeID, fakeConRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	// fakePermitListMultiVPC is added to the permit list which will trigger creation of a link
	// between VPCs across regions, and hence requiriing deployment of a transit gateway.
	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
		Rules:     fakePermitListMultiVPC,
	}

	resp, err := s.AddPermitListRules(ctx, addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAddPermitListRulesPublicGateway(t *testing.T) {
	fakeControllerServer, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	fakeControllerServer.Counter = 1
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with two VPCs (and subnets) across regions
	fakeIBMServerState := &fakeIBMServerState{
		VPCs:          createFakeVPC(false),
		Instance:      createFakeInstance(),
		SecurityGroup: createFakeSecurityGroup(false),
		subnetVPC: map[string]string{
			fakeID: fakeSubnet1,
		},
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()
	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	// fakePermitListPublic is added to the permit list which will trigger creation of a public gateway
	// to connect the instance to an external system
	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
		Rules:     fakePermitListPublic,
	}

	resp, err := s.AddPermitListRules(ctx, addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAddPermitListRulesExistingPublicGateway(t *testing.T) {
	fakeControllerServer, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	fakeControllerServer.Counter = 1
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with two VPCs (and subnets) across regions
	fakeIBMServerState := &fakeIBMServerState{
		VPCs:          createFakeVPC(false),
		Instance:      createFakeInstance(),
		SecurityGroup: createFakeSecurityGroup(false),
		subnetVPC: map[string]string{
			fakeID: fakeSubnet1,
		},
		publicGateway: true,
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()
	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	// fakePermitListPublic is added to the permit list which will trigger creation of a public gateway
	// to connect the instance to an external system
	addRulesRequest := &paragliderpb.AddPermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
		Rules:     fakePermitListPublic,
	}

	resp, err := s.AddPermitListRules(ctx, addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestDeletePermitListRules(t *testing.T) {
	store := map[string]string{
		kvstore.GetFullKey(fakePermitListVPC[0].Name, utils.IBM, fakeNamespace): fakeID,
		kvstore.GetFullKey(fakePermitListVPC[1].Name, utils.IBM, fakeNamespace): fakeID2,
	}
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServerWithStore(utils.IBM, store)
	if err != nil {
		t.Fatal(err)
	}

	// fakeIBMServerState with an instance and security group with rules
	fakeIBMServerState := &fakeIBMServerState{
		Instance:      createFakeInstance(),
		SecurityGroup: createFakeSecurityGroup(true),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()
	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	deleteRulesRequest := &paragliderpb.DeletePermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
		RuleNames: []string{fakePermitListVPC[0].Name, fakePermitListVPC[1].Name},
	}

	resp, err := s.DeletePermitListRules(ctx, deleteRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestDeletePermitListRulesMissingInstance(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState without an instance
	fakeIBMServerState := &fakeIBMServerState{}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()
	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	// Currently the plugin takes rule ID since names are not supported by IBM Cloud SDK
	deleteRulesRequest := &paragliderpb.DeletePermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
		RuleNames: []string{fakePermitListVPC[0].Name, fakePermitListVPC[1].Name},
	}

	resp, err := s.DeletePermitListRules(ctx, deleteRulesRequest)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestDeletePermitListRulesWrongNamespace(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with a VM and security group
	fakeIBMServerState := &fakeIBMServerState{
		Instance:      createFakeInstance(),
		SecurityGroup: createFakeSecurityGroup(true),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()
	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	deleteRulesRequest := &paragliderpb.DeletePermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
		RuleNames: []string{fakePermitListVPC[0].Name, fakePermitListVPC[1].Name},
	}

	resp, err := s.DeletePermitListRules(ctx, deleteRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)
}
func TestGetPermitList(t *testing.T) {
	store := map[string]string{
		kvstore.GetFullKey(fakeID, utils.IBM, fakeNamespace):  fakePermitListVPC[0].Name,
		kvstore.GetFullKey(fakeID2, utils.IBM, fakeNamespace): fakePermitListVPC[1].Name,
	}
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServerWithStore(utils.IBM, store)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with a VM and security group with rules
	fakeIBMServerState := &fakeIBMServerState{
		Instance:      createFakeInstance(),
		SecurityGroup: createFakeSecurityGroup(true),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()
	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	getRulesRequest := &paragliderpb.GetPermitListRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
	}

	resp, err := s.GetPermitList(ctx, getRulesRequest)
	require.NoError(t, err)
	fmt.Printf("Retu %v\n", resp.Rules)
	fmt.Printf("Need %v\n", fakePermitListVPC)

	require.ElementsMatch(t, resp.Rules, fakePermitListVPC)
}

func TestGetPermitListEmpty(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with a VM and security group without rules
	fakeIBMServerState := &fakeIBMServerState{
		Instance:      createFakeInstance(),
		SecurityGroup: createFakeSecurityGroup(false),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()
	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	getRulesRequest := &paragliderpb.GetPermitListRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
	}

	resp, err := s.GetPermitList(ctx, getRulesRequest)
	require.NoError(t, err)
	require.Empty(t, resp.Rules)
}

func TestGetPermitListMissingInstance(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with no instance
	fakeIBMServerState := &fakeIBMServerState{}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()
	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	getRulesRequest := &paragliderpb.GetPermitListRequest{
		Namespace: fakeNamespace,
		Resource:  fakeInstanceID,
	}

	resp, err := s.GetPermitList(ctx, getRulesRequest)
	require.Error(t, err)
	require.Nil(t, resp)
}

func TestGetPermitListWrongNamespace(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	// fakeIBMServerState with a VM and security group with rules
	fakeIBMServerState := &fakeIBMServerState{
		Instance:      createFakeInstance(),
		SecurityGroup: createFakeSecurityGroup(true),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer fakeServer.Close()
	s := &IBMPluginServer{
		cloudClient: map[string]*CloudClient{
			getClientMapKey(fakeID, fakeRegion): fakeClient,
		},
		orchestratorServerAddr: fakeControllerServerAddr,
	}

	getRulesRequest := &paragliderpb.GetPermitListRequest{
		Namespace: wrongNamespace,
		Resource:  fakeInstanceID,
	}

	resp, err := s.GetPermitList(ctx, getRulesRequest)
	require.Error(t, err)
	require.Nil(t, resp)
}
