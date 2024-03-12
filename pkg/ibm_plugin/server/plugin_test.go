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

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/IBM/platform-services-go-sdk/globaltaggingv1"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/stretchr/testify/require"

	fake "github.com/NetSys/invisinets/pkg/fake/controller/rpc"
	sdk "github.com/NetSys/invisinets/pkg/ibm_plugin/sdk"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	utils "github.com/NetSys/invisinets/pkg/utils"
)

const (
	fakeResGroup  = "invisinets-fake"
	fakeRegion    = "us-east"
	fakeConRegion = "us-south"
	fakeZone      = fakeRegion + "-a"
	fakeInstance  = "vm-invisinets-fake"
	fakeImage     = "fake-image"
	fakeVPC       = "invisinets-fake-vpc"
	fakeID        = "12345"
	fakeID2       = "123452"
	fakeRule      = "fake-rule"
	fakeRuleID1   = "fake-rule1"
	fakeRuleID2   = "fake-rule2"
	fakeCRN       = "crn:" + fakeID
	fakeSubnet    = "invisinets-fake-subnet"
	fakeSG        = "invisinets-fake-sg"
	fakeGw        = "invisnets-fake-gw"
	fakeIP        = "10.0.0.2"
	fakeSubnet1   = "10.0.0.0/16"
	fakeSubnet2   = "20.1.1.0/28"
	fakeProfile   = "bx2-2x8"
	invTag        = "inv"

	fakeResourceID = "/ResourceGroupName/" + fakeResGroup + "/Zone/" + fakeZone + "/ResourceID/" + fakeInstance
	fakeNamespace  = "inv-namespace"
)

var fakePermitList []*invisinetspb.PermitListRule = []*invisinetspb.PermitListRule{
	{
		Id:        fakeRuleID1,
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   443,
		DstPort:   443,
		Protocol:  6,
		Targets:   []string{"10.0.0.0/18"},
	},
	{
		Id:        fakeRuleID2,
		Direction: invisinetspb.Direction_OUTBOUND,
		SrcPort:   -1,
		DstPort:   -1,
		Protocol:  -1,
		Targets:   []string{"10.0.64.1"},
	},
}

var fakePermitList2 []*invisinetspb.PermitListRule = []*invisinetspb.PermitListRule{
	{
		Id:        fakeRuleID1,
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   443,
		DstPort:   443,
		Protocol:  6,
		Targets:   []string{"20.1.1.5"},
	},
}

type fakeIBMServerState struct {
	fakeVPCs          []*vpcv1.VPC
	fakeInstance      *vpcv1.Instance
	fakeSecurityGroup *vpcv1.SecurityGroup
	connectSubnet     *string
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

func createFakeInstance() *vpcv1.Instance {
	var in vpcv1.Instance
	var vpcRef vpcv1.VPCReference
	in.CRN = core.StringPtr(fakeCRN)
	in.Name = core.StringPtr(fakeInstance)
	in.ID = core.StringPtr(fakeID)
	in.Status = core.StringPtr(vpcv1.InstanceStatusRunningConst)
	in.NetworkInterfaces = make([]vpcv1.NetworkInterfaceInstanceContextReference, 1)
	in.NetworkInterfaces[0].PrimaryIP = &vpcv1.ReservedIPReference{Address: core.StringPtr(fakeIP)}
	vpcRef.ID = core.StringPtr(fakeID)
	vpcRef.CRN = core.StringPtr(fakeCRN)
	in.VPC = &vpcRef
	return &in
}

func createFakeVPC(connectVPC bool) []*vpcv1.VPC {
	var vpcs []*vpcv1.VPC
	var vpc vpcv1.VPC
	vpc.CRN = core.StringPtr(fakeCRN)
	vpc.Name = core.StringPtr(fakeVPC)
	vpc.ID = core.StringPtr(fakeID)
	vpcs = append(vpcs, &vpc)
	if connectVPC {
		var vpc vpcv1.VPC
		vpc.CRN = core.StringPtr(fakeCRN + "2")
		vpc.Name = core.StringPtr(fakeVPC)
		vpc.ID = core.StringPtr(fakeID2)
		vpcs = append(vpcs, &vpc)
	}
	return vpcs
}

func createFakeSecurityGroup(addRules bool) *vpcv1.SecurityGroup {
	var sg vpcv1.SecurityGroup
	sg.CRN = core.StringPtr(fakeCRN)
	sg.Name = core.StringPtr(fakeSG)
	sg.ID = core.StringPtr(fakeID)
	if addRules {
		sgRules := make([]vpcv1.SecurityGroupRuleIntf, 2)
		sgRules[0] = &vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp{
			ID:        core.StringPtr(fakeRuleID1),
			Direction: core.StringPtr("inbound"),
			Protocol:  core.StringPtr("tcp"),
			PortMin:   core.Int64Ptr(443),
			PortMax:   core.Int64Ptr(443),
			Remote:    &vpcv1.SecurityGroupRuleRemoteCIDR{CIDRBlock: core.StringPtr("10.0.0.0/18")},
		}
		sgRules[1] = &vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAll{
			ID:        core.StringPtr(fakeRuleID2),
			Direction: core.StringPtr("outbound"),
			Protocol:  core.StringPtr("all"),
			Remote:    &vpcv1.SecurityGroupRuleRemoteIP{Address: core.StringPtr("10.0.64.1")},
		}
		sg.Rules = sgRules
	}
	return &sg
}

func getFakeIBMServerHandler(fakeIBMServerState *fakeIBMServerState) http.HandlerFunc {
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
		fmt.Printf("IBM fake server %s path: %s\n", r.Method, path)
		switch {
		case path == "/v3/resources/search":
			var req map[string]interface{}
			err := json.Unmarshal(body, &req)
			if err != nil {
				fmt.Printf("%s\n", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Printf("Received search query %s\n", req["query"])
			res := ""
			tags := []string{}
			var searchResult globalsearchv2.ScanResult
			searchResult.Items = make([]globalsearchv2.ResultItem, 0)
			for _, tokens := range strings.Split(req["query"].(string), "AND") {
				keys := strings.Split(tokens, ":")
				switch strings.TrimSpace(keys[0]) {
				case "type":
					res = strings.TrimSpace(keys[1])
				case "tags":
					tags = append(tags, strings.TrimSpace(keys[1]))
				}
			}
			fmt.Printf("%s: %+v\n", res, tags)
			switch res {
			case "instance":
				if fakeIBMServerState.fakeInstance != nil {
					var resultItem globalsearchv2.ResultItem
					resultItem.CRN = fakeIBMServerState.fakeInstance.CRN
					searchResult.Items = append(searchResult.Items, resultItem)
				}
			case "security-group":
				if fakeIBMServerState.fakeSecurityGroup != nil {
					var resultItem globalsearchv2.ResultItem
					resultItem.CRN = fakeIBMServerState.fakeSecurityGroup.CRN
					searchResult.Items = append(searchResult.Items, resultItem)
				}
			case "vpc":
				if fakeIBMServerState.fakeVPCs != nil {
					for i, fakeVPC := range fakeIBMServerState.fakeVPCs {
						var resultItem globalsearchv2.ResultItem
						resultItem.CRN = fakeVPC.CRN
						resultItem.SetProperty("region", fakeRegion)
						if i == 1 {
							resultItem.SetProperty("region", fakeConRegion)
						}
						searchResult.Items = append(searchResult.Items, resultItem)
					}
				}
			}

			fmt.Printf("Sending search result : %+v\n", searchResult)

			sendFakeResponse(w, searchResult)
			return
		case path == "/vpcs":
			var req map[string]interface{}
			err := json.Unmarshal(body, &req)
			if err != nil {
				fmt.Printf("%s\n", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Printf("Received VPC %+v\n", req)
			var newVPC vpcv1.VPC
			newVPC.CRN = core.StringPtr(fakeVPC)
			newVPC.Name = core.StringPtr(fakeVPC)
			newVPC.ID = core.StringPtr(fakeID)
			sendFakeResponse(w, newVPC)
			return
		case path == "/v3/tags/attach":
			var req map[string]interface{}
			err := json.Unmarshal(body, &req)
			if err != nil {
				fmt.Printf("%s\n", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Printf("Received attach tag %+v\n", req)
			var tagResult globaltaggingv1.TagResults
			tagResult.Results = make([]globaltaggingv1.TagResultsItem, 1)
			tagResult.Results[0].IsError = core.BoolPtr(false)
			sendFakeResponse(w, tagResult)
			return
		case path == "/vpcs/"+fakeID+"/address_prefixes":
			var req map[string]interface{}
			err := json.Unmarshal(body, &req)
			if err != nil {
				fmt.Printf("%s\n", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Printf("Received VPC Address Prefix: %+v\n", req)
			var newVPCPrefix vpcv1.AddressPrefix
			sendFakeResponse(w, newVPCPrefix)
			return
		case path == "/subnets":
			if r.Method == http.MethodPost {
				var req vpcv1.CreateSubnetOptions
				err := json.Unmarshal(body, &req)
				if err != nil {
					fmt.Printf("%s\n", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				fmt.Printf("Received Subnets: %+v\n", req)
				var subnet vpcv1.Subnet
				subnet.CRN = core.StringPtr(fakeSubnet)
				subnet.ID = core.StringPtr(fakeID)
				sendFakeResponse(w, subnet)
				return
			}
			if r.Method == http.MethodGet {
				fmt.Printf("Received Subnets: %s\n", r.URL.Query().Get("vpc.id"))
				var subnets vpcv1.SubnetCollection

				subnets.Subnets = make([]vpcv1.Subnet, 1)
				subnets.Subnets[0].ID = core.StringPtr(r.URL.Query().Get("vpc.id"))

				sendFakeResponse(w, subnets)
				return
			}
		case path == "/subnets/"+fakeID:
			var subnet vpcv1.Subnet
			subnet.Ipv4CIDRBlock = core.StringPtr(fakeSubnet1)
			sendFakeResponse(w, subnet)
			return
		case path == "/subnets/"+fakeID2:
			var subnet vpcv1.Subnet
			if fakeIBMServerState.connectSubnet != nil {
				subnet.Ipv4CIDRBlock = fakeIBMServerState.connectSubnet
			}
			sendFakeResponse(w, subnet)
			return
		case path == "/keys":
			var req map[string]interface{}
			err := json.Unmarshal(body, &req)
			if err != nil {
				fmt.Printf("%s\n", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Printf("Received Keys: %+v\n", req)
			var key vpcv1.Key
			key.ID = core.StringPtr(fakeID)
			sendFakeResponse(w, key)
			return
		case path == "/security_groups":
			if r.Method == http.MethodPost { // Create a security group
				var req map[string]interface{}
				err := json.Unmarshal(body, &req)
				if err != nil {
					fmt.Printf("%s\n", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				fmt.Printf("Received Security Groups: %+v\n", req)
				var sg vpcv1.SecurityGroup
				sg.CRN = core.StringPtr(fakeSG)
				sg.ID = core.StringPtr(fakeID)
				sendFakeResponse(w, sg)
				return
			}
		case path == "/security_groups/"+fakeID+"/rules":
			if r.Method == http.MethodGet { // Get rules of a security group
				fmt.Printf("Received list Security Group rules\n")
				if fakeIBMServerState.fakeSecurityGroup == nil {
					http.Error(w, "Security Group not found", http.StatusNotFound)
					return
				}
				var sg vpcv1.SecurityGroupRuleCollection
				sg.Rules = fakeIBMServerState.fakeSecurityGroup.Rules
				sendFakeResponse(w, sg)
				return
			}
			if r.Method == http.MethodPost { // Add rules to a security group
				var req vpcv1.CreateSecurityGroupRuleOptions
				err := json.Unmarshal(body, &req)
				if err != nil {
					fmt.Printf("%s\n", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				fmt.Printf("Received Add Security Group rules: %+v\n", req)
				var sg vpcv1.SecurityGroupRuleIntf
				sendFakeResponse(w, sg)
				return
			}
		case strings.Contains(path, "/security_groups/"+fakeID+"/rules/"):
			if r.Method == http.MethodDelete { // Delete a rule
				w.WriteHeader(http.StatusOK)
				return
			}
		case path == "/instances":
			if r.Method == http.MethodPost { // Create
				var req vpcv1.CreateInstanceOptions
				err := json.Unmarshal(body, &req)
				if err != nil {
					fmt.Printf("%s\n", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				fmt.Printf("Received Instances: %+v\n", req)
				fakeIBMServerState.fakeInstance = createFakeInstance()
				sendFakeResponse(w, fakeIBMServerState.fakeInstance)
				return
			}
			if r.Method == http.MethodGet { // List Instances
				fmt.Printf("Received Instances List\n")
				var instanceCol vpcv1.InstanceCollection
				instanceCol.Instances = make([]vpcv1.Instance, 1)
				instanceCol.Instances[0] = *fakeIBMServerState.fakeInstance
				sendFakeResponse(w, instanceCol)
				return
			}
		case path == "/instances/"+fakeID: // Get an Instance
			if r.Method == http.MethodGet {
				if fakeIBMServerState.fakeInstance == nil {
					http.Error(w, "Instance not found", http.StatusNotFound)
					return
				}
				sendFakeResponse(w, fakeIBMServerState.fakeInstance)
				return
			}
		case path == "/instances/"+fakeID+"/network_interfaces":
			if r.Method == http.MethodGet { // List an Instance's network interfaces
				if fakeIBMServerState.fakeInstance == nil {
					http.Error(w, "Instance not found", http.StatusNotFound)
					return
				}
				var netIntf vpcv1.NetworkInterfaceUnpaginatedCollection
				netIntf.NetworkInterfaces = make([]vpcv1.NetworkInterface, 1)
				netIntf.NetworkInterfaces[0].SecurityGroups = make([]vpcv1.SecurityGroupReference, 1)
				netIntf.NetworkInterfaces[0].SecurityGroups[0].Name = fakeIBMServerState.fakeSecurityGroup.Name
				netIntf.NetworkInterfaces[0].SecurityGroups[0].ID = fakeIBMServerState.fakeSecurityGroup.ID
				sendFakeResponse(w, netIntf)
				return
			}
		case path == "/transit_gateways":
			if r.Method == http.MethodPost { // Create transit gateway
				var gw transitgatewayapisv1.TransitGateway
				gw.Name = core.StringPtr(fakeGw)
				gw.ID = core.StringPtr(fakeID)
				sendFakeResponse(w, gw)
				return
			}
		case path == "/transit_gateways/"+fakeID+"/connections":
			if r.Method == http.MethodPost {
				var conn transitgatewayapisv1.TransitGatewayConnectionCust
				conn.ID = core.StringPtr(fakeID)
				conn.Name = core.StringPtr(fakeGw)
				conn.NetworkID = core.StringPtr("vpc")
				sendFakeResponse(w, conn)
				return
			}
		}
		fmt.Printf("unsupported request: %s %s\n", r.Method, path)
		http.Error(w, fmt.Sprintf("unsupported request: %s %s", r.Method, path), http.StatusBadRequest)
	})
}

func setup(t *testing.T, fakeIBMServerState *fakeIBMServerState) (fakeServer *httptest.Server, ctx context.Context, fakeClient *sdk.CloudClient) {
	var err error
	fakeServer = httptest.NewServer(getFakeIBMServerHandler(fakeIBMServerState))
	ctx = context.Background()
	fmt.Printf("Setting a fake server at %s\n", fakeServer.URL)
	fakeClient, err = sdk.FakeIBMCloudClient(fakeServer.URL, fakeID, fakeRegion)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// Cleans up fake http server and fake client
func teardown(fakeServer *httptest.Server) {
	fakeServer.Close()
}

func TestCreateResourceNewVPC(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	fakeIBMServerState := &fakeIBMServerState{}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer teardown(fakeServer)
	imageIdentity := vpcv1.ImageIdentityByID{ID: core.StringPtr(fakeImage)}
	zoneIdentity := vpcv1.ZoneIdentityByName{Name: core.StringPtr(fakeZone)}
	myTestProfile := string(fakeProfile)

	testPrototype := &vpcv1.InstancePrototypeInstanceByImage{
		Image:   &imageIdentity,
		Zone:    &zoneIdentity,
		Name:    core.StringPtr(fakeInstance),
		Profile: &vpcv1.InstanceProfileIdentityByName{Name: &myTestProfile},
	}

	s := &ibmPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*sdk.CloudClient{
			getClientMapKey(fakeResGroup, fakeRegion): fakeClient,
		}}

	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(testPrototype)})
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Id: fakeResourceID, Description: description, Namespace: fakeNamespace}
	resp, err := s.CreateResource(ctx, resource)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCreateResourceExistingVPC(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	fakeIBMServerState := &fakeIBMServerState{
		fakeVPCs: createFakeVPC(false),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer teardown(fakeServer)
	imageIdentity := vpcv1.ImageIdentityByID{ID: core.StringPtr(fakeImage)}
	zoneIdentity := vpcv1.ZoneIdentityByName{Name: core.StringPtr(fakeZone)}
	myTestProfile := string(fakeProfile)

	testPrototype := &vpcv1.InstancePrototypeInstanceByImage{
		Image:   &imageIdentity,
		Zone:    &zoneIdentity,
		Name:    core.StringPtr(fakeInstance),
		Profile: &vpcv1.InstanceProfileIdentityByName{Name: &myTestProfile},
	}

	s := &ibmPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*sdk.CloudClient{
			getClientMapKey(fakeResGroup, fakeRegion): fakeClient,
		}}

	description, err := json.Marshal(vpcv1.CreateInstanceOptions{InstancePrototype: vpcv1.InstancePrototypeIntf(testPrototype)})
	require.NoError(t, err)

	resource := &invisinetspb.ResourceDescription{Id: fakeResourceID, Description: description, Namespace: fakeNamespace}
	resp, err := s.CreateResource(ctx, resource)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestGetUsedAddressSpaces(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	fakeIBMServerState := &fakeIBMServerState{}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer teardown(fakeServer)

	s := &ibmPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*sdk.CloudClient{
			getClientMapKey(fakeResGroup, fakeRegion): fakeClient,
		}}
	deployment := &invisinetspb.GetUsedAddressSpacesRequest{
		Deployments: []*invisinetspb.InvisinetsDeployment{
			{Id: fakeResourceID, Namespace: fakeNamespace},
		},
	}

	usedAddressSpace, err := s.GetUsedAddressSpaces(ctx, deployment)
	require.NoError(t, err)
	require.NotEmpty(t, usedAddressSpace)
}

func TestAddPermitListRules(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	fakeIBMServerState := &fakeIBMServerState{
		fakeVPCs:          createFakeVPC(false),
		fakeInstance:      createFakeInstance(),
		fakeSecurityGroup: createFakeSecurityGroup(false),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer teardown(fakeServer)

	s := &ibmPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*sdk.CloudClient{
			getClientMapKey(fakeResGroup, fakeRegion): fakeClient,
		}}

	addRulesRequest := &invisinetspb.AddPermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeResourceID,
		Rules:     fakePermitList,
	}

	resp, err := s.AddPermitListRules(ctx, addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestAddPermitListRulesTransitGw(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	fakeIBMServerState := &fakeIBMServerState{
		fakeVPCs:          createFakeVPC(true),
		fakeInstance:      createFakeInstance(),
		fakeSecurityGroup: createFakeSecurityGroup(false),
		connectSubnet:     core.StringPtr(fakeSubnet2),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer teardown(fakeServer)
	s := &ibmPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*sdk.CloudClient{
			getClientMapKey(fakeResGroup, fakeRegion):    fakeClient,
			getClientMapKey(fakeResGroup, fakeConRegion): fakeClient,
		}}

	addRulesRequest := &invisinetspb.AddPermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeResourceID,
		Rules:     fakePermitList2,
	}

	resp, err := s.AddPermitListRules(ctx, addRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestDeletePermitListRules(t *testing.T) {
	fakeIBMServerState := &fakeIBMServerState{
		fakeInstance:      createFakeInstance(),
		fakeSecurityGroup: createFakeSecurityGroup(true),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer teardown(fakeServer)
	s := &ibmPluginServer{
		cloudClient: map[string]*sdk.CloudClient{
			getClientMapKey(fakeResGroup, fakeRegion): fakeClient,
		}}

	deleteRulesRequest := &invisinetspb.DeletePermitListRulesRequest{
		Namespace: fakeNamespace,
		Resource:  fakeResourceID,
		RuleNames: []string{fakePermitList[0].Id, fakePermitList[1].Id},
	}

	resp, err := s.DeletePermitListRules(ctx, deleteRulesRequest)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestGetPermitList(t *testing.T) {
	_, fakeControllerServerAddr, err := fake.SetupFakeOrchestratorRPCServer(utils.IBM)
	if err != nil {
		t.Fatal(err)
	}
	fakeIBMServerState := &fakeIBMServerState{
		fakeInstance:      createFakeInstance(),
		fakeSecurityGroup: createFakeSecurityGroup(true),
	}
	fakeServer, ctx, fakeClient := setup(t, fakeIBMServerState)
	defer teardown(fakeServer)
	s := &ibmPluginServer{
		orchestratorServerAddr: fakeControllerServerAddr,
		cloudClient: map[string]*sdk.CloudClient{
			getClientMapKey(fakeResGroup, fakeRegion): fakeClient,
		}}

	getRulesRequest := &invisinetspb.GetPermitListRequest{
		Namespace: fakeNamespace,
		Resource:  fakeResourceID,
	}

	resp, err := s.GetPermitList(ctx, getRulesRequest)
	require.NoError(t, err)
	require.ElementsMatch(t, resp.Rules, fakePermitList)
}
