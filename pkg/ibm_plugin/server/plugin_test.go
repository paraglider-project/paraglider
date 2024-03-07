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
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
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
	fakeResGroup = "invisinets-fake"
	fakeRegion   = "us-east"
	fakeZone     = fakeRegion + "-a"
	fakeInstance = "vm-invisinets-fake"
	fakeImage    = "fake-image"
	fakeVPC      = "invisinets-fake-vpc"
	fakeID       = "12345"
	fakeSubnet   = "fake-subnet"
	fakeSG       = "fake-sg"
	fakeIP       = "10.0.0.2"
	fakeProfile  = "bx2-2x8"

	fakeResourceID = "/ResourceGroupName/" + fakeResGroup + "/Zone/" + fakeZone + "/ResourceID/" + fakeInstance
	fakeNamespace  = "inv-namespace"
)

type fakeIBMServerState struct {
	//fakeVPC      *vpcv1.VPC
	fakeInstance *vpcv1.Instance
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
	in.CRN = core.StringPtr(fakeImage)
	in.Name = core.StringPtr(fakeInstance)
	in.ID = core.StringPtr(fakeID)
	in.Status = core.StringPtr(vpcv1.InstanceStatusRunningConst)
	in.NetworkInterfaces = make([]vpcv1.NetworkInterfaceInstanceContextReference, 1)
	in.NetworkInterfaces[0].PrimaryIP = &vpcv1.ReservedIPReference{Address: core.StringPtr(fakeIP)}
	return &in
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
			fmt.Printf("Received search query %+v\n", req["query"])
			var searchResult globalsearchv2.ScanResult
			searchResult.Items = make([]globalsearchv2.ResultItem, 0)
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
		case path == "/instances":
			if r.Method == http.MethodPost {
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
		case path == "/instances/"+fakeID:
			if r.Method == http.MethodGet {
				if fakeIBMServerState.fakeInstance == nil {
					http.Error(w, "Instance not found", http.StatusNotFound)
					return
				}
				sendFakeResponse(w, fakeIBMServerState.fakeInstance)
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
	if err != nil {
		println(err)
	}
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
