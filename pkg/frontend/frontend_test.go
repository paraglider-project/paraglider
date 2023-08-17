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

package frontend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"io"
	"net"
	"log"
	"bytes"
	"strconv"

	"github.com/gin-gonic/gin"
	grpc "google.golang.org/grpc"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock values
const addressSpaceRegion = "us-west"
const addressSpaceAddress = "10.0.0.0/16"

// Mock Cloud Plugin Server
type mockCloudPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
}

func (s *mockCloudPluginServer) GetPermitList(c context.Context, r *invisinetspb.ResourceID) (*invisinetspb.PermitList, error) {
	return &invisinetspb.PermitList{AssociatedResource: r.Id}, nil
}

func (s *mockCloudPluginServer) AddPermitListRules(c context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: permitList.AssociatedResource}, nil
}

func (s *mockCloudPluginServer) DeletePermitListRules(c context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: permitList.AssociatedResource}, nil
}

func (s *mockCloudPluginServer) CreateResource(c context.Context, resource *invisinetspb.ResourceDescription) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: resource.Id}, nil
}

func (s *mockCloudPluginServer) GetUsedAddressSpaces(c context.Context, deployment *invisinetspb.InvisinetsDeployment) (*invisinetspb.AddressSpaceList, error) {
	mapping := invisinetspb.RegionAddressSpaceMap{Region: addressSpaceRegion, AddressSpace: addressSpaceAddress}
	return &invisinetspb.AddressSpaceList{Mappings: [](*invisinetspb.RegionAddressSpaceMap){&mapping}}, nil
}

func newServer() *mockCloudPluginServer {
	s := &mockCloudPluginServer{}
	return s
}

func setupServer(port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	invisinetspb.RegisterCloudPluginServer(grpcServer, newServer())
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func SetUpRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	gin.DefaultWriter = io.Discard
	router := gin.New()
	return router
}

func TestPermitListGet(t *testing.T) {
	// Setup
	port := 10001
	pluginAddresses["example"] = fmt.Sprintf("localhost:%d", port)

	go setupServer(port)

	r := SetUpRouter()
	r.GET("/cloud/:cloud/resources/:id/permit-list/", permitListGet)

	// Well-formed request
	id := "123"
	permitListJson := "{\"associated_resource\":\"123\"}"
	expectedResponse := map[string]string{
		"id":              id,
		"resource":        id,
		"permitlist_json": permitListJson,
	}

	url := fmt.Sprintf("/cloud/%s/resources/%s/permit-list/", "example", id)
	req, _ := http.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var jsonMap map[string]string
	err := json.Unmarshal(responseData, &jsonMap)
	require.Nil(t, err)
    assert.Equal(t, expectedResponse, jsonMap)
    assert.Equal(t, http.StatusOK, w.Code)

	// Bad cloud name
	url = fmt.Sprintf("/cloud/%s/resources/%s/permit-list/", "wrong", id)
	req, _ = http.NewRequest("GET", url, nil)
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermitListRulesAdd(t *testing.T) {
	// Setup
	port := 10002
	pluginAddresses["example"] = fmt.Sprintf("localhost:%d", port)

	go setupServer(port)

	r := SetUpRouter()
	r.POST("/cloud/:cloud/resources/:id/permit-list/rules", permitListRulesAdd)

	// Well-formed request
	id := "123"
	tags := []string{"tag"}
	rule := &invisinetspb.PermitListRule{
		Id: id, 
		Tag: tags,
		Direction: invisinetspb.Direction_INBOUND, 
		SrcPort: 1, 
		DstPort: 2, 
		Protocol: 1 }
	rulesList := &invisinetspb.PermitList{AssociatedResource: "123", Rules: []*invisinetspb.PermitListRule{rule}}
	jsonValue, _ := json.Marshal(rulesList)

	url := fmt.Sprintf("/cloud/%s/resources/%s/permit-list/rules", "example", id)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusOK, w.Code)

	// Bad cloud name
	url = fmt.Sprintf("/cloud/%s/resources/%s/permit-list/rules", "wrong", id)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf("/cloud/%s/resources/%s/permit-list/rules", "example", id)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermitListRulesDelete(t *testing.T) {
	// Setup
	port := 10003
	pluginAddresses["example"] = fmt.Sprintf("localhost:%d", port)

	go setupServer(port)

	r := SetUpRouter()
	r.DELETE("/cloud/:cloud/resources/:id/permit-list/rules", permitListRulesDelete)

	// Well-formed request
	id := "123"
	tags := []string{"tag"}
	rule := &invisinetspb.PermitListRule{
		Id: "id", 
		Tag: tags,
		Direction: invisinetspb.Direction_INBOUND, 
		SrcPort: 1, 
		DstPort: 2, 
		Protocol: 1 }
	rulesList := &invisinetspb.PermitList{AssociatedResource: "123", Rules: []*invisinetspb.PermitListRule{rule}}
	jsonValue, _ := json.Marshal(rulesList)

	url := fmt.Sprintf("/cloud/%s/resources/%s/permit-list/rules", "example", id)
	req, _ := http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusOK, w.Code)

	// Bad cloud name
	url = fmt.Sprintf("/cloud/%s/resources/%s/permit-list/rules", "wrong", id)
	req, _ = http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf("/cloud/%s/resources/%s/permit-list/rules", "example", id)
	req, _ = http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateResource(t *testing.T) {
	// Setup
	port := 10004
	pluginAddresses["example"] = fmt.Sprintf("localhost:%d", port)
	region := "us-west"
	addressSpaceMap[region] = "10.1.0.0/24"

	go setupServer(port)

	r := SetUpRouter()
	r.POST("/cloud/:cloud/region/:region/resources/:id/", resourceCreate)

	// Well-formed request
	id := "123"
	resource := &invisinetspb.ResourceDescriptionString{
		Id: id, 
		Description: "description" }
	jsonValue, _ := json.Marshal(resource)

	url := fmt.Sprintf("/cloud/%s/region/%s/resources/%s/", "example", region, id)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusOK, w.Code)

	// Bad cloud name
	url = fmt.Sprintf("/cloud/%s/region/%s/resources/%s/", "wrong", region, id)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf("/cloud/%s/region/%s/resources/%s/", "example", region, id)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAddressSpaces(t *testing.T) {
	// Setup
	port := 10005
	pluginAddresses["example"] = fmt.Sprintf("localhost:%d", port)

	go setupServer(port)

	// Well-formed call
	addressList, _ := getAddressSpaces(context.Background(), "example", "id")
    assert.Equal(t, addressList.Mappings[0].Region, addressSpaceRegion)


	// Bad cloud name
	emptyList, err := getAddressSpaces(context.Background(), "wrong", "id")
    require.NotNil(t, err)
	require.Nil(t, emptyList)
}

func TestUpdateAddressSpaceMap(t *testing.T) {
	port := 10006
	pluginAddresses["example"] = fmt.Sprintf("localhost:%d", port)

	go setupServer(port)

	// Valid cloud list 
	cloud := Cloud{Name: "example",  Host: "localhost", Port: strconv.Itoa(port), InvDeployment: ""}
	config = Config{Clouds: []Cloud{cloud}}
	err := updateAddressSpaceMap(context.Background())
	require.Nil(t, err)
	assert.Equal(t, addressSpaceMap["example\\" + addressSpaceRegion], addressSpaceAddress)

	// Invalid cloud list 
	cloud = Cloud{Name: "wrong",  Host: "localhost", Port: strconv.Itoa(port), InvDeployment: ""}
	config = Config{Clouds: []Cloud{cloud}}
	err = updateAddressSpaceMap(context.Background())
	require.NotNil(t, err)
}

func TestGetNewAddressSpace(t *testing.T) {
	// No entries in address space map
	addressSpaceMap = make(map[string]string)
	address, err := getNewAddressSpace(context.Background())
	require.Nil(t, err)
	assert.Equal(t, address, "10.0.0.0/16")

	// Next entry
	addressSpaceMap["example\\us-west"] = "10.0.0.0/16"
	address, err = getNewAddressSpace(context.Background())
	require.Nil(t, err)
	assert.Equal(t, address, "10.1.0.0/16")

	// Out of addresses
	addressSpaceMap["example\\us-west"] = "10.255.0.0/16"
	_, err = getNewAddressSpace(context.Background())
	require.NotNil(t, err)
}
