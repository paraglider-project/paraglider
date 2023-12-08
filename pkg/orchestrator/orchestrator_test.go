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

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	grpc "google.golang.org/grpc"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"

	utils "github.com/NetSys/invisinets/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var portNum = 10000

// Mock values
var tagUri = "uri"
var tagIp = "ip"
var resolvedTagIp = "1.2.3.4"

const addressSpaceAddress = "10.0.0.0/16"
const exampleCloudName = "example"

const validTagName = "validTagName"
const defaultNamespace = "default"
const validLastLevelTagName = "validLastLevelTagName"
const validParentTagName = "validParentTagName"

var exampleRule = &invisinetspb.PermitListRule{Id: "example-rule", Tags: []string{validTagName, "1.2.3.4"}, SrcPort: 1, DstPort: 1, Protocol: 1, Direction: invisinetspb.Direction_INBOUND}

type mockTagServiceServer struct {
	tagservicepb.UnimplementedTagServiceServer
}

func (s *mockTagServiceServer) GetTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.TagMapping, error) {
	if strings.HasPrefix(tag.TagName, validLastLevelTagName) {
		return &tagservicepb.TagMapping{TagName: tag.TagName, Uri: &tagUri, Ip: &tagIp}, nil
	}
	if strings.HasPrefix(tag.TagName, validParentTagName) {
		return &tagservicepb.TagMapping{TagName: tag.TagName, ChildTags: []string{"child"}}, nil
	}
	return nil, fmt.Errorf("GetTag: Invalid tag name")
}

func (s *mockTagServiceServer) ResolveTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.TagMappingList, error) {
	if strings.HasPrefix(tag.TagName, validTagName) {
		newUri := "uri/" + tag.TagName
		return &tagservicepb.TagMappingList{Mappings: []*tagservicepb.TagMapping{&tagservicepb.TagMapping{TagName: tag.TagName, Uri: &newUri, Ip: &resolvedTagIp}}}, nil
	}
	return nil, fmt.Errorf("ResolveTag: Invalid tag name")
}

func (s *mockTagServiceServer) SetTag(c context.Context, tagMapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error) {
	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully created tag: %s", tagMapping.TagName)}, nil
}

func (s *mockTagServiceServer) DeleteTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.BasicResponse, error) {
	if strings.HasPrefix(tag.TagName, validTagName) {
		return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully deleted tag: %s", tag.TagName)}, nil
	}
	return &tagservicepb.BasicResponse{Success: false, Message: fmt.Sprintf("tag %s does not exist", tag.TagName)}, fmt.Errorf("tag does not exist")
}

func (s *mockTagServiceServer) DeleteTagMember(c context.Context, tagMapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error) {
	if strings.HasPrefix(tagMapping.TagName, validTagName) {
		return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully deleted member %s from tag %s", tagMapping.ChildTags[0], tagMapping.TagName)}, nil
	}
	return &tagservicepb.BasicResponse{Success: false, Message: "parent tag does not exist"}, fmt.Errorf("parentTag does not exist")
}

func (s *mockTagServiceServer) Subscribe(c context.Context, sub *tagservicepb.Subscription) (*tagservicepb.BasicResponse, error) {
	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully subscribed to tag: %s", sub.TagName)}, nil
}

func (s *mockTagServiceServer) Unsubscribe(c context.Context, sub *tagservicepb.Subscription) (*tagservicepb.BasicResponse, error) {
	if strings.HasPrefix(sub.TagName, validTagName) {
		return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully unsubscribed from tag: %s", sub.TagName)}, nil
	}
	return &tagservicepb.BasicResponse{Success: false, Message: fmt.Sprintf("no subscriptions for tag: %s", sub.TagName)}, fmt.Errorf("tag has no subscribers")
}

func (s *mockTagServiceServer) GetSubscribers(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.SubscriberList, error) {
	if strings.HasPrefix(tag.TagName, validTagName) {
		return &tagservicepb.SubscriberList{Subscribers: []string{exampleCloudName + ">uri"}}, nil
	}
	return nil, fmt.Errorf("Tag does not exist")
}

// Mock Cloud Plugin Server
type mockCloudPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
	mockTagServiceServer
}

func (s *mockCloudPluginServer) GetPermitList(c context.Context, r *invisinetspb.ResourceID) (*invisinetspb.PermitList, error) {
	return &invisinetspb.PermitList{AssociatedResource: r.Id, Rules: []*invisinetspb.PermitListRule{exampleRule}}, nil
}

func (s *mockCloudPluginServer) AddPermitListRules(c context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: permitList.AssociatedResource}, nil
}

func (s *mockCloudPluginServer) DeletePermitListRules(c context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: permitList.AssociatedResource}, nil
}

func (s *mockCloudPluginServer) CreateResource(c context.Context, resource *invisinetspb.ResourceDescription) (*invisinetspb.CreateResourceResponse, error) {
	return &invisinetspb.CreateResourceResponse{Name: "resource_name", Uri: resource.Id}, nil
}

func (s *mockCloudPluginServer) GetUsedAddressSpaces(c context.Context, deployment *invisinetspb.InvisinetsDeployment) (*invisinetspb.AddressSpaceList, error) {
	return &invisinetspb.AddressSpaceList{AddressSpaces: []string{addressSpaceAddress}}, nil
}

func getNewPortNumber() int {
	portNum = portNum + 1
	return portNum
}

func newPluginServer() *mockCloudPluginServer {
	s := &mockCloudPluginServer{}
	return s
}

func newTagServer() *mockTagServiceServer {
	s := &mockTagServiceServer{}
	return s
}

func newFrontendServer() *ControllerServer {
	s := &ControllerServer{pluginAddresses: make(map[string]string), usedAddressSpaces: make(map[string]map[string][]string), namespace: defaultNamespace}
	return s
}

func setupPluginServer(port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	invisinetspb.RegisterCloudPluginServer(grpcServer, newPluginServer())
	tagservicepb.RegisterTagServiceServer(grpcServer, newPluginServer())
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println(err.Error())
		}
	}()
}

func setupTagServer(port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	tagservicepb.RegisterTagServiceServer(grpcServer, newTagServer())
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println(err.Error())
		}
	}()
}

func SetUpRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	gin.DefaultWriter = io.Discard
	router := gin.New()
	return router
}

type PermitListGetResponse struct {
	Id         string                   `json:"id"`
	PermitList *invisinetspb.PermitList `json:"permitlist"`
}

func TestPermitListGet(t *testing.T) {
	// Setup
	frontendServer := newFrontendServer()
	port := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	setupPluginServer(port)

	r := SetUpRouter()
	r.GET("/cloud/:cloud/permit-list/:id", frontendServer.permitListGet)

	// Well-formed request
	id := "123"
	expectedResponse := PermitListGetResponse{
		Id:         id,
		PermitList: &invisinetspb.PermitList{AssociatedResource: id, Rules: []*invisinetspb.PermitListRule{exampleRule}},
	}

	url := fmt.Sprintf("/cloud/%s/permit-list/%s", exampleCloudName, id)
	req, _ := http.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var permitList PermitListGetResponse
	err := json.Unmarshal(responseData, &permitList)
	require.Nil(t, err)
	assert.Equal(t, expectedResponse.Id, permitList.Id)
	assert.Equal(t, expectedResponse.PermitList.AssociatedResource, permitList.PermitList.AssociatedResource)
	assert.Equal(t, expectedResponse.PermitList.Rules[0].Tags, permitList.PermitList.Rules[0].Tags)
	assert.Equal(t, http.StatusOK, w.Code)

	// Bad cloud name
	url = fmt.Sprintf("/cloud/%s/permit-list/%s", "wrong", id)
	req, _ = http.NewRequest("GET", url, nil)
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermitListRulesAdd(t *testing.T) {
	// Setup
	frontendServer := newFrontendServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	frontendServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	setupPluginServer(cloudPluginPort)
	setupTagServer(tagServerPort)

	r := SetUpRouter()
	r.POST("/cloud/:cloud/permit-list/rules", frontendServer.permitListRulesAdd)

	// Well-formed request
	id := "123"
	tags := []string{validTagName}
	rule := &invisinetspb.PermitListRule{
		Id:        id,
		Tags:      tags,
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	rulesList := &invisinetspb.PermitList{AssociatedResource: id, Rules: []*invisinetspb.PermitListRule{rule}}
	jsonValue, _ := json.Marshal(rulesList)

	url := fmt.Sprintf("/cloud/%s/permit-list/rules", exampleCloudName)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Invalid tag name (cannot be resolved)
	tags = []string{"tag"}
	rule = &invisinetspb.PermitListRule{
		Id:        id,
		Tags:      tags,
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	rulesList = &invisinetspb.PermitList{AssociatedResource: id, Rules: []*invisinetspb.PermitListRule{rule}}
	jsonValue, _ = json.Marshal(rulesList)

	url = fmt.Sprintf("/cloud/%s/permit-list/rules", exampleCloudName)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Bad cloud name
	url = fmt.Sprintf("/cloud/%s/permit-list/rules", "wrong")
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf("/cloud/%s/permit-list/rules", exampleCloudName)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermitListRulesDelete(t *testing.T) {
	// Setup
	frontendServer := newFrontendServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	frontendServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	setupPluginServer(cloudPluginPort)
	setupTagServer(tagServerPort)

	r := SetUpRouter()
	r.DELETE("/cloud/:cloud/permit-list/rules", frontendServer.permitListRulesDelete)

	// Well-formed request
	id := "123"
	tags := []string{validTagName}
	rule := &invisinetspb.PermitListRule{
		Id:        "id",
		Tags:      tags,
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	rulesList := &invisinetspb.PermitList{AssociatedResource: id, Rules: []*invisinetspb.PermitListRule{rule}}

	jsonValue, _ := json.Marshal(rulesList)

	url := fmt.Sprintf("/cloud/%s/permit-list/rules", exampleCloudName)
	req, _ := http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Bad cloud name
	url = fmt.Sprintf("/cloud/%s/permit-list/rules", "wrong")
	req, _ = http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf("/cloud/%s/permit-list/rules", exampleCloudName)
	req, _ = http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateResource(t *testing.T) {
	// Setup
	frontendServer := newFrontendServer()
	port := getNewPortNumber()
	tagServerPort := getNewPortNumber()
	frontendServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)
	frontendServer.usedAddressSpaces[defaultNamespace] = make(map[string][]string)
	frontendServer.usedAddressSpaces[defaultNamespace][exampleCloudName] = []string{"10.1.0.0/24"}

	setupPluginServer(port)
	setupTagServer(tagServerPort)

	r := SetUpRouter()
	r.POST("/cloud/:cloud/resources/", frontendServer.resourceCreate)

	// Well-formed request
	id := "123"
	resource := &invisinetspb.ResourceDescriptionString{
		Id:          id,
		Description: "description",
	}
	jsonValue, _ := json.Marshal(resource)

	url := fmt.Sprintf("/cloud/%s/resources/", exampleCloudName)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Bad cloud name
	url = fmt.Sprintf("/cloud/%s/resources/", "wrong")
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf("/cloud/%s/resources/", exampleCloudName)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAddressSpaces(t *testing.T) {
	// Setup
	frontendServer := newFrontendServer()
	port := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	setupPluginServer(port)

	// Well-formed call
	addressList, _ := frontendServer.getAddressSpaces(exampleCloudName, "id", defaultNamespace)
	assert.Equal(t, addressList.AddressSpaces[0], addressSpaceAddress)

	// Bad cloud name
	emptyList, err := frontendServer.getAddressSpaces("wrong", "id", defaultNamespace)
	require.NotNil(t, err)

	require.Nil(t, emptyList)
}

func TestUpdateUsedAddressSpacesMap(t *testing.T) {
	frontendServer := newFrontendServer()
	port := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	setupPluginServer(port)

	// Valid cloud list
	cloud := Cloud{Name: exampleCloudName, Host: "localhost", Port: strconv.Itoa(port), InvDeployment: ""}
	frontendServer.config = Config{Clouds: []Cloud{cloud}}
	err := frontendServer.updateUsedAddressSpacesMap(defaultNamespace)
	require.Nil(t, err)
	assert.Equal(t, frontendServer.usedAddressSpaces[defaultNamespace][exampleCloudName][0], addressSpaceAddress)

	// Invalid cloud list
	cloud = Cloud{Name: "wrong", Host: "localhost", Port: strconv.Itoa(port), InvDeployment: ""}
	frontendServer.config = Config{Clouds: []Cloud{cloud}}
	err = frontendServer.updateUsedAddressSpacesMap(defaultNamespace)

	require.NotNil(t, err)
}

func TestFindUnusedAddressSpace(t *testing.T) {
	frontendServer := newFrontendServer()
	frontendServer.usedAddressSpaces[defaultNamespace] = make(map[string][]string)

	// No entries in address space map
	address, err := frontendServer.FindUnusedAddressSpace(context.Background(), &invisinetspb.Namespace{Namespace: defaultNamespace})
	require.Nil(t, err)
	assert.Equal(t, address.Address, "10.0.0.0/16")

	// Next entry
	frontendServer.usedAddressSpaces[defaultNamespace][exampleCloudName] = []string{"10.0.0.0/16"}
	address, err = frontendServer.FindUnusedAddressSpace(context.Background(), &invisinetspb.Namespace{Namespace: defaultNamespace})
	require.Nil(t, err)
	assert.Equal(t, address.Address, "10.1.0.0/16")

	// Different Namespace
	address, err = frontendServer.FindUnusedAddressSpace(context.Background(), &invisinetspb.Namespace{Namespace: "other"})
	require.Nil(t, err)
	assert.Equal(t, address.Address, "10.0.0.0/16")

	// Out of addresses
	frontendServer.usedAddressSpaces[defaultNamespace][exampleCloudName] = []string{"10.255.0.0/16"}
	_, err = frontendServer.FindUnusedAddressSpace(context.Background(), &invisinetspb.Namespace{Namespace: defaultNamespace})
	require.NotNil(t, err)
}

func TestGetTag(t *testing.T) {
	frontendServer := newFrontendServer()
	tagServerPort := getNewPortNumber()
	frontendServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	setupTagServer(tagServerPort)

	r := SetUpRouter()
	r.GET("/tags/:tag", frontendServer.getTag)

	// Well-formed request for non-last-level tag
	tag := validParentTagName
	expectedResult := &tagservicepb.TagMapping{TagName: tag, ChildTags: []string{"child"}}

	url := fmt.Sprintf("/tags/%s", tag)
	req, _ := http.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var tagMap *tagservicepb.TagMapping
	err := json.Unmarshal(responseData, &tagMap)

	require.Nil(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedResult, tagMap)

	// Well-formed request for last-level tag
	tag = validLastLevelTagName
	expectedResult = &tagservicepb.TagMapping{TagName: tag, Uri: &tagUri, Ip: &tagIp}

	url = fmt.Sprintf("/tags/%s", tag)
	req, _ = http.NewRequest("GET", url, nil)
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ = io.ReadAll(w.Body)
	var newTagMap *tagservicepb.TagMapping
	err = json.Unmarshal(responseData, &newTagMap)

	require.Nil(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedResult, newTagMap)

	// Request for non-existent tag
	tag = "badtag"

	url = fmt.Sprintf("/tags/%s", tag)
	req, _ = http.NewRequest("GET", url, nil)
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResolveTag(t *testing.T) {
	frontendServer := newFrontendServer()
	tagServerPort := getNewPortNumber()
	frontendServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	setupTagServer(tagServerPort)

	r := SetUpRouter()
	r.GET("/tags/:tag/resolve", frontendServer.resolveTag)

	// Well-formed request
	tag := validTagName
	newUri := "uri/" + tag
	expectedResult := &tagservicepb.TagMapping{TagName: tag, Uri: &newUri, Ip: &resolvedTagIp}

	url := fmt.Sprintf("/tags/%s/resolve", tag)
	req, _ := http.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var nameMaps *tagservicepb.TagMappingList
	err := json.Unmarshal(responseData, &nameMaps)

	require.Nil(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedResult, nameMaps.Mappings[0])

	// Resolve non-existent tag
	tag = "badtag"

	url = fmt.Sprintf("/tags/%s/resolve", tag)
	req, _ = http.NewRequest("GET", url, nil)
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetTag(t *testing.T) {
	frontendServer := newFrontendServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	frontendServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	setupPluginServer(cloudPluginPort)
	setupTagServer(tagServerPort)

	r := SetUpRouter()
	r.POST("/tags/:tag", frontendServer.setTag)

	// Well-formed request
	tagMapping := &tagservicepb.TagMapping{TagName: validTagName, ChildTags: []string{validTagName + "child"}}
	jsonValue, _ := json.Marshal(tagMapping)

	url := fmt.Sprintf("/tags/%s", tagMapping.TagName)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var jsonMap map[string]string
	err := json.Unmarshal(responseData, &jsonMap)

	require.Nil(t, err)
	assert.Equal(t, http.StatusOK, w.Code)

	// Malformed request
	jsonValue, _ = json.Marshal(tagMapping.ChildTags)

	url = fmt.Sprintf("/tags/%s", tagMapping.TagName)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(responseData, &jsonMap)

	require.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteTagMember(t *testing.T) {
	frontendServer := newFrontendServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	frontendServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	setupPluginServer(cloudPluginPort)
	setupTagServer(tagServerPort)

	r := SetUpRouter()
	r.DELETE("/tags/:tag/members", frontendServer.deleteTagMember)

	// Well-formed request
	tagMapping := &tagservicepb.TagMapping{TagName: validTagName, ChildTags: []string{"child"}}
	jsonValue, _ := json.Marshal(tagMapping.ChildTags)

	url := fmt.Sprintf("/tags/%s/members", tagMapping.TagName)
	req, _ := http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var jsonMap map[string]string
	err := json.Unmarshal(responseData, &jsonMap)

	require.Nil(t, err)
	assert.Equal(t, http.StatusOK, w.Code)

	// Non-existent tag
	tagMapping = &tagservicepb.TagMapping{TagName: "badtag", ChildTags: []string{"child"}}
	jsonValue, _ = json.Marshal(tagMapping.ChildTags)

	url = fmt.Sprintf("/tags/%s/members", tagMapping.TagName)
	req, _ = http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Malformed request
	jsonValue, _ = json.Marshal(tagMapping)

	url = fmt.Sprintf("/tags/%s/members", tagMapping.TagName)
	req, _ = http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(responseData, &jsonMap)

	require.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteTag(t *testing.T) {
	frontendServer := newFrontendServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	frontendServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	setupPluginServer(cloudPluginPort)
	setupTagServer(tagServerPort)

	r := SetUpRouter()
	r.DELETE("/tags/:tag/", frontendServer.deleteTag)

	// Well-formed request
	tag := validTagName

	url := fmt.Sprintf("/tags/%s/", tag)
	req, _ := http.NewRequest("DELETE", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var jsonMap map[string]string
	err := json.Unmarshal(responseData, &jsonMap)
	require.Nil(t, err)

	assert.Equal(t, http.StatusOK, w.Code)

	// Delete non-existent tag
	tag = "badtag"

	url = fmt.Sprintf("/tags/%s/", tag)
	req, _ = http.NewRequest("DELETE", url, nil)
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResolvePermitListRules(t *testing.T) {
	// Setup
	frontendServer := newFrontendServer()
	tagServerPort := getNewPortNumber()
	frontendServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	setupTagServer(tagServerPort)

	// Permit list rule that contains tags, IPs, and names
	id := "id"
	rule := &invisinetspb.PermitListRule{
		Id:        "id",
		Tags:      []string{validTagName + "1", validTagName + "2", "2.3.4.5"},
		Targets:   []string{},
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	rulesList := &invisinetspb.PermitList{AssociatedResource: id, Rules: []*invisinetspb.PermitListRule{rule}}
	expectedRule := &invisinetspb.PermitListRule{
		Id:        "id",
		Tags:      []string{validTagName + "1", validTagName + "2", "2.3.4.5"},
		Targets:   []string{resolvedTagIp, resolvedTagIp, "2.3.4.5"},
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	expectedRulesList := &invisinetspb.PermitList{AssociatedResource: id, Rules: []*invisinetspb.PermitListRule{expectedRule}}

	resolvedRules, err := frontendServer.resolvePermitListRules(rulesList, false, exampleCloudName)
	assert.Nil(t, err)
	assert.Equal(t, expectedRulesList, resolvedRules)
}

func TestGetIPsFromResolvedTag(t *testing.T) {
	ip1 := "1.2.3.4"
	ip2 := "2.3.4.5"
	uri1 := "uri/name1"
	uri2 := "uri/name2"
	mappings := []*tagservicepb.TagMapping{
		&tagservicepb.TagMapping{TagName: "name1", Uri: &uri1, Ip: &ip1},
		&tagservicepb.TagMapping{TagName: "name2", Uri: &uri2, Ip: &ip2},
	}
	expectedIps := []string{ip1, ip2}

	ips := getIPsFromResolvedTag(mappings)
	assert.Equal(t, expectedIps, ips)
}

func TestCheckAndCleanRule(t *testing.T) {
	// Rule with correct formatting
	rule := &invisinetspb.PermitListRule{
		Id:        "id",
		Tags:      []string{validTagName + "1", validTagName + "2", "2.3.4.5"},
		Targets:   []string{},
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}

	cleanRule, _, err := checkAndCleanRule(rule)
	assert.Nil(t, err)
	assert.Equal(t, rule, cleanRule)

	// Rule with no tags
	badRule := &invisinetspb.PermitListRule{
		Id:        "id",
		Tags:      []string{},
		Targets:   []string{},
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}

	_, _, err = checkAndCleanRule(badRule)
	assert.NotNil(t, err)

	// Rule with targets
	badRule = &invisinetspb.PermitListRule{
		Id:        "id",
		Tags:      []string{validTagName + "1", validTagName + "2", "2.3.4.5"},
		Targets:   []string{validTagName + "1", validTagName + "2", "2.3.4.5"},
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}

	cleanRule, warning, err := checkAndCleanRule(badRule)
	assert.Nil(t, err)
	assert.NotNil(t, warning)
	assert.Equal(t, []string{}, cleanRule.Targets)
}

func TestIsIpAddrOrCidr(t *testing.T) {
	ip := "1.2.3.4"
	cidr := "2.3.4.5/20"
	nonIp := "tag"
	nonIpWithSlash := "tag/insidetag"

	assert.True(t, isIpAddrOrCidr(ip))
	assert.True(t, isIpAddrOrCidr(cidr))
	assert.False(t, isIpAddrOrCidr(nonIp))
	assert.False(t, isIpAddrOrCidr(nonIpWithSlash))
}

func TestCreateSubscriberName(t *testing.T) {
	origCloudName := "cloudname"
	origUri := "uri"
	subName := createSubscriberName(origCloudName, origUri)
	cloud, uri := parseSubscriberName(subName)

	assert.Equal(t, origCloudName, cloud)
	assert.Equal(t, origUri, uri)
}

func TestDiffTagReferences(t *testing.T) {
	beforePermitList := &invisinetspb.PermitList{
		AssociatedResource: "uri",
		Rules: []*invisinetspb.PermitListRule{
			&invisinetspb.PermitListRule{
				Tags: []string{"tag1", "1.2.3.4"},
			},
			&invisinetspb.PermitListRule{
				Tags: []string{"tag1", "tag2", "tag3"},
			},
		},
	}

	afterPermitList := &invisinetspb.PermitList{
		AssociatedResource: "uri",
		Rules: []*invisinetspb.PermitListRule{
			&invisinetspb.PermitListRule{
				Tags: []string{"tag1", "1.2.3.4"},
			},
			&invisinetspb.PermitListRule{
				Tags: []string{"tag3"},
			},
		},
	}

	tagDiff := diffTagReferences(beforePermitList, afterPermitList)
	expectedDiff := []string{"tag2"}

	assert.Equal(t, expectedDiff, tagDiff)
}

func TestCheckAndUnsubscribe(t *testing.T) {
	// Setup
	frontendServer := newFrontendServer()
	tagServerPort := getNewPortNumber()
	frontendServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	setupTagServer(tagServerPort)

	beforePermitList := &invisinetspb.PermitList{
		AssociatedResource: "uri",
		Rules: []*invisinetspb.PermitListRule{
			&invisinetspb.PermitListRule{
				Tags: []string{validTagName + "1", "1.2.3.4"},
			},
			&invisinetspb.PermitListRule{
				Tags: []string{validTagName + "1", validTagName + "2", validTagName + "2"},
			},
		},
	}

	afterPermitList := &invisinetspb.PermitList{
		AssociatedResource: "uri",
		Rules: []*invisinetspb.PermitListRule{
			&invisinetspb.PermitListRule{
				Tags: []string{validTagName + "1", "1.2.3.4"},
			},
			&invisinetspb.PermitListRule{
				Tags: []string{validTagName + "3"},
			},
		},
	}

	err := frontendServer.checkAndUnsubscribe(beforePermitList, afterPermitList)
	assert.Nil(t, err)
}

func TestClearRuleTargets(t *testing.T) {
	permitList := &invisinetspb.PermitList{
		AssociatedResource: "uri",
		Rules: []*invisinetspb.PermitListRule{
			&invisinetspb.PermitListRule{
				Targets: []string{"1.2.3.4"},
			},
			&invisinetspb.PermitListRule{
				Targets: []string{"1.2.3.4", "2.3.4.5"},
			},
			&invisinetspb.PermitListRule{
				Tags: []string{"1.2.3.4", "2.3.4.5"},
			},
		},
	}

	expectedPermitList := &invisinetspb.PermitList{
		AssociatedResource: "uri",
		Rules: []*invisinetspb.PermitListRule{
			&invisinetspb.PermitListRule{
				Targets: []string{},
			},
			&invisinetspb.PermitListRule{
				Targets: []string{},
			},
			&invisinetspb.PermitListRule{
				Targets: []string{},
				Tags:    []string{"1.2.3.4", "2.3.4.5"},
			},
		},
	}

	clearedRules := clearRuleTargets(permitList)

	assert.ElementsMatch(t, expectedPermitList.Rules, clearedRules.Rules)
}

func TestUpdateSubscribers(t *testing.T) {
	frontendServer := newFrontendServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	frontendServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	setupPluginServer(cloudPluginPort)
	setupTagServer(tagServerPort)

	err := frontendServer.updateSubscribers(validTagName)
	assert.Nil(t, err)
}

func TestGetUsedAddressSpaces(t *testing.T) {
	frontendServer := newFrontendServer()

	gcp_address_spaces := []string{"10.0.0.0/16", "10.1.0.0/16"}
	azure_address_spaces := []string{"10.2.0.0/16", "10.3.0.0/16"}
	frontendServer.usedAddressSpaces = map[string]map[string][]string{
		defaultNamespace: {
			utils.GCP:   {"10.0.0.0/16", "10.1.0.0/16"},
			utils.AZURE: {"10.2.0.0/16", "10.3.0.0/16"},
		},
	}
	addressSpaces, err := frontendServer.GetUsedAddressSpaces(context.Background(), &invisinetspb.Namespace{Namespace: defaultNamespace})
	require.Nil(t, err)
	assert.ElementsMatch(t, addressSpaces.AddressSpaceMappings, []*invisinetspb.AddressSpaceMapping{
		{AddressSpaces: gcp_address_spaces, Cloud: utils.GCP, Namespace: defaultNamespace},
		{AddressSpaces: azure_address_spaces, Cloud: utils.AZURE, Namespace: defaultNamespace},
	})

	// Empty namespace
	addressSpaces, err = frontendServer.GetUsedAddressSpaces(context.Background(), &invisinetspb.Namespace{Namespace: "empty"})
	require.Nil(t, err)
	assert.Equal(t, 0, len(addressSpaces.AddressSpaceMappings))
}

func TestGetNamespace(t *testing.T) {
	frontendServer := newFrontendServer()

	r := SetUpRouter()
	r.GET("/namespace/", frontendServer.getNamespace)

	url := "/namespace/"
	req, _ := http.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var jsonMap map[string]string
	err := json.Unmarshal(responseData, &jsonMap)
	require.Nil(t, err)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, frontendServer.namespace, jsonMap["namespace"])
}

func TestSetNamespace(t *testing.T) {
	frontendServer := newFrontendServer()

	r := SetUpRouter()
	r.POST("/namespace/:namespace", frontendServer.setNamespace)

	newNamespace := "newnamespace"
	url := fmt.Sprintf("/namespace/%s", newNamespace)
	req, _ := http.NewRequest("POST", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, newNamespace, frontendServer.namespace)
}
