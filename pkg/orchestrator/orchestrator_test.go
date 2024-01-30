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
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/orchestrator/config"
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"

	fakeplugin "github.com/NetSys/invisinets/pkg/fake/cloudplugin"
	faketagservice "github.com/NetSys/invisinets/pkg/fake/tagservice"
	utils "github.com/NetSys/invisinets/pkg/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const defaultNamespace = "default"
const exampleCloudName = "example"

var portNum = 10000

func getNewPortNumber() int {
	portNum = portNum + 1
	return portNum
}

func newOrchestratorServer() *ControllerServer {
	s := &ControllerServer{
		pluginAddresses:           make(map[string]string),
		usedBgpPeeringIpAddresses: make(map[string][]string),
		namespace:                 defaultNamespace,
	}
	return s
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
	orchestratorServer := newOrchestratorServer()
	port := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	fakeplugin.SetupFakePluginServer(port)

	r := SetUpRouter()
	r.GET("/cloud/:cloud/permit-list/:id", orchestratorServer.permitListGet)

	// Well-formed request
	id := "123"
	expectedResponse := PermitListGetResponse{
		Id:         id,
		PermitList: &invisinetspb.PermitList{AssociatedResource: id, Rules: []*invisinetspb.PermitListRule{fakeplugin.ExampleRule}},
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
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.POST("/cloud/:cloud/permit-list/rules", orchestratorServer.permitListRulesAdd)

	// Well-formed request
	id := "123"
	tags := []string{faketagservice.ValidTagName}
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
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.DELETE("/cloud/:cloud/permit-list/rules", orchestratorServer.permitListRulesDelete)

	// Well-formed request
	id := "123"
	tags := []string{faketagservice.ValidTagName}
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
	orchestratorServer := newOrchestratorServer()
	port := getNewPortNumber()
	tagServerPort := getNewPortNumber()
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)
	orchestratorServer.usedAddressSpaces = []*invisinetspb.AddressSpaceMapping{
		{
			AddressSpaces: []string{"10.1.0.0/24"},
			Cloud:         exampleCloudName,
			Namespace:     defaultNamespace,
		},
	}

	fakeplugin.SetupFakePluginServer(port)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.POST("/cloud/:cloud/resources/", orchestratorServer.resourceCreate)

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
	orchestratorServer := newOrchestratorServer()
	port := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	fakeplugin.SetupFakePluginServer(port)

	// Well-formed call
	addressSpaceMappings, _ := orchestratorServer.getAddressSpaces(exampleCloudName)
	assert.Len(t, addressSpaceMappings, 1)
	assert.Equal(t, addressSpaceMappings[0].AddressSpaces[0], fakeplugin.AddressSpaceAddress)

	// Bad cloud name
	emptyList, err := orchestratorServer.getAddressSpaces("wrong")
	require.NotNil(t, err)

	require.Nil(t, emptyList)
}

func TestUpdateUsedAddressSpacesMap(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	port := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	fakeplugin.SetupFakePluginServer(port)

	// Valid cloud list
	cloud := config.CloudPlugin{Name: exampleCloudName, Host: "localhost", Port: strconv.Itoa(port)}
	orchestratorServer.config = config.Config{CloudPlugins: []config.CloudPlugin{cloud}}
	err := orchestratorServer.updateUsedAddressSpaces()
	require.Nil(t, err)
	assert.Len(t, orchestratorServer.usedAddressSpaces, 1)
	assert.Equal(t, orchestratorServer.usedAddressSpaces[0].AddressSpaces[0], fakeplugin.AddressSpaceAddress)

	// Invalid cloud list
	cloud = config.CloudPlugin{Name: "wrong", Host: "localhost", Port: strconv.Itoa(port)}
	orchestratorServer.config = config.Config{CloudPlugins: []config.CloudPlugin{cloud}}
	err = orchestratorServer.updateUsedAddressSpaces()

	require.NotNil(t, err)
}

func TestFindUnusedAddressSpace(t *testing.T) {
	orchestratorServer := newOrchestratorServer()

	// No entries in address space map
	address, err := orchestratorServer.FindUnusedAddressSpace(context.Background(), &invisinetspb.Empty{})
	require.Nil(t, err)
	assert.Equal(t, address.Address, "10.0.0.0/16")

	// Next entry
	orchestratorServer.usedAddressSpaces = []*invisinetspb.AddressSpaceMapping{
		{
			AddressSpaces: []string{"10.0.0.0/16"},
			Cloud:         exampleCloudName,
			Namespace:     defaultNamespace,
		},
	}
	address, err = orchestratorServer.FindUnusedAddressSpace(context.Background(), &invisinetspb.Empty{})
	require.Nil(t, err)
	assert.Equal(t, address.Address, "10.1.0.0/16")

	// Account for all namespaces
	orchestratorServer.usedAddressSpaces = []*invisinetspb.AddressSpaceMapping{
		{
			AddressSpaces: []string{"10.0.0.0/16"},
			Cloud:         exampleCloudName,
			Namespace:     defaultNamespace,
		},
		{
			AddressSpaces: []string{"10.1.0.0/16"},
			Cloud:         exampleCloudName,
			Namespace:     "otherNamespace",
		},
	}
	address, err = orchestratorServer.FindUnusedAddressSpace(context.Background(), &invisinetspb.Empty{})
	require.Nil(t, err)
	assert.Equal(t, address.Address, "10.2.0.0/16")

	// Out of addresses
	orchestratorServer.usedAddressSpaces = []*invisinetspb.AddressSpaceMapping{
		{
			AddressSpaces: []string{"10.255.0.0/16"},
			Cloud:         exampleCloudName,
			Namespace:     defaultNamespace,
		},
	}
	_, err = orchestratorServer.FindUnusedAddressSpace(context.Background(), &invisinetspb.Empty{})
	require.NotNil(t, err)
}

func TestGetUsedAsns(t *testing.T) {
	// Setup
	frontendServer := newOrchestratorServer()
	port := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	fakeplugin.SetupFakePluginServer(port)

	// Well-formed call
	resp, err := frontendServer.getUsedAsns(exampleCloudName)
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint32{fakeplugin.Asn}, resp.Asns)

	// Bad cloud name
	_, err = frontendServer.getUsedAsns("wrong")
	require.Error(t, err)
}

func TestUpdateUsedAsns(t *testing.T) {
	frontendServer := newOrchestratorServer()
	port := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	fakeplugin.SetupFakePluginServer(port)

	// Valid cloud list
	cloud := config.CloudPlugin{Name: exampleCloudName, Host: "localhost", Port: strconv.Itoa(port)}
	frontendServer.config = config.Config{CloudPlugins: []config.CloudPlugin{cloud}}
	err := frontendServer.updateUsedAsns()
	require.NoError(t, err)
	require.ElementsMatch(t, []uint32{fakeplugin.Asn}, frontendServer.usedAsns)

	// Invalid cloud list
	cloud = config.CloudPlugin{Name: "wrong", Host: "localhost", Port: strconv.Itoa(port)}
	frontendServer.config = config.Config{CloudPlugins: []config.CloudPlugin{cloud}}
	err = frontendServer.updateUsedAsns()
	require.Error(t, err)
}

func TestFindUnusedAsn(t *testing.T) {
	frontendServer := newOrchestratorServer()
	ctx := context.Background()

	// Typical case
	frontendServer.usedAsns = []uint32{64512}
	asn, err := frontendServer.FindUnusedAsn(ctx, &invisinetspb.Empty{})
	require.NoError(t, err)
	require.Equal(t, uint32(64513), asn.Asn)

	// Gap in usedAsns
	frontendServer.usedAsns = []uint32{64512, 64514}
	asn, err = frontendServer.FindUnusedAsn(ctx, &invisinetspb.Empty{})
	require.NoError(t, err)
	require.Equal(t, uint32(64513), asn.Asn)

	// No entries in asn map
	frontendServer.usedAsns = []uint32{}
	asn, err = frontendServer.FindUnusedAsn(ctx, &invisinetspb.Empty{})
	require.NoError(t, err)
	require.Equal(t, uint32(64512), asn.Asn)

	// 4-bit ASN
	frontendServer.usedAsns = make([]uint32, MAX_PRIVATE_ASN_2BYTE-MIN_PRIVATE_ASN_2BYTE+1)
	for i := MIN_PRIVATE_ASN_2BYTE; i <= MAX_PRIVATE_ASN_2BYTE; i++ {
		frontendServer.usedAsns[i-MIN_PRIVATE_ASN_2BYTE] = i
	}
	asn, err = frontendServer.FindUnusedAsn(ctx, &invisinetspb.Empty{})
	require.NoError(t, err)
	require.Equal(t, uint32(4200000000), asn.Asn)
}

func TestGetUsedBgpPeeringIpAddresses(t *testing.T) {
	// Setup
	frontendServer := newOrchestratorServer()
	port := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	fakeplugin.SetupFakePluginServer(port)

	// Well-formed call
	resp, err := frontendServer.getUsedBgpPeeringIpAddresses(exampleCloudName)
	require.NoError(t, err)
	assert.ElementsMatch(t, fakeplugin.BgpPeeringIpAddresses, resp.IpAddresses)

	// Bad cloud name
	_, err = frontendServer.getUsedBgpPeeringIpAddresses("wrong")
	require.Error(t, err)
}

func TestUpdateUsedBgpPeeringIpAddresses(t *testing.T) {
	frontendServer := newOrchestratorServer()
	port := getNewPortNumber()
	frontendServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	fakeplugin.SetupFakePluginServer(port)

	// Valid cloud list
	cloud := config.CloudPlugin{Name: exampleCloudName, Host: "localhost", Port: strconv.Itoa(port)}
	frontendServer.config = config.Config{CloudPlugins: []config.CloudPlugin{cloud}}
	err := frontendServer.updateUsedBgpPeeringIpAddresses(defaultNamespace)
	require.NoError(t, err)
	require.ElementsMatch(t, fakeplugin.BgpPeeringIpAddresses, frontendServer.usedBgpPeeringIpAddresses[exampleCloudName])

	// Invalid cloud list
	cloud = config.CloudPlugin{Name: "wrong", Host: "localhost", Port: strconv.Itoa(port)}
	frontendServer.config = config.Config{CloudPlugins: []config.CloudPlugin{cloud}}
	err = frontendServer.updateUsedBgpPeeringIpAddresses(defaultNamespace)
	require.Error(t, err)
}

func TestFindUnusedBgpPeeringSubnets(t *testing.T) {
	frontendServer := newOrchestratorServer()
	ctx := context.Background()

	// Typical case between Azure and GCP
	frontendServer.usedBgpPeeringIpAddresses[utils.AZURE] = []string{"169.254.21.1", "169.254.21.5"}
	frontendServer.usedBgpPeeringIpAddresses[utils.GCP] = []string{"169.254.21.2", "169.254.21.6"}
	subnets, err := frontendServer.findUnusedBgpPeeringIpAddresses(ctx, utils.AZURE, utils.GCP, defaultNamespace)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"169.254.21.9", "169.254.21.10", "169.254.21.13", "169.254.21.14"}, subnets)

	// Gap in usedBgpPeeringIpAddresses
	frontendServer.usedBgpPeeringIpAddresses[utils.AZURE] = []string{"169.254.21.1", "169.254.22.1"}
	frontendServer.usedBgpPeeringIpAddresses[utils.GCP] = []string{"169.254.21.2", "169.254.22.2"}
	subnets, err = frontendServer.findUnusedBgpPeeringIpAddresses(ctx, utils.AZURE, utils.GCP, defaultNamespace)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"169.254.21.5", "169.254.21.6", "169.254.21.9", "169.254.21.10"}, subnets)

	// No entries in bgp peering map
	frontendServer.usedBgpPeeringIpAddresses[utils.AZURE] = []string{}
	frontendServer.usedBgpPeeringIpAddresses[utils.GCP] = []string{}
	subnets, err = frontendServer.findUnusedBgpPeeringIpAddresses(ctx, utils.AZURE, utils.GCP, defaultNamespace)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"169.254.21.1", "169.254.21.2", "169.254.21.5", "169.254.21.6"}, subnets)

	// Different spaces
	frontendServer.usedBgpPeeringIpAddresses[utils.AZURE] = []string{"169.254.21.1", "169.254.21.9"}
	frontendServer.usedBgpPeeringIpAddresses[utils.GCP] = []string{"169.254.21.2", "169.254.21.5"}
	subnets, err = frontendServer.findUnusedBgpPeeringIpAddresses(ctx, utils.AZURE, utils.GCP, defaultNamespace)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"169.254.21.13", "169.254.21.14", "169.254.21.17", "169.254.21.18"}, subnets)
}

func TestGetTag(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.GET("/tags/:tag", orchestratorServer.getTag)

	// Well-formed request for non-last-level tag
	tag := faketagservice.ValidParentTagName
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
	tag = faketagservice.ValidLastLevelTagName
	expectedResult = &tagservicepb.TagMapping{TagName: tag, Uri: &faketagservice.TagUri, Ip: &faketagservice.TagIp}

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
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.GET("/tags/:tag/resolve", orchestratorServer.resolveTag)

	// Well-formed request
	tag := faketagservice.ValidTagName
	newUri := "uri/" + tag
	expectedResult := &tagservicepb.TagMapping{TagName: tag, Uri: &newUri, Ip: &faketagservice.ResolvedTagIp}

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
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)
	faketagservice.SubscriberCloudName = exampleCloudName

	r := SetUpRouter()
	r.POST("/tags/:tag", orchestratorServer.setTag)

	// Well-formed request
	tagMapping := &tagservicepb.TagMapping{TagName: faketagservice.ValidTagName, ChildTags: []string{faketagservice.ValidTagName + "child"}}
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
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)
	faketagservice.SubscriberCloudName = exampleCloudName

	r := SetUpRouter()
	r.DELETE("/tags/:tag/members", orchestratorServer.deleteTagMember)

	// Well-formed request
	tagMapping := &tagservicepb.TagMapping{TagName: faketagservice.ValidTagName, ChildTags: []string{"child"}}
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
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)
	faketagservice.SubscriberCloudName = exampleCloudName

	r := SetUpRouter()
	r.DELETE("/tags/:tag/", orchestratorServer.deleteTag)

	// Well-formed request
	tag := faketagservice.ValidTagName

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
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	faketagservice.SetupFakeTagServer(tagServerPort)

	// Permit list rule that contains tags, IPs, and names
	id := "id"
	rule := &invisinetspb.PermitListRule{
		Id:        "id",
		Tags:      []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", "2.3.4.5"},
		Targets:   []string{},
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	rulesList := &invisinetspb.PermitList{AssociatedResource: id, Rules: []*invisinetspb.PermitListRule{rule}}
	expectedRule := &invisinetspb.PermitListRule{
		Id:        "id",
		Tags:      []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", "2.3.4.5"},
		Targets:   []string{faketagservice.ResolvedTagIp, faketagservice.ResolvedTagIp, "2.3.4.5"},
		Direction: invisinetspb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	expectedRulesList := &invisinetspb.PermitList{AssociatedResource: id, Rules: []*invisinetspb.PermitListRule{expectedRule}}

	resolvedRules, err := orchestratorServer.resolvePermitListRules(rulesList, false, exampleCloudName)
	assert.Nil(t, err)
	assert.Equal(t, expectedRulesList, resolvedRules)
}

func TestGetIPsFromResolvedTag(t *testing.T) {
	ip1 := "1.2.3.4"
	ip2 := "2.3.4.5"
	uri1 := "uri/name1"
	uri2 := "uri/name2"
	mappings := []*tagservicepb.TagMapping{
		{TagName: "name1", Uri: &uri1, Ip: &ip1},
		{TagName: "name2", Uri: &uri2, Ip: &ip2},
	}
	expectedIps := []string{ip1, ip2}

	ips := getIPsFromResolvedTag(mappings)
	assert.Equal(t, expectedIps, ips)
}

func TestCheckAndCleanRule(t *testing.T) {
	// Rule with correct formatting
	rule := &invisinetspb.PermitListRule{
		Id:        "id",
		Tags:      []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", "2.3.4.5"},
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
		Tags:      []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", "2.3.4.5"},
		Targets:   []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", "2.3.4.5"},
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
			{Tags: []string{"tag1", "1.2.3.4"}},
			{Tags: []string{"tag1", "tag2", "tag3"}},
		},
	}

	afterPermitList := &invisinetspb.PermitList{
		AssociatedResource: "uri",
		Rules: []*invisinetspb.PermitListRule{
			{Tags: []string{"tag1", "1.2.3.4"}},
			{Tags: []string{"tag3"}},
		},
	}

	tagDiff := diffTagReferences(beforePermitList, afterPermitList)
	expectedDiff := []string{"tag2"}

	assert.Equal(t, expectedDiff, tagDiff)
}

func TestCheckAndUnsubscribe(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	faketagservice.SetupFakeTagServer(tagServerPort)

	beforePermitList := &invisinetspb.PermitList{
		AssociatedResource: "uri",
		Rules: []*invisinetspb.PermitListRule{
			{Tags: []string{faketagservice.ValidTagName + "1", "1.2.3.4"}},
			{Tags: []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", faketagservice.ValidTagName + "2"}},
		},
	}

	afterPermitList := &invisinetspb.PermitList{
		AssociatedResource: "uri",
		Rules: []*invisinetspb.PermitListRule{
			{Tags: []string{faketagservice.ValidTagName + "1", "1.2.3.4"}},
			{Tags: []string{faketagservice.ValidTagName + "3"}},
		},
	}

	err := orchestratorServer.checkAndUnsubscribe(beforePermitList, afterPermitList)
	assert.Nil(t, err)
}

func TestClearRuleTargets(t *testing.T) {
	permitList := &invisinetspb.PermitList{
		AssociatedResource: "uri",
		Rules: []*invisinetspb.PermitListRule{
			{Targets: []string{"1.2.3.4"}},
			{Targets: []string{"1.2.3.4", "2.3.4.5"}},
			{Tags: []string{"1.2.3.4", "2.3.4.5"}},
		},
	}

	expectedPermitList := &invisinetspb.PermitList{
		AssociatedResource: "uri",
		Rules: []*invisinetspb.PermitListRule{
			{Targets: []string{}},
			{Targets: []string{}},
			{Targets: []string{}, Tags: []string{"1.2.3.4", "2.3.4.5"}},
		},
	}

	clearedRules := clearRuleTargets(permitList)

	assert.ElementsMatch(t, expectedPermitList.Rules, clearedRules.Rules)
}

func TestUpdateSubscribers(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)
	faketagservice.SubscriberCloudName = exampleCloudName

	err := orchestratorServer.updateSubscribers(faketagservice.ValidTagName)
	assert.Nil(t, err)
}

func TestGetUsedAddressSpaces(t *testing.T) {
	orchestratorServer := newOrchestratorServer()

	gcp_address_spaces := []string{"10.0.0.0/16", "10.1.0.0/16"}
	azure_address_spaces := []string{"10.2.0.0/16", "10.3.0.0/16"}
	orchestratorServer.usedAddressSpaces = []*invisinetspb.AddressSpaceMapping{
		{
			AddressSpaces: gcp_address_spaces,
			Cloud:         utils.GCP,
			Namespace:     defaultNamespace,
		},
		{
			AddressSpaces: azure_address_spaces,
			Cloud:         utils.AZURE,
			Namespace:     "otherNamespace",
		},
	}
	addressSpaces, err := orchestratorServer.GetUsedAddressSpaces(context.Background(), &invisinetspb.Empty{})
	require.Nil(t, err)
	assert.ElementsMatch(t, addressSpaces.AddressSpaceMappings, []*invisinetspb.AddressSpaceMapping{
		{AddressSpaces: gcp_address_spaces, Cloud: utils.GCP, Namespace: defaultNamespace},
		{AddressSpaces: azure_address_spaces, Cloud: utils.AZURE, Namespace: "otherNamespace"},
	})
}

func TestGetNamespace(t *testing.T) {
	orchestratorServer := newOrchestratorServer()

	r := SetUpRouter()
	r.GET("/namespace/", orchestratorServer.getNamespace)

	url := "/namespace/"
	req, _ := http.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var jsonMap map[string]string
	err := json.Unmarshal(responseData, &jsonMap)
	require.Nil(t, err)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, orchestratorServer.namespace, jsonMap["namespace"])
}

func TestSetNamespace(t *testing.T) {
	orchestratorServer := newOrchestratorServer()

	r := SetUpRouter()
	r.POST("/namespace/:namespace", orchestratorServer.setNamespace)

	newNamespace := "newnamespace"
	url := fmt.Sprintf("/namespace/%s", newNamespace)
	req, _ := http.NewRequest("POST", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, newNamespace, orchestratorServer.namespace)
}
