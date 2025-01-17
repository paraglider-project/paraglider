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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	config "github.com/paraglider-project/paraglider/pkg/orchestrator/config"
	paragliderpb "github.com/paraglider-project/paraglider/pkg/paragliderpb"
	tagservicepb "github.com/paraglider-project/paraglider/pkg/tag_service/tagservicepb"

	fakeplugin "github.com/paraglider-project/paraglider/pkg/fake/cloudplugin"
	fakekvstore "github.com/paraglider-project/paraglider/pkg/fake/kvstore"
	faketagservice "github.com/paraglider-project/paraglider/pkg/fake/tagservice"
	utils "github.com/paraglider-project/paraglider/pkg/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const defaultNamespace = "default"
const exampleCloudName = "example"

var portNum = 10000

var exampleRule = &paragliderpb.PermitListRule{Name: "example-rule", Tags: []string{faketagservice.ValidTagName, "1.2.3.4"}, SrcPort: 1, DstPort: 1, Protocol: 1, Direction: paragliderpb.Direction_INBOUND}

func getNewPortNumber() int {
	portNum = portNum + 1
	return portNum
}

func newOrchestratorServer() *ControllerServer {
	s := &ControllerServer{
		pluginAddresses:           make(map[string]string),
		usedBgpPeeringIpAddresses: make(map[string][]string),
		namespace:                 defaultNamespace,
		config: config.Config{AddressSpace: []string{defaultAddressSpace},
			FeatureFlags: config.Flags{OrchestratorFlags: config.OrchestratorFlags{AttachResourceEnabled: false}},
		},
	}
	return s
}

func SetUpRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	gin.DefaultWriter = io.Discard
	router := gin.New()
	return router
}

func TestPermitListGet(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.GET(GetPermitListRulesURL, orchestratorServer.permitListGet)

	// Well-formed request
	name := faketagservice.ValidLastLevelTagName
	expectedResponse := []*paragliderpb.PermitListRule{exampleRule}

	url := fmt.Sprintf(GetFormatterString(GetPermitListRulesURL), defaultNamespace, exampleCloudName, name)
	req, _ := http.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var permitList []*paragliderpb.PermitListRule
	err := json.Unmarshal(responseData, &permitList)
	require.Nil(t, err)
	assert.Equal(t, expectedResponse[0].Tags, permitList[0].Tags)
	assert.Equal(t, http.StatusOK, w.Code)

	// Bad cloud name
	url = fmt.Sprintf(GetFormatterString(GetPermitListRulesURL), defaultNamespace, "wrong", name)
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
	r.POST(AddPermitListRulesURL, orchestratorServer.permitListRulesBulkAdd)

	// Well-formed request
	name := faketagservice.ValidLastLevelTagName
	tags := []string{faketagservice.ValidTagName}
	rule := &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      tags,
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	rulesList := []*paragliderpb.PermitListRule{rule}
	jsonValue, _ := json.Marshal(rulesList)

	url := fmt.Sprintf(GetFormatterString(AddPermitListRulesURL), defaultNamespace, exampleCloudName, name)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Invalid resource name
	badName := "badname"
	jsonValue, _ = json.Marshal(rulesList)

	url = fmt.Sprintf(GetFormatterString(AddPermitListRulesURL), defaultNamespace, exampleCloudName, badName)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Invalid tag name (cannot be resolved)
	tags = []string{"tag"}
	rule = &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      tags,
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	rulesList = []*paragliderpb.PermitListRule{rule}
	jsonValue, _ = json.Marshal(rulesList)

	url = fmt.Sprintf(GetFormatterString(AddPermitListRulesURL), defaultNamespace, exampleCloudName, name)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Bad cloud name
	url = fmt.Sprintf(GetFormatterString(AddPermitListRulesURL), defaultNamespace, "wrong", name)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf(GetFormatterString(AddPermitListRulesURL), defaultNamespace, exampleCloudName, name)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermitListRulePut(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.PUT(PermitListRulePUTURL, orchestratorServer.permitListRuleAdd)

	// Well-formed request
	name := faketagservice.ValidLastLevelTagName
	tags := []string{faketagservice.ValidTagName}
	rule := &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      tags,
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	jsonValue, _ := json.Marshal(rule)

	url := fmt.Sprintf(GetFormatterString(PermitListRulePUTURL), defaultNamespace, exampleCloudName, name, rule.Name)
	req, _ := http.NewRequest("PUT", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Invalid resource name
	badName := "badname"

	url = fmt.Sprintf(GetFormatterString(PermitListRulePUTURL), defaultNamespace, exampleCloudName, badName, rule.Name)
	req, _ = http.NewRequest("PUT", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Invalid tag name (cannot be resolved)
	tags = []string{"tag"}
	rule = &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      tags,
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	jsonValue, _ = json.Marshal(rule)

	url = fmt.Sprintf(GetFormatterString(PermitListRulePUTURL), defaultNamespace, exampleCloudName, name, rule.Name)
	req, _ = http.NewRequest("PUT", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Bad cloud name
	url = fmt.Sprintf(GetFormatterString(PermitListRulePUTURL), defaultNamespace, "wrong", name, rule.Name)
	req, _ = http.NewRequest("PUT", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf(GetFormatterString(PermitListRulePUTURL), defaultNamespace, exampleCloudName, name, rule.Name)
	req, _ = http.NewRequest("PUT", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermitListRulePost(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.POST(PermitListRulePOSTURL, orchestratorServer.permitListRuleAdd)

	// Well-formed request
	name := faketagservice.ValidLastLevelTagName
	tags := []string{faketagservice.ValidTagName}
	rule := &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      tags,
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	jsonValue, _ := json.Marshal(rule)

	url := fmt.Sprintf(GetFormatterString(PermitListRulePOSTURL), defaultNamespace, exampleCloudName, name)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Invalid resource name
	badName := "badname"
	jsonValue, _ = json.Marshal(rule)

	url = fmt.Sprintf(GetFormatterString(PermitListRulePOSTURL), defaultNamespace, exampleCloudName, badName)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Invalid tag name (cannot be resolved)
	tags = []string{"tag"}
	rule = &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      tags,
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	jsonValue, _ = json.Marshal(rule)

	url = fmt.Sprintf(GetFormatterString(PermitListRulePOSTURL), defaultNamespace, exampleCloudName, name)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Bad cloud name
	url = fmt.Sprintf(GetFormatterString(PermitListRulePOSTURL), defaultNamespace, "wrong", name)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf(GetFormatterString(PermitListRulePOSTURL), defaultNamespace, exampleCloudName, name)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermitListRuleTagAdd(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.POST(RuleOnTagURL, orchestratorServer.permitListRuleAddTag)

	// Well-formed request
	tags := []string{"1.1.1.1"}
	rule := &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      tags,
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	jsonValue, _ := json.Marshal(rule)

	url := fmt.Sprintf(GetFormatterString(RuleOnTagURL), defaultNamespace+"."+exampleCloudName+"."+faketagservice.ValidTagName)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Bad tag name
	url = fmt.Sprintf(GetFormatterString(RuleOnTagURL), "badtag")
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermitListRuleTagDelete(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.DELETE(RuleOnTagURL, orchestratorServer.permitListRuleDeleteTag)

	// Well-formed request
	rules := []string{"ruleName"}
	jsonValue, _ := json.Marshal(rules)

	url := fmt.Sprintf(GetFormatterString(RuleOnTagURL), defaultNamespace+"."+exampleCloudName+"."+faketagservice.ValidTagName)
	req, _ := http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Bad tag name
	url = fmt.Sprintf(GetFormatterString(RuleOnTagURL), "badtag")
	req, _ = http.NewRequest("DELETE", url, bytes.NewBuffer(jsonValue))
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
	r.POST(DeletePermitListRulesURL, orchestratorServer.permitListRulesDelete)

	// Well-formed request
	name := faketagservice.ValidLastLevelTagName
	rulesList := []string{"ruleName"}

	jsonValue, _ := json.Marshal(rulesList)

	url := fmt.Sprintf(GetFormatterString(DeletePermitListRulesURL), defaultNamespace, exampleCloudName, name)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Invalid resource name
	badName := "badname"
	jsonValue, _ = json.Marshal(rulesList)

	url = fmt.Sprintf(GetFormatterString(DeletePermitListRulesURL), defaultNamespace, exampleCloudName, badName)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Bad cloud name
	url = fmt.Sprintf(GetFormatterString(DeletePermitListRulesURL), defaultNamespace, "wrong", name)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf(GetFormatterString(DeletePermitListRulesURL), defaultNamespace, exampleCloudName, name)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPermitListRuleDelete(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	cloudPluginPort := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", cloudPluginPort)
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	fakeplugin.SetupFakePluginServer(cloudPluginPort)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.DELETE(PermitListRulePUTURL, orchestratorServer.permitListRuleDelete)

	// Well-formed request
	name := faketagservice.ValidLastLevelTagName
	ruleName := "rulename"

	url := fmt.Sprintf(GetFormatterString(PermitListRulePUTURL), defaultNamespace, exampleCloudName, name, ruleName)
	req, _ := http.NewRequest("DELETE", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Invalid resource name
	badName := "badname"

	url = fmt.Sprintf(GetFormatterString(PermitListRulePUTURL), defaultNamespace, exampleCloudName, badName, ruleName)
	req, _ = http.NewRequest("DELETE", url, nil)
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Bad cloud name
	url = fmt.Sprintf(GetFormatterString(PermitListRulePUTURL), defaultNamespace, "wrong", name, ruleName)
	req, _ = http.NewRequest("DELETE", url, nil)
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateResourcePost(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	port := getNewPortNumber()
	tagServerPort := getNewPortNumber()
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)
	orchestratorServer.usedAddressSpaces = []*paragliderpb.AddressSpaceMapping{
		{
			AddressSpaces: []string{"10.1.0.0/24"},
			Cloud:         exampleCloudName,
			Namespace:     defaultNamespace,
		},
	}

	fakeplugin.SetupFakePluginServer(port)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.POST(CreateOrAttachResourcePOSTURL, orchestratorServer.handleCreateOrAttachResource)

	// Well-formed request
	name := "resource-name"
	resource := &paragliderpb.ResourceDescriptionString{
		Name:        name,
		Description: "description",
	}
	jsonValue, _ := json.Marshal(resource)

	url := fmt.Sprintf(GetFormatterString(CreateOrAttachResourcePOSTURL), defaultNamespace, exampleCloudName)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Bad cloud name
	url = fmt.Sprintf(GetFormatterString(CreateOrAttachResourcePOSTURL), defaultNamespace, "wrong")
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf(GetFormatterString(CreateOrAttachResourcePOSTURL), defaultNamespace, exampleCloudName)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateResourcePut(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	port := getNewPortNumber()
	tagServerPort := getNewPortNumber()
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)
	orchestratorServer.usedAddressSpaces = []*paragliderpb.AddressSpaceMapping{
		{
			AddressSpaces: []string{"10.0.0.0/16"},
			Cloud:         exampleCloudName,
			Namespace:     defaultNamespace,
		},
	}

	fakeplugin.SetupFakePluginServer(port)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.POST(CreateResourcePUTURL, orchestratorServer.handleCreateOrAttachResource)

	// Well-formed request
	name := "resource-name"
	resource := &paragliderpb.ResourceDescriptionString{
		Description: "description",
	}
	jsonValue, _ := json.Marshal(resource)

	url := fmt.Sprintf(GetFormatterString(CreateResourcePUTURL), defaultNamespace, exampleCloudName, name)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Bad cloud name
	url = fmt.Sprintf(GetFormatterString(CreateResourcePUTURL), defaultNamespace, "wrong", name)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	badRequest := "{\"test\": 1}"
	jsonValue, _ = json.Marshal(&badRequest)

	url = fmt.Sprintf(GetFormatterString(CreateResourcePUTURL), defaultNamespace, exampleCloudName, name)
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAttachResourcePost(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	port := getNewPortNumber()
	tagServerPort := getNewPortNumber()
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)
	orchestratorServer.usedAddressSpaces = []*paragliderpb.AddressSpaceMapping{
		{
			AddressSpaces: []string{"10.1.0.0/24"},
			Cloud:         exampleCloudName,
			Namespace:     defaultNamespace,
		},
	}
	orchestratorServer.config.FeatureFlags.OrchestratorFlags.AttachResourceEnabled = true

	fakeplugin.SetupFakePluginServer(port)
	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.POST(CreateOrAttachResourcePOSTURL, orchestratorServer.handleCreateOrAttachResource)

	// Invalid request body
	resource := &ResourceID{Id: ""}
	jsonValue, _ := json.Marshal(resource)

	url := fmt.Sprintf(GetFormatterString(CreateOrAttachResourcePOSTURL), defaultNamespace, exampleCloudName)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Well-formed request
	resource = &ResourceID{Id: "id"}
	jsonValue, _ = json.Marshal(resource)

	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Bad cloud name
	url = fmt.Sprintf(GetFormatterString(CreateOrAttachResourcePOSTURL), defaultNamespace, "wrong")
	req, _ = http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Feature disabled
	orchestratorServer.config.FeatureFlags.OrchestratorFlags.AttachResourceEnabled = false

	url = fmt.Sprintf(GetFormatterString(CreateOrAttachResourcePOSTURL), defaultNamespace, exampleCloudName)
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

func TestFindUnusedAddressSpaces(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	// No entries in address space map
	resp, err := orchestratorServer.FindUnusedAddressSpaces(context.Background(), &paragliderpb.FindUnusedAddressSpacesRequest{})
	require.Nil(t, err)
	assert.Equal(t, resp.AddressSpaces[0], "10.0.0.0/16")

	// Next entry
	orchestratorServer.usedAddressSpaces = []*paragliderpb.AddressSpaceMapping{
		{
			AddressSpaces: []string{"10.0.0.0/16"},
			Cloud:         exampleCloudName,
			Namespace:     defaultNamespace,
		},
	}
	resp, err = orchestratorServer.FindUnusedAddressSpaces(context.Background(), &paragliderpb.FindUnusedAddressSpacesRequest{})
	require.Nil(t, err)
	assert.Equal(t, resp.AddressSpaces[0], "10.1.0.0/16")

	// Account for all namespaces
	orchestratorServer.usedAddressSpaces = []*paragliderpb.AddressSpaceMapping{
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
	resp, err = orchestratorServer.FindUnusedAddressSpaces(context.Background(), &paragliderpb.FindUnusedAddressSpacesRequest{})
	require.Nil(t, err)
	assert.Equal(t, resp.AddressSpaces[0], "10.2.0.0/16")

	// Multiple spaces
	orchestratorServer.usedAddressSpaces = []*paragliderpb.AddressSpaceMapping{}
	resp, err = orchestratorServer.FindUnusedAddressSpaces(context.Background(), &paragliderpb.FindUnusedAddressSpacesRequest{Sizes: []int32{200, 1000, 4}})
	require.Nil(t, err)
	assert.Equal(t, resp.AddressSpaces[0], "10.0.0.0/24")
	assert.Equal(t, resp.AddressSpaces[1], "10.1.0.0/22")
	assert.Equal(t, resp.AddressSpaces[2], "10.1.4.0/30")

	// Out of addresses
	orchestratorServer.usedAddressSpaces = []*paragliderpb.AddressSpaceMapping{
		{
			AddressSpaces: []string{"10.0.0.0/10", "10.64.0.0/10", "10.128.0.0/10", "10.192.0.0/10"},
			Cloud:         exampleCloudName,
			Namespace:     defaultNamespace,
		},
	}
	_, err = orchestratorServer.FindUnusedAddressSpaces(context.Background(), &paragliderpb.FindUnusedAddressSpacesRequest{})
	require.NotNil(t, err)
}

func TestGetUsedAsns(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	port := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	fakeplugin.SetupFakePluginServer(port)

	// Well-formed call
	resp, err := orchestratorServer.getUsedAsns(exampleCloudName)
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint32{fakeplugin.Asn}, resp.Asns)

	// Bad cloud name
	_, err = orchestratorServer.getUsedAsns("wrong")
	require.Error(t, err)
}

func TestUpdateUsedAsns(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	port := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	fakeplugin.SetupFakePluginServer(port)

	// Valid cloud list
	cloud := config.CloudPlugin{Name: exampleCloudName, Host: "localhost", Port: strconv.Itoa(port)}
	orchestratorServer.config = config.Config{CloudPlugins: []config.CloudPlugin{cloud}}
	err := orchestratorServer.updateUsedAsns()
	require.NoError(t, err)
	require.ElementsMatch(t, []uint32{fakeplugin.Asn}, orchestratorServer.usedAsns)

	// Invalid cloud list
	cloud = config.CloudPlugin{Name: "wrong", Host: "localhost", Port: strconv.Itoa(port)}
	orchestratorServer.config = config.Config{CloudPlugins: []config.CloudPlugin{cloud}}
	err = orchestratorServer.updateUsedAsns()
	require.Error(t, err)
}

func TestFindUnusedAsn(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	ctx := context.Background()

	// Typical case
	orchestratorServer.usedAsns = []uint32{64512}
	asn, err := orchestratorServer.FindUnusedAsn(ctx, &paragliderpb.FindUnusedAsnRequest{})
	require.NoError(t, err)
	require.Equal(t, uint32(64513), asn.Asn)

	// Gap in usedAsns
	orchestratorServer.usedAsns = []uint32{64512, 64514}
	asn, err = orchestratorServer.FindUnusedAsn(ctx, &paragliderpb.FindUnusedAsnRequest{})
	require.NoError(t, err)
	require.Equal(t, uint32(64513), asn.Asn)

	// No entries in asn map
	orchestratorServer.usedAsns = []uint32{}
	asn, err = orchestratorServer.FindUnusedAsn(ctx, &paragliderpb.FindUnusedAsnRequest{})
	require.NoError(t, err)
	require.Equal(t, uint32(64512), asn.Asn)

	// 4-bit ASN
	orchestratorServer.usedAsns = make([]uint32, MAX_PRIVATE_ASN_2BYTE-MIN_PRIVATE_ASN_2BYTE+1)
	for i := MIN_PRIVATE_ASN_2BYTE; i <= MAX_PRIVATE_ASN_2BYTE; i++ {
		orchestratorServer.usedAsns[i-MIN_PRIVATE_ASN_2BYTE] = i
	}
	asn, err = orchestratorServer.FindUnusedAsn(ctx, &paragliderpb.FindUnusedAsnRequest{})
	require.NoError(t, err)
	require.Equal(t, uint32(4200000000), asn.Asn)
}

func TestGetUsedBgpPeeringIpAddresses(t *testing.T) {
	// Setup
	orchestratorServer := newOrchestratorServer()
	port := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	fakeplugin.SetupFakePluginServer(port)

	// Well-formed call
	resp, err := orchestratorServer.getUsedBgpPeeringIpAddresses(exampleCloudName)
	require.NoError(t, err)
	assert.ElementsMatch(t, fakeplugin.BgpPeeringIpAddresses, resp.IpAddresses)

	// Bad cloud name
	_, err = orchestratorServer.getUsedBgpPeeringIpAddresses("wrong")
	require.Error(t, err)
}

func TestUpdateUsedBgpPeeringIpAddresses(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	port := getNewPortNumber()
	orchestratorServer.pluginAddresses[exampleCloudName] = fmt.Sprintf("localhost:%d", port)

	fakeplugin.SetupFakePluginServer(port)

	// Valid cloud list
	cloud := config.CloudPlugin{Name: exampleCloudName, Host: "localhost", Port: strconv.Itoa(port)}
	orchestratorServer.config = config.Config{CloudPlugins: []config.CloudPlugin{cloud}}
	err := orchestratorServer.updateUsedBgpPeeringIpAddresses(defaultNamespace)
	require.NoError(t, err)
	require.ElementsMatch(t, fakeplugin.BgpPeeringIpAddresses, orchestratorServer.usedBgpPeeringIpAddresses[exampleCloudName])

	// Invalid cloud list
	cloud = config.CloudPlugin{Name: "wrong", Host: "localhost", Port: strconv.Itoa(port)}
	orchestratorServer.config = config.Config{CloudPlugins: []config.CloudPlugin{cloud}}
	err = orchestratorServer.updateUsedBgpPeeringIpAddresses(defaultNamespace)
	require.Error(t, err)
}

func TestFindUnusedBgpPeeringSubnets(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	ctx := context.Background()

	// Typical case between Azure and GCP
	orchestratorServer.usedBgpPeeringIpAddresses[utils.AZURE] = []string{"169.254.21.1", "169.254.21.5"}
	orchestratorServer.usedBgpPeeringIpAddresses[utils.GCP] = []string{"169.254.21.2", "169.254.21.6"}
	subnets, err := orchestratorServer.findUnusedBgpPeeringIpAddresses(ctx, utils.AZURE, utils.GCP, defaultNamespace)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"169.254.21.9", "169.254.21.10", "169.254.21.13", "169.254.21.14"}, subnets)

	// Gap in usedBgpPeeringIpAddresses
	orchestratorServer.usedBgpPeeringIpAddresses[utils.AZURE] = []string{"169.254.21.1", "169.254.22.1"}
	orchestratorServer.usedBgpPeeringIpAddresses[utils.GCP] = []string{"169.254.21.2", "169.254.22.2"}
	subnets, err = orchestratorServer.findUnusedBgpPeeringIpAddresses(ctx, utils.AZURE, utils.GCP, defaultNamespace)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"169.254.21.5", "169.254.21.6", "169.254.21.9", "169.254.21.10"}, subnets)

	// No entries in bgp peering map
	orchestratorServer.usedBgpPeeringIpAddresses[utils.AZURE] = []string{}
	orchestratorServer.usedBgpPeeringIpAddresses[utils.GCP] = []string{}
	subnets, err = orchestratorServer.findUnusedBgpPeeringIpAddresses(ctx, utils.AZURE, utils.GCP, defaultNamespace)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"169.254.21.1", "169.254.21.2", "169.254.21.5", "169.254.21.6"}, subnets)

	// Different spaces
	orchestratorServer.usedBgpPeeringIpAddresses[utils.AZURE] = []string{"169.254.21.1", "169.254.21.9"}
	orchestratorServer.usedBgpPeeringIpAddresses[utils.GCP] = []string{"169.254.21.2", "169.254.21.5"}
	subnets, err = orchestratorServer.findUnusedBgpPeeringIpAddresses(ctx, utils.AZURE, utils.GCP, defaultNamespace)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"169.254.21.13", "169.254.21.14", "169.254.21.17", "169.254.21.18"}, subnets)
}

func TestGetTag(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	faketagservice.SetupFakeTagServer(tagServerPort)

	r := SetUpRouter()
	r.GET(GetTagURL, orchestratorServer.getTag)

	// Well-formed request for non-last-level tag
	tag := faketagservice.ValidParentTagName
	expectedResult := &tagservicepb.TagMapping{Name: tag, ChildTags: []string{"child"}}

	url := fmt.Sprintf(GetFormatterString(GetTagURL), tag)
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
	expectedResult = &tagservicepb.TagMapping{Name: tag, Uri: &faketagservice.TagUri, Ip: &faketagservice.TagIp}

	url = fmt.Sprintf(GetFormatterString(GetTagURL), tag)
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

	url = fmt.Sprintf(GetFormatterString(GetTagURL), tag)
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
	r.GET(ResolveTagURL, orchestratorServer.resolveTag)

	// Well-formed request
	tag := faketagservice.ValidTagName
	newUri := "uri/" + tag
	expectedResult := &tagservicepb.TagMapping{Name: tag, Uri: &newUri, Ip: &faketagservice.ResolvedTagIp}

	url := fmt.Sprintf(GetFormatterString(ResolveTagURL), tag)
	req, _ := http.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	nameMaps := []*tagservicepb.TagMapping{}
	err := json.Unmarshal(responseData, &nameMaps)

	require.Nil(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedResult, nameMaps[0])

	// Resolve non-existent tag
	tag = "badtag"

	url = fmt.Sprintf(GetFormatterString(ResolveTagURL), tag)
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
	r.POST(SetTagURL, orchestratorServer.setTag)

	// Well-formed request
	tagMapping := &tagservicepb.TagMapping{Name: faketagservice.ValidTagName, ChildTags: []string{faketagservice.ValidTagName + "child"}}
	jsonValue, _ := json.Marshal(tagMapping)

	url := fmt.Sprintf(GetFormatterString(SetTagURL), tagMapping.Name)
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

	url = fmt.Sprintf(GetFormatterString(SetTagURL), tagMapping.Name)
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
	r.DELETE(DeleteTagMemberURL, orchestratorServer.deleteTagMember)

	// Well-formed request
	tagMapping := &tagservicepb.TagMapping{Name: faketagservice.ValidTagName, ChildTags: []string{"child"}}

	url := fmt.Sprintf(GetFormatterString(DeleteTagMemberURL), tagMapping.Name, tagMapping.ChildTags[0])
	req, _ := http.NewRequest("DELETE", url, nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var jsonMap map[string]string
	err := json.Unmarshal(responseData, &jsonMap)

	require.Nil(t, err)
	assert.Equal(t, http.StatusOK, w.Code)

	// Non-existent tag
	tagMapping = &tagservicepb.TagMapping{Name: "badtag", ChildTags: []string{"child"}}

	url = fmt.Sprintf(GetFormatterString(DeleteTagMemberURL), tagMapping.Name, tagMapping.ChildTags[0])
	req, _ = http.NewRequest("DELETE", url, nil)
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)

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
	r.DELETE(DeleteTagURL, orchestratorServer.deleteTag)

	// Well-formed request
	tag := faketagservice.ValidTagName

	url := fmt.Sprintf(GetFormatterString(DeleteTagURL), tag)
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

	url = fmt.Sprintf(GetFormatterString(DeleteTagURL), tag)
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
	rule := &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", "2.3.4.5"},
		Targets:   []string{},
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	rulesList := []*paragliderpb.PermitListRule{rule}
	expectedRule := &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", "2.3.4.5"},
		Targets:   []string{faketagservice.ResolvedTagIp, faketagservice.ResolvedTagIp, "2.3.4.5"},
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}
	expectedRulesList := []*paragliderpb.PermitListRule{expectedRule}
	resource := &ResourceInfo{uri: "uri", cloud: exampleCloudName, namespace: defaultNamespace}

	resolvedRules, err := orchestratorServer.resolvePermitListRules(rulesList, resource, false)
	assert.Nil(t, err)
	assert.Equal(t, expectedRulesList, resolvedRules)
}

func TestGetIPsFromResolvedTag(t *testing.T) {
	ip1 := "1.2.3.4"
	ip2 := "2.3.4.5"
	uri1 := "uri/name1"
	uri2 := "uri/name2"
	mappings := []*tagservicepb.TagMapping{
		{Name: "name1", Uri: &uri1, Ip: &ip1},
		{Name: "name2", Uri: &uri2, Ip: &ip2},
	}
	expectedIps := []string{ip1, ip2}

	ips := getIPsFromResolvedTag(mappings)
	assert.Equal(t, expectedIps, ips)
}

func TestCheckAndCleanRule(t *testing.T) {
	// Rule with correct formatting
	rule := &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", "2.3.4.5"},
		Targets:   []string{},
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}

	cleanRule, _, err := checkAndCleanRule(rule)
	assert.Nil(t, err)
	assert.Equal(t, rule, cleanRule)

	// Rule with no tags
	badRule := &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      []string{},
		Targets:   []string{},
		Direction: paragliderpb.Direction_INBOUND,
		SrcPort:   1,
		DstPort:   2,
		Protocol:  1}

	_, _, err = checkAndCleanRule(badRule)
	assert.NotNil(t, err)

	// Rule with targets
	badRule = &paragliderpb.PermitListRule{
		Name:      "rulename",
		Tags:      []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", "2.3.4.5"},
		Targets:   []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", "2.3.4.5"},
		Direction: paragliderpb.Direction_INBOUND,
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
	subName := createSubscriberName(defaultNamespace, origCloudName, origUri)
	namespace, cloud, uri := parseSubscriberName(subName)

	assert.Equal(t, defaultNamespace, namespace)
	assert.Equal(t, origCloudName, cloud)
	assert.Equal(t, origUri, uri)
}

func TestDiffTagReferences(t *testing.T) {
	beforePermitList := []*paragliderpb.PermitListRule{
		&paragliderpb.PermitListRule{
			Tags: []string{"tag1", "1.2.3.4"},
		},
		&paragliderpb.PermitListRule{
			Tags: []string{"tag1", "tag2", "tag3"},
		},
	}

	afterPermitList := []*paragliderpb.PermitListRule{
		&paragliderpb.PermitListRule{
			Tags: []string{"tag1", "1.2.3.4"},
		},
		&paragliderpb.PermitListRule{
			Tags: []string{"tag3"},
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

	resource := ResourceInfo{uri: "uri", cloud: exampleCloudName, namespace: defaultNamespace}

	beforePermitList := []*paragliderpb.PermitListRule{
		&paragliderpb.PermitListRule{
			Tags: []string{faketagservice.ValidTagName + "1", "1.2.3.4"},
		},
		&paragliderpb.PermitListRule{
			Tags: []string{faketagservice.ValidTagName + "1", faketagservice.ValidTagName + "2", faketagservice.ValidTagName + "2"},
		},
	}

	afterPermitList := []*paragliderpb.PermitListRule{
		&paragliderpb.PermitListRule{
			Tags: []string{faketagservice.ValidTagName + "1", "1.2.3.4"},
		},
		&paragliderpb.PermitListRule{
			Tags: []string{faketagservice.ValidTagName + "3"},
		},
	}

	err := orchestratorServer.checkAndUnsubscribe(&resource, beforePermitList, afterPermitList)
	assert.Nil(t, err)
}

func TestClearRuleTargets(t *testing.T) {
	permitList := []*paragliderpb.PermitListRule{
		&paragliderpb.PermitListRule{
			Targets: []string{"1.2.3.4"},
		},
		&paragliderpb.PermitListRule{
			Targets: []string{"1.2.3.4", "2.3.4.5"},
		},
		&paragliderpb.PermitListRule{
			Tags: []string{"1.2.3.4", "2.3.4.5"},
		},
	}

	expectedPermitList := []*paragliderpb.PermitListRule{
		&paragliderpb.PermitListRule{
			Targets: []string{},
		},
		&paragliderpb.PermitListRule{
			Targets: []string{},
		},
		&paragliderpb.PermitListRule{
			Targets: []string{},
			Tags:    []string{"1.2.3.4", "2.3.4.5"},
		},
	}

	clearedRules := clearRuleTargets(permitList)

	assert.ElementsMatch(t, expectedPermitList, clearedRules)
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
	orchestratorServer.usedAddressSpaces = []*paragliderpb.AddressSpaceMapping{
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
	orchestratorServer.config.Namespaces = map[string][]config.CloudDeployment{
		defaultNamespace: {{Name: utils.GCP, Deployment: "deployment1"}},
		"otherNamespace": {{Name: utils.AZURE, Deployment: "deployment2"}},
	}

	getUsedAddressSpacesResp, err := orchestratorServer.GetUsedAddressSpaces(context.Background(), &emptypb.Empty{})
	require.Nil(t, err)
	assert.ElementsMatch(t, getUsedAddressSpacesResp.AddressSpaceMappings, []*paragliderpb.AddressSpaceMapping{
		{AddressSpaces: gcp_address_spaces, Cloud: utils.GCP, Namespace: defaultNamespace, Deployment: proto.String("deployment1")},
		{AddressSpaces: azure_address_spaces, Cloud: utils.AZURE, Namespace: "otherNamespace", Deployment: proto.String("deployment2")},
	})
}

func TestGetTagUri(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)

	faketagservice.SetupFakeTagServer(tagServerPort)

	// Valid last level tag
	uri, err := orchestratorServer.getTagUri(faketagservice.ValidLastLevelTagName)
	require.Nil(t, err)
	assert.Equal(t, faketagservice.TagUri, uri)

	// invalid last level tag
	uri, err = orchestratorServer.getTagUri("invalidtag")
	require.NotNil(t, err)
	assert.Equal(t, "", uri)
}

func TestGetAndValidateResourceURLParams(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	tagServerPort := getNewPortNumber()
	orchestratorServer.localTagService = fmt.Sprintf("localhost:%d", tagServerPort)
	cloudPluginAddr := "address"
	orchestratorServer.pluginAddresses[exampleCloudName] = cloudPluginAddr

	faketagservice.SetupFakeTagServer(tagServerPort)

	ctx := gin.Context{}
	ctx.Params = gin.Params{gin.Param{Key: "namespace", Value: defaultNamespace}, gin.Param{Key: "cloud", Value: exampleCloudName}, gin.Param{Key: "resourceName", Value: faketagservice.ValidLastLevelTagName}}

	expectedResourceInfo := &ResourceInfo{uri: faketagservice.TagUri, name: faketagservice.ValidLastLevelTagName, cloud: exampleCloudName, namespace: defaultNamespace}

	// Resolve the tag
	resource, cloudPlugin, err := orchestratorServer.getAndValidateResourceURLParams(&ctx, true)

	assert.Nil(t, err)
	assert.Equal(t, expectedResourceInfo, resource)
	assert.Equal(t, cloudPluginAddr, cloudPlugin)

	// Do not resolve the tag
	expectedResourceInfo = &ResourceInfo{name: faketagservice.ValidLastLevelTagName, cloud: exampleCloudName, namespace: defaultNamespace}

	resource, cloudPlugin, err = orchestratorServer.getAndValidateResourceURLParams(&ctx, false)

	assert.Nil(t, err)
	assert.Equal(t, expectedResourceInfo, resource)
	assert.Equal(t, cloudPluginAddr, cloudPlugin)

	// Invalid cloud name
	ctx.Params = gin.Params{gin.Param{Key: "namespace", Value: defaultNamespace}, gin.Param{Key: "cloud", Value: "wrong"}, gin.Param{Key: "resourceName", Value: faketagservice.ValidLastLevelTagName}}
	_, _, err = orchestratorServer.getAndValidateResourceURLParams(&ctx, true)

	assert.NotNil(t, err)
}

func TestGetValue(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	kvStorePort := getNewPortNumber()
	fakekvstore.SetupFakeTagServer(kvStorePort)
	orchestratorServer.localKVStoreService = fmt.Sprintf("localhost:%d", kvStorePort)

	// Well-formed call
	resp, err := orchestratorServer.GetValue(context.Background(), &paragliderpb.GetValueRequest{Key: fakekvstore.ValidKey, Cloud: exampleCloudName, Namespace: defaultNamespace})
	require.Nil(t, err)
	assert.Equal(t, resp.Value, fakekvstore.ValidValue)

	// Non-existent key
	resp, err = orchestratorServer.GetValue(context.Background(), &paragliderpb.GetValueRequest{Key: "invalidkey", Cloud: exampleCloudName, Namespace: defaultNamespace})
	require.NotNil(t, err)
	require.Nil(t, resp)
}

func TestSetValue(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	kvStorePort := getNewPortNumber()
	fakekvstore.SetupFakeTagServer(kvStorePort)
	orchestratorServer.localKVStoreService = fmt.Sprintf("localhost:%d", kvStorePort)

	// Well-formed call
	resp, err := orchestratorServer.SetValue(context.Background(), &paragliderpb.SetValueRequest{Key: fakekvstore.ValidKey, Value: fakekvstore.ValidValue, Cloud: exampleCloudName, Namespace: defaultNamespace})
	require.Nil(t, err)
	require.NotNil(t, resp)

	// Bad key (already used, for example)
	resp, err = orchestratorServer.SetValue(context.Background(), &paragliderpb.SetValueRequest{Key: "invalidkey", Value: fakekvstore.ValidValue, Cloud: exampleCloudName, Namespace: defaultNamespace})
	require.NotNil(t, err)
	require.Nil(t, resp)
}

func TestDeleteValue(t *testing.T) {
	orchestratorServer := newOrchestratorServer()
	kvStorePort := getNewPortNumber()
	fakekvstore.SetupFakeTagServer(kvStorePort)
	orchestratorServer.localKVStoreService = fmt.Sprintf("localhost:%d", kvStorePort)

	// Well-formed call
	resp, err := orchestratorServer.DeleteValue(context.Background(), &paragliderpb.DeleteValueRequest{Key: fakekvstore.ValidKey, Cloud: exampleCloudName, Namespace: defaultNamespace})
	require.Nil(t, err)
	require.NotNil(t, resp)

	// Bad key
	resp, err = orchestratorServer.DeleteValue(context.Background(), &paragliderpb.DeleteValueRequest{Key: "invalidkey", Cloud: exampleCloudName, Namespace: defaultNamespace})
	require.NotNil(t, err)
	require.Nil(t, resp)
}
