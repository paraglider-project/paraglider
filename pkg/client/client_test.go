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

package client

import (
	"testing"

	fake "github.com/paraglider-project/paraglider/pkg/fake/orchestrator/rest"
	"github.com/paraglider-project/paraglider/pkg/orchestrator"
	"github.com/paraglider-project/paraglider/pkg/paragliderpb"
	"github.com/stretchr/testify/assert"
)

func setupClientWithFakeOrchestratorServer() Client {
	s := fake.FakeOrchestratorRESTServer{}
	controllerAddress := s.SetupFakeOrchestratorRESTServer()
	return Client{ControllerAddress: controllerAddress}
}

func TestGetPermitList(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	resourceName := "resourceName"
	rules, err := client.GetPermitList(fake.Namespace, fake.CloudName, resourceName)

	assert.Nil(t, err)
	assert.Equal(t, fake.GetFakePermitListRules()[0].Name, rules[0].Name)
}

func TestAddPermitListRules(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	err := client.AddPermitListRules(fake.Namespace, fake.CloudName, "resourceName", fake.GetFakePermitListRules())

	assert.Nil(t, err)
}

func TestDeletePermitListRules(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	err := client.DeletePermitListRules(fake.Namespace, fake.CloudName, "resourceName", fake.GetFakePermitListRuleNames())

	assert.Nil(t, err)
}

func TestTagAddPermitListRules(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	err := client.AddPermitListRulesTag("tagName", fake.GetFakePermitListRules())

	assert.Nil(t, err)
}

func TestTagDeletePermitListRules(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	err := client.DeletePermitListRulesTag("tagName", fake.GetFakePermitListRuleNames())

	assert.Nil(t, err)
}

func TestCreateResource(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	resource, err := client.CreateResource(fake.Namespace, fake.CloudName, fake.ResourceName, &paragliderpb.ResourceDescriptionString{Name: fake.ResourceName, Description: fake.ResourceDesc})
	assert.Nil(t, err)
	assert.Equal(t, fake.ResourceName, resource["name"])
	assert.Equal(t, fake.Uri, resource["uri"])
	assert.Equal(t, fake.Ip, resource["ip"])
}

func TestAttachResource(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	resource, err := client.AttachResource(fake.Namespace, fake.CloudName, &orchestrator.ResourceID{Id: fake.Uri})
	assert.Nil(t, err)
	assert.Equal(t, fake.Uri, resource["uri"])
	assert.Equal(t, fake.Ip, resource["ip"])
	assert.Equal(t, fake.ResourceName, resource["name"])
}

func TestGetTag(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	tagName := "tag"
	tag, err := client.GetTag(tagName)

	assert.Nil(t, err)
	assert.Equal(t, tagName, tag.Name)
}

func TestResolveTag(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	tagName := "tag"
	tags, err := client.ResolveTag(tagName)

	assert.Nil(t, err)
	assert.Equal(t, tagName, tags[0].Name)
	assert.NotNil(t, tags[0].Uri)
}

func TestSetTag(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	tagName := "tag"
	tagMapping := fake.GetFakeTagMapping(tagName)
	err := client.SetTag(tagName, tagMapping)

	assert.Nil(t, err)
}

func TestDeleteTag(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	tagName := "tag"
	err := client.DeleteTag(tagName)

	assert.Nil(t, err)
}

func TestDeleteTagMembers(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	tagName := "tag"
	err := client.DeleteTagMembers(tagName, "member1")

	assert.Nil(t, err)
}

func TestSetNamespace(t *testing.T) {
	client := setupClientWithFakeOrchestratorServer()

	namespaces, err := client.ListNamespaces()

	assert.Nil(t, err)
	assert.Equal(t, fake.GetFakeNamespaces(), namespaces)
}
