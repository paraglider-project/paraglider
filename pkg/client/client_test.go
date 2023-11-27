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

package client

import (
	"testing"

	fake "github.com/NetSys/invisinets/pkg/fake"
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/assert"
)

func TestGetPermitList(t *testing.T) {
	s := fake.FakeFrontendServer{}
	controllerAddress := s.SetupFakeFrontendServer()
	client := Client{ControllerAddress: controllerAddress}

	resourceId := "uri"
	permitList, err := client.GetPermitList(fake.CloudName, resourceId)

	assert.Nil(t, err)
	assert.Equal(t, resourceId, permitList.AssociatedResource)
}

func TestAddPermitListRules(t *testing.T) {
	s := fake.FakeFrontendServer{}
	controllerAddress := s.SetupFakeFrontendServer()
	client := Client{ControllerAddress: controllerAddress}

	err := client.AddPermitListRules(fake.CloudName, fake.GetFakePermitList("uri"))

	assert.Nil(t, err)
}

func TestDeletePermitListRules(t *testing.T) {
	s := fake.FakeFrontendServer{}
	controllerAddress := s.SetupFakeFrontendServer()
	client := Client{ControllerAddress: controllerAddress}

	err := client.DeletePermitListRules(fake.CloudName, fake.GetFakePermitList("uri"))

	assert.Nil(t, err)
}

func TestCreateResource(t *testing.T) {
	s := fake.FakeFrontendServer{}
	controllerAddress := s.SetupFakeFrontendServer()
	client := Client{ControllerAddress: controllerAddress}

	err := client.CreateResource(fake.CloudName, &invisinetspb.ResourceDescriptionString{Id: "uri"})

	assert.Nil(t, err)
}

func TestGetTag(t *testing.T) {
	s := fake.FakeFrontendServer{}
	controllerAddress := s.SetupFakeFrontendServer()
	client := Client{ControllerAddress: controllerAddress}

	tagName := "tag"
	tag, err := client.GetTag(tagName)

	assert.Nil(t, err)
	assert.Equal(t, tagName, tag.TagName)
}

func TestResolveTag(t *testing.T) {
	s := fake.FakeFrontendServer{}
	controllerAddress := s.SetupFakeFrontendServer()
	client := Client{ControllerAddress: controllerAddress}

	tagName := "tag"
	tags, err := client.ResolveTag(tagName)

	assert.Nil(t, err)
	assert.Equal(t, tagName, tags[0].TagName)
	assert.NotNil(t, tags[0].Uri)
}

func TestSetTag(t *testing.T) {
	s := fake.FakeFrontendServer{}
	controllerAddress := s.SetupFakeFrontendServer()
	client := Client{ControllerAddress: controllerAddress}

	tagName := "tag"
	tagMapping := fake.GetFakeTagMapping(tagName)
	err := client.SetTag(tagName, tagMapping)

	assert.Nil(t, err)
}

func TestDeleteTag(t *testing.T) {
	s := fake.FakeFrontendServer{}
	controllerAddress := s.SetupFakeFrontendServer()
	client := Client{ControllerAddress: controllerAddress}

	tagName := "tag"
	err := client.DeleteTag(tagName)

	assert.Nil(t, err)
}

func TestDeleteTagMembers(t *testing.T) {
	s := fake.FakeFrontendServer{}
	controllerAddress := s.SetupFakeFrontendServer()
	client := Client{ControllerAddress: controllerAddress}

	tagName := "tag"
	err := client.DeleteTagMembers(tagName, []string{"member1", "member2"})

	assert.Nil(t, err)
}

func TestGetNamespace(t *testing.T) {
	s := fake.FakeFrontendServer{}
	controllerAddress := s.SetupFakeFrontendServer()
	client := Client{ControllerAddress: controllerAddress}

	namespace, err := client.GetNamespace()

	assert.Nil(t, err)
	assert.Equal(t, fake.Namespace, namespace)
}

func TestSetNamespace(t *testing.T) {
	s := fake.FakeFrontendServer{}
	controllerAddress := s.SetupFakeFrontendServer()
	client := Client{ControllerAddress: controllerAddress}

	namespace := "namespace"
	err := client.SetNamespace(namespace)

	assert.Nil(t, err)
}
