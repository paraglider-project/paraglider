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
	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
)

type InvisinetsControllerClient interface {
	GetPermitList(cloud string, id string) (invisinetspb.PermitList, error)
	AddPermitListRules(cloud string, permitList invisinetspb.PermitList) error
	DeletePermitListRules(cloud string, permitList invisinetspb.PermitList) error
	CreateResource(cloud string, resource invisinetspb.ResourceDescriptionString) error
	GetTag(tag string) (tagservicepb.TagMapping, error)
	ResolveTag(tag string) ([]tagservicepb.TagMapping, error)
	SetTag(tag string, tagMapping tagservicepb.TagMapping) error
	DeleteTag(tag string) error
	DeleteTagMembers(tag string, members []string) error
	GetNamespace() (string, error)
	SetNamespace(namespace string) error
}
