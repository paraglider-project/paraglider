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

package cloud_plugin

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	"google.golang.org/grpc"

	fake "github.com/NetSys/invisinets/pkg/fake/tagservice"
)

const AddressSpaceAddress = "10.0.0.0/16"
const Asn = 64512

var ExampleRule = &invisinetspb.PermitListRule{Id: "example-rule", Tags: []string{fake.ValidTagName, "1.2.3.4"}, SrcPort: 1, DstPort: 1, Protocol: 1, Direction: invisinetspb.Direction_INBOUND}

// Mock Cloud Plugin Server
type fakeCloudPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
	fake.FakeTagServiceServer
}

func (s *fakeCloudPluginServer) GetPermitList(c context.Context, r *invisinetspb.ResourceID) (*invisinetspb.PermitList, error) {
	return &invisinetspb.PermitList{AssociatedResource: r.Id, Rules: []*invisinetspb.PermitListRule{ExampleRule}}, nil
}

func (s *fakeCloudPluginServer) AddPermitListRules(c context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: permitList.AssociatedResource}, nil
}

func (s *fakeCloudPluginServer) DeletePermitListRules(c context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: permitList.AssociatedResource}, nil
}

func (s *fakeCloudPluginServer) CreateResource(c context.Context, resource *invisinetspb.ResourceDescription) (*invisinetspb.CreateResourceResponse, error) {
	return &invisinetspb.CreateResourceResponse{Name: "resource_name", Uri: resource.Id}, nil
}

func (s *fakeCloudPluginServer) GetUsedAddressSpaces(c context.Context, deployment *invisinetspb.InvisinetsDeployment) (*invisinetspb.AddressSpaceList, error) {
	return &invisinetspb.AddressSpaceList{AddressSpaces: []string{AddressSpaceAddress}}, nil
}

func (s *fakeCloudPluginServer) GetUsedAsns(c context.Context, req *invisinetspb.GetUsedAsnsRequest) (*invisinetspb.GetUsedAsnsResponse, error) {
	return &invisinetspb.GetUsedAsnsResponse{Asns: []uint32{Asn}}, nil
}

func NewFakePluginServer() *fakeCloudPluginServer {
	s := &fakeCloudPluginServer{}
	return s
}

func SetupFakePluginServer(port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	invisinetspb.RegisterCloudPluginServer(grpcServer, NewFakePluginServer())
	tagservicepb.RegisterTagServiceServer(grpcServer, fake.NewFakeTagServer())
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println(err.Error())
		}
	}()
}
