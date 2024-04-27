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

package cloud_plugin

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/paraglider-project/paraglider/pkg/invisinetspb"
	"github.com/paraglider-project/paraglider/pkg/tag_service/tagservicepb"
	"google.golang.org/grpc"

	fake "github.com/paraglider-project/paraglider/pkg/fake/tagservice"
)

const AddressSpaceAddress = "10.0.0.0/16"
const Asn = 64512

var BgpPeeringIpAddresses = []string{"169.254.21.1", "169.254.22.1"}
var ExampleRule = &invisinetspb.PermitListRule{Name: "example-rule", Tags: []string{fake.ValidTagName, "1.2.3.4"}, SrcPort: 1, DstPort: 1, Protocol: 1, Direction: invisinetspb.Direction_INBOUND}

// Mock Cloud Plugin Server
type fakeCloudPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
	fake.FakeTagServiceServer
}

func (s *fakeCloudPluginServer) GetPermitList(c context.Context, req *invisinetspb.GetPermitListRequest) (*invisinetspb.GetPermitListResponse, error) {
	return &invisinetspb.GetPermitListResponse{Rules: []*invisinetspb.PermitListRule{ExampleRule}}, nil
}

func (s *fakeCloudPluginServer) AddPermitListRules(c context.Context, req *invisinetspb.AddPermitListRulesRequest) (*invisinetspb.AddPermitListRulesResponse, error) {
	return &invisinetspb.AddPermitListRulesResponse{}, nil
}

func (s *fakeCloudPluginServer) DeletePermitListRules(c context.Context, req *invisinetspb.DeletePermitListRulesRequest) (*invisinetspb.DeletePermitListRulesResponse, error) {
	return &invisinetspb.DeletePermitListRulesResponse{}, nil
}

func (s *fakeCloudPluginServer) CreateResource(c context.Context, req *invisinetspb.ResourceDescription) (*invisinetspb.CreateResourceResponse, error) {
	return &invisinetspb.CreateResourceResponse{Name: "resource_name", Uri: "resource_uri"}, nil
}

func (s *fakeCloudPluginServer) GetUsedAddressSpaces(c context.Context, req *invisinetspb.GetUsedAddressSpacesRequest) (*invisinetspb.GetUsedAddressSpacesResponse, error) {
	resp := &invisinetspb.GetUsedAddressSpacesResponse{
		AddressSpaceMappings: []*invisinetspb.AddressSpaceMapping{
			{
				AddressSpaces: []string{AddressSpaceAddress},
				Cloud:         "fakecloud",
				Namespace:     "fakenamespace",
			},
		},
	}
	return resp, nil
}

func (s *fakeCloudPluginServer) GetUsedAsns(c context.Context, req *invisinetspb.GetUsedAsnsRequest) (*invisinetspb.GetUsedAsnsResponse, error) {
	return &invisinetspb.GetUsedAsnsResponse{Asns: []uint32{Asn}}, nil
}

func (s *fakeCloudPluginServer) GetUsedBgpPeeringIpAddresses(c context.Context, req *invisinetspb.GetUsedBgpPeeringIpAddressesRequest) (*invisinetspb.GetUsedBgpPeeringIpAddressesResponse, error) {
	return &invisinetspb.GetUsedBgpPeeringIpAddressesResponse{IpAddresses: BgpPeeringIpAddresses}, nil
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
