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

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 1002, "The server port")
)

type cloudPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
	tagservicepb.UnimplementedTagServiceServer
}

func (s *cloudPluginServer) GetPermitList(c context.Context, r *invisinetspb.ResourceID) (*invisinetspb.PermitList, error) {
	return &invisinetspb.PermitList{AssociatedResource: r.Id}, nil
}

func (s *cloudPluginServer) AddPermitListRules(c context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: permitList.AssociatedResource}, nil
}

func (s *cloudPluginServer) DeletePermitListRules(c context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: permitList.AssociatedResource}, nil
}

func (s *cloudPluginServer) CreateResource(c context.Context, resource *invisinetspb.ResourceDescription) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: resource.Id}, nil
}

func (s *cloudPluginServer) GetUsedAddressSpaces(c context.Context, deployment *invisinetspb.InvisinetsDeployment) (*invisinetspb.AddressSpaceList, error) {
	return &invisinetspb.AddressSpaceList{AddressSpaces: []string{"10.0.0.0/16"}}, nil
}

func (s *cloudPluginServer) GetTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.TagMapping, error) {
	return &tagservicepb.TagMapping{ParentTag: "parent", ChildTags: []string{"child"}}, nil
}

func (s *cloudPluginServer) SetTag(c context.Context, tagMapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error) {
	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully created tag: %s", tagMapping.ParentTag)}, nil
}

func (s *cloudPluginServer) DeleteTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.BasicResponse, error) {
	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully deleted tag: %s", tag.TagName)}, nil
}

func (s *cloudPluginServer) DeleteTagMember(c context.Context, tagMapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error) {
	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully deleted member %s from tag %s", tagMapping.ChildTags[0], tagMapping.ParentTag)}, nil
}

func newServer() *cloudPluginServer {
	s := &cloudPluginServer{}
	return s
}

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	invisinetspb.RegisterCloudPluginServer(grpcServer, newServer())
	tagservicepb.RegisterTagServiceServer(grpcServer, newServer())
	fmt.Printf("Hosting Example Cloud Plugin Server on port %d\n", *port)
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}
