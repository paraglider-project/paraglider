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
	"google.golang.org/grpc"
)

var (
	port      = flag.Int("port", 1002, "The server port")
	print     = true
	storeData = true
)

type cloudPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
	permitListState map[string][]*invisinetspb.PermitListRule
}

func (s *cloudPluginServer) GetPermitList(c context.Context, req *invisinetspb.GetPermitListRequest) (*invisinetspb.GetPermitListResponse, error) {
	if storeData {
		permitList, ok := s.permitListState[req.Resource]
		if ok {
			return &invisinetspb.GetPermitListResponse{Rules: permitList}, nil
		}
	}
	return &invisinetspb.GetPermitListResponse{}, nil
}

func (s *cloudPluginServer) AddPermitListRules(c context.Context, req *invisinetspb.AddPermitListRulesRequest) (*invisinetspb.AddPermitListRulesResponse, error) {
	if print {
		fmt.Println("Rules to add:")
		fmt.Printf("%v\n", req.Rules)
	}
	if storeData {
		s.permitListState[req.Resource] = req.Rules
	}
	return &invisinetspb.AddPermitListRulesResponse{}, nil
}

func (s *cloudPluginServer) DeletePermitListRules(c context.Context, req *invisinetspb.DeletePermitListRulesRequest) (*invisinetspb.DeletePermitListRulesResponse, error) {
	return &invisinetspb.DeletePermitListRulesResponse{}, nil
}

func (s *cloudPluginServer) CreateResource(c context.Context, resource *invisinetspb.ResourceDescription) (*invisinetspb.CreateResourceResponse, error) {
	return &invisinetspb.CreateResourceResponse{Name: "vm"}, nil
}

func (s *cloudPluginServer) GetUsedAddressSpaces(c context.Context, deployment *invisinetspb.InvisinetsDeployment) (*invisinetspb.AddressSpaceList, error) {
	return &invisinetspb.AddressSpaceList{AddressSpaces: []string{"10.0.0.0/16"}}, nil
}

func newServer() *cloudPluginServer {
	s := &cloudPluginServer{}
	s.permitListState = make(map[string][]*invisinetspb.PermitListRule)
	return s
}

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	invisinetspb.RegisterCloudPluginServer(grpcServer, newServer())
	fmt.Printf("Hosting Example Cloud Plugin Server on port %d\n", *port)
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}
