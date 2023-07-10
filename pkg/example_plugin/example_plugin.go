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

package frontend

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
	port = flag.Int("port", 50051, "The server port")
)

type cloudPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
}

func (s *cloudPluginServer) SetPermitList(c context.Context, pl *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully set permit list with ID=%s", pl.Id)}, nil
}

func (s *cloudPluginServer) GetPermitList(c context.Context, r *invisinetspb.Resource) (*invisinetspb.PermitList, error) {
	return &invisinetspb.PermitList{Id: r.Id}, nil
}

func newServer() *cloudPluginServer {
	s := &cloudPluginServer{}
	return s
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	invisinetspb.RegisterCloudPluginServer(grpcServer, newServer())
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}
