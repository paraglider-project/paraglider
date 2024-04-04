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

package kvstore

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/NetSys/invisinets/pkg/kv_store/storepb"
	"google.golang.org/grpc"
)

const (
	ValidKey   = "validKey"
	ValidValue = "value"
)

type FakeKVStoreServer struct {
	storepb.UnimplementedKVStoreServer
}

func (s *FakeKVStoreServer) Get(c context.Context, req *storepb.GetRequest) (*storepb.GetResponse, error) {
	if req.Key == ValidKey {
		return &storepb.GetResponse{Value: ValidValue}, nil
	}
	return nil, fmt.Errorf("Get: Invalid key")
}

func (s *FakeKVStoreServer) Set(c context.Context, req *storepb.SetRequest) (*storepb.SetResponse, error) {
	if req.Key == ValidKey {
		return &storepb.SetResponse{}, nil
	}
	return nil, fmt.Errorf("Set: Invalid key")
}

func (s *FakeKVStoreServer) Delete(c context.Context, req *storepb.DeleteRequest) (*storepb.DeleteResponse, error) {
	if req.Key == ValidKey {
		return &storepb.DeleteResponse{}, nil
	}
	return nil, fmt.Errorf("Delete: Invalid key")
}

func NewFakeKVStoreServer() *FakeKVStoreServer {
	s := &FakeKVStoreServer{}
	return s
}

func SetupFakeTagServer(port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	storepb.RegisterKVStoreServer(grpcServer, NewFakeKVStoreServer())
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println(err.Error())
		}
	}()
}
