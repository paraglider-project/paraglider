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

package rpc

import (
	"context"
	"fmt"
	"net"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/NetSys/invisinets/pkg/kvstore"
	"github.com/NetSys/invisinets/pkg/orchestrator"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// Sets up fake orchestrator server
// Note: this is only meant to be used with one cloud (i.e. primarily for each cloud plugin's unit/integration tests)
type FakeOrchestratorRPCServer struct {
	invisinetspb.UnimplementedControllerServer
	Cloud   string
	Counter int
	kvStore map[string]string
}

func (f *FakeOrchestratorRPCServer) FindUnusedAddressSpaces(ctx context.Context, req *invisinetspb.FindUnusedAddressSpacesRequest) (*invisinetspb.FindUnusedAddressSpacesResponse, error) {
	numAddresses := 1
	if req.Num != nil {
		numAddresses = int(*req.Num)
	}
	addresses := make([]string, numAddresses)
	for i := 0; i < numAddresses; i++ {
		if f.Counter == 256 {
			return nil, fmt.Errorf("ran out of address spaces")
		}
		address := fmt.Sprintf("10.%d.0.0/16", f.Counter)
		f.Counter = f.Counter + 1
		addresses[i] = address
	}
	return &invisinetspb.FindUnusedAddressSpacesResponse{AddressSpaces: addresses}, nil
}

func (f *FakeOrchestratorRPCServer) FindUnusedAsn(ctx context.Context, _ *invisinetspb.FindUnusedAsnRequest) (*invisinetspb.FindUnusedAsnResponse, error) {
	return &invisinetspb.FindUnusedAsnResponse{Asn: orchestrator.MIN_PRIVATE_ASN_2BYTE}, nil
}

func (f *FakeOrchestratorRPCServer) GetUsedAddressSpaces(ctx context.Context, _ *invisinetspb.Empty) (*invisinetspb.GetUsedAddressSpacesResponse, error) {
	addressSpaces := make([]string, f.Counter)
	for i := 0; i < f.Counter; i++ {
		addressSpaces[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	resp := &invisinetspb.GetUsedAddressSpacesResponse{
		AddressSpaceMappings: []*invisinetspb.AddressSpaceMapping{
			{AddressSpaces: addressSpaces, Cloud: f.Cloud, Namespace: "default", Deployment: proto.String("test-deployment")},
		},
	}

	return resp, nil
}

func (f *FakeOrchestratorRPCServer) SetValue(ctx context.Context, in *invisinetspb.SetValueRequest) (*invisinetspb.SetValueResponse, error) {
	fullKey := kvstore.GetFullKey(in.Key, in.Cloud, in.Namespace)
	f.kvStore[fullKey] = in.Value

	return &invisinetspb.SetValueResponse{}, nil
}

func (f *FakeOrchestratorRPCServer) GetValue(ctx context.Context, in *invisinetspb.GetValueRequest) (*invisinetspb.GetValueResponse, error) {
	fullKey := kvstore.GetFullKey(in.Key, in.Cloud, in.Namespace)
	if val, ok := f.kvStore[fullKey]; ok {
		return &invisinetspb.GetValueResponse{Value: val}, nil
	}

	return &invisinetspb.GetValueResponse{}, nil
}

func (f *FakeOrchestratorRPCServer) DeleteValue(ctx context.Context, in *invisinetspb.DeleteValueRequest) (*invisinetspb.DeleteValueResponse, error) {
	fullKey := kvstore.GetFullKey(in.Key, in.Cloud, in.Namespace)
	delete(f.kvStore, fullKey)

	return &invisinetspb.DeleteValueResponse{}, nil
}

func SetupFakeOrchestratorRPCServer(cloud string) (*FakeOrchestratorRPCServer, string, error) {
	fakeControllerServer := &FakeOrchestratorRPCServer{
		Counter: 0,
		Cloud:   cloud,
		kvStore: make(map[string]string),
	}
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, "", err
	}
	gsrv := grpc.NewServer()
	invisinetspb.RegisterControllerServer(gsrv, fakeControllerServer)
	fakeControllerServerAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err)
		}
	}()

	return fakeControllerServer, fakeControllerServerAddr, nil
}

func SetupFakeOrchestratorRPCServerWithStore(cloud string, kvStore map[string]string) (*FakeOrchestratorRPCServer, string, error) {
	fakeControllerServer := &FakeOrchestratorRPCServer{
		Counter: 0,
		Cloud:   cloud,
		kvStore: kvStore,
	}
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, "", err
	}
	gsrv := grpc.NewServer()
	invisinetspb.RegisterControllerServer(gsrv, fakeControllerServer)
	fakeControllerServerAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err)
		}
	}()

	return fakeControllerServer, fakeControllerServerAddr, nil
}
