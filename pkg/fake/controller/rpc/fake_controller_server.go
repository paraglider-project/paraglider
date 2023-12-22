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
	"google.golang.org/grpc"
)

// Sets up fake frontend controller server
// Note: this is only meant to be used with one cloud (i.e. primarily for each cloud plugin's unit/integration tests)
type FakeControllerServer struct {
	invisinetspb.UnimplementedControllerServer
	Cloud   string
	Counter int
}

func (f *FakeControllerServer) FindUnusedAddressSpace(ctx context.Context, namespace *invisinetspb.Namespace) (*invisinetspb.AddressSpace, error) {
	if f.Counter == 256 {
		return nil, fmt.Errorf("ran out of address spaces")
	}
	address := fmt.Sprintf("10.%d.0.0/16", f.Counter)
	f.Counter = f.Counter + 1
	return &invisinetspb.AddressSpace{Address: address}, nil
}

func (f *FakeControllerServer) GetUsedAddressSpaces(ctx context.Context, namespace *invisinetspb.Namespace) (*invisinetspb.AddressSpaceMappingList, error) {
	addressSpaces := make([]string, f.Counter)
	for i := 0; i < f.Counter; i++ {
		addressSpaces[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	addressSpaceMappingList := &invisinetspb.AddressSpaceMappingList{
		AddressSpaceMappings: []*invisinetspb.AddressSpaceMapping{
			{AddressSpaces: addressSpaces, Cloud: f.Cloud},
		},
	}
	return addressSpaceMappingList, nil
}

func SetupFakeControllerServer(cloud string) (*FakeControllerServer, string, error) {
	fakeControllerServer := &FakeControllerServer{Counter: 0, Cloud: cloud}
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
