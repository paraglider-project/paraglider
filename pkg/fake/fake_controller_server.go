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

package fake

import (
	"context"
	"fmt"
	"net"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"google.golang.org/grpc"
)

// Sets up fake frontend controller server for getting unused address spaces
type FakeControllerServer struct {
	invisinetspb.UnimplementedControllerServer
	counter int
}

func (f *FakeControllerServer) FindUnusedAddressSpace(ctx context.Context, e *invisinetspb.Empty) (*invisinetspb.AddressSpace, error) {
	if f.counter == 256 {
		return nil, fmt.Errorf("ran out of address spaces")
	}
	address := fmt.Sprintf("10.%d.0.0/16", f.counter)
	f.counter = f.counter + 1
	return &invisinetspb.AddressSpace{Address: address}, nil
}

func (f *FakeControllerServer) GetUsedAddressSpaces(ctx context.Context, e *invisinetspb.Empty) (*invisinetspb.AddressSpaceMappingList, error) {
	// TODO @seankimkdy
	return nil, nil
}

func SetupFakeControllerServer() (string, error) {
	fakeControllerServer := &FakeControllerServer{counter: 0}
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", err
	}
	gsrv := grpc.NewServer()
	invisinetspb.RegisterControllerServer(gsrv, fakeControllerServer)
	fakeServerAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err)
		}
	}()

	return fakeServerAddr, nil
}
