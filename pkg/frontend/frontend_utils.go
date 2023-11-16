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
	"net"

	config "github.com/NetSys/invisinets/pkg/frontend/config"
	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	grpc "google.golang.org/grpc"
)

func SetupControllerServer(cfg config.Config) string {
	controllerServer := &ControllerServer{
		pluginAddresses:   make(map[string]string),
		usedAddressSpaces: make(map[string]map[string][]string),
		config:            cfg,
	}
	for _, c := range controllerServer.config.CloudPlugins {
		controllerServer.pluginAddresses[c.Name] = c.Host + ":" + c.Port
	}
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic("error occured while setting up controller server")
	}
	gsrv := grpc.NewServer()
	invisinetspb.RegisterControllerServer(gsrv, controllerServer)
	controllerServerAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err)
		}
	}()
	return controllerServerAddr
}
