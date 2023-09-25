package frontend

import (
	"net"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	grpc "google.golang.org/grpc"
)

// TODO @seankimkdy: change this back to only return address
func SetupControllerServer(cfg Config) (*ControllerServer, string) {
	controllerServer := &ControllerServer{
		pluginAddresses:   make(map[string]string),
		usedAddressSpaces: make(map[string][]string),
		config:            cfg,
	}
	for _, c := range controllerServer.config.Clouds {
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
	return controllerServer, controllerServerAddr
}
