package main

import (
	"context"
	"flag"
	"log"
	"net"
	"fmt"
	"google.golang.org/grpc"
	"github.com/NetSys/invisinets/src/invisinetspb"
  )

var (
	tls        = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile   = flag.String("cert_file", "", "The TLS cert file")
	keyFile    = flag.String("key_file", "", "The TLS key file")
	jsonDBFile = flag.String("json_db_file", "", "A json file containing a list of features")
	port       = flag.Int("port", 50051, "The server port")
)

type cloudPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
}

func (s* cloudPluginServer) SetPermitList(c context.Context, pl *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully set permit list with ID=%s", pl.Id)}, nil
}

func (s* cloudPluginServer) GetPermitList(c context.Context, r *invisinetspb.Resource) (*invisinetspb.PermitList, error) {
	return &invisinetspb.PermitList{Id: r.Id}, nil
}

func (s* cloudPluginServer) CreateEnabledResource(c context.Context, r *invisinetspb.EnabledResource) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully create resource=%s", r.Resource)}, nil
}

func (s* cloudPluginServer) TagResource(c context.Context, t *invisinetspb.TagList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: "success"}, nil
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
	// if *tls {
	// 	if *certFile == "" {
	// 		*certFile = data.Path("x509/server_cert.pem")
	// 	}
	// 	if *keyFile == "" {
	// 		*keyFile = data.Path("x509/server_key.pem")
	// 	}
	// 	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	// 	if err != nil {
	// 		log.Fatalf("Failed to generate credentials: %v", err)
	// 	}
	// 	opts = []grpc.ServerOption{grpc.Creds(creds)}
	// }
	grpcServer := grpc.NewServer(opts...)
	invisinetspb.RegisterCloudPluginServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}