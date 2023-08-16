//go:build unit

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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"io"
	"net"
	"log"

	"github.com/gin-gonic/gin"
	grpc "google.golang.org/grpc"

	invisinetspb "github.com/NetSys/invisinets/pkg/invisinetspb"
	"github.com/stretchr/testify/assert"
)


// Mock Cloud Plugin Server
type mockCloudPluginServer struct {
	invisinetspb.UnimplementedCloudPluginServer
}

func (s *mockCloudPluginServer) GetPermitList(c context.Context, r *invisinetspb.ResourceID) (*invisinetspb.PermitList, error) {
	return &invisinetspb.PermitList{AssociatedResource: r.Id}, nil
}

func (s *mockCloudPluginServer) AddPermitListRules(c context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: permitList.AssociatedResource}, nil
}

func (s *mockCloudPluginServer) DeletePermitListRules(c context.Context, permitList *invisinetspb.PermitList) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: permitList.AssociatedResource}, nil
}

func (s *mockCloudPluginServer) CreateResource(c context.Context, resource *invisinetspb.ResourceDescription) (*invisinetspb.BasicResponse, error) {
	return &invisinetspb.BasicResponse{Success: true, Message: resource.Id}, nil
}

func (s *mockCloudPluginServer) GetUsedAddressSpaces(c context.Context, deployment *invisinetspb.InvisinetsDeployment) (*invisinetspb.AddressSpaceList, error) {
	mapping := invisinetspb.RegionAddressSpaceMap{Region: "us-west", AddressSpace: "10.0.0.0/16"}
	return &invisinetspb.AddressSpaceList{Mappings: [](*invisinetspb.RegionAddressSpaceMap){&mapping}}, nil
}

// // Local dialer through a buffer connection
// func dialer() func(context.Context, string) (net.Conn, error) {
// 	listener := bufconn.Listen(1024)
 
// 	server := grpc.NewServer()
 
// 	invisinetspb.RegisterCloudPluginServer(server, &mockCloudPluginServer{})
 
// 	go func() {
// 		if err := server.Serve(listener); err != nil {
// 			log.Fatal(err)
// 		}
// 	}()
 
// 	return func(context.Context, string) (net.Conn, error) {
// 		return listener.Dial()
// 	}
// }

func newServer() *mockCloudPluginServer {
	s := &mockCloudPluginServer{}
	return s
}

func setupServer(port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	invisinetspb.RegisterCloudPluginServer(grpcServer, newServer())
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func SetUpRouter() *gin.Engine{
	gin.SetMode(gin.ReleaseMode)
	gin.DefaultWriter = io.Discard
    router := gin.New()
    return router
}


func TestPermitListGetValidRequest(t *testing.T) {
	port := 10001
	pluginAddresses["example"] = fmt.Sprintf("localhost:%d", port)

	id := "123"
	permitListJson := "{\"associated_resource\":\"123\"}"
	expectedResponse := map[string]string{
		"id":              id,
		"resource":        id,
		"permitlist_json": permitListJson,
	}

	go setupServer(port)

	r := SetUpRouter()
	url := fmt.Sprintf("/cloud/%s/resources/%s/permit-list/", "example", id)
    r.GET("/cloud/:cloud/resources/:id/permit-list/", permitListGet)
	req, _ := http.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()


	r.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	var jsonMap map[string]string
	json.Unmarshal(responseData, &jsonMap)
    assert.Equal(t, expectedResponse, jsonMap)
    assert.Equal(t, http.StatusOK, w.Code)
}