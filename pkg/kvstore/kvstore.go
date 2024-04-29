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

	storepb "github.com/NetSys/invisinets/pkg/kvstore/storepb"
	redis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

func GetFullKey(key string, cloud string, namespace string) string {
	return fmt.Sprintf("%s:%s:%s", namespace, cloud, key)
}

type kvStoreServer struct {
	storepb.UnimplementedKVStoreServer
	client *redis.Client
}

func NewKVStoreServer(client *redis.Client) *kvStoreServer {
	return &kvStoreServer{
		client: client,
	}
}

func (s *kvStoreServer) Get(ctx context.Context, req *storepb.GetRequest) (*storepb.GetResponse, error) {
	value, err := s.client.Get(ctx, GetFullKey(req.Key, req.Cloud, req.Namespace)).Result()
	if err != nil {
		return nil, err
	}
	return &storepb.GetResponse{
		Value: value,
	}, nil
}

func (s *kvStoreServer) Set(ctx context.Context, req *storepb.SetRequest) (*storepb.SetResponse, error) {
	err := s.client.Set(ctx, GetFullKey(req.Key, req.Cloud, req.Namespace), req.Value, 0).Err()
	if err != nil {
		return nil, err
	}
	return &storepb.SetResponse{}, nil
}

func (s *kvStoreServer) Delete(ctx context.Context, req *storepb.DeleteRequest) (*storepb.DeleteResponse, error) {
	err := s.client.Del(ctx, GetFullKey(req.Key, req.Cloud, req.Namespace)).Err()
	if err != nil {
		return nil, err
	}
	return &storepb.DeleteResponse{}, nil
}

// Setup and run the server
func Setup(dbPort int, serverPort int, clearKeys bool) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("localhost:%d", dbPort),
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	if clearKeys {
		fmt.Printf("Flushed all keys.")
		client.FlushAll(context.Background())
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", serverPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	storepb.RegisterKVStoreServer(grpcServer, NewKVStoreServer(client))
	fmt.Printf("Serving KV Store at localhost:%d", serverPort)
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}
