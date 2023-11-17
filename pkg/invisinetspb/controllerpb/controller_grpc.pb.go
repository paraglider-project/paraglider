//
//Copyright 2023 The Invisinets Authors.
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.23.2
// source: controller.proto

package controllerpb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	Controller_FindUnusedAddressSpace_FullMethodName = "/controllerpb.Controller/FindUnusedAddressSpace"
	Controller_GetUsedAddressSpaces_FullMethodName   = "/controllerpb.Controller/GetUsedAddressSpaces"
	Controller_ConnectClouds_FullMethodName          = "/controllerpb.Controller/ConnectClouds"
)

// ControllerClient is the client API for Controller service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ControllerClient interface {
	FindUnusedAddressSpace(ctx context.Context, in *FindUnusedAddressSpaceRequest, opts ...grpc.CallOption) (*FindUnusedAddressSpaceResponse, error)
	GetUsedAddressSpaces(ctx context.Context, in *GetUsedAddressSpacesRequest, opts ...grpc.CallOption) (*GetUsedAddressSpacesResponse, error)
	ConnectClouds(ctx context.Context, in *ConnectCloudsRequest, opts ...grpc.CallOption) (*ConnectCloudsResponse, error)
}

type controllerClient struct {
	cc grpc.ClientConnInterface
}

func NewControllerClient(cc grpc.ClientConnInterface) ControllerClient {
	return &controllerClient{cc}
}

func (c *controllerClient) FindUnusedAddressSpace(ctx context.Context, in *FindUnusedAddressSpaceRequest, opts ...grpc.CallOption) (*FindUnusedAddressSpaceResponse, error) {
	out := new(FindUnusedAddressSpaceResponse)
	err := c.cc.Invoke(ctx, Controller_FindUnusedAddressSpace_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *controllerClient) GetUsedAddressSpaces(ctx context.Context, in *GetUsedAddressSpacesRequest, opts ...grpc.CallOption) (*GetUsedAddressSpacesResponse, error) {
	out := new(GetUsedAddressSpacesResponse)
	err := c.cc.Invoke(ctx, Controller_GetUsedAddressSpaces_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *controllerClient) ConnectClouds(ctx context.Context, in *ConnectCloudsRequest, opts ...grpc.CallOption) (*ConnectCloudsResponse, error) {
	out := new(ConnectCloudsResponse)
	err := c.cc.Invoke(ctx, Controller_ConnectClouds_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ControllerServer is the server API for Controller service.
// All implementations must embed UnimplementedControllerServer
// for forward compatibility
type ControllerServer interface {
	FindUnusedAddressSpace(context.Context, *FindUnusedAddressSpaceRequest) (*FindUnusedAddressSpaceResponse, error)
	GetUsedAddressSpaces(context.Context, *GetUsedAddressSpacesRequest) (*GetUsedAddressSpacesResponse, error)
	ConnectClouds(context.Context, *ConnectCloudsRequest) (*ConnectCloudsResponse, error)
	mustEmbedUnimplementedControllerServer()
}

// UnimplementedControllerServer must be embedded to have forward compatible implementations.
type UnimplementedControllerServer struct {
}

func (UnimplementedControllerServer) FindUnusedAddressSpace(context.Context, *FindUnusedAddressSpaceRequest) (*FindUnusedAddressSpaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FindUnusedAddressSpace not implemented")
}
func (UnimplementedControllerServer) GetUsedAddressSpaces(context.Context, *GetUsedAddressSpacesRequest) (*GetUsedAddressSpacesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUsedAddressSpaces not implemented")
}
func (UnimplementedControllerServer) ConnectClouds(context.Context, *ConnectCloudsRequest) (*ConnectCloudsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ConnectClouds not implemented")
}
func (UnimplementedControllerServer) mustEmbedUnimplementedControllerServer() {}

// UnsafeControllerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ControllerServer will
// result in compilation errors.
type UnsafeControllerServer interface {
	mustEmbedUnimplementedControllerServer()
}

func RegisterControllerServer(s grpc.ServiceRegistrar, srv ControllerServer) {
	s.RegisterService(&Controller_ServiceDesc, srv)
}

func _Controller_FindUnusedAddressSpace_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FindUnusedAddressSpaceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControllerServer).FindUnusedAddressSpace(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Controller_FindUnusedAddressSpace_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControllerServer).FindUnusedAddressSpace(ctx, req.(*FindUnusedAddressSpaceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Controller_GetUsedAddressSpaces_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUsedAddressSpacesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControllerServer).GetUsedAddressSpaces(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Controller_GetUsedAddressSpaces_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControllerServer).GetUsedAddressSpaces(ctx, req.(*GetUsedAddressSpacesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Controller_ConnectClouds_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ConnectCloudsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControllerServer).ConnectClouds(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Controller_ConnectClouds_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControllerServer).ConnectClouds(ctx, req.(*ConnectCloudsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Controller_ServiceDesc is the grpc.ServiceDesc for Controller service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Controller_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "controllerpb.Controller",
	HandlerType: (*ControllerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "FindUnusedAddressSpace",
			Handler:    _Controller_FindUnusedAddressSpace_Handler,
		},
		{
			MethodName: "GetUsedAddressSpaces",
			Handler:    _Controller_GetUsedAddressSpaces_Handler,
		},
		{
			MethodName: "ConnectClouds",
			Handler:    _Controller_ConnectClouds_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "controller.proto",
}
