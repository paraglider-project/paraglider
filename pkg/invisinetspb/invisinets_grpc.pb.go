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
// source: invisinets.proto

package __

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
	CloudPlugin_SetPermitList_FullMethodName = "/invisinetspb.CloudPlugin/SetPermitList"
	CloudPlugin_GetPermitList_FullMethodName = "/invisinetspb.CloudPlugin/GetPermitList"
)

// CloudPluginClient is the client API for CloudPlugin service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CloudPluginClient interface {
	SetPermitList(ctx context.Context, in *PermitList, opts ...grpc.CallOption) (*BasicResponse, error)
	GetPermitList(ctx context.Context, in *Resource, opts ...grpc.CallOption) (*PermitList, error)
}

type cloudPluginClient struct {
	cc grpc.ClientConnInterface
}

func NewCloudPluginClient(cc grpc.ClientConnInterface) CloudPluginClient {
	return &cloudPluginClient{cc}
}

func (c *cloudPluginClient) SetPermitList(ctx context.Context, in *PermitList, opts ...grpc.CallOption) (*BasicResponse, error) {
	out := new(BasicResponse)
	err := c.cc.Invoke(ctx, CloudPlugin_SetPermitList_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudPluginClient) GetPermitList(ctx context.Context, in *Resource, opts ...grpc.CallOption) (*PermitList, error) {
	out := new(PermitList)
	err := c.cc.Invoke(ctx, CloudPlugin_GetPermitList_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CloudPluginServer is the server API for CloudPlugin service.
// All implementations must embed UnimplementedCloudPluginServer
// for forward compatibility
type CloudPluginServer interface {
	SetPermitList(context.Context, *PermitList) (*BasicResponse, error)
	GetPermitList(context.Context, *Resource) (*PermitList, error)
	mustEmbedUnimplementedCloudPluginServer()
}

// UnimplementedCloudPluginServer must be embedded to have forward compatible implementations.
type UnimplementedCloudPluginServer struct {
}

func (UnimplementedCloudPluginServer) SetPermitList(context.Context, *PermitList) (*BasicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetPermitList not implemented")
}
func (UnimplementedCloudPluginServer) GetPermitList(context.Context, *Resource) (*PermitList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPermitList not implemented")
}
func (UnimplementedCloudPluginServer) mustEmbedUnimplementedCloudPluginServer() {}

// UnsafeCloudPluginServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CloudPluginServer will
// result in compilation errors.
type UnsafeCloudPluginServer interface {
	mustEmbedUnimplementedCloudPluginServer()
}

func RegisterCloudPluginServer(s grpc.ServiceRegistrar, srv CloudPluginServer) {
	s.RegisterService(&CloudPlugin_ServiceDesc, srv)
}

func _CloudPlugin_SetPermitList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PermitList)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudPluginServer).SetPermitList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CloudPlugin_SetPermitList_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudPluginServer).SetPermitList(ctx, req.(*PermitList))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudPlugin_GetPermitList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Resource)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudPluginServer).GetPermitList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CloudPlugin_GetPermitList_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudPluginServer).GetPermitList(ctx, req.(*Resource))
	}
	return interceptor(ctx, in, info, handler)
}

// CloudPlugin_ServiceDesc is the grpc.ServiceDesc for CloudPlugin service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CloudPlugin_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "invisinetspb.CloudPlugin",
	HandlerType: (*CloudPluginServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SetPermitList",
			Handler:    _CloudPlugin_SetPermitList_Handler,
		},
		{
			MethodName: "GetPermitList",
			Handler:    _CloudPlugin_GetPermitList_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "invisinets.proto",
}
