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

package invisinetspb

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
	CloudPlugin_GetUsedAddressSpaces_FullMethodName  = "/invisinetspb.CloudPlugin/GetUsedAddressSpaces"
	CloudPlugin_CreateResource_FullMethodName        = "/invisinetspb.CloudPlugin/CreateResource"
	CloudPlugin_GetPermitList_FullMethodName         = "/invisinetspb.CloudPlugin/GetPermitList"
	CloudPlugin_AddPermitListRules_FullMethodName    = "/invisinetspb.CloudPlugin/AddPermitListRules"
	CloudPlugin_DeletePermitListRules_FullMethodName = "/invisinetspb.CloudPlugin/DeletePermitListRules"
)

// CloudPluginClient is the client API for CloudPlugin service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CloudPluginClient interface {
	GetUsedAddressSpaces(ctx context.Context, in *InvisinetsDeployment, opts ...grpc.CallOption) (*AddressSpaceList, error)
	CreateResource(ctx context.Context, in *ResourceDescription, opts ...grpc.CallOption) (*BasicResponse, error)
	GetPermitList(ctx context.Context, in *ResourceID, opts ...grpc.CallOption) (*PermitList, error)
	AddPermitListRules(ctx context.Context, in *PermitList, opts ...grpc.CallOption) (*BasicResponse, error)
	DeletePermitListRules(ctx context.Context, in *PermitList, opts ...grpc.CallOption) (*BasicResponse, error)
}

type cloudPluginClient struct {
	cc grpc.ClientConnInterface
}

func NewCloudPluginClient(cc grpc.ClientConnInterface) CloudPluginClient {
	return &cloudPluginClient{cc}
}

func (c *cloudPluginClient) GetUsedAddressSpaces(ctx context.Context, in *InvisinetsDeployment, opts ...grpc.CallOption) (*AddressSpaceList, error) {
	out := new(AddressSpaceList)
	err := c.cc.Invoke(ctx, CloudPlugin_GetUsedAddressSpaces_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudPluginClient) CreateResource(ctx context.Context, in *ResourceDescription, opts ...grpc.CallOption) (*BasicResponse, error) {
	out := new(BasicResponse)
	err := c.cc.Invoke(ctx, CloudPlugin_CreateResource_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudPluginClient) GetPermitList(ctx context.Context, in *ResourceID, opts ...grpc.CallOption) (*PermitList, error) {
	out := new(PermitList)
	err := c.cc.Invoke(ctx, CloudPlugin_GetPermitList_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudPluginClient) AddPermitListRules(ctx context.Context, in *PermitList, opts ...grpc.CallOption) (*BasicResponse, error) {
	out := new(BasicResponse)
	err := c.cc.Invoke(ctx, CloudPlugin_AddPermitListRules_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cloudPluginClient) DeletePermitListRules(ctx context.Context, in *PermitList, opts ...grpc.CallOption) (*BasicResponse, error) {
	out := new(BasicResponse)
	err := c.cc.Invoke(ctx, CloudPlugin_DeletePermitListRules_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CloudPluginServer is the server API for CloudPlugin service.
// All implementations must embed UnimplementedCloudPluginServer
// for forward compatibility
type CloudPluginServer interface {
	GetUsedAddressSpaces(context.Context, *InvisinetsDeployment) (*AddressSpaceList, error)
	CreateResource(context.Context, *ResourceDescription) (*BasicResponse, error)
	GetPermitList(context.Context, *ResourceID) (*PermitList, error)
	AddPermitListRules(context.Context, *PermitList) (*BasicResponse, error)
	DeletePermitListRules(context.Context, *PermitList) (*BasicResponse, error)
	mustEmbedUnimplementedCloudPluginServer()
}

// UnimplementedCloudPluginServer must be embedded to have forward compatible implementations.
type UnimplementedCloudPluginServer struct {
}

func (UnimplementedCloudPluginServer) GetUsedAddressSpaces(context.Context, *InvisinetsDeployment) (*AddressSpaceList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUsedAddressSpaces not implemented")
}
func (UnimplementedCloudPluginServer) CreateResource(context.Context, *ResourceDescription) (*BasicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateResource not implemented")
}
func (UnimplementedCloudPluginServer) GetPermitList(context.Context, *ResourceID) (*PermitList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPermitList not implemented")
}
func (UnimplementedCloudPluginServer) AddPermitListRules(context.Context, *PermitList) (*BasicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddPermitListRules not implemented")
}
func (UnimplementedCloudPluginServer) DeletePermitListRules(context.Context, *PermitList) (*BasicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeletePermitListRules not implemented")
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

func _CloudPlugin_GetUsedAddressSpaces_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InvisinetsDeployment)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudPluginServer).GetUsedAddressSpaces(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CloudPlugin_GetUsedAddressSpaces_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudPluginServer).GetUsedAddressSpaces(ctx, req.(*InvisinetsDeployment))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudPlugin_CreateResource_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResourceDescription)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudPluginServer).CreateResource(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CloudPlugin_CreateResource_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudPluginServer).CreateResource(ctx, req.(*ResourceDescription))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudPlugin_GetPermitList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResourceID)
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
		return srv.(CloudPluginServer).GetPermitList(ctx, req.(*ResourceID))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudPlugin_AddPermitListRules_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PermitList)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudPluginServer).AddPermitListRules(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CloudPlugin_AddPermitListRules_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudPluginServer).AddPermitListRules(ctx, req.(*PermitList))
	}
	return interceptor(ctx, in, info, handler)
}

func _CloudPlugin_DeletePermitListRules_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PermitList)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CloudPluginServer).DeletePermitListRules(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CloudPlugin_DeletePermitListRules_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CloudPluginServer).DeletePermitListRules(ctx, req.(*PermitList))
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
			MethodName: "GetUsedAddressSpaces",
			Handler:    _CloudPlugin_GetUsedAddressSpaces_Handler,
		},
		{
			MethodName: "CreateResource",
			Handler:    _CloudPlugin_CreateResource_Handler,
		},
		{
			MethodName: "GetPermitList",
			Handler:    _CloudPlugin_GetPermitList_Handler,
		},
		{
			MethodName: "AddPermitListRules",
			Handler:    _CloudPlugin_AddPermitListRules_Handler,
		},
		{
			MethodName: "DeletePermitListRules",
			Handler:    _CloudPlugin_DeletePermitListRules_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "invisinets.proto",
}

const (
	Controller_FindUnusedAddressSpace_FullMethodName = "/invisinetspb.Controller/FindUnusedAddressSpace"
)

// ControllerClient is the client API for Controller service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ControllerClient interface {
	FindUnusedAddressSpace(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*AddressSpace, error)
}

type controllerClient struct {
	cc grpc.ClientConnInterface
}

func NewControllerClient(cc grpc.ClientConnInterface) ControllerClient {
	return &controllerClient{cc}
}

func (c *controllerClient) FindUnusedAddressSpace(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*AddressSpace, error) {
	out := new(AddressSpace)
	err := c.cc.Invoke(ctx, Controller_FindUnusedAddressSpace_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ControllerServer is the server API for Controller service.
// All implementations must embed UnimplementedControllerServer
// for forward compatibility
type ControllerServer interface {
	FindUnusedAddressSpace(context.Context, *Empty) (*AddressSpace, error)
	mustEmbedUnimplementedControllerServer()
}

// UnimplementedControllerServer must be embedded to have forward compatible implementations.
type UnimplementedControllerServer struct {
}

func (UnimplementedControllerServer) FindUnusedAddressSpace(context.Context, *Empty) (*AddressSpace, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FindUnusedAddressSpace not implemented")
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
	in := new(Empty)
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
		return srv.(ControllerServer).FindUnusedAddressSpace(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

// Controller_ServiceDesc is the grpc.ServiceDesc for Controller service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Controller_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "invisinetspb.Controller",
	HandlerType: (*ControllerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "FindUnusedAddressSpace",
			Handler:    _Controller_FindUnusedAddressSpace_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "invisinets.proto",
}
