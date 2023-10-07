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
// source: tagservice.proto

package tagservicepb

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
	TagService_SetTag_FullMethodName          = "/tagservicepb.TagService/SetTag"
	TagService_GetTag_FullMethodName          = "/tagservicepb.TagService/GetTag"
	TagService_ResolveTag_FullMethodName      = "/tagservicepb.TagService/ResolveTag"
	TagService_DeleteTagMember_FullMethodName = "/tagservicepb.TagService/DeleteTagMember"
	TagService_DeleteTag_FullMethodName       = "/tagservicepb.TagService/DeleteTag"
	TagService_Subscribe_FullMethodName       = "/tagservicepb.TagService/Subscribe"
	TagService_Unsubscribe_FullMethodName     = "/tagservicepb.TagService/Unsubscribe"
	TagService_GetSubscribers_FullMethodName  = "/tagservicepb.TagService/GetSubscribers"
)

// TagServiceClient is the client API for TagService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TagServiceClient interface {
	SetTag(ctx context.Context, in *TagMapping, opts ...grpc.CallOption) (*BasicResponse, error)
	GetTag(ctx context.Context, in *Tag, opts ...grpc.CallOption) (*TagMapping, error)
	ResolveTag(ctx context.Context, in *Tag, opts ...grpc.CallOption) (*TagMappingList, error)
	DeleteTagMember(ctx context.Context, in *TagMapping, opts ...grpc.CallOption) (*BasicResponse, error)
	DeleteTag(ctx context.Context, in *Tag, opts ...grpc.CallOption) (*BasicResponse, error)
	Subscribe(ctx context.Context, in *Subscription, opts ...grpc.CallOption) (*BasicResponse, error)
	Unsubscribe(ctx context.Context, in *Subscription, opts ...grpc.CallOption) (*BasicResponse, error)
	GetSubscribers(ctx context.Context, in *Tag, opts ...grpc.CallOption) (*SubscriberList, error)
}

type tagServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTagServiceClient(cc grpc.ClientConnInterface) TagServiceClient {
	return &tagServiceClient{cc}
}

func (c *tagServiceClient) SetTag(ctx context.Context, in *TagMapping, opts ...grpc.CallOption) (*BasicResponse, error) {
	out := new(BasicResponse)
	err := c.cc.Invoke(ctx, TagService_SetTag_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tagServiceClient) GetTag(ctx context.Context, in *Tag, opts ...grpc.CallOption) (*TagMapping, error) {
	out := new(TagMapping)
	err := c.cc.Invoke(ctx, TagService_GetTag_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tagServiceClient) ResolveTag(ctx context.Context, in *Tag, opts ...grpc.CallOption) (*TagMappingList, error) {
	out := new(TagMappingList)
	err := c.cc.Invoke(ctx, TagService_ResolveTag_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tagServiceClient) DeleteTagMember(ctx context.Context, in *TagMapping, opts ...grpc.CallOption) (*BasicResponse, error) {
	out := new(BasicResponse)
	err := c.cc.Invoke(ctx, TagService_DeleteTagMember_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tagServiceClient) DeleteTag(ctx context.Context, in *Tag, opts ...grpc.CallOption) (*BasicResponse, error) {
	out := new(BasicResponse)
	err := c.cc.Invoke(ctx, TagService_DeleteTag_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tagServiceClient) Subscribe(ctx context.Context, in *Subscription, opts ...grpc.CallOption) (*BasicResponse, error) {
	out := new(BasicResponse)
	err := c.cc.Invoke(ctx, TagService_Subscribe_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tagServiceClient) Unsubscribe(ctx context.Context, in *Subscription, opts ...grpc.CallOption) (*BasicResponse, error) {
	out := new(BasicResponse)
	err := c.cc.Invoke(ctx, TagService_Unsubscribe_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tagServiceClient) GetSubscribers(ctx context.Context, in *Tag, opts ...grpc.CallOption) (*SubscriberList, error) {
	out := new(SubscriberList)
	err := c.cc.Invoke(ctx, TagService_GetSubscribers_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TagServiceServer is the server API for TagService service.
// All implementations must embed UnimplementedTagServiceServer
// for forward compatibility
type TagServiceServer interface {
	SetTag(context.Context, *TagMapping) (*BasicResponse, error)
	GetTag(context.Context, *Tag) (*TagMapping, error)
	ResolveTag(context.Context, *Tag) (*TagMappingList, error)
	DeleteTagMember(context.Context, *TagMapping) (*BasicResponse, error)
	DeleteTag(context.Context, *Tag) (*BasicResponse, error)
	Subscribe(context.Context, *Subscription) (*BasicResponse, error)
	Unsubscribe(context.Context, *Subscription) (*BasicResponse, error)
	GetSubscribers(context.Context, *Tag) (*SubscriberList, error)
	mustEmbedUnimplementedTagServiceServer()
}

// UnimplementedTagServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTagServiceServer struct {
}

func (UnimplementedTagServiceServer) SetTag(context.Context, *TagMapping) (*BasicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetTag not implemented")
}
func (UnimplementedTagServiceServer) GetTag(context.Context, *Tag) (*TagMapping, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTag not implemented")
}
func (UnimplementedTagServiceServer) ResolveTag(context.Context, *Tag) (*TagMappingList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ResolveTag not implemented")
}
func (UnimplementedTagServiceServer) DeleteTagMember(context.Context, *TagMapping) (*BasicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteTagMember not implemented")
}
func (UnimplementedTagServiceServer) DeleteTag(context.Context, *Tag) (*BasicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteTag not implemented")
}
func (UnimplementedTagServiceServer) Subscribe(context.Context, *Subscription) (*BasicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Subscribe not implemented")
}
func (UnimplementedTagServiceServer) Unsubscribe(context.Context, *Subscription) (*BasicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Unsubscribe not implemented")
}
func (UnimplementedTagServiceServer) GetSubscribers(context.Context, *Tag) (*SubscriberList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSubscribers not implemented")
}
func (UnimplementedTagServiceServer) mustEmbedUnimplementedTagServiceServer() {}

// UnsafeTagServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TagServiceServer will
// result in compilation errors.
type UnsafeTagServiceServer interface {
	mustEmbedUnimplementedTagServiceServer()
}

func RegisterTagServiceServer(s grpc.ServiceRegistrar, srv TagServiceServer) {
	s.RegisterService(&TagService_ServiceDesc, srv)
}

func _TagService_SetTag_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TagMapping)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TagServiceServer).SetTag(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TagService_SetTag_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TagServiceServer).SetTag(ctx, req.(*TagMapping))
	}
	return interceptor(ctx, in, info, handler)
}

func _TagService_GetTag_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Tag)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TagServiceServer).GetTag(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TagService_GetTag_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TagServiceServer).GetTag(ctx, req.(*Tag))
	}
	return interceptor(ctx, in, info, handler)
}

func _TagService_ResolveTag_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Tag)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TagServiceServer).ResolveTag(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TagService_ResolveTag_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TagServiceServer).ResolveTag(ctx, req.(*Tag))
	}
	return interceptor(ctx, in, info, handler)
}

func _TagService_DeleteTagMember_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TagMapping)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TagServiceServer).DeleteTagMember(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TagService_DeleteTagMember_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TagServiceServer).DeleteTagMember(ctx, req.(*TagMapping))
	}
	return interceptor(ctx, in, info, handler)
}

func _TagService_DeleteTag_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Tag)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TagServiceServer).DeleteTag(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TagService_DeleteTag_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TagServiceServer).DeleteTag(ctx, req.(*Tag))
	}
	return interceptor(ctx, in, info, handler)
}

func _TagService_Subscribe_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Subscription)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TagServiceServer).Subscribe(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TagService_Subscribe_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TagServiceServer).Subscribe(ctx, req.(*Subscription))
	}
	return interceptor(ctx, in, info, handler)
}

func _TagService_Unsubscribe_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Subscription)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TagServiceServer).Unsubscribe(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TagService_Unsubscribe_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TagServiceServer).Unsubscribe(ctx, req.(*Subscription))
	}
	return interceptor(ctx, in, info, handler)
}

func _TagService_GetSubscribers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Tag)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TagServiceServer).GetSubscribers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TagService_GetSubscribers_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TagServiceServer).GetSubscribers(ctx, req.(*Tag))
	}
	return interceptor(ctx, in, info, handler)
}

// TagService_ServiceDesc is the grpc.ServiceDesc for TagService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TagService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "tagservicepb.TagService",
	HandlerType: (*TagServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SetTag",
			Handler:    _TagService_SetTag_Handler,
		},
		{
			MethodName: "GetTag",
			Handler:    _TagService_GetTag_Handler,
		},
		{
			MethodName: "ResolveTag",
			Handler:    _TagService_ResolveTag_Handler,
		},
		{
			MethodName: "DeleteTagMember",
			Handler:    _TagService_DeleteTagMember_Handler,
		},
		{
			MethodName: "DeleteTag",
			Handler:    _TagService_DeleteTag_Handler,
		},
		{
			MethodName: "Subscribe",
			Handler:    _TagService_Subscribe_Handler,
		},
		{
			MethodName: "Unsubscribe",
			Handler:    _TagService_Unsubscribe_Handler,
		},
		{
			MethodName: "GetSubscribers",
			Handler:    _TagService_GetSubscribers_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "tagservice.proto",
}
