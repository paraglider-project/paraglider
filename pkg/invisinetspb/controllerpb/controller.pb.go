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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.23.2
// source: controller.proto

package controllerpb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type FindUnusedAddressSpaceRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Namespace string `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
}

func (x *FindUnusedAddressSpaceRequest) Reset() {
	*x = FindUnusedAddressSpaceRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FindUnusedAddressSpaceRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FindUnusedAddressSpaceRequest) ProtoMessage() {}

func (x *FindUnusedAddressSpaceRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FindUnusedAddressSpaceRequest.ProtoReflect.Descriptor instead.
func (*FindUnusedAddressSpaceRequest) Descriptor() ([]byte, []int) {
	return file_controller_proto_rawDescGZIP(), []int{0}
}

func (x *FindUnusedAddressSpaceRequest) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

type FindUnusedAddressSpaceResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AddressSpace string `protobuf:"bytes,1,opt,name=address_space,json=addressSpace,proto3" json:"address_space,omitempty"`
}

func (x *FindUnusedAddressSpaceResponse) Reset() {
	*x = FindUnusedAddressSpaceResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FindUnusedAddressSpaceResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FindUnusedAddressSpaceResponse) ProtoMessage() {}

func (x *FindUnusedAddressSpaceResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FindUnusedAddressSpaceResponse.ProtoReflect.Descriptor instead.
func (*FindUnusedAddressSpaceResponse) Descriptor() ([]byte, []int) {
	return file_controller_proto_rawDescGZIP(), []int{1}
}

func (x *FindUnusedAddressSpaceResponse) GetAddressSpace() string {
	if x != nil {
		return x.AddressSpace
	}
	return ""
}

type AddressSpaceMapping struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AddressSpaces []string `protobuf:"bytes,1,rep,name=address_spaces,json=addressSpaces,proto3" json:"address_spaces,omitempty"`
	Cloud         string   `protobuf:"bytes,2,opt,name=cloud,proto3" json:"cloud,omitempty"`
	Namespace     string   `protobuf:"bytes,3,opt,name=namespace,proto3" json:"namespace,omitempty"`
}

func (x *AddressSpaceMapping) Reset() {
	*x = AddressSpaceMapping{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddressSpaceMapping) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddressSpaceMapping) ProtoMessage() {}

func (x *AddressSpaceMapping) ProtoReflect() protoreflect.Message {
	mi := &file_controller_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddressSpaceMapping.ProtoReflect.Descriptor instead.
func (*AddressSpaceMapping) Descriptor() ([]byte, []int) {
	return file_controller_proto_rawDescGZIP(), []int{2}
}

func (x *AddressSpaceMapping) GetAddressSpaces() []string {
	if x != nil {
		return x.AddressSpaces
	}
	return nil
}

func (x *AddressSpaceMapping) GetCloud() string {
	if x != nil {
		return x.Cloud
	}
	return ""
}

func (x *AddressSpaceMapping) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

type GetUsedAddressSpacesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Namespace string `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
}

func (x *GetUsedAddressSpacesRequest) Reset() {
	*x = GetUsedAddressSpacesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetUsedAddressSpacesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetUsedAddressSpacesRequest) ProtoMessage() {}

func (x *GetUsedAddressSpacesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetUsedAddressSpacesRequest.ProtoReflect.Descriptor instead.
func (*GetUsedAddressSpacesRequest) Descriptor() ([]byte, []int) {
	return file_controller_proto_rawDescGZIP(), []int{3}
}

func (x *GetUsedAddressSpacesRequest) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

type GetUsedAddressSpacesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AddressSpaceMappings []*AddressSpaceMapping `protobuf:"bytes,1,rep,name=address_space_mappings,json=addressSpaceMappings,proto3" json:"address_space_mappings,omitempty"`
}

func (x *GetUsedAddressSpacesResponse) Reset() {
	*x = GetUsedAddressSpacesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetUsedAddressSpacesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetUsedAddressSpacesResponse) ProtoMessage() {}

func (x *GetUsedAddressSpacesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetUsedAddressSpacesResponse.ProtoReflect.Descriptor instead.
func (*GetUsedAddressSpacesResponse) Descriptor() ([]byte, []int) {
	return file_controller_proto_rawDescGZIP(), []int{4}
}

func (x *GetUsedAddressSpacesResponse) GetAddressSpaceMappings() []*AddressSpaceMapping {
	if x != nil {
		return x.AddressSpaceMappings
	}
	return nil
}

type ConnectCloudsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CloudA             string `protobuf:"bytes,1,opt,name=cloudA,proto3" json:"cloudA,omitempty"`
	CloudB             string `protobuf:"bytes,2,opt,name=cloudB,proto3" json:"cloudB,omitempty"`
	CloudAAddressSpace string `protobuf:"bytes,3,opt,name=cloudAAddressSpace,proto3" json:"cloudAAddressSpace,omitempty"`
	CloudBAddressSpace string `protobuf:"bytes,4,opt,name=cloudBAddressSpace,proto3" json:"cloudBAddressSpace,omitempty"`
	CloudANamespace    string `protobuf:"bytes,5,opt,name=cloudANamespace,proto3" json:"cloudANamespace,omitempty"`
	CloudBNamespace    string `protobuf:"bytes,6,opt,name=cloudBNamespace,proto3" json:"cloudBNamespace,omitempty"`
}

func (x *ConnectCloudsRequest) Reset() {
	*x = ConnectCloudsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConnectCloudsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConnectCloudsRequest) ProtoMessage() {}

func (x *ConnectCloudsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConnectCloudsRequest.ProtoReflect.Descriptor instead.
func (*ConnectCloudsRequest) Descriptor() ([]byte, []int) {
	return file_controller_proto_rawDescGZIP(), []int{5}
}

func (x *ConnectCloudsRequest) GetCloudA() string {
	if x != nil {
		return x.CloudA
	}
	return ""
}

func (x *ConnectCloudsRequest) GetCloudB() string {
	if x != nil {
		return x.CloudB
	}
	return ""
}

func (x *ConnectCloudsRequest) GetCloudAAddressSpace() string {
	if x != nil {
		return x.CloudAAddressSpace
	}
	return ""
}

func (x *ConnectCloudsRequest) GetCloudBAddressSpace() string {
	if x != nil {
		return x.CloudBAddressSpace
	}
	return ""
}

func (x *ConnectCloudsRequest) GetCloudANamespace() string {
	if x != nil {
		return x.CloudANamespace
	}
	return ""
}

func (x *ConnectCloudsRequest) GetCloudBNamespace() string {
	if x != nil {
		return x.CloudBNamespace
	}
	return ""
}

type ConnectCloudsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ConnectCloudsResponse) Reset() {
	*x = ConnectCloudsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConnectCloudsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConnectCloudsResponse) ProtoMessage() {}

func (x *ConnectCloudsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConnectCloudsResponse.ProtoReflect.Descriptor instead.
func (*ConnectCloudsResponse) Descriptor() ([]byte, []int) {
	return file_controller_proto_rawDescGZIP(), []int{6}
}

var File_controller_proto protoreflect.FileDescriptor

var file_controller_proto_rawDesc = []byte{
	0x0a, 0x10, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x70, 0x62,
	0x22, 0x3d, 0x0a, 0x1d, 0x46, 0x69, 0x6e, 0x64, 0x55, 0x6e, 0x75, 0x73, 0x65, 0x64, 0x41, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x22,
	0x45, 0x0a, 0x1e, 0x46, 0x69, 0x6e, 0x64, 0x55, 0x6e, 0x75, 0x73, 0x65, 0x64, 0x41, 0x64, 0x64,
	0x72, 0x65, 0x73, 0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x23, 0x0a, 0x0d, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x73, 0x70, 0x61,
	0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x22, 0x70, 0x0a, 0x13, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x25, 0x0a,
	0x0e, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0d, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70,
	0x61, 0x63, 0x65, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61,
	0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e,
	0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x22, 0x3b, 0x0a, 0x1b, 0x47, 0x65, 0x74, 0x55,
	0x73, 0x65, 0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x73,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65,
	0x73, 0x70, 0x61, 0x63, 0x65, 0x22, 0x77, 0x0a, 0x1c, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x64,
	0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x57, 0x0a, 0x16, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x5f, 0x73, 0x70, 0x61, 0x63, 0x65, 0x5f, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x70, 0x62, 0x2e, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70, 0x61, 0x63,
	0x65, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x14, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x22, 0xfa,
	0x01, 0x0a, 0x14, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x6f, 0x75, 0x64, 0x73,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x63, 0x6c, 0x6f, 0x75, 0x64,
	0x41, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x41, 0x12,
	0x16, 0x0a, 0x06, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x42, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x42, 0x12, 0x2e, 0x0a, 0x12, 0x63, 0x6c, 0x6f, 0x75, 0x64,
	0x41, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x12, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x41, 0x41, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x12, 0x2e, 0x0a, 0x12, 0x63, 0x6c, 0x6f, 0x75, 0x64,
	0x42, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x12, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x42, 0x41, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x12, 0x28, 0x0a, 0x0f, 0x63, 0x6c, 0x6f, 0x75, 0x64,
	0x41, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x41, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63,
	0x65, 0x12, 0x28, 0x0a, 0x0f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x42, 0x4e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x63, 0x6c, 0x6f, 0x75,
	0x64, 0x42, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x22, 0x17, 0x0a, 0x15, 0x43,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x6f, 0x75, 0x64, 0x73, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x32, 0xd0, 0x02, 0x0a, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x12, 0x75, 0x0a, 0x16, 0x46, 0x69, 0x6e, 0x64, 0x55, 0x6e, 0x75, 0x73, 0x65,
	0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70, 0x61, 0x63, 0x65, 0x12, 0x2b, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x70, 0x62, 0x2e, 0x46, 0x69, 0x6e,
	0x64, 0x55, 0x6e, 0x75, 0x73, 0x65, 0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70,
	0x61, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2c, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x70, 0x62, 0x2e, 0x46, 0x69, 0x6e, 0x64, 0x55, 0x6e,
	0x75, 0x73, 0x65, 0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70, 0x61, 0x63, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x6f, 0x0a, 0x14, 0x47, 0x65,
	0x74, 0x55, 0x73, 0x65, 0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70, 0x61, 0x63,
	0x65, 0x73, 0x12, 0x29, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x70,
	0x62, 0x2e, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x53, 0x70, 0x61, 0x63, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2a, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x70, 0x62, 0x2e, 0x47, 0x65, 0x74,
	0x55, 0x73, 0x65, 0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x70, 0x61, 0x63, 0x65,
	0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x5a, 0x0a, 0x0d, 0x43,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x6f, 0x75, 0x64, 0x73, 0x12, 0x22, 0x2e, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x70, 0x62, 0x2e, 0x43, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x43, 0x6c, 0x6f, 0x75, 0x64, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x23, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x70, 0x62, 0x2e,
	0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x6f, 0x75, 0x64, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x3c, 0x5a, 0x3a, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4e, 0x65, 0x74, 0x53, 0x79, 0x73, 0x2f, 0x69, 0x6e, 0x76,
	0x69, 0x73, 0x69, 0x6e, 0x65, 0x74, 0x73, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x69, 0x6e, 0x76, 0x69,
	0x73, 0x69, 0x6e, 0x65, 0x74, 0x73, 0x70, 0x62, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_proto_rawDescOnce sync.Once
	file_controller_proto_rawDescData = file_controller_proto_rawDesc
)

func file_controller_proto_rawDescGZIP() []byte {
	file_controller_proto_rawDescOnce.Do(func() {
		file_controller_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_proto_rawDescData)
	})
	return file_controller_proto_rawDescData
}

var file_controller_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_controller_proto_goTypes = []interface{}{
	(*FindUnusedAddressSpaceRequest)(nil),  // 0: controllerpb.FindUnusedAddressSpaceRequest
	(*FindUnusedAddressSpaceResponse)(nil), // 1: controllerpb.FindUnusedAddressSpaceResponse
	(*AddressSpaceMapping)(nil),            // 2: controllerpb.AddressSpaceMapping
	(*GetUsedAddressSpacesRequest)(nil),    // 3: controllerpb.GetUsedAddressSpacesRequest
	(*GetUsedAddressSpacesResponse)(nil),   // 4: controllerpb.GetUsedAddressSpacesResponse
	(*ConnectCloudsRequest)(nil),           // 5: controllerpb.ConnectCloudsRequest
	(*ConnectCloudsResponse)(nil),          // 6: controllerpb.ConnectCloudsResponse
}
var file_controller_proto_depIdxs = []int32{
	2, // 0: controllerpb.GetUsedAddressSpacesResponse.address_space_mappings:type_name -> controllerpb.AddressSpaceMapping
	0, // 1: controllerpb.Controller.FindUnusedAddressSpace:input_type -> controllerpb.FindUnusedAddressSpaceRequest
	3, // 2: controllerpb.Controller.GetUsedAddressSpaces:input_type -> controllerpb.GetUsedAddressSpacesRequest
	5, // 3: controllerpb.Controller.ConnectClouds:input_type -> controllerpb.ConnectCloudsRequest
	1, // 4: controllerpb.Controller.FindUnusedAddressSpace:output_type -> controllerpb.FindUnusedAddressSpaceResponse
	4, // 5: controllerpb.Controller.GetUsedAddressSpaces:output_type -> controllerpb.GetUsedAddressSpacesResponse
	6, // 6: controllerpb.Controller.ConnectClouds:output_type -> controllerpb.ConnectCloudsResponse
	4, // [4:7] is the sub-list for method output_type
	1, // [1:4] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_controller_proto_init() }
func file_controller_proto_init() {
	if File_controller_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FindUnusedAddressSpaceRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FindUnusedAddressSpaceResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AddressSpaceMapping); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetUsedAddressSpacesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetUsedAddressSpacesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConnectCloudsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConnectCloudsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controller_proto_goTypes,
		DependencyIndexes: file_controller_proto_depIdxs,
		MessageInfos:      file_controller_proto_msgTypes,
	}.Build()
	File_controller_proto = out.File
	file_controller_proto_rawDesc = nil
	file_controller_proto_goTypes = nil
	file_controller_proto_depIdxs = nil
}
