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

package tagservice

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/paraglider-project/paraglider/pkg/tag_service/tagservicepb"
	"google.golang.org/grpc"
)

const (
	ValidTagName          = "validTagName"
	ValidLastLevelTagName = "validLastLevelTagName"
	ValidParentTagName    = "validParentTagName"
)

var (
	TagUri              = "uri"
	TagIp               = "ip"
	ResolvedTagIp       = "1.2.3.4"
	SubscriberCloudName = "cloudName"
	SubscriberNamespace = "default"
)

type FakeTagServiceServer struct {
	tagservicepb.UnimplementedTagServiceServer
}

func (s *FakeTagServiceServer) GetTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.TagMapping, error) {
	if strings.HasPrefix(tag.TagName, ValidLastLevelTagName) {
		return &tagservicepb.TagMapping{TagName: tag.TagName, Uri: &TagUri, Ip: &TagIp}, nil
	}
	if strings.HasPrefix(tag.TagName, ValidParentTagName) {
		return &tagservicepb.TagMapping{TagName: tag.TagName, ChildTags: []string{"child"}}, nil
	}
	if strings.HasSuffix(tag.TagName, ValidLastLevelTagName) {
		return &tagservicepb.TagMapping{TagName: tag.TagName, Uri: &TagUri, Ip: &TagIp}, nil
	}
	return nil, fmt.Errorf("GetTag: Invalid tag name")
}

func (s *FakeTagServiceServer) ResolveTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.TagMappingList, error) {
	if strings.HasPrefix(tag.TagName, ValidTagName) {
		newUri := "uri/" + tag.TagName
		return &tagservicepb.TagMappingList{Mappings: []*tagservicepb.TagMapping{{TagName: tag.TagName, Uri: &newUri, Ip: &ResolvedTagIp}}}, nil
	}
	return nil, fmt.Errorf("ResolveTag: Invalid tag name")
}

func (s *FakeTagServiceServer) SetTag(c context.Context, tagMapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error) {
	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully created tag: %s", tagMapping.TagName)}, nil
}

func (s *FakeTagServiceServer) DeleteTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.BasicResponse, error) {
	if strings.HasPrefix(tag.TagName, ValidTagName) {
		return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully deleted tag: %s", tag.TagName)}, nil
	}
	return &tagservicepb.BasicResponse{Success: false, Message: fmt.Sprintf("tag %s does not exist", tag.TagName)}, fmt.Errorf("tag does not exist")
}

func (s *FakeTagServiceServer) DeleteTagMember(c context.Context, tagMapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error) {
	if strings.HasPrefix(tagMapping.TagName, ValidTagName) {
		return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully deleted member %s from tag %s", tagMapping.ChildTags[0], tagMapping.TagName)}, nil
	}
	return &tagservicepb.BasicResponse{Success: false, Message: "parent tag does not exist"}, fmt.Errorf("parentTag does not exist")
}

func (s *FakeTagServiceServer) Subscribe(c context.Context, sub *tagservicepb.Subscription) (*tagservicepb.BasicResponse, error) {
	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully subscribed to tag: %s", sub.TagName)}, nil
}

func (s *FakeTagServiceServer) Unsubscribe(c context.Context, sub *tagservicepb.Subscription) (*tagservicepb.BasicResponse, error) {
	if strings.HasPrefix(sub.TagName, ValidTagName) {
		return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("successfully unsubscribed from tag: %s", sub.TagName)}, nil
	}
	return &tagservicepb.BasicResponse{Success: false, Message: fmt.Sprintf("no subscriptions for tag: %s", sub.TagName)}, fmt.Errorf("tag has no subscribers")
}

func (s *FakeTagServiceServer) GetSubscribers(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.SubscriberList, error) {
	if strings.HasPrefix(tag.TagName, ValidTagName) {
		return &tagservicepb.SubscriberList{Subscribers: []string{SubscriberNamespace + ">" + SubscriberCloudName + ">uri"}}, nil
	}
	return nil, fmt.Errorf("tag does not exist")
}

func NewFakeTagServer() *FakeTagServiceServer {
	s := &FakeTagServiceServer{}
	return s
}

func SetupFakeTagServer(port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	tagservicepb.RegisterTagServiceServer(grpcServer, NewFakeTagServer())
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Println(err.Error())
		}
	}()
}
