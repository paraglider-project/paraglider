/*
Copyright 2023 The Paraglider Authors.

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

func (s *FakeTagServiceServer) GetTag(c context.Context, req *tagservicepb.GetTagRequest) (*tagservicepb.GetTagResponse, error) {
	if strings.HasPrefix(req.TagName, ValidLastLevelTagName) {
		return &tagservicepb.GetTagResponse{Tag: &tagservicepb.TagMapping{Name: req.TagName, Uri: &TagUri, Ip: &TagIp}}, nil
	}
	if strings.HasPrefix(req.TagName, ValidParentTagName) {
		return &tagservicepb.GetTagResponse{Tag: &tagservicepb.TagMapping{Name: req.TagName, ChildTags: []string{"child"}}}, nil
	}
	if strings.HasSuffix(req.TagName, ValidLastLevelTagName) {
		return &tagservicepb.GetTagResponse{Tag: &tagservicepb.TagMapping{Name: req.TagName, Uri: &TagUri, Ip: &TagIp}}, nil
	}
	return nil, fmt.Errorf("GetTag: Invalid tag name")
}

func (s *FakeTagServiceServer) ResolveTag(c context.Context, req *tagservicepb.ResolveTagRequest) (*tagservicepb.ResolveTagResponse, error) {
	if strings.HasPrefix(req.TagName, ValidTagName) {
		newUri := "uri/" + req.TagName
		return &tagservicepb.ResolveTagResponse{Tags: []*tagservicepb.TagMapping{{Name: req.TagName, Uri: &newUri, Ip: &ResolvedTagIp}}}, nil
	}
	return nil, fmt.Errorf("ResolveTag: Invalid tag name")
}

func (s *FakeTagServiceServer) SetTag(c context.Context, tagMapping *tagservicepb.SetTagRequest) (*tagservicepb.SetTagResponse, error) {
	return &tagservicepb.SetTagResponse{}, nil
}

func (s *FakeTagServiceServer) DeleteTag(c context.Context, req *tagservicepb.DeleteTagRequest) (*tagservicepb.DeleteTagResponse, error) {
	if strings.HasPrefix(req.TagName, ValidTagName) {
		return &tagservicepb.DeleteTagResponse{}, nil
	}
	return &tagservicepb.DeleteTagResponse{}, fmt.Errorf("tag does not exist")
}

func (s *FakeTagServiceServer) DeleteTagMember(c context.Context, req *tagservicepb.DeleteTagMemberRequest) (*tagservicepb.DeleteTagMemberResponse, error) {
	if strings.HasPrefix(req.ParentTag, ValidTagName) {
		return &tagservicepb.DeleteTagMemberResponse{}, nil
	}
	return &tagservicepb.DeleteTagMemberResponse{}, fmt.Errorf("parentTag does not exist")
}

func (s *FakeTagServiceServer) Subscribe(c context.Context, req *tagservicepb.SubscribeRequest) (*tagservicepb.SubscribeResponse, error) {
	return &tagservicepb.SubscribeResponse{}, nil
}

func (s *FakeTagServiceServer) Unsubscribe(c context.Context, req *tagservicepb.UnsubscribeRequest) (*tagservicepb.UnsubscribeResponse, error) {
	if strings.HasPrefix(req.Subscription.TagName, ValidTagName) {
		return &tagservicepb.UnsubscribeResponse{}, nil
	}
	return &tagservicepb.UnsubscribeResponse{}, fmt.Errorf("tag has no subscribers")
}

func (s *FakeTagServiceServer) GetSubscribers(c context.Context, req *tagservicepb.GetSubscribersRequest) (*tagservicepb.GetSubscribersResponse, error) {
	if strings.HasPrefix(req.TagName, ValidTagName) {
		return &tagservicepb.GetSubscribersResponse{Subscribers: []string{SubscriberNamespace + ">" + SubscriberCloudName + ">uri"}}, nil
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
