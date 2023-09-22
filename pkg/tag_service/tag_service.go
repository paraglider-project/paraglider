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
	"net/netip"
	"strings"

	redis "github.com/redis/go-redis/v9"
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	
	"google.golang.org/grpc"
)

type tagServiceServer struct {
	tagservicepb.UnimplementedTagServiceServer
	client *redis.Client
}

func (s *tagServiceServer) SetTag(c context.Context, mapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error){
	err := s.client.SAdd(c, mapping.ParentTag, mapping.ChildTags).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetTag: %v", err)
	}

    return  &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Created/updated tag: %s", mapping.ParentTag)}, nil
}

func (s *tagServiceServer) SetName(c context.Context, mapping *tagservicepb.NameMapping) (*tagservicepb.BasicResponse, error){
	// TODO: Make it so that you can only set the name once
	err := s.client.HSet(c, mapping.TagName, map[string]string{"uri": mapping.Uri, "ip": mapping.Ip}).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetName: %v", err)
	}

    return  &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Created/updated name: %s", mapping.TagName)}, nil
}

func (s *tagServiceServer) GetTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.TagMapping, error){
	childrenTags, err := s.client.SMembers(c, tag.TagName).Result()
	if err != nil {
		return nil, fmt.Errorf("GetTag %s: %v", tag.TagName, err)
	}
    return &tagservicepb.TagMapping{ParentTag: tag.TagName, ChildTags: childrenTags}, nil
}

func isIpAddrOrCidr(value string) bool {
	if strings.Contains(value, "/") {
		_, err := netip.ParsePrefix(value)
		if err != nil {
			return false
		}
		return true
	} else {
		_, err := netip.ParseAddr(value)
		if err != nil {
			return false
		}
		return true
	}
}

func (s *tagServiceServer) _resolveTags(c context.Context, tags []string, resolvedTags []*tagservicepb.NameMapping) ([]*tagservicepb.NameMapping, error){
	for _, tag := range tags {
		isIp := isIpAddrOrCidr(tag)
		if isIp {
			ip_tag := &tagservicepb.NameMapping{TagName: "", Uri: "", Ip: tag}
			resolvedTags = append(resolvedTags, ip_tag)
		} else {
			valType, err := s.client.Type(c, tag).Result()
			if err != nil {
				return nil, fmt.Errorf("ResolveTag TYPE %s: %v", tag, err)
			}

			if valType == "none" {
				return nil, fmt.Errorf("Tried to resolve non-existing tag %s", tag)
			} else if valType ==  "hash" {
				info, err := s.client.HGetAll(c, tag).Result()
				if err != nil {
					return nil, fmt.Errorf("ResolveTag HGETALL %s: %v", tag, err)
				}
				resolvedTags = append(resolvedTags, &tagservicepb.NameMapping{TagName: tag, Uri: info["uri"], Ip: info["ip"]})
			} else {
				childrenTags, err := s.client.SMembers(c, tag).Result()
				if err != nil {
					return nil, fmt.Errorf("ResolveTag SMEMBERS %s: %v", tag, err)
				}

				resolvedChildTags, err := s._resolveTags(c, childrenTags, resolvedTags)
				if err != nil {
					return nil, fmt.Errorf("ResolveTag %s: %v", tag, err)
				}
				resolvedTags = append(resolvedTags, resolvedChildTags...)
			}
		}
	}
	return resolvedTags, nil
}

func (s *tagServiceServer) ResolveTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.NameMappingList, error){
	var emptyTagList []*tagservicepb.NameMapping
	resolvedTags, err := s._resolveTags(c, []string{tag.TagName}, emptyTagList)
	if err != nil {
		return nil, err
	}

    return &tagservicepb.NameMappingList{Mappings: resolvedTags}, nil
}

func (s *tagServiceServer) DeleteTagMember(c context.Context, mapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error){
	err := s.client.SRem(c, mapping.ParentTag, mapping.ChildTags).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("DeleteTagMember %s: %v", mapping.ParentTag, err)
	}
    return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Deleted members from tag: %s", mapping.ParentTag)}, nil
}

func (s *tagServiceServer) DeleteTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.BasicResponse, error){
	// TODO: Delete the subscription of the tag too
	childrenTags, err := s.client.SMembers(c, tag.TagName).Result()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("DeleteTag %s: %v", tag.TagName, err)
	}

	err = s.client.SRem(c, tag.TagName, childrenTags).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("DeleteTag %s: %v", tag.TagName, err)
	}
    return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Deleted tag: %s", tag.TagName)}, nil
}

func (s *tagServiceServer) DeleteName(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.BasicResponse, error){
	keys, err := s.client.HKeys(c, tag.TagName).Result()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("DeleteName %s: %v", tag.TagName, err)
	}

	err = s.client.HDel(c, tag.TagName, keys...).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("DeleteName %s: %v", tag.TagName, err)
	}
    return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Deleted name: %s", tag.TagName)}, nil
}

func (s *tagServiceServer) Subscribe(c context.Context, sub *tagservicepb.Subscription) (*tagservicepb.BasicResponse, error){
	err := s.client.SAdd(c, "SUB:"+sub.TagName, sub.Subscriber).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("Subscribe: %v", err)
	}

    return  &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Subscribed %s to tag %s", sub.Subscriber, sub.TagName)}, nil
}

func (s *tagServiceServer) Unsubscribe(c context.Context, sub *tagservicepb.Subscription) (*tagservicepb.BasicResponse, error){
	err := s.client.SRem(c, "SUB:"+sub.TagName, sub.Subscriber).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("Unsubscribe: %v", err)
	}

    return  &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Unsubscribed %s from tag %s", sub.Subscriber, sub.TagName)}, nil
}

func newServer(database *redis.Client) *tagServiceServer {
	s := &tagServiceServer{client: database}
	return s
}

func Setup(dbPort int, serverPort int, clearKeys bool) {
	client := redis.NewClient(&redis.Options{
        Addr:	  fmt.Sprintf("localhost:%d", dbPort),
        Password: "", // no password set
        DB:		  0,  // use default DB
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
	tagservicepb.RegisterTagServiceServer(grpcServer, newServer(client))
	fmt.Printf("Serving TagService at localhost:%d", serverPort)
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}


