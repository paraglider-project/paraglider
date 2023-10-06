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

	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
	redis "github.com/redis/go-redis/v9"

	"google.golang.org/grpc"
)

type tagServiceServer struct {
	tagservicepb.UnimplementedTagServiceServer
	client *redis.Client
}

func getSubscriptionKey(tagName string) string {
	return "SUB:" + tagName
}

// Returns true if the string is a valid IP or CIDR
func isIpAddrOrCidr(value string) bool {
	if strings.Contains(value, "/") {
		_, err := netip.ParsePrefix(value)
		return err == nil
	} else {
		_, err := netip.ParseAddr(value)
		return err == nil
	}
}

// Determines if a tag is a descendent of another tag
func (s *tagServiceServer) isDescendent(c context.Context, tag string, potentialChild string) (bool, error) {
	// Only do SMEMBERS if the tag is a set, otherwise it cannot be a parent
	valType, err := s.client.Type(c, tag).Result()
	if err != nil {
		return false, fmt.Errorf("isDescendent TYPE %s: %v", tag, err)
	}
	if valType != "set" {
		return false, nil
	}

	childrenTags, err := s.client.SMembers(c, tag).Result()
	if err != nil {
		return false, fmt.Errorf("isDescendent %s: %v", tag, err)
	}
	for _, child := range childrenTags {
		if child == potentialChild {
			return true, nil
		}
		isDescendent, err := s.isDescendent(c, child, potentialChild)
		if err != nil {
			return false, fmt.Errorf("isDescendent %s: %v", tag, err)
		}
		if isDescendent {
			return true, nil
		}
	}
	return false, nil
}

// Set tag relationship by adding child tag to parent tag's set
func (s *tagServiceServer) SetTag(c context.Context, mapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error) {
	// Prevent cycles by checking if the parent tag is a descendent of any child tags
	for _, child := range mapping.ChildTags {
		parentTagIsDescendent, err := s.isDescendent(c, child, mapping.ParentTag)
		if err != nil {
			return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetTag: %v", err)
		}
		if parentTagIsDescendent {
			return &tagservicepb.BasicResponse{Success: false, Message: fmt.Sprintf("Cannot set tag %s as a child of %s (cycle).", child, mapping.ParentTag)}, nil
		}
	}

	// Add the tags
	err := s.client.SAdd(c, mapping.ParentTag, mapping.ChildTags).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetTag: %v", err)
	}

	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Created/updated tag: %s", mapping.ParentTag)}, nil
}

// Record name tag by storing mapping to URI and IP
func (s *tagServiceServer) SetName(c context.Context, mapping *tagservicepb.NameMapping) (*tagservicepb.BasicResponse, error) {
	// TODO @smcclure20: Make it so that you can only set the name once
	err := s.client.HSet(c, mapping.TagName, map[string]string{"uri": mapping.Uri, "ip": mapping.Ip}).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetName: %v", err)
	}

	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Created/updated name: %s", mapping.TagName)}, nil
}

// Get the members of a tag
func (s *tagServiceServer) GetTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.TagMapping, error) {
	childrenTags, err := s.client.SMembers(c, tag.TagName).Result()
	if err != nil {
		return nil, fmt.Errorf("GetTag %s: %v", tag.TagName, err)
	}
	return &tagservicepb.TagMapping{ParentTag: tag.TagName, ChildTags: childrenTags}, nil
}

// Resolve a list of tags into all base-level IPs
func (s *tagServiceServer) _resolveTags(c context.Context, tags []string, resolvedTags []*tagservicepb.NameMapping) ([]*tagservicepb.NameMapping, error) {
	for _, tag := range tags {
		// If the tag is an IP, it is already resolved
		isIp := isIpAddrOrCidr(tag)
		if isIp {
			ip_tag := &tagservicepb.NameMapping{TagName: "", Uri: "", Ip: tag}
			resolvedTags = append(resolvedTags, ip_tag)
		} else {
			// Get the tag record type since may be hash (if name value) or set (if parent tag)
			valType, err := s.client.Type(c, tag).Result()
			if err != nil {
				return nil, fmt.Errorf("ResolveTag TYPE %s: %v", tag, err)
			}

			if valType == "none" { // The tag is not present
				continue
			} else if valType == "hash" { // The tag is a name record
				info, err := s.client.HGetAll(c, tag).Result()
				if err != nil {
					return nil, fmt.Errorf("ResolveTag HGETALL %s: %v", tag, err)
				}
				resolvedTags = append(resolvedTags, &tagservicepb.NameMapping{TagName: tag, Uri: info["uri"], Ip: info["ip"]})
			} else { // The tag has children that may also need resolved
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

// Resolve a tag down to all the IPs in it
func (s *tagServiceServer) ResolveTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.NameMappingList, error) {
	var emptyTagList []*tagservicepb.NameMapping
	resolvedTags, err := s._resolveTags(c, []string{tag.TagName}, emptyTagList)
	if err != nil {
		return nil, err
	}

	return &tagservicepb.NameMappingList{Mappings: resolvedTags}, nil
}

// Delete a member of a tag
func (s *tagServiceServer) DeleteTagMember(c context.Context, mapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error) {
	err := s.client.SRem(c, mapping.ParentTag, mapping.ChildTags).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("DeleteTagMember %s: %v", mapping.ParentTag, err)
	}
	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Deleted members from tag: %s", mapping.ParentTag)}, nil
}

// Delete a tag and its relationship to its children tags
func (s *tagServiceServer) DeleteTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.BasicResponse, error) {
	// Delete all children in mapping
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

// Delete a name record for a tag
func (s *tagServiceServer) DeleteName(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.BasicResponse, error) {
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

// Subscribe to a tag
func (s *tagServiceServer) Subscribe(c context.Context, sub *tagservicepb.Subscription) (*tagservicepb.BasicResponse, error) {
	err := s.client.SAdd(c, getSubscriptionKey(sub.TagName), sub.Subscriber).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("Subscribe: %v", err)
	}

	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Subscribed %s to tag %s", sub.Subscriber, sub.TagName)}, nil
}

// Unsubscribe from a tag
func (s *tagServiceServer) Unsubscribe(c context.Context, sub *tagservicepb.Subscription) (*tagservicepb.BasicResponse, error) {
	err := s.client.SRem(c, getSubscriptionKey(sub.TagName), sub.Subscriber).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("Unsubscribe: %v", err)
	}

	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Unsubscribed %s from tag %s", sub.Subscriber, sub.TagName)}, nil
}

// Get all subscribers to a tag
func (s *tagServiceServer) GetSubscribers(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.SubscriberList, error) {
	subs, err := s.client.SMembers(c, getSubscriptionKey(tag.TagName)).Result()
	if err != nil {
		return nil, fmt.Errorf("GetSubscribers: %v", err)
	}

	return &tagservicepb.SubscriberList{Subscribers: subs}, nil
}

// Create a server for the tag service
func newServer(database *redis.Client) *tagServiceServer {
	s := &tagServiceServer{client: database}
	return s
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
	tagservicepb.RegisterTagServiceServer(grpcServer, newServer(client))
	fmt.Printf("Serving TagService at localhost:%d", serverPort)
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}
