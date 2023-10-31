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

func isLeafTagMapping(mapping *tagservicepb.TagMapping) (bool, error) {
	hasChildren := len(mapping.ChildTags) > 0
	hasUriOrIp := mapping.Uri != nil || mapping.Ip != nil
	if hasChildren && hasUriOrIp {
		return false, fmt.Errorf("TagMapping %s has both children and URI/IP", mapping.TagName)
	}

	return !hasChildren && hasUriOrIp, nil
}

func (s *tagServiceServer) isLeafTag(c context.Context, tag *tagservicepb.Tag) (bool, error) {
	recordType, err := s.client.Type(c, tag.TagName).Result()
	if err != nil {
		return false, fmt.Errorf("isLeafTag TYPE %s: %v", tag.TagName, err)
	}
	return recordType == "hash", nil
}

// Record tag by storing mapping to URI and IP
func (s *tagServiceServer) _setLeafTag(c context.Context, mapping *tagservicepb.TagMapping) error {
	// TODO @smcclure20: Make it so that you can only set the leaf tag once?
	err := s.client.HSet(c, mapping.TagName, map[string]string{"uri": *mapping.Uri, "ip": *mapping.Ip}).Err()
	if err != nil {
		return err
	}
	return nil
}

// Set tag relationship by adding child tag to parent tag's set
func (s *tagServiceServer) SetTag(c context.Context, mapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error) {
	// If tag is leaf entry (no children), set as a hash record and return
	isLeaf, err := isLeafTagMapping(mapping)
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetTag: %v", err)
	}
	if isLeaf {
		err := s._setLeafTag(c, mapping)
		if err != nil {
			return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetTag: %v", err)
		}
		return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Created/updated tag: %s", mapping.TagName)}, nil
	}

	// If tag is not leaf entry, set as a set record and return
	// Prevent cycles by checking if the parent tag is a descendent of any child tags
	for _, child := range mapping.ChildTags {
		parentTagIsDescendent, err := s.isDescendent(c, child, mapping.TagName)
		if err != nil {
			return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetTag: %v", err)
		}
		if parentTagIsDescendent {
			return &tagservicepb.BasicResponse{Success: false, Message: fmt.Sprintf("Cannot set tag %s as a child of %s (cycle).", child, mapping.TagName)}, nil
		}
	}

	// Add the tags
	err = s.client.SAdd(c, mapping.TagName, mapping.ChildTags).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("SetTag: %v", err)
	}

	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Created/updated tag: %s", mapping.TagName)}, nil
}

// Get the members of a tag
func (s *tagServiceServer) GetTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.TagMapping, error) {
	// Determine if the tag is a leaf tag or not
	isLeaf, err := s.isLeafTag(c, &tagservicepb.Tag{TagName: tag.TagName})
	if err != nil {
		return nil, fmt.Errorf("GetTag %s: %v", tag.TagName, err)
	}

	// If it is, retrieve the hash record
	if isLeaf {
		info, err := s.client.HGetAll(c, tag.TagName).Result()
		if err != nil {
			return nil, fmt.Errorf("GetTag %s: %v", tag.TagName, err)
		}
		uri := info["uri"]
		ip := info["ip"]
		return &tagservicepb.TagMapping{TagName: tag.TagName, Uri: &uri, Ip: &ip}, nil
	}

	// Otherwise, retrieve set of child tags
	childrenTags, err := s.client.SMembers(c, tag.TagName).Result()
	if err != nil {
		return nil, fmt.Errorf("GetTag %s: %v", tag.TagName, err)
	}
	return &tagservicepb.TagMapping{TagName: tag.TagName, ChildTags: childrenTags}, nil
}

// Resolve a list of tags into all base-level IPs
func (s *tagServiceServer) _resolveTags(c context.Context, tags []string, resolvedTags []*tagservicepb.TagMapping) ([]*tagservicepb.TagMapping, error) {
	for _, tag := range tags {
		// If the tag is an IP, it is already resolved
		isIp := isIpAddrOrCidr(tag)
		if isIp {
			ip_tag := &tagservicepb.TagMapping{TagName: "", Uri: nil, Ip: &tag}
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
				uri := info["uri"]
				ip := info["ip"]
				resolvedTags = append(resolvedTags, &tagservicepb.TagMapping{TagName: tag, Uri: &uri, Ip: &ip})
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
func (s *tagServiceServer) ResolveTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.TagMappingList, error) {
	var emptyTagList []*tagservicepb.TagMapping
	resolvedTags, err := s._resolveTags(c, []string{tag.TagName}, emptyTagList)
	if err != nil {
		return nil, err
	}

	return &tagservicepb.TagMappingList{Mappings: resolvedTags}, nil
}

// Delete a member of a tag
func (s *tagServiceServer) DeleteTagMember(c context.Context, mapping *tagservicepb.TagMapping) (*tagservicepb.BasicResponse, error) {
	err := s.client.SRem(c, mapping.TagName, mapping.ChildTags).Err()
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("DeleteTagMember %s: %v", mapping.TagName, err)
	}
	return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Deleted members from tag: %s", mapping.TagName)}, nil
}

// Delete a leaf record for a tag
func (s *tagServiceServer) _deleteLeafTag(c context.Context, tag *tagservicepb.Tag) error {
	keys, err := s.client.HKeys(c, tag.TagName).Result()
	if err != nil {
		return err
	}

	err = s.client.HDel(c, tag.TagName, keys...).Err()
	if err != nil {
		return err
	}
	return nil
}

// Delete a tag and its relationship to its children tags
func (s *tagServiceServer) DeleteTag(c context.Context, tag *tagservicepb.Tag) (*tagservicepb.BasicResponse, error) {
	// If the tag is a leaf tag, delete the hash record
	isLeaf, err := s.isLeafTag(c, tag)
	if err != nil {
		return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("DeleteTag %s: %v", tag.TagName, err)
	}
	if isLeaf {
		err := s._deleteLeafTag(c, tag)
		if err != nil {
			return &tagservicepb.BasicResponse{Success: false, Message: err.Error()}, fmt.Errorf("DeleteTag %s: %v", tag.TagName, err)
		}
		return &tagservicepb.BasicResponse{Success: true, Message: fmt.Sprintf("Deleted tag: %s", tag.TagName)}, nil
	}

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
		log.Fatalf("[TAG SERVICE] failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	tagservicepb.RegisterTagServiceServer(grpcServer, newServer(client))
	fmt.Printf("[TAG SERVICE] Serving TagService at localhost:%d", serverPort)
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}
