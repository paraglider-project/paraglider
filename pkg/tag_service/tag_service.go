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
	"net/netip"
	"os/exec"
	"strings"

	tagservicepb "github.com/paraglider-project/paraglider/pkg/tag_service/tagservicepb"
	utils "github.com/paraglider-project/paraglider/pkg/utils"
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

func isLeafTagMapping(tag *tagservicepb.TagMapping) (bool, error) {
	hasChildren := len(tag.ChildTags) > 0
	hasUriOrIp := tag.Uri != nil || tag.Ip != nil
	if hasChildren && hasUriOrIp {
		return false, fmt.Errorf("TagMapping %s has both children and URI/IP", tag.Name)
	}

	return !hasChildren && hasUriOrIp, nil
}

func (s *tagServiceServer) isLeafTag(c context.Context, tag string) (bool, error) {
	recordType, err := s.client.Type(c, tag).Result()
	if err != nil {
		return false, fmt.Errorf("isLeafTag TYPE %s: %v", tag, err)
	}
	return recordType == "hash", nil
}

// Record tag by storing mapping to URI and IP
func (s *tagServiceServer) _setLeafTag(c context.Context, tag *tagservicepb.TagMapping) error {
	exists, err := s.client.HExists(c, tag.Name, "uri").Result()
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("Cannot set tag %s as a leaf tag because it already exists.", tag.Name)
	}

	uri := ""
	if tag.Uri != nil {
		uri = *tag.Uri
	}
	ip := ""
	if tag.Ip != nil {
		ip = *tag.Ip
	}

	err = s.client.HSet(c, tag.Name, map[string]string{"uri": uri, "ip": ip}).Err()
	if err != nil {
		return err
	}
	return nil
}

// Set tag relationship by adding child tag to parent tag's set
func (s *tagServiceServer) SetTag(c context.Context, req *tagservicepb.SetTagRequest) (*tagservicepb.SetTagResponse, error) {
	// If tag is leaf entry (no children), set as a hash record and return
	isLeaf, err := isLeafTagMapping(req.Tag)
	if err != nil {
		return &tagservicepb.SetTagResponse{}, fmt.Errorf("SetTag: %v", err)
	}
	if isLeaf {
		err := s._setLeafTag(c, req.Tag)
		if err != nil {
			return &tagservicepb.SetTagResponse{}, fmt.Errorf("SetTag: %v", err)
		}
		return &tagservicepb.SetTagResponse{}, nil
	}

	// If tag is not leaf entry, set as a set record and return
	// Prevent cycles by checking if the parent tag is a descendent of any child tags
	for _, child := range req.Tag.ChildTags {
		parentTagIsDescendent, err := s.isDescendent(c, child, req.Tag.Name)
		if err != nil {
			return &tagservicepb.SetTagResponse{}, fmt.Errorf("SetTag: %v", err)
		}
		if parentTagIsDescendent {
			return &tagservicepb.SetTagResponse{}, nil
		}
	}

	// Add the tags
	err = s.client.SAdd(c, req.Tag.Name, req.Tag.ChildTags).Err()
	if err != nil {
		return &tagservicepb.SetTagResponse{}, fmt.Errorf("SetTag: %v", err)
	}

	return &tagservicepb.SetTagResponse{}, nil
}

// Get the members of a tag
func (s *tagServiceServer) GetTag(c context.Context, req *tagservicepb.GetTagRequest) (*tagservicepb.GetTagResponse, error) {
	// Determine if the tag is a leaf tag or not
	isLeaf, err := s.isLeafTag(c, req.TagName)
	if err != nil {
		return nil, fmt.Errorf("GetTag %s: %v", req.TagName, err)
	}

	// If it is, retrieve the hash record
	if isLeaf {
		info, err := s.client.HGetAll(c, req.TagName).Result()
		if err != nil {
			return nil, fmt.Errorf("GetTag %s: %v", req.TagName, err)
		}
		uri := info["uri"]
		ip := info["ip"]
		return &tagservicepb.GetTagResponse{Tag: &tagservicepb.TagMapping{Name: req.TagName, Uri: &uri, Ip: &ip}}, nil
	}

	// Otherwise, retrieve set of child tags
	childrenTags, err := s.client.SMembers(c, req.TagName).Result()
	if err != nil {
		return nil, fmt.Errorf("GetTag %s: %v", req.TagName, err)
	}
	return &tagservicepb.GetTagResponse{Tag: &tagservicepb.TagMapping{Name: req.TagName, ChildTags: childrenTags}}, nil
}

// Resolve a list of tags into all base-level IPs
func (s *tagServiceServer) _resolveTags(c context.Context, tags []string, resolvedTags []*tagservicepb.TagMapping) ([]*tagservicepb.TagMapping, error) {
	for _, tag := range tags {
		// If the tag is an IP, it is already resolved
		isIP := isIpAddrOrCidr(tag)
		if isIP {
			ipTag := &tagservicepb.TagMapping{Name: "", Uri: nil, Ip: &tag}
			resolvedTags = append(resolvedTags, ipTag)
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
				resolvedTags = append(resolvedTags, &tagservicepb.TagMapping{Name: tag, Uri: &uri, Ip: &ip})
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
func (s *tagServiceServer) ResolveTag(c context.Context, req *tagservicepb.ResolveTagRequest) (*tagservicepb.ResolveTagResponse, error) {
	var emptyTagList []*tagservicepb.TagMapping
	resolvedTags, err := s._resolveTags(c, []string{req.TagName}, emptyTagList)
	if err != nil {
		return nil, err
	}

	return &tagservicepb.ResolveTagResponse{Tags: resolvedTags}, nil
}

// Resolve a list of tags into all base-level IPs
func (s *tagServiceServer) ListTags(c context.Context, req *tagservicepb.ListTagsRequest) (*tagservicepb.ListTagsResponse, error) {
	var resolvedTagList []*tagservicepb.TagMapping
	tags := s.client.Keys(c, "*").Val()
	for _, tag := range tags {
		resp, err := s.GetTag(c, &tagservicepb.GetTagRequest{TagName: tag})
		if err != nil {
			// Ignore errors
			utils.Log.Printf("Failed to get tag mapping of %s: %v\n", tag, err)
			continue
		}
		resolvedTagList = append(resolvedTagList, resp.Tag)
	}

	return &tagservicepb.ListTagsResponse{Tags: resolvedTagList}, nil
}

// Delete a member of a tag
func (s *tagServiceServer) DeleteTagMember(c context.Context, req *tagservicepb.DeleteTagMemberRequest) (*tagservicepb.DeleteTagMemberResponse, error) {
	err := s.client.SRem(c, req.ParentTag, req.ChildTag).Err()
	if err != nil {
		return &tagservicepb.DeleteTagMemberResponse{}, fmt.Errorf("DeleteTagMember %s: %v", req.ParentTag, err)
	}
	return &tagservicepb.DeleteTagMemberResponse{}, nil
}

// Delete a leaf record for a tag
func (s *tagServiceServer) _deleteLeafTag(c context.Context, tag *tagservicepb.TagMapping) error {
	keys, err := s.client.HKeys(c, tag.Name).Result()
	if err != nil {
		return err
	}

	err = s.client.HDel(c, tag.Name, keys...).Err()
	if err != nil {
		return err
	}
	return nil
}

// Delete a tag and its relationship to its children tags
func (s *tagServiceServer) DeleteTag(c context.Context, req *tagservicepb.DeleteTagRequest) (*tagservicepb.DeleteTagResponse, error) {
	// If the tag is a leaf tag, delete the hash record
	isLeaf, err := s.isLeafTag(c, req.TagName)
	if err != nil {
		return &tagservicepb.DeleteTagResponse{}, fmt.Errorf("DeleteTag %s: %v", req.TagName, err)
	}
	if isLeaf {
		err := s._deleteLeafTag(c, &tagservicepb.TagMapping{Name: req.TagName})
		if err != nil {
			return &tagservicepb.DeleteTagResponse{}, fmt.Errorf("DeleteTag %s: %v", req.TagName, err)
		}
		return &tagservicepb.DeleteTagResponse{}, nil
	}

	// Delete all children in mapping
	childrenTags, err := s.client.SMembers(c, req.TagName).Result()
	if err != nil {
		return &tagservicepb.DeleteTagResponse{}, fmt.Errorf("DeleteTag %s: %v", req.TagName, err)
	}

	err = s.client.SRem(c, req.TagName, childrenTags).Err()
	if err != nil {
		return &tagservicepb.DeleteTagResponse{}, fmt.Errorf("DeleteTag %s: %v", req.TagName, err)
	}
	return &tagservicepb.DeleteTagResponse{}, nil
}

// Subscribe to a tag
func (s *tagServiceServer) Subscribe(c context.Context, req *tagservicepb.SubscribeRequest) (*tagservicepb.SubscribeResponse, error) {
	err := s.client.SAdd(c, getSubscriptionKey(req.Subscription.TagName), req.Subscription.Subscriber).Err()
	if err != nil {
		return &tagservicepb.SubscribeResponse{}, fmt.Errorf("Subscribe: %v", err)
	}

	return &tagservicepb.SubscribeResponse{}, nil
}

// Unsubscribe from a tag
func (s *tagServiceServer) Unsubscribe(c context.Context, req *tagservicepb.UnsubscribeRequest) (*tagservicepb.UnsubscribeResponse, error) {
	err := s.client.SRem(c, getSubscriptionKey(req.Subscription.TagName), req.Subscription.Subscriber).Err()
	if err != nil {
		return &tagservicepb.UnsubscribeResponse{}, fmt.Errorf("Unsubscribe: %v", err)
	}

	return &tagservicepb.UnsubscribeResponse{}, nil
}

// Get all subscribers to a tag
func (s *tagServiceServer) GetSubscribers(c context.Context, req *tagservicepb.GetSubscribersRequest) (*tagservicepb.GetSubscribersResponse, error) {
	subs, err := s.client.SMembers(c, getSubscriptionKey(req.TagName)).Result()
	if err != nil {
		return nil, fmt.Errorf("GetSubscribers: %v", err)
	}

	return &tagservicepb.GetSubscribersResponse{Subscribers: subs}, nil
}

// Create a server for the tag service
func newServer(database *redis.Client) *tagServiceServer {
	s := &tagServiceServer{client: database}
	return s
}

// Setup and run the server
func Setup(dbPort int, serverPort int, clearKeys bool) {
	// Start the Redis server if it's not already running
	pgrepCmd := exec.Command("pgrep", "redis-server")
	if err := pgrepCmd.Run(); err != nil {
		if err.Error() == "exit status 1" {
			// According to man pgrep, exit status 1 means "no processes matched or none of them could be signalled"
			redisServerCmd := exec.Command("redis-server")
			if err := redisServerCmd.Start(); err != nil {
				fmt.Println("Failed to start redis server")
			}
		} else {
			fmt.Printf("Failed to check if redis-server is already running: %v\n", err.Error())
		}
	}

	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("localhost:%d", dbPort),
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	if clearKeys {
		fmt.Println("Flushed all keys")
		client.FlushAll(context.Background())
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", serverPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	tagservicepb.RegisterTagServiceServer(grpcServer, newServer(client))
	fmt.Printf("Serving TagService at localhost:%d\n", serverPort)
	err = grpcServer.Serve(lis)
	if err != nil {
		fmt.Println(err.Error())
	}
}
