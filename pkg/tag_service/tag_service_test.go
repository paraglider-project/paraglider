//go:build unit

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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	redismock "github.com/go-redis/redismock/v9"
	redis "github.com/redis/go-redis/v9"

	tagservicepb "github.com/paraglider-project/paraglider/pkg/tag_service/tagservicepb"
)

var (
	uriVal = "uri"
	ipVal  = "ip"
)

func newTagServiceServer(database *redis.Client) *tagServiceServer {
	s := &tagServiceServer{client: database}
	return s
}

func TestIsDescendent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	// Test simple case of direct parent/child relationship
	parent := "parent"
	child := "child"
	mock.ExpectType(parent).SetVal("set")
	mock.ExpectSMembers(parent).SetVal([]string{child})
	resp, _ := server.isDescendent(context.Background(), parent, child)
	assert.True(t, resp)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// Test multiple levels of parent/child relationship
	grandchild := "grandchild"
	mock.ExpectType(parent).SetVal("set")
	mock.ExpectSMembers(parent).SetVal([]string{child})
	mock.ExpectType(child).SetVal("set")
	mock.ExpectSMembers(child).SetVal([]string{grandchild})
	resp, _ = server.isDescendent(context.Background(), parent, grandchild)
	assert.True(t, resp)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// Test not a descendent
	mock.ExpectType(parent).SetVal("set")
	mock.ExpectSMembers(parent).SetVal([]string{child})
	mock.ExpectType(child).SetVal("hash")
	resp, _ = server.isDescendent(context.Background(), parent, "not-a-descendent")
	assert.False(t, resp)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestIsLeafTagMapping(t *testing.T) {
	leafTag := &tagservicepb.TagMapping{Name: "tagname", ChildTags: []string{}, Uri: &uriVal, Ip: &ipVal}
	notLeafTag := &tagservicepb.TagMapping{Name: "tagname", ChildTags: []string{"child"}}
	malformedTag := &tagservicepb.TagMapping{Name: "tagname", ChildTags: []string{"child"}, Uri: &uriVal, Ip: &ipVal}

	result, err := isLeafTagMapping(leafTag)
	assert.True(t, result)
	assert.Nil(t, err)

	result, err = isLeafTagMapping(notLeafTag)
	assert.False(t, result)
	assert.Nil(t, err)

	result, err = isLeafTagMapping(malformedTag)
	assert.False(t, result)
	assert.NotNil(t, err)
}

func TestIsLeafTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	leafTag := "leaf"
	mock.ExpectType(leafTag).SetVal("hash")

	result, _ := server.isLeafTag(context.Background(), leafTag)
	assert.True(t, result)

	nonLeafTag := "nonleaflevel"
	mock.ExpectType(nonLeafTag).SetVal("set")

	result, _ = server.isLeafTag(context.Background(), nonLeafTag)
	assert.False(t, result)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestSetLeafTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	newTag := tagservicepb.TagMapping{Name: "tag", Uri: &uriVal, Ip: &ipVal}
	mock.ExpectHExists(newTag.Name, "uri").SetVal(false)
	mock.ExpectHSet(newTag.Name, map[string]string{"uri": *newTag.Uri, "ip": *newTag.Ip}).SetVal(0)

	err := server._setLeafTag(context.Background(), &newTag)

	assert.Nil(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// Test tag already exists
	mock.ExpectHExists(newTag.Name, "uri").SetVal(true)

	err = server._setLeafTag(context.Background(), &newTag)

	assert.NotNil(t, err)

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestSetTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	// Tag mapping to children tags
	newTag := tagservicepb.TagMapping{Name: "parent", ChildTags: []string{"child"}}
	mock.ExpectType(newTag.ChildTags[0]).SetVal("hash")
	mock.ExpectSAdd(newTag.Name, newTag.ChildTags).SetVal(0)

	_, err := server.SetTag(context.Background(), &tagservicepb.SetTagRequest{Tag: &newTag})

	assert.Nil(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// Leaf tag mapping
	newTag = tagservicepb.TagMapping{Name: "tag", Uri: &uriVal, Ip: &ipVal}
	mock.ExpectHExists(newTag.Name, "uri").SetVal(false)
	mock.ExpectHSet(newTag.Name, map[string]string{"uri": *newTag.Uri, "ip": *newTag.Ip}).SetVal(0)

	_, err = server.SetTag(context.Background(), &tagservicepb.SetTagRequest{Tag: &newTag})

	assert.Nil(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGetTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	// Non-leaf tag
	tag := &tagservicepb.TagMapping{Name: "parent", ChildTags: []string{"child"}}
	mock.ExpectType(tag.Name).SetVal("set")
	mock.ExpectSMembers(tag.Name).SetVal(tag.ChildTags)
	resp, err := server.GetTag(context.Background(), &tagservicepb.GetTagRequest{TagName: tag.Name})
	assert.Nil(t, err)
	assert.Equal(t, resp.Tag, tag)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// Leaf tag
	tag = &tagservicepb.TagMapping{Name: "tag", Uri: &uriVal, Ip: &ipVal}
	mock.ExpectType(tag.Name).SetVal("hash")
	mock.ExpectHGetAll(tag.Name).SetVal(map[string]string{"uri": *tag.Uri, "ip": *tag.Ip})
	resp, err = server.GetTag(context.Background(), &tagservicepb.GetTagRequest{TagName: tag.Name})
	assert.Nil(t, err)
	assert.Equal(t, resp.Tag, tag)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGetTagNotPresent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{Name: "parent", ChildTags: []string{"child"}}
	mock.ExpectType(tag.Name).SetVal("set")
	mock.ExpectSMembers(tag.Name).SetErr(errors.New("no such tag present"))
	resp, err := server.GetTag(context.Background(), &tagservicepb.GetTagRequest{TagName: tag.Name})
	var nilresult *tagservicepb.GetTagResponse
	assert.ErrorContains(t, err, "no such tag present")
	assert.Equal(t, resp, nilresult)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestResolveTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	childMapping := &tagservicepb.TagMapping{Name: "child1", Uri: &uriVal, Ip: &ipVal}
	childIp := "1.2.3.4"
	mapping := &tagservicepb.TagMapping{Name: "parent", ChildTags: []string{childMapping.Name, childIp}}
	mock.ExpectType(mapping.Name).SetVal("set")
	mock.ExpectSMembers(mapping.Name).SetVal(mapping.ChildTags)
	mock.ExpectType(childMapping.Name).SetVal("hash")
	mock.ExpectHGetAll(childMapping.Name).SetVal(map[string]string{"uri": *childMapping.Uri, "ip": *childMapping.Ip})

	resp, err := server.ResolveTag(context.Background(), &tagservicepb.ResolveTagRequest{TagName: mapping.Name})
	assert.Nil(t, err)
	assert.Equal(t, resp.Tags[0], childMapping)
	assert.Equal(t, *(resp.Tags[1].Ip), childIp)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestResolveTagMemberNotPresent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	childMapping := &tagservicepb.TagMapping{Name: "child1", Uri: &uriVal, Ip: &ipVal}
	childIp := "1.2.3.4"
	mapping := &tagservicepb.TagMapping{Name: "parent", ChildTags: []string{childMapping.Name, "non-existent-tag", childIp}}
	mock.ExpectType(mapping.Name).SetVal("set")
	mock.ExpectSMembers(mapping.Name).SetVal(mapping.ChildTags)
	mock.ExpectType(childMapping.Name).SetVal("hash")
	mock.ExpectHGetAll(childMapping.Name).SetVal(map[string]string{"uri": *childMapping.Uri, "ip": *childMapping.Ip})
	mock.ExpectType("non-existent-tag").SetVal("none")

	resp, err := server.ResolveTag(context.Background(), &tagservicepb.ResolveTagRequest{TagName: mapping.Name})
	assert.Nil(t, err)
	assert.Equal(t, resp.Tags[0], childMapping)
	assert.Equal(t, *(resp.Tags[1].Ip), childIp)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteTagMember(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{Name: "parent", ChildTags: []string{"child1", "child2"}}
	mock.ExpectSRem(tag.Name, tag.ChildTags[0]).SetVal(0)
	_, err := server.DeleteTagMember(context.Background(), &tagservicepb.DeleteTagMemberRequest{ParentTag: tag.Name, ChildTag: tag.ChildTags[0]})
	assert.Nil(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteTagMemberNotPresent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{Name: "parent", ChildTags: []string{"child"}}
	mock.ExpectSRem(tag.Name, tag.ChildTags).SetErr(errors.New("no such tag present"))
	_, err := server.DeleteTagMember(context.Background(), &tagservicepb.DeleteTagMemberRequest{ParentTag: tag.Name, ChildTag: tag.ChildTags[0]})
	assert.NotNil(t, err)
	assert.ErrorContains(t, err, "no such tag present")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	// Non-leaf tag
	tag := &tagservicepb.TagMapping{Name: "parent", ChildTags: []string{"child1", "child2"}}
	mock.ExpectType(tag.Name).SetVal("set")
	mock.ExpectSMembers(tag.Name).SetVal(tag.ChildTags)
	mock.ExpectSRem(tag.Name, tag.ChildTags).SetVal(0)
	_, err := server.DeleteTag(context.Background(), &tagservicepb.DeleteTagRequest{TagName: tag.Name})
	assert.Nil(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// Leaf tag
	tag = &tagservicepb.TagMapping{Name: "tag", Uri: &uriVal, Ip: &ipVal}
	keys := []string{"uri", "ip"}
	mock.ExpectType(tag.Name).SetVal("hash")
	mock.ExpectHKeys(tag.Name).SetVal(keys)
	mock.ExpectHDel(tag.Name, keys...).SetVal(0)
	_, err = server.DeleteTag(context.Background(), &tagservicepb.DeleteTagRequest{TagName: tag.Name})
	assert.Nil(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteTagNotPresent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{Name: "parent", ChildTags: []string{"child1", "child2"}}
	mock.ExpectType(tag.Name).SetVal("set")
	mock.ExpectSMembers(tag.Name).SetErr(errors.New("no such tag present"))
	_, err := server.DeleteTag(context.Background(), &tagservicepb.DeleteTagRequest{TagName: tag.Name})
	assert.NotNil(t, err)
	assert.ErrorContains(t, err, "no such tag present")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteLeafTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	keys := []string{"uri", "ip"}
	nameMapping := &tagservicepb.TagMapping{Name: "example", Uri: &uriVal, Ip: &ipVal}
	mock.ExpectHKeys(nameMapping.Name).SetVal(keys)
	mock.ExpectHDel(nameMapping.Name, keys...).SetVal(0)
	err := server._deleteLeafTag(context.Background(), &tagservicepb.TagMapping{Name: nameMapping.Name})
	assert.Nil(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestSubscribe(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	sub := &tagservicepb.Subscription{TagName: "example", Subscriber: "sub/uri"}
	mock.ExpectSAdd("SUB:"+sub.TagName, sub.Subscriber).SetVal(0)
	_, err := server.Subscribe(context.Background(), &tagservicepb.SubscribeRequest{Subscription: sub})
	assert.Nil(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestUnsubscribe(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	sub := &tagservicepb.Subscription{TagName: "example", Subscriber: "sub/uri"}
	mock.ExpectSRem("SUB:"+sub.TagName, sub.Subscriber).SetVal(0)
	_, err := server.Unsubscribe(context.Background(), &tagservicepb.UnsubscribeRequest{Subscription: sub})
	assert.Nil(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGetSubscribers(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := "example"
	subscribers := []string{"uri1", "uri2"}
	mock.ExpectSMembers("SUB:" + tag).SetVal(subscribers)
	resp, _ := server.GetSubscribers(context.Background(), &tagservicepb.GetSubscribersRequest{TagName: tag})
	assert.Equal(t, subscribers, resp.Subscribers)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}
