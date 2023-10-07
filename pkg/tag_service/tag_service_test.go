//go:build unit

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

// TODO: Test the new helper functions

package tagservice

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	redismock "github.com/go-redis/redismock/v9"
	redis "github.com/redis/go-redis/v9"

	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
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

func TestIsLastLevelTagMapping(t *testing.T) {
	lastLevelTag := &tagservicepb.TagMapping{TagName: "tagname", ChildTags: []string{}, Uri: &uriVal, Ip: &ipVal}
	notLastLevelTag := &tagservicepb.TagMapping{TagName: "tagname", ChildTags: []string{"child"}}
	malformedTag := &tagservicepb.TagMapping{TagName: "tagname", ChildTags: []string{"child"}, Uri: &uriVal, Ip: &ipVal}

	result, err := isLastLevelTagMapping(lastLevelTag)
	assert.True(t, result)
	assert.Nil(t, err)

	result, err = isLastLevelTagMapping(notLastLevelTag)
	assert.False(t, result)
	assert.Nil(t, err)

	result, err = isLastLevelTagMapping(malformedTag)
	assert.False(t, result)
	assert.NotNil(t, err)
}

func TestIsLastLevelTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	lastLevelTag := &tagservicepb.Tag{TagName: "lastlevel"}
	mock.ExpectType(lastLevelTag.TagName).SetVal("hash")

	result, _ := server.isLastLevelTag(context.Background(), lastLevelTag)
	assert.True(t, result)

	nonLastLevelTag := &tagservicepb.Tag{TagName: "nonlastlevel"}
	mock.ExpectType(nonLastLevelTag.TagName).SetVal("set")

	result, _ = server.isLastLevelTag(context.Background(), nonLastLevelTag)
	assert.False(t, result)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestSetLastLevelTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	newTag := tagservicepb.TagMapping{TagName: "tag", Uri: &uriVal, Ip: &ipVal}
	mock.ExpectHSet(newTag.TagName, map[string]string{"uri": *newTag.Uri, "ip": *newTag.Ip}).SetVal(0)

	err := server._setLastLevelTag(context.Background(), &newTag)

	assert.Nil(t, err)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestSetTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	// Tag mapping to children tags
	newTag := tagservicepb.TagMapping{TagName: "parent", ChildTags: []string{"child"}}
	mock.ExpectType(newTag.ChildTags[0]).SetVal("hash")
	mock.ExpectSAdd(newTag.TagName, newTag.ChildTags).SetVal(0)

	resp, _ := server.SetTag(context.Background(), &newTag)

	assert.True(t, resp.Success)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// Last-level tag mapping
	newTag = tagservicepb.TagMapping{TagName: "tag", Uri: &uriVal, Ip: &ipVal}
	mock.ExpectHSet(newTag.TagName, map[string]string{"uri": *newTag.Uri, "ip": *newTag.Ip}).SetVal(0)

	resp, _ = server.SetTag(context.Background(), &newTag)

	assert.True(t, resp.Success)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGetTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	// Non-last-level tag
	tag := &tagservicepb.TagMapping{TagName: "parent", ChildTags: []string{"child"}}
	mock.ExpectType(tag.TagName).SetVal("set")
	mock.ExpectSMembers(tag.TagName).SetVal(tag.ChildTags)
	resp, _ := server.GetTag(context.Background(), &tagservicepb.Tag{TagName: tag.TagName})
	assert.Equal(t, resp, tag)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// Last-level tag
	tag = &tagservicepb.TagMapping{TagName: "tag", Uri: &uriVal, Ip: &ipVal}
	mock.ExpectType(tag.TagName).SetVal("hash")
	mock.ExpectHGetAll(tag.TagName).SetVal(map[string]string{"uri": *tag.Uri, "ip": *tag.Ip})
	resp, _ = server.GetTag(context.Background(), &tagservicepb.Tag{TagName: tag.TagName})
	assert.Equal(t, resp, tag)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGetTagNotPresent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{TagName: "parent", ChildTags: []string{"child"}}
	mock.ExpectType(tag.TagName).SetVal("set")
	mock.ExpectSMembers(tag.TagName).SetErr(errors.New("no such tag present"))
	resp, err := server.GetTag(context.Background(), &tagservicepb.Tag{TagName: tag.TagName})
	var nilresult *tagservicepb.TagMapping
	assert.ErrorContains(t, err, "no such tag present")
	assert.Equal(t, resp, nilresult)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestResolveTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	childMapping := &tagservicepb.TagMapping{TagName: "child1", Uri: &uriVal, Ip: &ipVal}
	childIp := "1.2.3.4"
	mapping := &tagservicepb.TagMapping{TagName: "parent", ChildTags: []string{childMapping.TagName, childIp}}
	mock.ExpectType(mapping.TagName).SetVal("set")
	mock.ExpectSMembers(mapping.TagName).SetVal(mapping.ChildTags)
	mock.ExpectType(childMapping.TagName).SetVal("hash")
	mock.ExpectHGetAll(childMapping.TagName).SetVal(map[string]string{"uri": *childMapping.Uri, "ip": *childMapping.Ip})

	resp, err := server.ResolveTag(context.Background(), &tagservicepb.Tag{TagName: mapping.TagName})
	assert.Nil(t, err)
	assert.Equal(t, resp.Mappings[0], childMapping)
	assert.Equal(t, *(resp.Mappings[1].Ip), childIp)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestResolveTagMemberNotPresent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	childMapping := &tagservicepb.TagMapping{TagName: "child1", Uri: &uriVal, Ip: &ipVal}
	childIp := "1.2.3.4"
	mapping := &tagservicepb.TagMapping{TagName: "parent", ChildTags: []string{childMapping.TagName, "non-existent-tag", childIp}}
	mock.ExpectType(mapping.TagName).SetVal("set")
	mock.ExpectSMembers(mapping.TagName).SetVal(mapping.ChildTags)
	mock.ExpectType(childMapping.TagName).SetVal("hash")
	mock.ExpectHGetAll(childMapping.TagName).SetVal(map[string]string{"uri": *childMapping.Uri, "ip": *childMapping.Ip})
	mock.ExpectType("non-existent-tag").SetVal("none")

	resp, err := server.ResolveTag(context.Background(), &tagservicepb.Tag{TagName: mapping.TagName})
	assert.Nil(t, err)
	assert.Equal(t, resp.Mappings[0], childMapping)
	assert.Equal(t, *(resp.Mappings[1].Ip), childIp)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteTagMember(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{TagName: "parent", ChildTags: []string{"child1", "child2"}}
	mock.ExpectSRem(tag.TagName, tag.ChildTags).SetVal(0)
	resp, _ := server.DeleteTagMember(context.Background(), tag)
	assert.True(t, resp.Success)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteTagMemberNotPresent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{TagName: "parent", ChildTags: []string{"child"}}
	mock.ExpectSRem(tag.TagName, tag.ChildTags).SetErr(errors.New("no such tag present"))
	resp, err := server.DeleteTagMember(context.Background(), tag)
	assert.False(t, resp.Success)
	assert.ErrorContains(t, err, "no such tag present")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	// Non-last-level tag
	tag := &tagservicepb.TagMapping{TagName: "parent", ChildTags: []string{"child1", "child2"}}
	mock.ExpectType(tag.TagName).SetVal("set")
	mock.ExpectSMembers(tag.TagName).SetVal(tag.ChildTags)
	mock.ExpectSRem(tag.TagName, tag.ChildTags).SetVal(0)
	resp, _ := server.DeleteTag(context.Background(), &tagservicepb.Tag{TagName: tag.TagName})
	assert.True(t, resp.Success)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// Last-level tag
	tag = &tagservicepb.TagMapping{TagName: "tag", Uri: &uriVal, Ip: &ipVal}
	keys := []string{"uri", "ip"}
	mock.ExpectType(tag.TagName).SetVal("hash")
	mock.ExpectHKeys(tag.TagName).SetVal(keys)
	mock.ExpectHDel(tag.TagName, keys...).SetVal(0)
	resp, _ = server.DeleteTag(context.Background(), &tagservicepb.Tag{TagName: tag.TagName})
	assert.True(t, resp.Success)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteTagNotPresent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{TagName: "parent", ChildTags: []string{"child1", "child2"}}
	mock.ExpectType(tag.TagName).SetVal("set")
	mock.ExpectSMembers(tag.TagName).SetErr(errors.New("no such tag present"))
	resp, err := server.DeleteTag(context.Background(), &tagservicepb.Tag{TagName: tag.TagName})
	assert.False(t, resp.Success)
	assert.ErrorContains(t, err, "no such tag present")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteLastLevelTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	keys := []string{"uri", "ip"}
	nameMapping := &tagservicepb.TagMapping{TagName: "example", Uri: &uriVal, Ip: &ipVal}
	mock.ExpectHKeys(nameMapping.TagName).SetVal(keys)
	mock.ExpectHDel(nameMapping.TagName, keys...).SetVal(0)
	err := server._deleteLastLevelTag(context.Background(), &tagservicepb.Tag{TagName: nameMapping.TagName})
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
	resp, _ := server.Subscribe(context.Background(), sub)
	assert.True(t, resp.Success)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestUnsubscribe(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	sub := &tagservicepb.Subscription{TagName: "example", Subscriber: "sub/uri"}
	mock.ExpectSRem("SUB:"+sub.TagName, sub.Subscriber).SetVal(0)
	resp, _ := server.Unsubscribe(context.Background(), sub)
	assert.True(t, resp.Success)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGetSubscribers(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.Tag{TagName: "example"}
	subscribers := []string{"uri1", "uri2"}
	mock.ExpectSMembers("SUB:" + tag.TagName).SetVal(subscribers)
	resp, _ := server.GetSubscribers(context.Background(), tag)
	assert.Equal(t, subscribers, resp.Subscribers)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}
