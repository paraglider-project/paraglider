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

// TODO: Add a test case where a tag member is being resolved but no longer exists

package tagservice

import (
	"testing"
	"context"
	"github.com/stretchr/testify/assert"
	"errors"

	redis "github.com/redis/go-redis/v9"
	redismock "github.com/go-redis/redismock/v9"
	
	tagservicepb "github.com/NetSys/invisinets/pkg/tag_service/tagservicepb"
)

func newTagServiceServer(database *redis.Client) *tagServiceServer {
	s := &tagServiceServer{client: database}
	return s
}
// TODO: UPDATE THE TESTS!!
func TestSetTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	newTag := tagservicepb.TagMapping{ParentTag: "parent", ChildTags: []string{"child"}}
	mock.ExpectSAdd(newTag.ParentTag, newTag.ChildTags).SetVal(0)
	
	resp, _ := server.SetTag(context.Background(), &newTag)
	
	assert.True(t, resp.Success)
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestSetName(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	name := &tagservicepb.NameMapping{TagName: "example", Uri: "resource/id", Ip:"1.2.3.4"}
	mock.ExpectHSet(name.TagName, map[string]string{"uri": name.Uri, "ip": name.Ip}).SetVal(0)
	resp, _ := server.SetName(context.Background(), name)
	assert.True(t, resp.Success)
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGetTag(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{ParentTag: "parent", ChildTags: []string{"child"}}
	mock.ExpectSMembers(tag.ParentTag).SetVal(tag.ChildTags)
	resp, _ := server.GetTag(context.Background(), &tagservicepb.Tag{TagName: tag.ParentTag})
	assert.Equal(t, resp, tag)
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGetTagNotPresent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{ParentTag: "parent", ChildTags: []string{"child"}}
	mock.ExpectSMembers(tag.ParentTag).SetErr(errors.New("no such tag present"))
	resp, err := server.GetTag(context.Background(), &tagservicepb.Tag{TagName: tag.ParentTag})
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

	childMapping := &tagservicepb.NameMapping{TagName: "child1", Uri: "child/uri", Ip: "2.3.4.5"}
	childIp := "1.2.3.4"
	mapping := &tagservicepb.TagMapping{ParentTag: "parent", ChildTags: []string{childMapping.TagName, childIp}}
	mock.ExpectHExists(mapping.ParentTag, "uri").SetVal(false)
	mock.ExpectSMembers(mapping.ParentTag).SetVal(mapping.ChildTags)
	mock.ExpectHExists(childMapping.TagName, "uri").SetVal(true)
	mock.ExpectHGetAll(childMapping.TagName).SetVal(map[string]string{"uri": childMapping.Uri, "ip": childMapping.Ip})
	
	resp, err := server.ResolveTag(context.Background(), &tagservicepb.Tag{TagName: mapping.ParentTag})
	assert.Nil(t, err)
	assert.Equal(t, resp.Mappings[0], childMapping)
	assert.Equal(t, resp.Mappings[1].Ip, childIp)
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteTagMember(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{ParentTag: "parent", ChildTags: []string{"child1", "child2"}}
	mock.ExpectSRem(tag.ParentTag, tag.ChildTags).SetVal(0)
	resp, _ := server.DeleteTagMember(context.Background(), tag)
	assert.True(t, resp.Success)
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteTagMemberNotPresent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{ParentTag: "parent", ChildTags: []string{"child"}}
	mock.ExpectSRem(tag.ParentTag, tag.ChildTags).SetErr(errors.New("no such tag present"))
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

	tag := &tagservicepb.TagMapping{ParentTag: "parent", ChildTags: []string{"child1", "child2"}}
	mock.ExpectSMembers(tag.ParentTag).SetVal(tag.ChildTags)
	mock.ExpectSRem(tag.ParentTag, tag.ChildTags).SetVal(0)
	resp, _ := server.DeleteTag(context.Background(), &tagservicepb.Tag{TagName: tag.ParentTag})
	assert.True(t, resp.Success)
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteTagNotPresent(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	tag := &tagservicepb.TagMapping{ParentTag: "parent", ChildTags: []string{"child1", "child2"}}
	mock.ExpectSMembers(tag.ParentTag).SetErr(errors.New("no such tag present"))
	resp, err := server.DeleteTag(context.Background(), &tagservicepb.Tag{TagName: tag.ParentTag})
	assert.False(t, resp.Success)
	assert.ErrorContains(t, err, "no such tag present")
	
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestDeleteName(t *testing.T) {
	db, mock := redismock.NewClientMock()
	server := newTagServiceServer(db)

	keys := []string{"uri", "ip"}
	nameMapping := &tagservicepb.NameMapping{TagName: "example", Uri: "example/uri", Ip: "1.2.3.4"}
	mock.ExpectHKeys(nameMapping.TagName).SetVal(keys)
	mock.ExpectHDel(nameMapping.TagName, keys...).SetVal(0)
	resp, _ := server.DeleteName(context.Background(), &tagservicepb.Tag{TagName: nameMapping.TagName})
	assert.True(t, resp.Success)
	
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
