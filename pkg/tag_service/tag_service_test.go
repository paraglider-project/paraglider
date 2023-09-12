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
